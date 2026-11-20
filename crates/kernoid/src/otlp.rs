// SPDX-License-Identifier: AGPL-3.0-or-later
//! Traces to an OpenTelemetry collector, kernoid's own: a `tracing` layer that turns closed spans into OTLP spans and
//! sends them in batches over OTLP/HTTP with binary protobuf (OpenTelemetry Protocol 1.x, `ExportTraceServiceRequest`
//! of `opentelemetry/proto/collector/trace/v1`) to `log.otlp_endpoint`.
//!
//! - **Spans** keep their parent within the process, their fields as attributes, the events logged in them as span
//!   events (an `ERROR` event marks the span as failed), and the fields `otel.name`, `otel.kind`,
//!   `otel.status_code` and `otel.status_message` of the OpenTelemetry conventions. Trace ids are new for every
//!   root span: kernoid neither reads nor sends `traceparent`.
//! - **The resource** is `service.name = kernoid` with what `OTEL_RESOURCE_ATTRIBUTES` adds.
//! - **Sending** happens on a thread of its own, in batches of at most [`BATCH`] spans or every [`EVERY`]; at most
//!   [`QUEUE`] spans wait – more are dropped, so that a collector that is away never holds the process up. A batch the
//!   collector refuses for a while (429, 502, 503, 504) is tried again up to three times, after its `Retry-After`.

use std::{
    fmt::Debug,
    sync::mpsc::{Receiver, RecvTimeoutError, SyncSender},
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

/// Most spans in one request.
const BATCH: usize = 512;
/// Longest a finished span waits before it is sent.
const EVERY: Duration = Duration::from_secs(5);
/// Most spans waiting to be sent.
const QUEUE: usize = 2048;
/// Longest the exporter waits for the collector at exit.
const SHUTDOWN: Duration = Duration::from_secs(5);

/// The layer and the exporter behind it.
pub fn exporter(endpoint: &str) -> Result<(OtlpLayer, Exporter), String> {
    let url = reqwest::Url::parse(endpoint).map_err(|e| format!("{endpoint:?} is not a URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{endpoint:?} is not an HTTP URL"));
    }
    let (sender, receiver) = std::sync::mpsc::sync_channel(QUEUE);
    let resource = resource(std::env::var("OTEL_RESOURCE_ATTRIBUTES").ok().as_deref());
    let thread = std::thread::Builder::new()
        .name("otlp".into())
        .spawn(move || send_batches(url, resource, receiver))
        .map_err(|e| format!("cannot start the exporter: {e}"))?;
    Ok((OtlpLayer { sender: sender.clone() }, Exporter { sender, thread: Some(thread) }))
}

/// Sends what is left and stops – at exit.
#[derive(Debug)]
pub struct Exporter {
    sender: SyncSender<Message>,
    thread: Option<JoinHandle<()>>,
}

impl Exporter {
    pub fn shutdown(mut self) {
        let _ = self.sender.send(Message::Stop);
        if let Some(thread) = self.thread.take() {
            let started = Instant::now();
            while !thread.is_finished() && started.elapsed() < SHUTDOWN + Duration::from_secs(1) {
                std::thread::sleep(Duration::from_millis(20));
            }
            if thread.is_finished() {
                let _ = thread.join();
            }
        }
    }
}

enum Message {
    Span(Box<SpanData>),
    Stop,
}

/// The layer: it records spans while they are open and queues them when they close.
#[derive(Debug, Clone)]
pub struct OtlpLayer {
    sender: SyncSender<Message>,
}

/// A span as OTLP describes it.
#[derive(Debug, Clone)]
struct SpanData {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    name: String,
    kind: u64,
    start: u64,
    end: u64,
    attributes: Vec<(String, Value)>,
    events: Vec<SpanEvent>,
    /// 0 unset, 1 ok, 2 error.
    status: u64,
    status_message: String,
}

#[derive(Debug, Clone)]
struct SpanEvent {
    time: u64,
    name: String,
    attributes: Vec<(String, Value)>,
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    String(String),
    Bool(bool),
    Int(i64),
    Double(f64),
}

/// Nanoseconds since the Unix epoch.
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_nanos() as u64)
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    // An id of zeros is invalid; the system's generator does not fail in practice, and if it did, the clock serves.
    if getrandom::fill(&mut bytes).is_err() || bytes.iter().all(|b| *b == 0) {
        let fallback = now().to_le_bytes();
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = fallback[i % 8] ^ (i as u8 + 1);
        }
    }
    bytes
}

/// Fields as attributes; `otel.*` fields set the span's name, kind and status instead.
struct Fields<'a> {
    attributes: &'a mut Vec<(String, Value)>,
    message: Option<&'a mut Option<String>>,
}

impl Fields<'_> {
    fn put(&mut self, field: &Field, value: Value) {
        if field.name() == "message"
            && let (Some(message), Value::String(text)) = (self.message.as_mut(), &value)
        {
            **message = Some(text.clone());
            return;
        }
        let name = field.name().strip_prefix("r#").unwrap_or(field.name());
        match self.attributes.iter_mut().find(|(key, _)| key == name) {
            Some((_, existing)) => *existing = value,
            None => self.attributes.push((name.to_owned(), value)),
        }
    }
}

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.put(field, Value::String(format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, Value::String(value.to_owned()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, Value::Int(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match i64::try_from(value) {
            Ok(value) => self.put(field, Value::Int(value)),
            Err(_) => self.put(field, Value::String(value.to_string())),
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, Value::Double(value));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field, Value::String(value.to_string()));
    }
}

/// Moves the `otel.*` attributes into the span.
fn apply_conventions(span: &mut SpanData) {
    span.attributes.retain(|(key, value)| {
        let text = match value {
            Value::String(text) => text.clone(),
            other => format!("{other:?}"),
        };
        match key.as_str() {
            "otel.name" => span.name = text,
            "otel.kind" => {
                span.kind = match text.to_ascii_lowercase().as_str() {
                    "server" => 2,
                    "client" => 3,
                    "producer" => 4,
                    "consumer" => 5,
                    _ => 1,
                };
            }
            "otel.status_code" => {
                span.status = match text.to_ascii_lowercase().as_str() {
                    "ok" => 1,
                    "error" => 2,
                    _ => 0,
                };
            }
            "otel.status_message" => span.status_message = text,
            _ => return true,
        }
        false
    });
}

impl<S> Layer<S> for OtlpLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let parent = match attrs.parent() {
            Some(parent) => ctx.span(parent),
            None if attrs.is_contextual() => ctx.lookup_current(),
            None => None,
        };
        let parent =
            parent.and_then(|parent| parent.extensions().get::<SpanData>().map(|data| (data.trace_id, data.span_id)));
        let mut data = SpanData {
            trace_id: parent.map_or_else(random, |(trace, _)| trace),
            span_id: random(),
            parent_span_id: parent.map(|(_, span)| span),
            name: attrs.metadata().name().to_owned(),
            kind: 1,
            start: now(),
            end: 0,
            attributes: Vec::new(),
            events: Vec::new(),
            status: 0,
            status_message: String::new(),
        };
        attrs.record(&mut Fields { attributes: &mut data.attributes, message: None });
        span.extensions_mut().insert(data);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(data) = span.extensions_mut().get_mut::<SpanData>()
        {
            values.record(&mut Fields { attributes: &mut data.attributes, message: None });
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.event_span(event) else { return };
        let mut extensions = span.extensions_mut();
        let Some(data) = extensions.get_mut::<SpanData>() else { return };
        let metadata = event.metadata();
        let mut message = None;
        let mut attributes = vec![
            ("level".to_owned(), Value::String(metadata.level().as_str().to_owned())),
            ("target".to_owned(), Value::String(metadata.target().to_owned())),
        ];
        event.record(&mut Fields { attributes: &mut attributes, message: Some(&mut message) });
        if *metadata.level() == tracing::Level::ERROR && data.status == 0 {
            data.status = 2;
            data.status_message = message.clone().unwrap_or_default();
        }
        if data.events.len() < 128 {
            data.events.push(SpanEvent {
                time: now(),
                name: message.unwrap_or_else(|| metadata.name().to_owned()),
                attributes,
            });
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let Some(mut data) = span.extensions_mut().remove::<SpanData>() else { return };
        data.end = now();
        apply_conventions(&mut data);
        // A full queue drops the span: the collector is away or slow, and kernoid goes on.
        let _ = self.sender.try_send(Message::Span(Box::new(data)));
    }
}

/// `service.name` and the attributes of `OTEL_RESOURCE_ATTRIBUTES` (`key=value,…`, values percent-encoded).
fn resource(variable: Option<&str>) -> Vec<(String, Value)> {
    let mut attributes = vec![("service.name".to_owned(), Value::String("kernoid".into()))];
    for pair in variable.unwrap_or_default().split(',') {
        let Some((key, value)) = pair.split_once('=') else { continue };
        let (key, value) = (key.trim(), percent_encoding::percent_decode_str(value.trim()).decode_utf8_lossy());
        if key.is_empty() || key == "service.name" {
            continue;
        }
        attributes.push((key.to_owned(), Value::String(value.into_owned())));
    }
    attributes
}

/// The exporter's thread: its own runtime, and no subscriber, so that sending makes no spans of its own.
fn send_batches(url: reqwest::Url, resource: Vec<(String, Value)>, receiver: Receiver<Message>) {
    let _quiet = tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::default());
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).build() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("OTLP: no HTTP client: {error}");
            return;
        }
    };
    let mut batch = Vec::new();
    let mut failing = false;
    let mut deadline = Instant::now() + EVERY;
    loop {
        let stop = match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Message::Span(span)) => {
                batch.push(*span);
                false
            }
            Ok(Message::Stop) | Err(RecvTimeoutError::Disconnected) => true,
            Err(RecvTimeoutError::Timeout) => false,
        };
        if stop || batch.len() >= BATCH || Instant::now() >= deadline {
            if !batch.is_empty() {
                let body = encode_request(&resource, &batch);
                batch.clear();
                let patience = if stop { SHUTDOWN } else { Duration::from_secs(60) };
                match runtime.block_on(send(&client, &url, body, patience)) {
                    Ok(()) => failing = false,
                    Err(error) if !failing => {
                        // Once per outage, not for every batch.
                        eprintln!("OTLP: spans dropped: {error}");
                        failing = true;
                    }
                    Err(_) => {}
                }
            }
            deadline = Instant::now() + EVERY;
        }
        if stop {
            return;
        }
    }
}

/// One request, tried again while the collector asks for it and `patience` allows.
async fn send(client: &reqwest::Client, url: &reqwest::Url, body: Vec<u8>, patience: Duration) -> Result<(), String> {
    let started = Instant::now();
    let mut pause = Duration::from_secs(1);
    for attempt in 0..4 {
        let response = client
            .post(url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .body(body.clone())
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let again = matches!(status.as_u16(), 429 | 502 | 503 | 504);
        let wait = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()?.trim().parse::<u64>().ok())
            .map_or(pause, Duration::from_secs);
        if !again || attempt == 3 || started.elapsed() + wait > patience {
            return Err(format!("the collector answered {status}"));
        }
        tokio::time::sleep(wait).await;
        pause *= 2;
    }
    Err("the collector kept refusing".into())
}

/// Protocol buffers' wire format, as far as OTLP needs it.
#[derive(Default)]
struct Protobuf(Vec<u8>);

impl Protobuf {
    fn varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.0.push((value as u8) | 0x80);
            value >>= 7;
        }
        self.0.push(value as u8);
    }

    fn tag(&mut self, field: u64, wire_type: u64) {
        self.varint((field << 3) | wire_type);
    }

    fn uint(&mut self, field: u64, value: u64) {
        if value != 0 {
            self.tag(field, 0);
            self.varint(value);
        }
    }

    fn fixed64(&mut self, field: u64, value: u64) {
        self.tag(field, 1);
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn bytes(&mut self, field: u64, value: &[u8]) {
        self.tag(field, 2);
        self.varint(value.len() as u64);
        self.0.extend_from_slice(value);
    }

    fn string(&mut self, field: u64, value: &str) {
        if !value.is_empty() {
            self.bytes(field, value.as_bytes());
        }
    }

    fn message(&mut self, field: u64, build: impl FnOnce(&mut Protobuf)) {
        let mut inner = Protobuf::default();
        build(&mut inner);
        self.bytes(field, &inner.0);
    }

    /// `KeyValue { string key = 1; AnyValue value = 2; }`
    fn attribute(&mut self, field: u64, key: &str, value: &Value) {
        self.message(field, |pair| {
            pair.string(1, key);
            // AnyValue: string 1, bool 2, int64 3, double 4.
            pair.message(2, |any| match value {
                Value::String(text) => any.bytes(1, text.as_bytes()),
                Value::Bool(flag) => {
                    any.tag(2, 0);
                    any.varint(u64::from(*flag));
                }
                Value::Int(number) => {
                    any.tag(3, 0);
                    any.varint(*number as u64);
                }
                Value::Double(number) => any.fixed64(4, number.to_bits()),
            });
        });
    }
}

/// `ExportTraceServiceRequest { repeated ResourceSpans resource_spans = 1; }` with one resource and one scope.
fn encode_request(resource: &[(String, Value)], spans: &[SpanData]) -> Vec<u8> {
    let mut request = Protobuf::default();
    // ResourceSpans { Resource resource = 1; repeated ScopeSpans scope_spans = 2; }
    request.message(1, |resource_spans| {
        // Resource { repeated KeyValue attributes = 1; }
        resource_spans.message(1, |message| {
            for (key, value) in resource {
                message.attribute(1, key, value);
            }
        });
        // ScopeSpans { InstrumentationScope scope = 1; repeated Span spans = 2; }
        resource_spans.message(2, |scope_spans| {
            scope_spans.message(1, |scope| {
                scope.string(1, "kernoid");
                scope.string(2, env!("CARGO_PKG_VERSION"));
            });
            for span in spans {
                scope_spans.message(2, |message| encode_span(message, span));
            }
        });
    });
    request.0
}

/// `Span`: trace_id 1, span_id 2, parent_span_id 4, name 5, kind 6, start 7, end 8, attributes 9, events 11,
/// status 15 (`Status { string message = 2; StatusCode code = 3; }`).
fn encode_span(message: &mut Protobuf, span: &SpanData) {
    message.bytes(1, &span.trace_id);
    message.bytes(2, &span.span_id);
    if let Some(parent) = &span.parent_span_id {
        message.bytes(4, parent);
    }
    message.string(5, &span.name);
    message.uint(6, span.kind);
    message.fixed64(7, span.start);
    message.fixed64(8, span.end);
    for (key, value) in &span.attributes {
        message.attribute(9, key, value);
    }
    // Event { fixed64 time_unix_nano = 1; string name = 2; repeated KeyValue attributes = 3; }
    for event in &span.events {
        message.message(11, |encoded| {
            encoded.fixed64(1, event.time);
            encoded.string(2, &event.name);
            for (key, value) in &event.attributes {
                encoded.attribute(3, key, value);
            }
        });
    }
    if span.status != 0 {
        message.message(15, |status| {
            status.string(2, &span.status_message);
            status.uint(3, span.status);
        });
    }
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    /// A reader of the wire format for the tests: the fields of a message in order.
    fn fields(mut bytes: &[u8]) -> Vec<(u64, Field2)> {
        fn varint(bytes: &mut &[u8]) -> u64 {
            let mut value = 0;
            for shift in (0..64).step_by(7) {
                let byte = bytes[0];
                *bytes = &bytes[1..];
                value |= u64::from(byte & 0x7f) << shift;
                if byte < 0x80 {
                    break;
                }
            }
            value
        }
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let key = varint(&mut bytes);
            let field = match key & 7 {
                0 => Field2::Varint(varint(&mut bytes)),
                1 => {
                    let value = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                    bytes = &bytes[8..];
                    Field2::Fixed(value)
                }
                2 => {
                    let length = varint(&mut bytes) as usize;
                    let value = bytes[..length].to_vec();
                    bytes = &bytes[length..];
                    Field2::Bytes(value)
                }
                other => panic!("wire type {other}"),
            };
            out.push((key >> 3, field));
        }
        out
    }

    #[derive(Debug, Clone, PartialEq)]
    enum Field2 {
        Varint(u64),
        Fixed(u64),
        Bytes(Vec<u8>),
    }

    fn bytes(fields: &[(u64, Field2)], number: u64) -> Vec<Vec<u8>> {
        fields
            .iter()
            .filter(|(n, _)| *n == number)
            .map(|(_, field)| match field {
                Field2::Bytes(bytes) => bytes.clone(),
                other => panic!("{other:?}"),
            })
            .collect()
    }

    fn text(fields: &[(u64, Field2)], number: u64) -> String {
        String::from_utf8(bytes(fields, number).concat()).unwrap()
    }

    /// Attributes as `key=value` (strings) of a message's repeated KeyValue field.
    fn attributes(fields: &[(u64, Field2)], number: u64) -> Vec<String> {
        bytes(fields, number)
            .iter()
            .map(|pair| {
                let pair = fields_of(pair);
                let value = fields_of(&bytes(&pair, 2)[0]);
                let shown = match &value[0] {
                    (1, Field2::Bytes(text)) => String::from_utf8(text.clone()).unwrap(),
                    (_, Field2::Varint(number)) => number.to_string(),
                    (4, Field2::Fixed(bits)) => f64::from_bits(*bits).to_string(),
                    other => panic!("{other:?}"),
                };
                format!("{}={shown}", text(&pair, 1))
            })
            .collect()
    }

    fn fields_of(bytes: &[u8]) -> Vec<(u64, Field2)> {
        fields(bytes)
    }

    #[test]
    fn spans_are_recorded_with_parents_fields_and_events() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(16);
        let subscriber = tracing_subscriber::registry().with(OtlpLayer { sender });
        tracing::subscriber::with_default(subscriber, || {
            let outer =
                tracing::info_span!("request", method = "GET", otel.kind = "server", status = tracing::field::Empty);
            let _outer = outer.enter();
            {
                let inner = tracing::info_span!("query", rows = 3u64, ratio = 0.5, cached = false);
                let _inner = inner.enter();
                tracing::error!(code = 7, "the database is away");
            }
            outer.record("status", 503);
        });
        let spans: Vec<SpanData> = receiver
            .try_iter()
            .map(|message| match message {
                Message::Span(span) => *span,
                Message::Stop => panic!("no stop"),
            })
            .collect();
        let [inner, outer] = &spans[..] else { panic!("two spans: {spans:?}") };
        assert_eq!((inner.name.as_str(), outer.name.as_str()), ("query", "request"));
        assert_eq!(inner.trace_id, outer.trace_id);
        assert_eq!(inner.parent_span_id, Some(outer.span_id));
        assert_eq!(outer.parent_span_id, None);
        assert_eq!(outer.kind, 2, "otel.kind");
        assert!(!outer.attributes.iter().any(|(key, _)| key.starts_with("otel.")));
        assert!(outer.attributes.contains(&("status".into(), Value::Int(503))));
        assert_eq!(
            inner.attributes,
            [
                ("rows".into(), Value::Int(3)),
                ("ratio".into(), Value::Double(0.5)),
                ("cached".into(), Value::Bool(false))
            ]
        );
        assert_eq!((inner.status, inner.status_message.as_str()), (2, "the database is away"));
        assert_eq!(inner.events[0].name, "the database is away");
        assert!(inner.events[0].attributes.contains(&("code".into(), Value::Int(7))));
        assert!(inner.start <= inner.end && outer.start <= inner.start);

        // The request as the collector reads it.
        let request = encode_request(&resource(Some("deployment.environment=test%20vm,service.name=other")), &spans);
        let request = fields(&request);
        let resource_spans = fields(&bytes(&request, 1)[0]);
        let resource = fields(&bytes(&resource_spans, 1)[0]);
        assert_eq!(attributes(&resource, 1), ["service.name=kernoid", "deployment.environment=test vm"]);
        let scope_spans = fields(&bytes(&resource_spans, 2)[0]);
        assert_eq!(text(&fields(&bytes(&scope_spans, 1)[0]), 1), "kernoid");
        let encoded = bytes(&scope_spans, 2);
        assert_eq!(encoded.len(), 2);
        let first = fields(&encoded[0]);
        assert_eq!(bytes(&first, 1)[0], inner.trace_id);
        assert_eq!(bytes(&first, 2)[0], inner.span_id);
        assert_eq!(bytes(&first, 4)[0], outer.span_id);
        assert_eq!(text(&first, 5), "query");
        assert!(first.contains(&(6, Field2::Varint(1))));
        assert!(first.contains(&(7, Field2::Fixed(inner.start))));
        assert_eq!(attributes(&first, 9), ["rows=3", "ratio=0.5", "cached=0"]);
        let event = fields(&bytes(&first, 11)[0]);
        assert_eq!(text(&event, 2), "the database is away");
        assert!(attributes(&event, 3).contains(&"level=ERROR".to_owned()));
        let status = fields(&bytes(&first, 15)[0]);
        assert_eq!(status, [(2, Field2::Bytes(b"the database is away".to_vec())), (3, Field2::Varint(2))]);
    }

    #[test]
    fn a_collector_receives_the_batch_and_shutdown_sends_the_rest() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let received = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Read, Write};
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let (mut head, mut length) = (String::new(), 0);
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                head.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            reader.get_mut().write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").unwrap();
            (head, body)
        });
        let (layer, exporter) = exporter(&format!("http://{address}/v1/traces")).unwrap();
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let _span = tracing::info_span!("work").entered();
        });
        exporter.shutdown();
        let (head, body) = received.join().unwrap();
        assert!(head.starts_with("POST /v1/traces HTTP/1.1"), "{head}");
        assert!(head.to_ascii_lowercase().contains("content-type: application/x-protobuf"));
        let request = fields(&body);
        let scope_spans = fields(&bytes(&fields(&bytes(&request, 1)[0]), 2)[0]);
        assert_eq!(text(&fields(&bytes(&scope_spans, 2)[0]), 5), "work");
    }
}
