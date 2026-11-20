// SPDX-License-Identifier: AGPL-3.0-or-later
//! Prometheus metrics: request counts and durations by method, route pattern and status. Routes are recorded by
//! their pattern (`/modules/echo/{id}`), never by the concrete path, so that the number of series stays bounded.
//!
//! The values are kept by kernoid's own recorder of the `metrics` facade ([`install`]) and written in Prometheus's
//! text exposition format (version 0.0.4): counters, gauges, and histograms with fixed buckets.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use axum::{
    Router,
    extract::{MatchedPath, Request},
    http::header,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use metrics::{Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, SharedString, Unit};

pub async fn layer(request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = request.method().to_string();
    let route = request.extensions().get::<MatchedPath>().map_or("unmatched", MatchedPath::as_str).to_owned();
    let response = next.run(request).await;
    let labels = [("method", method), ("route", route), ("status", response.status().as_u16().to_string())];
    metrics::counter!("kernoid_http_requests_total", &labels).increment(1);
    metrics::histogram!("kernoid_http_request_duration_seconds", &labels).record(started.elapsed().as_secs_f64());
    response
}

/// `/metrics` in the Prometheus text format, for the internal metrics listener.
pub fn router(handle: Handle) -> Router {
    Router::new().route(
        "/metrics",
        get(move || {
            let text = handle.render();
            std::future::ready(
                ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], text).into_response(),
            )
        }),
    )
}

/// The upper bounds of every histogram's buckets – Prometheus's default ones, made for durations in seconds.
const BUCKETS: [f64; 11] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

/// Makes kernoid's recorder the process's; what it records is rendered through the returned handle.
pub fn install() -> Result<Handle, InstallError> {
    let handle = Handle::default();
    metrics::set_global_recorder(Recorder(handle.clone())).map_err(|_| InstallError)?;
    Ok(handle)
}

/// Another recorder was installed before.
#[derive(Debug, thiserror::Error)]
#[error("a metrics recorder is installed already")]
pub struct InstallError;

/// What the recorder keeps, and its rendering.
#[derive(Debug, Clone, Default)]
pub struct Handle(Arc<Mutex<Registry>>);

#[derive(Debug, Default)]
struct Registry {
    /// By metric name: its kind, help text and series by their labels.
    families: BTreeMap<String, Family>,
}

#[derive(Debug, Default)]
struct Family {
    kind: Option<Kind>,
    help: Option<String>,
    series: BTreeMap<Vec<(String, String)>, Series>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Counter,
    Gauge,
    Histogram,
}

#[derive(Debug, Clone)]
enum Series {
    Counter(Arc<CounterValue>),
    Gauge(Arc<GaugeValue>),
    Histogram(Arc<HistogramValue>),
}

#[derive(Debug, Default)]
struct CounterValue(AtomicU64);

impl CounterFn for CounterValue {
    fn increment(&self, value: u64) {
        self.0.fetch_add(value, Ordering::Relaxed);
    }

    fn absolute(&self, value: u64) {
        self.0.fetch_max(value, Ordering::Relaxed);
    }
}

/// An `f64` kept in an atomic as its bits.
#[derive(Debug, Default)]
struct AtomicF64(AtomicU64);

impl AtomicF64 {
    fn update(&self, change: impl Fn(f64) -> f64) {
        let mut now = self.0.load(Ordering::Relaxed);
        loop {
            let next = change(f64::from_bits(now)).to_bits();
            match self.0.compare_exchange_weak(now, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return,
                Err(actual) => now = actual,
            }
        }
    }

    fn get(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::Relaxed))
    }
}

#[derive(Debug, Default)]
struct GaugeValue(AtomicF64);

impl GaugeFn for GaugeValue {
    fn increment(&self, value: f64) {
        self.0.update(|now| now + value);
    }

    fn decrement(&self, value: f64) {
        self.0.update(|now| now - value);
    }

    fn set(&self, value: f64) {
        self.0.update(|_| value);
    }
}

#[derive(Debug, Default)]
struct HistogramValue {
    /// Observations per bucket (not cumulative); the last one counts those above every bound.
    buckets: [AtomicU64; BUCKETS.len() + 1],
    sum: AtomicF64,
}

impl HistogramFn for HistogramValue {
    fn record(&self, value: f64) {
        self.record_many(value, 1);
    }

    fn record_many(&self, value: f64, count: usize) {
        if value.is_nan() {
            return;
        }
        let bucket = BUCKETS.iter().position(|bound| value <= *bound).unwrap_or(BUCKETS.len());
        self.buckets[bucket].fetch_add(count as u64, Ordering::Relaxed);
        self.sum.update(|sum| sum + value * count as f64);
    }
}

struct Recorder(Handle);

impl Recorder {
    /// The series of `key`, made at its first use – none when the name is taken by another kind.
    fn series(&self, key: &Key, kind: Kind) -> Option<Series> {
        let mut registry = self.0.0.lock().expect("not poisoned");
        let family = registry.families.entry(key.name().to_owned()).or_default();
        if *family.kind.get_or_insert(kind) != kind {
            return None;
        }
        let mut labels: Vec<(String, String)> =
            key.labels().map(|label| (label.key().to_owned(), label.value().to_owned())).collect();
        labels.sort();
        let series = family.series.entry(labels).or_insert_with(|| match kind {
            Kind::Counter => Series::Counter(Arc::default()),
            Kind::Gauge => Series::Gauge(Arc::default()),
            Kind::Histogram => Series::Histogram(Arc::default()),
        });
        Some(series.clone())
    }

    fn describe(&self, name: KeyName, description: SharedString) {
        let mut registry = self.0.0.lock().expect("not poisoned");
        registry.families.entry(name.as_str().to_owned()).or_default().help = Some(description.into_owned());
    }
}

impl metrics::Recorder for Recorder {
    fn describe_counter(&self, key: KeyName, _unit: Option<Unit>, description: SharedString) {
        self.describe(key, description);
    }

    fn describe_gauge(&self, key: KeyName, _unit: Option<Unit>, description: SharedString) {
        self.describe(key, description);
    }

    fn describe_histogram(&self, key: KeyName, _unit: Option<Unit>, description: SharedString) {
        self.describe(key, description);
    }

    /// A name is of the kind it was first registered as; a handle of another kind for it records nothing.
    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        match self.series(key, Kind::Counter) {
            Some(Series::Counter(value)) => Counter::from_arc(value),
            _ => Counter::noop(),
        }
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        match self.series(key, Kind::Gauge) {
            Some(Series::Gauge(value)) => Gauge::from_arc(value),
            _ => Gauge::noop(),
        }
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        match self.series(key, Kind::Histogram) {
            Some(Series::Histogram(value)) => Histogram::from_arc(value),
            _ => Histogram::noop(),
        }
    }
}

impl Handle {
    /// Everything recorded, in the text exposition format.
    pub fn render(&self) -> String {
        let registry = self.0.lock().expect("not poisoned");
        let mut out = String::new();
        for (name, family) in &registry.families {
            let Some(kind) = family.kind else { continue };
            if let Some(help) = &family.help {
                let _ = writeln!(out, "# HELP {name} {}", help.replace('\\', "\\\\").replace('\n', "\\n"));
            }
            let kind_name = match kind {
                Kind::Counter => "counter",
                Kind::Gauge => "gauge",
                Kind::Histogram => "histogram",
            };
            let _ = writeln!(out, "# TYPE {name} {kind_name}");
            for (labels, series) in &family.series {
                match series {
                    Series::Counter(value) => {
                        let _ =
                            writeln!(out, "{name}{} {}", labels_text(labels, None), value.0.load(Ordering::Relaxed));
                    }
                    Series::Gauge(value) => {
                        let _ = writeln!(out, "{name}{} {}", labels_text(labels, None), number(value.0.get()));
                    }
                    Series::Histogram(value) => {
                        let mut count = 0u64;
                        for (index, bucket) in value.buckets.iter().enumerate() {
                            count += bucket.load(Ordering::Relaxed);
                            let bound = BUCKETS.get(index).map_or_else(|| "+Inf".to_owned(), |bound| number(*bound));
                            let _ = writeln!(out, "{name}_bucket{} {count}", labels_text(labels, Some(&bound)));
                        }
                        let _ = writeln!(out, "{name}_sum{} {}", labels_text(labels, None), number(value.sum.get()));
                        let _ = writeln!(out, "{name}_count{} {count}", labels_text(labels, None));
                    }
                }
            }
        }
        out
    }
}

/// `{a="1",b="2"}` (with `le` last for a bucket), or nothing without labels.
fn labels_text(labels: &[(String, String)], le: Option<&str>) -> String {
    let mut pairs: Vec<String> = labels
        .iter()
        .map(|(key, value)| {
            let value = value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
            format!("{key}=\"{value}\"")
        })
        .collect();
    if let Some(le) = le {
        pairs.push(format!("le=\"{le}\""));
    }
    if pairs.is_empty() { String::new() } else { format!("{{{}}}", pairs.join(",")) }
}

/// A sample value as Prometheus reads it.
fn number(value: f64) -> String {
    if value.is_nan() {
        "NaN".into()
    } else if value.is_infinite() {
        if value > 0.0 { "+Inf".into() } else { "-Inf".into() }
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_gauges_and_histograms_are_rendered_in_the_text_format() {
        let handle = Handle::default();
        let recorder = Recorder(handle.clone());
        metrics::with_local_recorder(&recorder, || {
            metrics::describe_counter!("requests_total", "Requests.\nAll of them.");
            let labels = [("route", "/a\"b".to_owned()), ("method", "GET".to_owned())];
            metrics::counter!("requests_total", &labels).increment(2);
            metrics::counter!("requests_total", &labels).increment(1);
            metrics::gauge!("open").set(1.5);
            metrics::gauge!("open").decrement(0.5);
            metrics::histogram!("duration_seconds").record(0.003);
            metrics::histogram!("duration_seconds").record(0.2);
            metrics::histogram!("duration_seconds").record(30.0);
            // Another kind under a name taken records nothing.
            metrics::gauge!("requests_total").set(9.0);
        });
        let text = handle.render();
        let expected = "\
# TYPE duration_seconds histogram
duration_seconds_bucket{le=\"0.005\"} 1
duration_seconds_bucket{le=\"0.01\"} 1
duration_seconds_bucket{le=\"0.025\"} 1
duration_seconds_bucket{le=\"0.05\"} 1
duration_seconds_bucket{le=\"0.1\"} 1
duration_seconds_bucket{le=\"0.25\"} 2
duration_seconds_bucket{le=\"0.5\"} 2
duration_seconds_bucket{le=\"1\"} 2
duration_seconds_bucket{le=\"2.5\"} 2
duration_seconds_bucket{le=\"5\"} 2
duration_seconds_bucket{le=\"10\"} 2
duration_seconds_bucket{le=\"+Inf\"} 3
duration_seconds_sum 30.203
duration_seconds_count 3
# TYPE open gauge
open 1
# HELP requests_total Requests.\\nAll of them.
# TYPE requests_total counter
requests_total{method=\"GET\",route=\"/a\\\"b\"} 3
";
        assert_eq!(text, expected);
    }
}
