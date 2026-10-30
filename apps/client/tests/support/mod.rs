// SPDX-License-Identifier: MIT
//! A small HTTP/1.1 server for the tests: it records each request and answers with what the test's handler says.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON body")
    }

    /// The method calls of a JMAP request: name and arguments.
    pub fn calls(&self) -> Vec<(String, serde_json::Value)> {
        self.json()["methodCalls"]
            .as_array()
            .expect("methodCalls")
            .iter()
            .map(|call| (call[0].as_str().unwrap().to_owned(), call[1].clone()))
            .collect()
    }
}

pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn json(status: u16, value: serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: value.to_string().into_bytes(),
        }
    }

    pub fn redirect(to: &str) -> Self {
        Self { status: 301, headers: vec![("location".into(), to.into())], body: Vec::new() }
    }

    pub fn bytes(body: &[u8]) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".into(), "application/octet-stream".into())],
            body: body.to_vec(),
        }
    }
}

pub type Handler = dyn Fn(&Request) -> Answer + Send + Sync;

pub struct Server {
    pub origin: String,
    pub requests: Arc<Mutex<Vec<Request>>>,
}

impl Server {
    pub fn start(handler: impl Fn(&Request) -> Answer + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let recorded = requests.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let (handler, recorded) = (handler.clone(), recorded.clone());
                thread::spawn(move || serve(stream, &*handler, &recorded));
            }
        });
        Self { origin, requests }
    }

    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    /// The JMAP API requests, in order.
    pub fn api_requests(&self) -> Vec<Request> {
        self.requests().into_iter().filter(|r| r.path == "/jmap/api").collect()
    }
}

fn serve(stream: TcpStream, handler: &Handler, recorded: &Mutex<Vec<Request>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = line.split_whitespace();
        let (method, path) = (parts.next().unwrap_or_default().to_owned(), parts.next().unwrap_or_default().to_owned());
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').unwrap();
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
        let header = |name: &str| headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());
        let mut body = Vec::new();
        if let Some(length) = header("content-length") {
            body.resize(length.parse().unwrap(), 0);
            reader.read_exact(&mut body).unwrap();
        } else if header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
            loop {
                let mut size = String::new();
                reader.read_line(&mut size).unwrap();
                let size = usize::from_str_radix(size.trim(), 16).unwrap();
                let mut chunk = vec![0; size + 2];
                reader.read_exact(&mut chunk).unwrap();
                if size == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..size]);
            }
        }
        let request = Request { method, path, headers, body };
        recorded.lock().unwrap().push(request.clone());
        let answer = handler(&request);
        let mut head = format!("HTTP/1.1 {} X\r\ncontent-length: {}\r\n", answer.status, answer.body.len());
        for (name, value) in &answer.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        if stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(&answer.body)).is_err() {
            return;
        }
    }
}
