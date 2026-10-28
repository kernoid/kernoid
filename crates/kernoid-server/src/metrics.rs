// SPDX-License-Identifier: AGPL-3.0-or-later
//! Prometheus metrics: request counts and durations by method, route pattern and status. Routes are recorded by
//! their pattern (`/modules/echo/{id}`), never by the concrete path, so that the number of series stays bounded.

use std::time::Instant;

use axum::{
    Router,
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
    routing::get,
};
use metrics_exporter_prometheus::PrometheusHandle;

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
pub fn router(handle: PrometheusHandle) -> Router {
    Router::new().route("/metrics", get(move || std::future::ready(handle.render())))
}
