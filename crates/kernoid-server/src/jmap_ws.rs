// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP over WebSocket (RFC 8887) at `/jmap/ws`, subprotocol `jmap`: requests and their responses on one connection,
//! and – after `WebSocketPushEnable` – a `StateChange` whenever an account the caller watches changes, as the
//! EventSource stream of `jmap.rs` sends them. The caller logs in as for HTTP; with the session cookie only from a
//! page of the instance (`cookie::from_own_page`).

use std::time::Duration;

use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use kernoid_jmap::{Caller, Jmap};
use serde_json::{Value, json};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{AppState, Client, Problem, instance::of_request, jmap::JmapCaller};

/// What a client sends (RFC 8887, 4.3).
enum Incoming {
    Request { id: Option<Value>, body: Vec<u8> },
    PushEnable,
    PushDisable,
    Invalid(&'static str),
}

fn incoming(text: &str) -> Incoming {
    let Ok(Value::Object(mut object)) = serde_json::from_str::<Value>(text) else {
        return Incoming::Invalid("not a JSON object");
    };
    match object.remove("@type").as_ref().and_then(Value::as_str) {
        Some("Request") => {
            let id = object.remove("id");
            Incoming::Request { id, body: serde_json::to_vec(&Value::Object(object)).unwrap_or_default() }
        }
        // `dataTypes` and `pushState` narrow and resume a push; every StateChange is complete, so neither is needed.
        Some("WebSocketPushEnable") => Incoming::PushEnable,
        Some("WebSocketPushDisable") => Incoming::PushDisable,
        _ => Incoming::Invalid("an unknown @type"),
    }
}

pub(crate) async fn upgrade(
    State(state): State<AppState>,
    JmapCaller(caller, _): JmapCaller,
    headers: HeaderMap,
    client: Option<axum::Extension<Client>>,
    socket: WebSocketUpgrade,
) -> Response {
    let Some(jmap) = state.jmap.clone() else {
        return Problem::new(StatusCode::NOT_FOUND).detail("no mail here").into_response();
    };
    if !headers.contains_key(header::AUTHORIZATION) {
        let instance = of_request(&state.identity, client.as_ref().map(|client| &client.0)).await.ok().flatten();
        if !instance.is_some_and(|instance| crate::cookie::from_own_page(&state, &headers, &instance)) {
            return Problem::new(StatusCode::FORBIDDEN)
                .detail("a WebSocket with the cookie only from a page of the instance")
                .into_response();
        }
    }
    let events = state.mail_events.as_ref().map(|events| events.subscribe());
    socket.protocols(["jmap"]).on_upgrade(move |socket| serve(socket, jmap, caller, events))
}

async fn serve(socket: WebSocket, jmap: Jmap, caller: Caller, events: Option<broadcast::Receiver<Uuid>>) {
    let (mut sender, mut receiver) = socket.split();
    let watched = jmap.watched(&caller).await.unwrap_or_else(|_| vec![caller.account]);
    let mut events = events;
    let mut pushing = false;
    let mut ping = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            message = receiver.next() => {
                let text = match message {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                    Some(Ok(_)) => continue,
                };
                let answer = match incoming(text.as_str()) {
                    Incoming::Request { id, body } if body.len() <= kernoid_jmap::MAX_SIZE_REQUEST => {
                        match jmap.api(&caller, &body).await {
                            Ok(response) => {
                                let mut response = serde_json::to_value(response).unwrap_or_default();
                                response["@type"] = json!("Response");
                                if let Some(id) = id {
                                    response["requestId"] = id;
                                }
                                Some(response)
                            }
                            Err(error) => {
                                let mut problem = serde_json::to_value(error.problem()).unwrap_or_default();
                                problem["@type"] = json!("RequestError");
                                if let Some(id) = id {
                                    problem["requestId"] = id;
                                }
                                Some(problem)
                            }
                        }
                    }
                    Incoming::Request { id, .. } => {
                        let mut problem = serde_json::to_value(kernoid_jmap::RequestError::Limit("maxSizeRequest").problem()).unwrap_or_default();
                        problem["@type"] = json!("RequestError");
                        if let Some(id) = id {
                            problem["requestId"] = id;
                        }
                        Some(problem)
                    }
                    Incoming::PushEnable => {
                        pushing = true;
                        jmap.state_change(&caller, &watched).await.ok()
                    }
                    Incoming::PushDisable => {
                        pushing = false;
                        None
                    }
                    Incoming::Invalid(why) => Some(json!({
                        "@type": "RequestError",
                        "type": "urn:ietf:params:jmap:error:notRequest",
                        "status": 400,
                        "detail": why,
                    })),
                };
                if let Some(answer) = answer
                    && sender.send(Message::Text(answer.to_string().into())).await.is_err()
                {
                    return;
                }
            }
            changed = async { match events.as_mut() { Some(events) => events.recv().await, None => std::future::pending().await } }, if pushing => {
                match changed {
                    Ok(account) if !watched.contains(&account) => continue,
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                        if let Ok(change) = jmap.state_change(&caller, &watched).await
                            && sender.send(Message::Text(change.to_string().into())).await.is_err()
                        {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => events = None,
                }
            }
            _ = ping.tick() => {
                if sender.send(Message::Ping(Default::default())).await.is_err() {
                    return;
                }
            }
        }
    }
}
