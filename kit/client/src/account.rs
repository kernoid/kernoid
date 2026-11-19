// SPDX-License-Identifier: MIT
//! The account's own everyday settings over kernoid's API (`/v1/account/…`): its name, picture, the language kernoid
//! writes to it in, and its mail settings. They take a session or an access token of kernoid's apps with the scope
//! `urn:kernoid:data` (RFC 0001) – not an app password, which gets [`Error::Unauthorized`](crate::Error).

use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Body, Client, Error, Result};

fn parse<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
    serde_json::from_str(text).map_err(|error| Error::Protocol(error.to_string()))
}

/// Changes the account's display name.
pub async fn set_name(client: &Client, name: &str) -> Result<()> {
    client.rest(Method::PATCH, "/v1/account", Some(Body::Json(json!({ "display_name": name })))).await?;
    Ok(())
}

/// The language kernoid writes its emails to the account in.
#[derive(Debug, Clone, Deserialize)]
pub struct Language {
    /// The account's own choice; none follows the tenant's.
    pub language: Option<String>,
    /// What kernoid writes in for the account now.
    pub used: String,
    /// The languages kernoid writes in.
    pub available: Vec<String>,
}

pub async fn language(client: &Client) -> Result<Language> {
    parse(&client.rest(Method::GET, "/v1/account/language", None).await?)
}

/// Chooses the language; `None` follows the tenant's.
pub async fn set_language(client: &Client, language: Option<&str>) -> Result<()> {
    client.rest(Method::PUT, "/v1/account/language", Some(Body::Json(json!({ "language": language })))).await?;
    Ok(())
}

/// How the account writes mail and how long its Trash keeps it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct MailSettings {
    /// Days the Trash keeps an email; none follows the tenant.
    pub trash_retention_days: Option<i32>,
    /// The tenant's days; none keeps emails in the Trash until they are deleted. Only read.
    #[serde(default, skip_serializing)]
    pub tenant_trash_retention_days: Option<i32>,
    /// The address new emails come from; none is the account's primary address.
    pub default_from: Option<String>,
    /// Seconds an email waits before it goes out, to be taken back (0 to 30).
    pub undo_send_seconds: i32,
}

pub async fn mail_settings(client: &Client) -> Result<MailSettings> {
    parse(&client.rest(Method::GET, "/v1/account/mail-settings", None).await?)
}

pub async fn set_mail_settings(client: &Client, settings: &MailSettings) -> Result<()> {
    let body = serde_json::to_value(settings).map_err(|error| Error::Protocol(error.to_string()))?;
    client.rest(Method::PUT, "/v1/account/mail-settings", Some(Body::Json(body))).await?;
    Ok(())
}

/// Sets the account's picture: a PNG, JPEG or WebP image of up to 1 MiB, best square (the server does not cut it).
pub async fn set_avatar(client: &Client, image: Vec<u8>, media_type: &str) -> Result<()> {
    client.rest(Method::PUT, "/v1/account/avatar", Some(Body::Bytes(image, media_type.to_owned()))).await?;
    Ok(())
}

pub async fn remove_avatar(client: &Client) -> Result<()> {
    client.rest(Method::DELETE, "/v1/account/avatar", None).await?;
    Ok(())
}

/// The picture of an account of the tenant – the own one too –, or none.
pub async fn avatar(client: &Client, account: &str) -> Result<Option<Vec<u8>>> {
    match client.rest_bytes(&format!("/v1/avatars/{}", crate::encode(account))).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Status(404, _)) => Ok(None),
        Err(error) => Err(error),
    }
}
