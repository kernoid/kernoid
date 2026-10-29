// SPDX-License-Identifier: AGPL-3.0-or-later
//! The resource `Kernoid` (`kernoid.dev/v1alpha1`): one kernoid installation – its image, its settings as
//! environment variables (`KERNOID__…`, the same as for a container), and how many processes of each role run.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{EnvVar, LocalObjectReference, ResourceRequirements, Volume, VolumeMount};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One kernoid installation.
#[derive(CustomResource, Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "kernoid.dev",
    version = "v1alpha1",
    kind = "Kernoid",
    namespaced,
    status = "KernoidStatus",
    shortname = "kn",
    printcolumn = r#"{"name": "Image", "type": "string", "jsonPath": ".status.migratedImage"}"#,
    printcolumn = r#"{"name": "Ready", "type": "string", "jsonPath": ".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name": "Age", "type": "date", "jsonPath": ".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct KernoidSpec {
    /// The kernoid image, e.g. `ghcr.io/kernoid/kernoid:0.2.0`. Changing it upgrades: the schema is migrated with
    /// the new image first, then the processes are replaced.
    pub image: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_pull_secrets: Vec<LocalObjectReference>,
    /// kernoid's settings for every process, as environment variables – `KERNOID__DATABASE__URL`,
    /// `KERNOID__BLOB__…`, `KERNOID__ENCRYPTION__MAIN_KEY` and so on –, secrets with `valueFrom.secretKeyRef`.
    /// `KERNOID__ROLES` is set by the operator.
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// More variables only for the migration: `KERNOID__DATABASE__MIGRATE_URL`, the schema owner's connection.
    #[serde(default)]
    pub migrate_env: Vec<EnvVar>,
    /// Volumes for every process – e.g. the certificate of the mail protocols from a Secret (`mail.tls`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<Volume>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volume_mounts: Vec<VolumeMount>,
    #[serde(default)]
    pub roles: Roles,
}

/// How many processes of each role run (docs: Operations). A role with no replicas runs nowhere.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct Roles {
    /// HTTP: the API, the login, the web app, JMAP, WebDAV, CalDAV and CardDAV.
    #[serde(default = "one")]
    pub api: Role,
    /// Background work.
    #[serde(default = "one")]
    pub worker: Role,
    /// The MX and submission; needs `[smtp]` in `env`.
    #[serde(default)]
    pub smtp: Role,
    /// IMAP and POP3; needs `[imap]` in `env`.
    #[serde(default)]
    pub imap: Role,
    /// The directory over LDAP; needs `[ldap]` in `env`.
    #[serde(default)]
    pub ldap: Role,
}

impl Default for Roles {
    fn default() -> Self {
        Self { api: one(), worker: one(), smtp: Role::default(), imap: Role::default(), ldap: Role::default() }
    }
}

fn one() -> Role {
    Role { replicas: 1, ..Role::default() }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    #[serde(default)]
    pub replicas: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    /// The Service of the role (not for `worker`): `ClusterIP` unless set – `LoadBalancer` for mail from outside.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub service_annotations: BTreeMap<String, String>,
}

/// What the operator has done.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KernoidStatus {
    /// The image the schema was migrated with – the one the processes run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrated_image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// A condition (Kubernetes' conventions): `Migrated`, `Ready`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "type")]
    pub kind: String,
    /// `True`, `False` or `Unknown`.
    pub status: String,
    pub reason: String,
    pub message: String,
}
