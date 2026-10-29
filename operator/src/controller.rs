// SPDX-License-Identifier: AGPL-3.0-or-later
//! Keeps each `Kernoid` running as it says (docs: Operations, Kubernetes):
//!
//! 1. The schema is migrated with the spec's image before anything runs it: a Job `kernoid migrate` per image. Until
//!    it succeeded, the processes keep the image they have – the first time, none run.
//! 2. Then each role runs as a Deployment of the migrated image, with a Service for its ports; a role without
//!    replicas is removed. If the spec asks for one, an Ingress leads its hosts to the `api` role.
//! 3. The status says which image the schema was migrated with, and whether every role is ready.
//!
//! Everything is applied server-side under the field manager `kernoid-operator`; what belongs to a `Kernoid` goes
//! when it goes (owner references).

use std::{sync::Arc, time::Duration};

use futures_util::StreamExt;
use k8s_openapi::api::{apps::v1::Deployment, batch::v1::Job, core::v1::Service, networking::v1::Ingress};
use kube::{
    Api, Client, ResourceExt,
    api::{DeleteParams, Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use serde_json::json;

use crate::{
    crd::{Condition, Kernoid},
    resources,
};

const MANAGER: &str = "kernoid-operator";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Kube(#[from] kube::Error),
    #[error("a Kernoid without a namespace")]
    NoNamespace,
}

struct Context {
    client: Client,
}

/// Watches every `Kernoid` – in one namespace, or in all – until the process is stopped.
pub async fn run(client: Client, namespace: Option<String>) {
    let (kernoids, deployments, jobs, services, ingresses) = (
        scoped::<Kernoid>(&client, &namespace),
        scoped::<Deployment>(&client, &namespace),
        scoped::<Job>(&client, &namespace),
        scoped::<Service>(&client, &namespace),
        scoped::<Ingress>(&client, &namespace),
    );
    let labels = watcher::Config::default().labels("app.kubernetes.io/managed-by=kernoid-operator");
    Controller::new(kernoids, watcher::Config::default())
        .owns(deployments, labels.clone())
        .owns(jobs, labels.clone())
        .owns(services, labels.clone())
        .owns(ingresses, labels)
        .shutdown_on_signal()
        .run(reconcile, error_policy, Arc::new(Context { client }))
        .for_each(|result| async move {
            match result {
                Ok((object, _)) => tracing::debug!(kernoid = %object.name, "reconciled"),
                Err(error) => tracing::warn!(%error, "reconciling"),
            }
        })
        .await;
}

/// The objects of one namespace, or of all.
fn scoped<K>(client: &Client, namespace: &Option<String>) -> Api<K>
where
    K: kube::Resource<Scope = kube::core::NamespaceResourceScope>,
    <K as kube::Resource>::DynamicType: Default,
{
    match namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    }
}

fn error_policy(_: Arc<Kernoid>, error: &Error, _: Arc<Context>) -> Action {
    tracing::warn!(%error, "will try again");
    Action::requeue(Duration::from_secs(30))
}

/// Where a migration Job stands.
#[derive(Debug, PartialEq, Eq)]
enum Migration {
    Running,
    Succeeded,
    Failed,
}

fn migration_state(job: &Job) -> Migration {
    let status = job.status.clone().unwrap_or_default();
    let condition = |kind: &str| {
        status.conditions.iter().flatten().any(|condition| condition.type_ == kind && condition.status == "True")
    };
    if condition("Complete") || status.succeeded.unwrap_or(0) > 0 {
        Migration::Succeeded
    } else if condition("Failed") {
        Migration::Failed
    } else {
        Migration::Running
    }
}

async fn reconcile(kernoid: Arc<Kernoid>, context: Arc<Context>) -> Result<Action, Error> {
    let namespace = kernoid.namespace().ok_or(Error::NoNamespace)?;
    let client = &context.client;
    let kernoids: Api<Kernoid> = Api::namespaced(client.clone(), &namespace);
    let jobs: Api<Job> = Api::namespaced(client.clone(), &namespace);
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), &namespace);
    let services: Api<Service> = Api::namespaced(client.clone(), &namespace);
    let ingresses: Api<Ingress> = Api::namespaced(client.clone(), &namespace);
    let apply = PatchParams::apply(MANAGER).force();
    let wanted = kernoid.spec.image.clone();
    let mut status = kernoid.status.clone().unwrap_or_default();

    // 1. The schema, with the image the spec names.
    let mut requeue = None;
    if status.migrated_image.as_deref() != Some(wanted.as_str()) {
        let job = resources::migration(&kernoid, &wanted);
        let name = resources::migration_name(&kernoid, &wanted);
        let job = jobs.patch(&name, &apply, &Patch::Apply(&job)).await?;
        let condition = match migration_state(&job) {
            Migration::Succeeded => {
                tracing::info!(kernoid = %kernoid.name_any(), image = %wanted, "schema migrated");
                status.migrated_image = Some(wanted.clone());
                condition("Migrated", "True", "Migrated", &format!("migrated with {wanted}"))
            }
            Migration::Failed => {
                requeue = Some(Duration::from_secs(60));
                condition("Migrated", "False", "MigrationFailed", &format!("the Job {name} failed: see its log"))
            }
            Migration::Running => {
                requeue = Some(Duration::from_secs(5));
                condition("Migrated", "False", "Migrating", &format!("migrating with {wanted} (Job {name})"))
            }
        };
        set(&mut status.conditions, condition);
    }

    // 2. The roles, with the image the schema was migrated with.
    let mut not_ready = Vec::new();
    if let Some(image) = status.migrated_image.clone() {
        for role in resources::ROLES {
            let name = resources::deployment_name(&kernoid, role);
            if resources::role(&kernoid, role).replicas <= 0 {
                remove(&deployments, &name).await?;
                remove(&services, &name).await?;
                continue;
            }
            let deployment = resources::deployment(&kernoid, role, &image);
            let applied = deployments.patch(&name, &apply, &Patch::Apply(&deployment)).await?;
            match resources::service(&kernoid, role) {
                Some(service) => {
                    services.patch(&name, &apply, &Patch::Apply(&service)).await?;
                }
                None => remove(&services, &name).await?,
            }
            if !rolled_out(&applied) {
                not_ready.push(role);
            }
        }
    }

    // The way in from outside, once the api role runs the migrated image.
    let ingress_name = resources::deployment_name(&kernoid, "api");
    match resources::ingress(&kernoid).filter(|_| status.migrated_image.is_some()) {
        Some(ingress) => {
            ingresses.patch(&ingress_name, &apply, &Patch::Apply(&ingress)).await?;
        }
        None => remove(&ingresses, &ingress_name).await?,
    }

    // 3. The status.
    let ready = if status.migrated_image.is_none() {
        condition("Ready", "False", "Migrating", "nothing runs before the schema is migrated")
    } else if not_ready.is_empty() {
        condition("Ready", "True", "Ready", "every role is rolled out and ready")
    } else {
        requeue = requeue.or(Some(Duration::from_secs(10)));
        condition("Ready", "False", "RollingOut", &format!("not yet ready: {}", not_ready.join(", ")))
    };
    set(&mut status.conditions, ready);
    status.observed_generation = kernoid.metadata.generation;
    if kernoid.status.as_ref() != Some(&status) {
        let patch = json!({ "apiVersion": "kernoid.dev/v1alpha1", "kind": "Kernoid", "status": status });
        kernoids.patch_status(&kernoid.name_any(), &apply, &Patch::Apply(&patch)).await?;
    }
    Ok(requeue.map_or_else(|| Action::requeue(Duration::from_secs(300)), Action::requeue))
}

/// Whether a Deployment runs its newest template with every replica ready.
fn rolled_out(deployment: &Deployment) -> bool {
    let wanted = deployment.spec.as_ref().and_then(|spec| spec.replicas).unwrap_or(1);
    let Some(status) = &deployment.status else { return wanted == 0 };
    status.observed_generation >= deployment.metadata.generation
        && status.updated_replicas.unwrap_or(0) >= wanted
        && status.ready_replicas.unwrap_or(0) >= wanted
        && status.replicas.unwrap_or(0) == wanted
}

async fn remove<K>(api: &Api<K>, name: &str) -> Result<(), Error>
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    match api.delete(name, &DeleteParams::background()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(response)) if response.code == 404 => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn condition(kind: &str, status: &str, reason: &str, message: &str) -> Condition {
    Condition { kind: kind.into(), status: status.into(), reason: reason.into(), message: message.into() }
}

/// Replaces the condition of the same type.
fn set(conditions: &mut Vec<Condition>, condition: Condition) {
    conditions.retain(|own| own.kind != condition.kind);
    conditions.push(condition);
    conditions.sort_by(|a, b| a.kind.cmp(&b.kind));
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::{
        apps::v1::{DeploymentSpec, DeploymentStatus},
        batch::v1::{JobCondition, JobStatus},
    };

    use super::*;

    #[test]
    fn migrations_are_read_from_the_jobs_status() {
        let job = |status: JobStatus| Job { status: Some(status), ..Job::default() };
        assert_eq!(migration_state(&Job::default()), Migration::Running);
        assert_eq!(
            migration_state(&job(JobStatus { succeeded: Some(1), ..JobStatus::default() })),
            Migration::Succeeded
        );
        let failed = JobCondition { type_: "Failed".into(), status: "True".into(), ..JobCondition::default() };
        assert_eq!(
            migration_state(&job(JobStatus { conditions: Some(vec![failed]), ..JobStatus::default() })),
            Migration::Failed
        );
    }

    #[test]
    fn a_deployment_is_rolled_out_when_every_replica_is_new_and_ready() {
        let deployment = |replicas, updated, ready, observed| Deployment {
            metadata: kube::api::ObjectMeta { generation: Some(2), ..Default::default() },
            spec: Some(DeploymentSpec { replicas: Some(replicas), ..DeploymentSpec::default() }),
            status: Some(DeploymentStatus {
                replicas: Some(replicas),
                updated_replicas: Some(updated),
                ready_replicas: Some(ready),
                observed_generation: Some(observed),
                ..DeploymentStatus::default()
            }),
        };
        assert!(rolled_out(&deployment(2, 2, 2, 2)));
        assert!(!rolled_out(&deployment(2, 1, 2, 2)));
        assert!(!rolled_out(&deployment(2, 2, 1, 2)));
        assert!(!rolled_out(&deployment(2, 2, 2, 1)));
    }

    #[test]
    fn conditions_are_replaced_by_type() {
        let mut conditions = Vec::new();
        set(&mut conditions, condition("Ready", "False", "Migrating", ""));
        set(&mut conditions, condition("Migrated", "True", "Migrated", ""));
        set(&mut conditions, condition("Ready", "True", "Ready", ""));
        let kinds: Vec<(&str, &str)> = conditions.iter().map(|c| (c.kind.as_str(), c.status.as_str())).collect();
        assert_eq!(kinds, [("Migrated", "True"), ("Ready", "True")]);
    }
}
