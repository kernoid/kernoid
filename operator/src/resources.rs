// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a `Kernoid` becomes in Kubernetes – pure functions, so that they can be tested without a cluster: the Job
//! that migrates the schema with an image, for each role with replicas a Deployment and (but for `worker`) a
//! Service, and, if asked for, an Ingress to the `api` role. Every object belongs to the `Kernoid` (owner reference)
//! and goes when it goes.

use std::collections::BTreeMap;

use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy, RollingUpdateDeployment},
        batch::v1::{Job, JobSpec},
        core::v1::{
            Capabilities, Container, ContainerPort, EnvVar, HTTPGetAction, PodSecurityContext, PodSpec,
            PodTemplateSpec, Probe, SeccompProfile, SecurityContext, Service, ServicePort, ServiceSpec, Sysctl,
            TCPSocketAction,
        },
        networking::v1::{
            HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule, IngressServiceBackend,
            IngressSpec, IngressTLS, ServiceBackendPort,
        },
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, ObjectMeta},
        util::intstr::IntOrString,
    },
};
use kube::{Resource, ResourceExt};
use sha2::{Digest, Sha256};

use crate::crd::{Kernoid, Role};

/// The roles, in the order they are rolled out.
pub const ROLES: [&str; 5] = ["worker", "api", "smtp", "imap", "ldap"];

pub fn role<'a>(kernoid: &'a Kernoid, name: &str) -> &'a Role {
    let roles = &kernoid.spec.roles;
    match name {
        "api" => &roles.api,
        "worker" => &roles.worker,
        "smtp" => &roles.smtp,
        "imap" => &roles.imap,
        _ => &roles.ldap,
    }
}

/// The ports a role listens on, inside the container: kernoid's defaults.
pub fn ports(role: &str) -> &'static [(&'static str, i32)] {
    match role {
        "api" => &[("http", 8080)],
        "smtp" => &[("smtp", 25), ("submission", 587), ("submissions", 465)],
        "imap" => &[("imap", 143), ("imaps", 993)],
        "ldap" => &[("ldap", 389), ("ldaps", 636)],
        _ => &[],
    }
}

fn labels(kernoid: &Kernoid, component: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("app.kubernetes.io/name".to_owned(), "kernoid".to_owned()),
        ("app.kubernetes.io/instance".to_owned(), kernoid.name_any()),
        ("app.kubernetes.io/component".to_owned(), component.to_owned()),
        ("app.kubernetes.io/managed-by".to_owned(), "kernoid-operator".to_owned()),
    ])
}

fn meta(kernoid: &Kernoid, name: String, component: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name),
        namespace: kernoid.namespace(),
        labels: Some(labels(kernoid, component)),
        owner_references: kernoid.controller_owner_ref(&()).map(|owner| vec![owner]),
        ..ObjectMeta::default()
    }
}

/// The Job's name for an image: the same image, the same Job – a migration runs once per image.
pub fn migration_name(kernoid: &Kernoid, image: &str) -> String {
    let hash = Sha256::digest(image.as_bytes());
    let short: String = hash.iter().take(5).map(|byte| format!("{byte:02x}")).collect();
    format!("{}-migrate-{short}", kernoid.name_any())
}

pub fn deployment_name(kernoid: &Kernoid, role: &str) -> String {
    format!("{}-{role}", kernoid.name_any())
}

/// Least privilege for every container: not root, no privilege escalation, no capabilities, a read-only root.
fn container_security() -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        read_only_root_filesystem: Some(true),
        run_as_non_root: Some(true),
        capabilities: Some(Capabilities { drop: Some(vec!["ALL".into()]), ..Capabilities::default() }),
        ..SecurityContext::default()
    }
}

/// The pod's security: the image's non-root user (65532), the runtime's seccomp profile, and – for the mail and
/// directory ports below 1024 – ports open to unprivileged processes (a namespaced, safe sysctl).
fn pod_security(low_ports: bool) -> PodSecurityContext {
    PodSecurityContext {
        run_as_non_root: Some(true),
        run_as_user: Some(65532),
        run_as_group: Some(65532),
        seccomp_profile: Some(SeccompProfile { type_: "RuntimeDefault".into(), ..SeccompProfile::default() }),
        sysctls: low_ports
            .then(|| vec![Sysctl { name: "net.ipv4.ip_unprivileged_port_start".into(), value: "0".into() }]),
        ..PodSecurityContext::default()
    }
}

fn container(image: &str, args: Vec<String>, env: Vec<EnvVar>) -> Container {
    Container {
        name: "kernoid".into(),
        image: Some(image.to_owned()),
        args: Some(args),
        env: Some(env),
        security_context: Some(container_security()),
        ..Container::default()
    }
}

fn pull_secrets(kernoid: &Kernoid) -> Option<Vec<k8s_openapi::api::core::v1::LocalObjectReference>> {
    (!kernoid.spec.image_pull_secrets.is_empty()).then(|| kernoid.spec.image_pull_secrets.clone())
}

/// The Job that brings the schema up to date with `image` (`kernoid migrate`), with the owner's connection.
pub fn migration(kernoid: &Kernoid, image: &str) -> Job {
    let mut env = kernoid.spec.env.clone();
    env.extend(kernoid.spec.migrate_env.iter().cloned());
    Job {
        metadata: meta(kernoid, migration_name(kernoid, image), "migrate"),
        spec: Some(JobSpec {
            backoff_limit: Some(3),
            // Kept a day for its log, then removed; a new image makes a new Job.
            ttl_seconds_after_finished: Some(86_400),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta { labels: Some(labels(kernoid, "migrate")), ..ObjectMeta::default() }),
                spec: Some(PodSpec {
                    restart_policy: Some("Never".into()),
                    security_context: Some(pod_security(false)),
                    image_pull_secrets: pull_secrets(kernoid),
                    containers: vec![container(image, vec!["migrate".into()], env)],
                    ..PodSpec::default()
                }),
            },
            ..JobSpec::default()
        }),
        ..Job::default()
    }
}

/// The Deployment of a role, running `image` – the image the schema was migrated with.
pub fn deployment(kernoid: &Kernoid, role_name: &str, image: &str) -> Deployment {
    let role = role(kernoid, role_name);
    let mut env: Vec<EnvVar> = kernoid.spec.env.iter().filter(|var| var.name != "KERNOID__ROLES").cloned().collect();
    env.push(EnvVar { name: "KERNOID__ROLES".into(), value: Some(format!("[\"{role_name}\"]")), ..EnvVar::default() });
    let ports = ports(role_name);
    let mut main = container(image, vec!["serve".into()], env);
    main.resources = role.resources.clone();
    main.ports = (!ports.is_empty()).then(|| {
        ports
            .iter()
            .map(|(name, port)| ContainerPort {
                name: Some((*name).to_owned()),
                container_port: *port,
                ..ContainerPort::default()
            })
            .collect()
    });
    // HTTP says whether the process is ready (`/readyz`: PostgreSQL and object storage answer); the others whether
    // they listen.
    let (readiness, liveness) = match ports.first() {
        Some((_, 8080)) => (http_probe("/readyz"), http_probe("/healthz")),
        Some((name, _)) => (tcp_probe(name), tcp_probe(name)),
        None => (None, None),
    };
    main.readiness_probe = readiness;
    main.liveness_probe = liveness;
    main.volume_mounts = (!kernoid.spec.volume_mounts.is_empty()).then(|| kernoid.spec.volume_mounts.clone());
    let selector = labels(kernoid, role_name);
    Deployment {
        metadata: meta(kernoid, deployment_name(kernoid, role_name), role_name),
        spec: Some(DeploymentSpec {
            replicas: Some(role.replicas),
            selector: LabelSelector { match_labels: Some(selector.clone()), ..LabelSelector::default() },
            strategy: Some(DeploymentStrategy {
                type_: Some("RollingUpdate".into()),
                rolling_update: Some(RollingUpdateDeployment {
                    max_unavailable: Some(IntOrString::Int(0)),
                    max_surge: Some(IntOrString::Int(1)),
                }),
            }),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta { labels: Some(selector), ..ObjectMeta::default() }),
                spec: Some(PodSpec {
                    security_context: Some(pod_security(ports.iter().any(|(_, port)| *port < 1024))),
                    image_pull_secrets: pull_secrets(kernoid),
                    volumes: (!kernoid.spec.volumes.is_empty()).then(|| kernoid.spec.volumes.clone()),
                    containers: vec![main],
                    ..PodSpec::default()
                }),
            },
            ..DeploymentSpec::default()
        }),
        ..Deployment::default()
    }
}

fn http_probe(path: &str) -> Option<Probe> {
    Some(Probe {
        http_get: Some(HTTPGetAction {
            path: Some(path.to_owned()),
            port: IntOrString::String("http".into()),
            ..HTTPGetAction::default()
        }),
        period_seconds: Some(10),
        failure_threshold: Some(3),
        ..Probe::default()
    })
}

fn tcp_probe(port: &str) -> Option<Probe> {
    Some(Probe {
        tcp_socket: Some(TCPSocketAction { port: IntOrString::String(port.to_owned()), ..TCPSocketAction::default() }),
        period_seconds: Some(10),
        failure_threshold: Some(3),
        ..Probe::default()
    })
}

/// The Service of a role with ports; none for `worker`.
pub fn service(kernoid: &Kernoid, role_name: &str) -> Option<Service> {
    let ports = ports(role_name);
    if ports.is_empty() {
        return None;
    }
    let role = role(kernoid, role_name);
    let mut metadata = meta(kernoid, deployment_name(kernoid, role_name), role_name);
    metadata.annotations = (!role.service_annotations.is_empty()).then(|| role.service_annotations.clone());
    let external = role.service_type.as_deref().is_some_and(|kind| kind != "ClusterIP");
    Some(Service {
        metadata,
        spec: Some(ServiceSpec {
            type_: Some(role.service_type.clone().unwrap_or_else(|| "ClusterIP".into())),
            selector: Some(labels(kernoid, role_name)),
            // Mail servers check where mail comes from: the client's own address must reach kernoid.
            external_traffic_policy: external.then(|| "Local".into()),
            ports: Some(
                ports
                    .iter()
                    .map(|(name, port)| ServicePort {
                        name: Some((*name).to_owned()),
                        port: *port,
                        target_port: Some(IntOrString::String((*name).to_owned())),
                        ..ServicePort::default()
                    })
                    .collect(),
            ),
            ..ServiceSpec::default()
        }),
        ..Service::default()
    })
}

/// The Ingress to the `api` role's Service, if the spec asks for one and `api` runs.
pub fn ingress(kernoid: &Kernoid) -> Option<Ingress> {
    let wanted = kernoid.spec.ingress.as_ref().filter(|ingress| !ingress.hosts.is_empty())?;
    if role(kernoid, "api").replicas <= 0 {
        return None;
    }
    let service = deployment_name(kernoid, "api");
    let mut metadata = meta(kernoid, service.clone(), "api");
    metadata.annotations = (!wanted.annotations.is_empty()).then(|| wanted.annotations.clone());
    let backend = IngressBackend {
        service: Some(IngressServiceBackend {
            name: service,
            port: Some(ServiceBackendPort { name: Some("http".into()), number: None }),
        }),
        resource: None,
    };
    Some(Ingress {
        metadata,
        spec: Some(IngressSpec {
            ingress_class_name: wanted.class_name.clone(),
            rules: Some(
                wanted
                    .hosts
                    .iter()
                    .map(|host| IngressRule {
                        host: Some(host.clone()),
                        http: Some(HTTPIngressRuleValue {
                            paths: vec![HTTPIngressPath {
                                path: Some("/".into()),
                                path_type: "Prefix".into(),
                                backend: backend.clone(),
                            }],
                        }),
                    })
                    .collect(),
            ),
            tls: wanted.tls_secret.as_ref().map(|secret| {
                vec![IngressTLS { hosts: Some(wanted.hosts.clone()), secret_name: Some(secret.clone()) }]
            }),
            ..IngressSpec::default()
        }),
        ..Ingress::default()
    })
}

#[cfg(test)]
mod tests {
    use crate::crd::KernoidSpec;

    use super::*;

    fn kernoid() -> Kernoid {
        let mut spec = KernoidSpec {
            image: "ghcr.io/kernoid/kernoid:0.2.0".into(),
            env: vec![
                EnvVar { name: "KERNOID__BLOB__KIND".into(), value: Some("s3".into()), ..EnvVar::default() },
                EnvVar { name: "KERNOID__ROLES".into(), value: Some("[\"all\"]".into()), ..EnvVar::default() },
            ],
            migrate_env: vec![EnvVar {
                name: "KERNOID__DATABASE__MIGRATE_URL".into(),
                value: Some("postgres://owner@db/kernoid".into()),
                ..EnvVar::default()
            }],
            ..KernoidSpec::default()
        };
        spec.roles.smtp.replicas = 2;
        spec.roles.smtp.service_type = Some("LoadBalancer".into());
        let mut kernoid = Kernoid::new("mail", spec);
        kernoid.metadata.namespace = Some("kernoid".into());
        kernoid.metadata.uid = Some("0f6e2bd1-6b3c-4a33-9b55-1f2f6d6b8a01".into());
        kernoid
    }

    #[test]
    fn a_migration_runs_once_per_image_with_the_owners_connection() {
        let kernoid = kernoid();
        let job = migration(&kernoid, "ghcr.io/kernoid/kernoid:0.2.0");
        let name = job.metadata.name.clone().unwrap();
        assert!(name.starts_with("mail-migrate-") && name.len() == "mail-migrate-".len() + 10, "{name}");
        assert_eq!(migration_name(&kernoid, "ghcr.io/kernoid/kernoid:0.2.0"), name);
        assert_ne!(migration_name(&kernoid, "ghcr.io/kernoid/kernoid:0.2.1"), name);
        let pod = job.spec.unwrap().template.spec.unwrap();
        let container = &pod.containers[0];
        assert_eq!(container.args.as_deref(), Some(&["migrate".to_owned()][..]));
        let env: Vec<&str> = container.env.as_ref().unwrap().iter().map(|var| var.name.as_str()).collect();
        assert!(env.contains(&"KERNOID__DATABASE__MIGRATE_URL"));
        assert_eq!(job.metadata.owner_references.unwrap()[0].kind, "Kernoid");
    }

    #[test]
    fn each_role_runs_alone_and_safely() {
        let kernoid = kernoid();
        let smtp = deployment(&kernoid, "smtp", "ghcr.io/kernoid/kernoid:0.2.0");
        let spec = smtp.spec.unwrap();
        assert_eq!(spec.replicas, Some(2));
        let pod = spec.template.spec.unwrap();
        let container = &pod.containers[0];
        let roles: Vec<_> = container.env.as_ref().unwrap().iter().filter(|var| var.name == "KERNOID__ROLES").collect();
        assert_eq!(roles.len(), 1, "the operator's roles replace the spec's");
        assert_eq!(roles[0].value.as_deref(), Some("[\"smtp\"]"));
        assert!(container.env.as_ref().unwrap().iter().all(|var| var.name != "KERNOID__DATABASE__MIGRATE_URL"));
        let security = container.security_context.as_ref().unwrap();
        assert_eq!(
            (security.read_only_root_filesystem, security.allow_privilege_escalation),
            (Some(true), Some(false))
        );
        let sysctls = pod.security_context.unwrap().sysctls.unwrap();
        assert_eq!(sysctls[0].name, "net.ipv4.ip_unprivileged_port_start");
        assert!(container.readiness_probe.as_ref().unwrap().tcp_socket.is_some());

        let api = deployment(&kernoid, "api", "x").spec.unwrap().template.spec.unwrap();
        assert!(api.security_context.unwrap().sysctls.is_none());
        let probe = api.containers[0].readiness_probe.clone().unwrap();
        assert_eq!(probe.http_get.unwrap().path.as_deref(), Some("/readyz"));
    }

    #[test]
    fn services_expose_the_roles_ports() {
        let kernoid = kernoid();
        assert!(service(&kernoid, "worker").is_none());
        let smtp = service(&kernoid, "smtp").unwrap().spec.unwrap();
        assert_eq!(smtp.type_.as_deref(), Some("LoadBalancer"));
        assert_eq!(smtp.external_traffic_policy.as_deref(), Some("Local"));
        let ports: Vec<i32> = smtp.ports.unwrap().iter().map(|port| port.port).collect();
        assert_eq!(ports, [25, 587, 465]);
        let api = service(&kernoid, "api").unwrap().spec.unwrap();
        assert_eq!((api.type_.as_deref(), api.external_traffic_policy), (Some("ClusterIP"), None));
    }

    #[test]
    fn an_ingress_leads_the_hosts_to_the_api_role() {
        let mut kernoid = kernoid();
        assert!(ingress(&kernoid).is_none(), "only when asked for");
        kernoid.spec.ingress = Some(crate::crd::Ingress {
            hosts: vec!["login.example.org".into(), "mail.example.org".into()],
            class_name: Some("nginx".into()),
            tls_secret: Some("kernoid-tls".into()),
            annotations: BTreeMap::from([("nginx.ingress.kubernetes.io/proxy-body-size".into(), "0".into())]),
        });
        let made = ingress(&kernoid).unwrap();
        assert_eq!(made.metadata.name.as_deref(), Some("mail-api"));
        assert_eq!(made.metadata.owner_references.unwrap()[0].kind, "Kernoid");
        assert!(made.metadata.annotations.unwrap().contains_key("nginx.ingress.kubernetes.io/proxy-body-size"));
        let spec = made.spec.unwrap();
        assert_eq!(spec.ingress_class_name.as_deref(), Some("nginx"));
        let rules = spec.rules.unwrap();
        assert_eq!(rules.len(), 2);
        let path = &rules[1].http.as_ref().unwrap().paths[0];
        let backend = path.backend.service.as_ref().unwrap();
        assert_eq!((backend.name.as_str(), backend.port.as_ref().unwrap().name.as_deref()), ("mail-api", Some("http")));
        assert_eq!(spec.tls.unwrap()[0].secret_name.as_deref(), Some("kernoid-tls"));

        kernoid.spec.roles.api.replicas = 0;
        assert!(ingress(&kernoid).is_none(), "nothing to lead to");
    }
}
