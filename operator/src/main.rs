// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kernoid-operator`: runs kernoid on Kubernetes as `Kernoid` resources describe (docs: Operations, Kubernetes).
//!
//! - `kernoid-operator run [--namespace <NS>]` – the controller, in the cluster with its service account or outside
//!   with a kubeconfig.
//! - `kernoid-operator crd` – the CustomResourceDefinition of `Kernoid`, as JSON for `kubectl apply -f -`.

mod controller;
mod crd;
mod resources;

use clap::{Parser, Subcommand};
use kube::CustomResourceExt;

#[derive(Debug, Parser)]
#[command(version, about = "Runs kernoid on Kubernetes")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Keeps every `Kernoid` running as it says.
    Run {
        /// Only the `Kernoid` resources of this namespace; all namespaces unless set.
        #[arg(long, env = "KERNOID_OPERATOR_NAMESPACE")]
        namespace: Option<String>,
        /// `json` for logs a collector reads.
        #[arg(long, env = "KERNOID_OPERATOR_LOG_FORMAT", default_value = "text")]
        log_format: String,
    },
    /// Prints the CustomResourceDefinition of `Kernoid`.
    Crd,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Crd => {
            println!("{}", serde_json::to_string_pretty(&crd::Kernoid::crd())?);
            Ok(())
        }
        Command::Run { namespace, log_format } => {
            let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            let logs = tracing_subscriber::fmt().with_env_filter(filter);
            if log_format == "json" {
                logs.json().init()
            } else {
                logs.init()
            }
            let client = kube::Client::try_default().await?;
            tracing::info!(version = env!("CARGO_PKG_VERSION"), ?namespace, "starting");
            controller::run(client, namespace).await;
            Ok(())
        }
    }
}
