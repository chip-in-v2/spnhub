//! # Microservice Management
//!
//! This module acts as the control-plane responsible for the lifecycle of microservices.
//!
//! It handles:
//! - Spawning (starting) providers.
//! - Stopping (scaling down) and removing providers.
//!
//! ## Runtime Assumptions
//! - Supports **Docker**, **Nomad**, and **Kubernetes** as backends.
//! - Backend selection is based on the `clusterManagerUrn` prefix:
//!   - `docker:`: Local container management.
//!   - `nomad:`: Nomad Job/Task scaling.
//!   - `k8s:`: Kubernetes Deployment scaling.
//!
//! ## Connection & Authentication
//! - **Docker**: Connects via local Unix domain socket.
//! - **Nomad/Kubernetes**: Connects via HTTP/HTTPS APIs.
//!   - If `ACCESS_TOKEN` is provided in `AvailabilityManagementConfig.env`, it is injected as a Bearer token (K8s) or `X-Nomad-Token` (Nomad).
//!   - Token injection is logged with masking (showing only the first and last 3 characters).
//!
//! ## Security Note
//! - Configuration is assumed to be trusted.
//! - Limited sanitization is performed on parameters like `options`, `command`, or `env`.
//!
//! ## Concurrency Model
//! - Uses asynchronous APIs to avoid blocking the event loop.
//!
//! ## API Surface
//! - `start_provider`: Asynchronously starts a provider using the configured backend.
//! - `stop_provider`: Asynchronously stops and removes a provider.

use crate::config::AvailabilityManagementConfig;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

// --- Public Interface Definitions ---

/// A handle to a started container.
#[derive(Debug)]
pub struct ContainerHandle {
    /// Backend-specific container/task ID.
    pub id: String,
}

/// Errors that can occur during microservice startup.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("Nomad error: {0}")]
    Nomad(#[from] reqwest::Error),
    #[error("Kubernetes error: {0}")]
    K8s(#[from] kube::Error),
    #[error("Error: {0}")]
    Other(String),
}

/// Errors that can occur during microservice shutdown.
#[derive(Debug, thiserror::Error)]
pub enum StopError {
    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("Nomad error: {0}")]
    Nomad(#[from] reqwest::Error),
    #[error("Kubernetes error: {0}")]
    K8s(#[from] kube::Error),
    #[error("Error: {0}")]
    Other(String),
}

/// Routes the start request to the appropriate backend based on the URN prefix.
pub async fn start_provider(
    config: &AvailabilityManagementConfig,
) -> Result<ContainerHandle, StartError> {
    let urn = config._cluster_manager_urn.as_deref().ok_or_else(|| {
        StartError::Other("clusterManagerUrn is required but missing".to_string())
    })?;

    let result = if urn.starts_with("k8s:") {
        k8s_backend::scale_deployment(config, 1)
            .await
            .map(|_| ContainerHandle { id: config.service_id.clone() })
            .map_err(|e| StartError::Other(e.to_string()))
    } else if urn.starts_with("nomad:") {
        nomad_backend::scale_task(config, 1)
            .await
            .map(|_| ContainerHandle { id: config.service_id.clone() })
            .map_err(|e| StartError::Other(e.to_string()))
    } else if urn.starts_with("docker:") {
        docker_backend::start_container(
            &config.image,
            config.options.as_deref(),
            &config.service_id,
            config.env.as_ref(),
            config.command.as_deref(),
        )
        .await
    } else {
        Err(StartError::Other(format!("Unsupported cluster manager URN: {}", urn)))
    };

    match &result {
        Ok(handle) => info!("start_provider result: success, id={}", handle.id),
        Err(e) => info!("start_provider result: failure, error={}", e),
    }
    result
}

/// Routes the stop request to the appropriate backend based on the URN prefix.
pub async fn stop_provider(config: &AvailabilityManagementConfig) -> Result<(), StopError> {
    let urn = config._cluster_manager_urn.as_deref().ok_or_else(|| {
        StopError::Other("clusterManagerUrn is required but missing".to_string())
    })?;

    if urn.starts_with("k8s:") {
        k8s_backend::scale_deployment(config, 0)
            .await
            .map_err(|e| StopError::Other(e.to_string()))
    } else if urn.starts_with("nomad:") {
        nomad_backend::scale_task(config, 0)
            .await
            .map_err(|e| StopError::Other(e.to_string()))
    } else if urn.starts_with("docker:") {
        docker_backend::stop_container(&config.service_id).await
    } else {
        Err(StopError::Other(format!("Unsupported or invalid cluster manager URN prefix: {}", urn)))
    }
}

// --- Docker Backend Implementation ---

mod docker_backend {
    use super::*;
    use bollard::Docker;
    use bollard::errors::Error as DockerError;
    use bollard::models::{ContainerCreateBody, HostConfig, PortBinding};
    use bollard::query_parameters::{
        CreateContainerOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
    };

    /// Starts a Docker container asynchronously.
    pub async fn start_container(
        image: &str,
        options: Option<&[String]>,
        service_id: &str,
        env: Option<&HashMap<String, String>>,
        command: Option<&[String]>,
    ) -> Result<ContainerHandle, StartError> {
        debug!(
            service_id,
            image,
            ?options,
            ?env,
            command = ?command,
            "Docker: Starting container."
        );

        info!(
            endpoint = "/containers/create",
            "Docker: Calling API."
        );
        // Prepare connection to the Unix domain socket. Involves I/O but is a very lightweight synchronous operation.
        let docker = Docker::connect_with_local_defaults()?;
        // Generate container name (sanitization process)
        let container_name = format!(
            "spn_{}",
            service_id.replace(|c: char| !c.is_alphanumeric(), "_")
        );

        // Parse string array options into structures for the Docker API
        let mut network_mode = None;
        let mut binds = Vec::new();
        let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
        let mut privileged = false;
        let mut cap_add = Vec::new();

        if let Some(options) = options {
            let mut i = 0;
            while i < options.len() {
                match options[i].as_str() {
                    "-p" | "--publish" if i + 1 < options.len() => {
                        if let Some((host, container)) = options[i + 1].split_once(':') {
                            let container_port = format!("{}/tcp", container);
                            let binding = PortBinding {
                                host_ip: Some("0.0.0.0".to_string()),
                                host_port: Some(host.to_string()),
                            };
                            port_bindings
                                .entry(container_port)
                                .or_default()
                                .get_or_insert_with(Vec::new)
                                .push(binding);
                        }
                        i += 1;
                    }

                    "--network" if i + 1 < options.len() => {
                        network_mode = Some(options[i + 1].to_string());
                        i += 1;
                    }
                    "-v" | "--volume" if i + 1 < options.len() => {
                        binds.push(options[i + 1].to_string());
                        i += 1;
                    }
                    "--privileged" => privileged = true,
                    "--cap-add" if i + 1 < options.len() => {
                        cap_add.push(options[i + 1].to_string());
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }
        }

        let env_vars = env.map(|map| {
            map.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
        });

        let host_config = HostConfig {
            network_mode,
            binds: Some(binds),
            port_bindings: Some(port_bindings),
            privileged: Some(privileged),
            cap_add: Some(cap_add),
            ..Default::default()
        };

        let config = ContainerCreateBody {
            image: Some(image.to_string()),
            host_config: Some(host_config),
            env: env_vars,
            cmd: command.map(|v| v.to_vec()),
            ..Default::default()
        };

        let create_options = CreateContainerOptions {
            name: Some(container_name.clone()),
            ..Default::default()
        };

        // Create or find existing container
        let id = match docker.create_container(Some(create_options), config).await {
            Ok(c) => c.id,
            Err(DockerError::DockerResponseServerError {
                status_code: 409, ..
            }) => {
                // If it already exists, get its ID
                let inspect = docker.inspect_container(&container_name, None).await?;
                inspect.id.ok_or_else(|| {
                    StartError::Other("Container exists but has no ID".to_string())
                })?
            }
            Err(e) => return Err(e.into()),
        };

        // Start the container
        match docker
            .start_container(&container_name, None::<StartContainerOptions>)
            .await
        {
            Ok(_) => {
                info!(endpoint = format!("/containers/{}/start", container_name), "Docker: Calling API.");
                info!("Docker: Container {} started.", container_name);
            },
            Err(DockerError::DockerResponseServerError {
                status_code: 304, ..
            }) => {
                info!("Docker: Container {} is already running.", container_name);
            }
            Err(e) => return Err(e.into()),
        }

        Ok(ContainerHandle { id })
    }

    /// Stops and removes a Docker container asynchronously.
    pub async fn stop_container(service_id: &str) -> Result<(), StopError> {
        info!(serviceId = service_id, "Docker: Stopping container.");

        let docker = Docker::connect_with_local_defaults()?;
        let container_name = format!(
            "spn_{}",
            service_id.replace(|c: char| !c.is_alphanumeric(), "_")
        );

        info!(
            endpoint = format!("/containers/{}/stop", container_name),
            "Docker: Calling API."
        );

        // Stop with 10s timeout
        let stop_options = Some(StopContainerOptions {
            signal: None,
            t: Some(10),
        });
        if let Err(e) = docker.stop_container(&container_name, stop_options).await {
            if let DockerError::DockerResponseServerError {
                status_code: 404, ..
            } = e
            {
                info!("Docker: Container {} not found.", container_name);
            } else {
                return Err(e.into());
            }
        } else {
            info!("Docker: Container {} stopped.", container_name);
        }

        info!(
            endpoint = format!("/containers/{}", container_name),
            "Docker: Calling API (Delete)."
        );

        // Forced removal (removes if stopped)
        let remove_options = Some(RemoveContainerOptions {
            force: true,
            ..Default::default()
        });
        if let Err(e) = docker
            .remove_container(&container_name, remove_options)
            .await
        {
            if let DockerError::DockerResponseServerError {
                status_code: 404, ..
            } = e
            {
                // Already removed
            } else {
                warn!(
                    "Docker: Failed to remove container {}: {}",
                    container_name,
                    e
                );
            }
        } else {
            info!("Docker: Container {} removed.", container_name);
        }

        Ok(())
    }
}

// --- Kubernetes Backend Implementation ---

mod k8s_backend {
    use super::*;
    use kube::{Client, Api, Config, Resource, api::{Patch, PatchParams}};
    use k8s_openapi::api::apps::v1::Deployment;
    use serde_json::json;

    /// Scales a Kubernetes Deployment to the specified replica count.
    ///
    /// Expects URN format `k8s:<namespace>`.
    /// Uses `service_id` as the Deployment name.
    pub async fn scale_deployment(
        config: &AvailabilityManagementConfig,
        count: i32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let urn = config
            ._cluster_manager_urn
            .as_deref()
            .ok_or("Kubernetes cluster manager URN is missing")?;

        let body = urn
            .strip_prefix("k8s:")
            .ok_or("Invalid Kubernetes URN prefix (must start with 'k8s:')")?;

        // Load base config from environment
        let mut k8s_config = Config::infer().await?;

        // Optional: Parse "url/namespace" or just "namespace"
        let namespace = if let Some((url, ns)) = body.rsplit_once('/') {
            if !url.is_empty() {
                info!("Kubernetes: Overriding API cluster_url to {}", url);
                k8s_config.cluster_url = url.parse()?;
            }
            ns
        } else {
            body
        };

        // Use "default" namespace if empty
        let namespace = if namespace.is_empty() { "default" } else { namespace };

        // Override bearer token if ACCESS_TOKEN is provided in config env
        if let Some(token) = config.env.as_ref().and_then(|m| m.get("ACCESS_TOKEN")) {
            let masked = if token.len() >= 6 {
                format!("{}...{}", &token[..3], &token[token.len() - 3..])
            } else {
                "***".to_string()
            };
            info!("Kubernetes: Injecting ACCESS_TOKEN ({})", masked);
            k8s_config.auth_info.token = Some(token.clone().into());
        } else {
            info!("Kubernetes: No ACCESS_TOKEN injected.");
        }

        // Initialize client
        let client = Client::try_from(k8s_config.clone())?;
        let deployments: Api<Deployment> = Api::namespaced(client, namespace);

        // Construct the full URL using the library's resource path logic
        let name = &config.service_id;
        let base_url = k8s_config.cluster_url.to_string();
        let api_path = Deployment::url_path(&(), Some(namespace));
        let full_url = format!(
            "{}/{}/{}",
            base_url.trim_end_matches('/'),
            api_path.trim_start_matches('/'),
            name
        );

        info!(
            url = %full_url,
            deployment = name,
            count = count,
            "Kubernetes: Calling API to scale deployment."
        );

        // Create patch data for replica count
        let patch = json!({
            "spec": {
                "replicas": count
            }
        });

        // Apply Strategic Merge Patch
        deployments
            .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;

        Ok(())
    }
}

// --- Nomad Backend Implementation ---

mod nomad_backend {
    use super::*;
    use serde_json::json;

    /// Scales a Nomad task group to the specified count.
    ///
    /// Expects URN format `nomad:<api_url>`.
    /// Uses `image` (task group name) as the scaling target.
    pub async fn scale_task(
        config: &AvailabilityManagementConfig,
        count: i32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let urn = config
            ._cluster_manager_urn
            .as_deref()
            .ok_or("Nomad cluster manager URN is missing")?;

        let base_url = urn
            .strip_prefix("nomad:")
            .ok_or("Invalid Nomad URN prefix (must start with 'nomad:')")?
            .trim_end_matches('/');

        let url = format!("{}/scale", base_url);
        let group_id = &config.image;

        let body = json!({
            "Target": { "Group": group_id },
            "Count": count,
            "ErrorOnConflict": false
        });
        debug!(
            "Nomad API Request Body: {}",
            serde_json::to_string(&body).unwrap_or_default()
        );

        // Initialize client and request
        let client = reqwest::Client::new();
        let mut request_builder = client.post(url).json(&body);

        // Inject Nomad Token if ACCESS_TOKEN is provided in config env
        if let Some(token) = config.env.as_ref().and_then(|m| m.get("ACCESS_TOKEN")) {
            let masked = if token.len() >= 6 {
                format!("{}...{}", &token[..3], &token[token.len() - 3..])
            } else {
                "***".to_string()
            };
            info!("Nomad: Injecting ACCESS_TOKEN ({})", masked);
            request_builder = request_builder.header("X-Nomad-Token", token);
        } else {
            info!("Nomad: No ACCESS_TOKEN injected.");
        }

        // Build the actual request to extract the final resolved URL for logging
        let request = request_builder.build()?;
        info!(
            url = %request.url(),
            group = group_id,
            count = count,
            "Nomad: Calling API to scale task."
        );

        let response = client.execute(request).await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Empty response body".to_string());
            error!(
                "Nomad API error response: status={}, body={}",
                status,
                error_text
            );
            return Err(format!("Nomad API error ({}): {}", status, error_text).into());
        }

        Ok(())
    }
}
