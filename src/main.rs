//! # SPN Hub Server
//!
//! `spn` is an infrastructure system for building and managing distributed component applications,
//! particularly those that are containerized. The system consists of two main parts that
//! work in tandem: `spn_hub` and `spn_agent`. This crate implements `spn_hub`.
//!
//! ## Usage
//! To run the hub with info-level logging:
//! `RUST_LOG=info cargo run`
//!
//! ## TODO
//! - Replace target provider on consumer reconnection.

use std::collections::{HashMap, hash_map::Entry};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{RwLock, mpsc};
use tokio::time::{self, Duration, Instant};
use tracing::{Instrument, debug, error, info, info_span, warn};
use tracing_subscriber::EnvFilter;

mod config;
mod microservice;
mod utils;
mod tls_kx_intercept;

use crate::config::{
    AppConfig, ConfigHotReloadService, HubConfig, RealmConfig, load_initial_config,
};

// --- QUIC Parameters ---
const QUIC_MAX_CONCURRENT_UNI_STREAMS: u8 = 0;
const QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 1024 * 1024;
const QUIC_KEEP_ALIVE_INTERVAL_SECS: u64 = 5;
const QUIC_IDLE_TIMEOUT_SECS: u64 = 20;

// --- Application Logic Constants ---
/// Interval for reporting server statistics.
const STATS_REPORT_INTERVAL_SECS: u64 = 10;
/// Interval for a consumer to retry finding a provider.
const PROVIDER_SEARCH_INTERVAL_SECS: u64 = 1;
/// The maximum time a consumer will wait to find an available provider.
const PROVIDER_SEARCH_TIMEOUT_SECS: u64 = 600;
/// Capacity for the MPSC channel that reports errors from stream proxy tasks.
const ERROR_CHANNEL_CAPACITY: usize = 32;
/// The delay between retries when a consumer fails to connect to a provider, to prevent busy-looping.
const CONSUMER_PROVIDER_RETRY_DELAY: Duration = Duration::from_millis(500);
/// The polling interval to check if all connections are drained during a graceful shutdown.
const GRACEFUL_SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// The minimum interval between on-demand start requests from the same consumer to prevent abuse.
const ONDEMAND_SERVICE_START_RATE_LIMIT_PER_CONSUMER: Duration = Duration::from_secs(10);
/// The maximum time to wait for connections to drain during a graceful shutdown.
const GRACEFUL_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

// --- Application-Specific QUIC Error Codes ---
/// Error code for when a client connects without a valid CN or ALPN.
const APP_ERR_CODE_MISSING_IDENTITY: u32 = 1;
/// Error code for when a client connects with an unsupported ALPN role.
const APP_ERR_CODE_UNSUPPORTED_ROLE: u32 = 2;
/// Error code for when a consumer cannot find an available provider for its service.
const APP_ERR_CODE_NO_PROVIDER_FOUND: u32 = 100;

/// Command-line arguments.
#[derive(Parser)]
struct Args {
    /// Path to the configuration file or URL of the repository server.
    #[arg(
        long,
        env = "SPNHUB_INVENTORY_URL",
        default_value = "http://localhost:3000/v1"
    )]
    config: String,
}

/// Holds service information looked up from the config.
#[derive(Clone, Debug)]
struct ServiceInfo {
    name: String,
    urn: String,
}

type HubKey = (String, String); // (RealmName, HubName)

#[derive(Clone, Copy, Debug)]
enum ShutdownMode {
    Graceful,
    Immediate,
}

struct RunningHub {
    handle: tokio::task::JoinHandle<()>,
    shutdown_tx: mpsc::Sender<ShutdownMode>,
    config: HubConfig,
    realm_ca_cert: String,
    endpoint: quinn::Endpoint,
    // Add a swappable service map to allow hot-reloading it.
    service_map_swap: Arc<ArcSwap<HashMap<String, ServiceInfo>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // log
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .json()
        .with_current_span(false)
        .init();

    let args = Args::parse();

    // QUIC setup (normal)
    // default_provider()
    //    .install_default()
    //    .expect("Failed to install crypto provider");

    // QUIC setup with TLS intercept - Temporary workaround; revisit for cleaner implementation in Quinn 0.12.
    tls_kx_intercept::install_intercept_provider();

    info!(
        "SPN Hub Server started (Version: {}, PID: {}) with inventory configuration: {}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        args.config
    );

    // Load initial config
    let (initial_config, initial_content) = load_initial_config(&args.config).await?;
    let shared_config = Arc::new(ArcSwap::from_pointee(initial_config.clone()));

    // Start hot-reload service
    let reload_service =
        ConfigHotReloadService::new(args.config.clone(), shared_config.clone(), initial_content);

    let mut running_hubs: HashMap<HubKey, RunningHub> = HashMap::new();

    // Initial start
    reconcile_hubs(&initial_config, &mut running_hubs, shared_config.clone()).await;

    info!(
        "Started {} hubs. Waiting for connections...",
        running_hubs.len()
    );

    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    let shutdown_mode;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C (SIGINT) received, shutting down immediately...");
                shutdown_mode = ShutdownMode::Immediate;
                break;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down gracefully...");
                shutdown_mode = ShutdownMode::Graceful;
                break;
            }
            _ = sigusr1.recv() => {
                info!("SIGUSR1 received, reloading configuration...");
                if let Some(new_config) = reload_service.check_and_reload().await {
                    reconcile_hubs(&new_config, &mut running_hubs, shared_config.clone()).await;
                } else {
                    info!("Configuration has not changed, no action taken.");
                }
            }
        }
    }

    // Wait for all servers to finish
    for (_, hub) in running_hubs {
        let _ = hub.shutdown_tx.send(shutdown_mode).await;
        let _ = hub.handle.await;
    }

    Ok(())
}

async fn reconcile_hubs(
    config: &AppConfig,
    running_hubs: &mut HashMap<HubKey, RunningHub>,
    shared_config: Arc<ArcSwap<AppConfig>>,
) {
    info!("Loaded configuration details:");
    for realm in &config.realms {
        info!(
            "- Realm: '{}' (disabled: {})",
            realm.realm_name, realm.disabled
        );
        for hub in &realm.hubs {
            info!(
                "  - Hub: '{}' listening on {}:{}",
                hub.name, hub.server_address, hub.server_port
            );
        }
    }

    // 1. Identify hubs that need to be stopped (removed or port changed)
    let mut to_stop = Vec::new();
    for (key, running_hub) in running_hubs.iter_mut() {
        let (realm_name, hub_name) = key;

        // Find corresponding hub in new config
        let new_config_entry = config
            .realms
            .iter()
            .find(|r| r.realm_name == *realm_name && !r.disabled)
            .and_then(|r| r.hubs.iter().find(|h| h.name == *hub_name).map(|h| (r, h)));

        match new_config_entry {
            None => {
                // Not found in new config (or realm disabled) -> Remove
                to_stop.push(key.clone());
            }
            Some((new_realm, new_hub)) => {
                // Check if restart is needed (Address/Port change)
                if running_hub.config.server_address != new_hub.server_address
                    || running_hub.config.server_port != new_hub.server_port
                {
                    info!(
                        "Network configuration changed for hub: {} (Realm: {}). Restarting...",
                        hub_name, realm_name
                    );
                    to_stop.push(key.clone());
                } else {
                    // Check if certificate update is needed
                    if running_hub.config.server_cert != new_hub.server_cert
                        || running_hub.config.server_cert_key != new_hub.server_cert_key
                        || running_hub.realm_ca_cert != new_realm.realm_ca_cert
                    {
                        info!(
                            "Certificate changed for hub: {}. Reloading certificates...",
                            hub_name
                        );
                        let reload_result = || -> Result<(), Box<dyn std::error::Error>> {
                            let (certs, key, truststore) = utils::load_certs_and_key_from_strings(
                                &new_hub.server_cert,
                                &new_hub.server_cert_key,
                                &new_realm.realm_ca_cert,
                            )?;
                            let server_config = utils::create_server_config(
                                certs,
                                key,
                                truststore,
                                &[b"sc01-provider", b"sc01-consumer"],
                            )?;
                            running_hub.endpoint.set_server_config(Some(server_config));
                            Ok(())
                        };

                        if let Err(e) = reload_result() {
                            error!("Failed to reload certificates for hub {}: {}", hub_name, e);
                            continue;
                        }
                        info!("Certificates reloaded for hub: {}", hub_name);
                    }

                    // Update stored config state
                    running_hub.config = new_hub.clone();
                    running_hub.realm_ca_cert = new_realm.realm_ca_cert.clone();

                    // Check if service list has changed and reload the service map if so.
                    if running_hub.config.services != new_hub.services {
                        info!(
                            "Service list changed for hub: {}. Reloading service map...",
                            hub_name
                        );
                        let new_service_map = Arc::new(build_service_map(&new_hub.services));
                        running_hub.service_map_swap.store(new_service_map);
                        info!("Service map reloaded for hub: {}", hub_name);
                    }
                }
            }
        }
    }

    // 2. Stop removed/restarting hubs
    for k in to_stop {
        if let Some(hub) = running_hubs.remove(&k) {
            info!("Stopping hub: {} (Realm: {})", k.1, k.0);
            let _ = hub.shutdown_tx.send(ShutdownMode::Graceful).await;
            let _ = hub.handle.await; // Wait for release port
            info!("Hub stopped: {} (Realm: {})", k.1, k.0);
        }
    }

    // 3. Start new hubs
    for realm in &config.realms {
        if realm.disabled {
            info!("Skipping disabled realm: {}", realm.realm_name);
            continue;
        }
        for hub in &realm.hubs {
            let key = (realm.realm_name.clone(), hub.name.clone());
            if let Entry::Vacant(e) = running_hubs.entry(key) {
                info!(
                    "Starting hub: {} (Realm: {}) on host: {}",
                    hub.name, realm.realm_name, hub.server_address
                );
                match start_hub(realm, hub, shared_config.clone()).await {
                    Ok(running_hub) => {
                        e.insert(running_hub);
                    }
                    Err(e) => {
                        error!("Failed to start hub {}: {}", hub.name, e);
                    }
                }
            }
        }
    }
}

/// Builds a map from a client URN (CN) to its service information.
fn build_service_map(services: &[config::ServiceConfig]) -> HashMap<String, ServiceInfo> {
    let mut service_map = HashMap::new();
    for service in services {
        let service_info = ServiceInfo {
            name: service.name.clone(),
            urn: service.urn.clone(),
        };
        service_map.insert(service.provider.clone(), service_info.clone());
        for consumer in &service.consumers {
            service_map.insert(consumer.clone(), service_info.clone());
        }
    }
    service_map
}

async fn start_hub(
    realm: &RealmConfig,
    hub: &HubConfig,
    shared_config: Arc<ArcSwap<AppConfig>>,
) -> Result<RunningHub, Box<dyn std::error::Error>> {
    let (certs, key, truststore) = utils::load_certs_and_key_from_strings(
        &hub.server_cert,
        &hub.server_cert_key,
        &realm.realm_ca_cert,
    )?;

    let endpoint = utils::create_quic_server_endpoint(
        &hub.server_address,
        hub.server_port,
        certs,
        key,
        truststore,
        &[b"sc01-provider", b"sc01-consumer"],
    )?;

    let provider_connections = Arc::new(RwLock::new(HashMap::new()));
    let consumer_connections = Arc::new(RwLock::new(HashMap::new()));

    let service_map = build_service_map(&hub.services);
    info!(
        "Initial service map for hub {}: {:?}",
        hub.name, service_map
    );
    let service_map_swap = Arc::new(ArcSwap::from_pointee(service_map));

    let server = Server::new(
        realm.realm_name.clone(),
        hub.name.clone(),
        endpoint.clone(),
        provider_connections,
        consumer_connections,
        service_map_swap.clone(),
        shared_config,
    )?;

    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let handle = tokio::spawn(async move {
        server.run(shutdown_rx).await;
    });

    Ok(RunningHub {
        handle,
        shutdown_tx,
        config: hub.clone(),
        realm_ca_cert: realm.realm_ca_cert.clone(),
        endpoint,
        service_map_swap,
    })
}

/// Manages the overall lifecycle of the server.
struct Server {
    realm_name: String,
    hub_name: String,
    /// The QUIC endpoint bound to the server socket.
    endpoint: quinn::Endpoint,
    /// A map storing provider connections.
    /// Key: Service name -> Inner Key: Connection ID -> Value: Provider Entry.
    provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
    /// A map storing consumer connections.
    /// Key: Consumer URI (CN) -> Inner Key: Connection ID -> Value: QUIC connection.
    consumer_connections: Arc<RwLock<HashMap<String, HashMap<usize, ConsumerEntry>>>>,
    /// A map for looking up the service name associated with a given endpoint URI (CN).
    service_map: Arc<ArcSwap<HashMap<String, ServiceInfo>>>,
    /// Shared application configuration, used for features like on-demand start.
    shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
}

impl Server {
    /// Creates a new server instance.
    fn new(
        realm_name: String,
        hub_name: String,
        endpoint: quinn::Endpoint,
        provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
        consumer_connections: Arc<RwLock<HashMap<String, HashMap<usize, ConsumerEntry>>>>,
        service_map: Arc<ArcSwap<HashMap<String, ServiceInfo>>>,
        shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        info!(
            "Listening on {} (Realm: {}, Hub: {})",
            endpoint.local_addr()?,
            realm_name,
            hub_name
        );
        Ok(Self {
            realm_name,
            hub_name,
            endpoint,
            provider_connections,
            consumer_connections,
            service_map,
            shared_config,
        })
    }

    /// Runs the main server loop to accept connections.
    async fn run(&self, mut shutdown_rx: mpsc::Receiver<ShutdownMode>) {
        info!(
            "Server (Realm: {}, Hub: {}) is ready to accept connections.",
            self.realm_name, self.hub_name
        );

        let mut stats_interval = time::interval(Duration::from_secs(STATS_REPORT_INTERVAL_SECS));
        // Prevent tick buildup if processing lags
        stats_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = stats_interval.tick() => {
                    let realm_name = self.realm_name.clone();
                    let hub_name = self.hub_name.clone();
                    let providers = self.provider_connections.clone();
                    let consumers = self.consumer_connections.clone();
                    let service_map = self.service_map.clone();
                    let shared_config = self.shared_config.clone();

                    tokio::spawn(async move {
                        Self::update_provider_idle_and_report_connection_stats(
                            &realm_name,
                            &hub_name,
                            &providers,
                            &consumers,
                            &service_map,
                            &shared_config
                        ).await;
                    });
                }
                Some(connecting) = self.endpoint.accept() => {
                    info!("QUIC Connection incoming from {}", connecting.remote_address());

                    let provider_connections = self.provider_connections.clone();
                    let consumer_connections = self.consumer_connections.clone();
                    let realm_name = self.realm_name.clone();
                    let hub_name = self.hub_name.clone();
                    let service_map = self.service_map.clone();
                    let shared_config = self.shared_config.clone();
                    // Spawn an asynchronous task for each new connection.
                    tokio::spawn(async move {
                        match connecting.await {
                            Ok(connection) => {
                                let span = info_span!(
                                    "quic connection",
                                    id = connection.stable_id(),
                                    remote = %connection.remote_address()
                                );

                                // The future created by the async block is instrumented with the span.
                                async move {
                                    // get connection information
                                    let (cert_cn_opt, alpn_opt) =
                                        utils::check_and_get_info_connection(connection.clone()).await;
                                    let (cn, alpn) = match (cert_cn_opt, alpn_opt) {
                                        (Some(cn), Some(alpn)) => (cn, alpn),
                                        _ => {
                                            warn!("Could not identify client by CN or ALPN. Closing connection.");
                                            // Close the connection with an application-defined error code.
                                            connection.close(APP_ERR_CODE_MISSING_IDENTITY.into(), b"Missing CN or ALPN");
                                            return;
                                        }
                                    };

                                    info!("connected: cn={}, alpn={}", cn.clone(), alpn.clone());

                                    // Dispatch to the appropriate handler based on the ALPN protocol.
                                    let handle_result = match alpn.as_str() {
                                        "sc01-provider" => {
                                            let connection_id = connection.stable_id();
                                            ProviderHandler::new(
                                                connection.clone(),
                                                cn,
                                                provider_connections,
                                                service_map,
                                                shared_config.clone(),
                                            ).run()
                                                .instrument(info_span!("provider_handler", id = connection_id))
                                                .await
                                        }
                                        "sc01-consumer" => {
                                            // `handler` needs to be mutable because `run()` modifies its internal state
                                            // (e.g., `target_provider`).
                                            let connection_id = connection.stable_id();
                                            ConsumerHandler::new(
                                                connection.clone(),
                                                cn,
                                                realm_name,
                                                hub_name,
                                                provider_connections,
                                                consumer_connections,
                                                service_map,
                                                shared_config,
                                            ).run()
                                                .instrument(info_span!("consumer_handler", id = connection_id))
                                                .await
                                        }
                                        unsupported => {
                                            warn!(
                                                "Unsupported ALPN protocol: {}. Closing connection.",
                                                unsupported
                                            );
                                            connection.close(APP_ERR_CODE_UNSUPPORTED_ROLE.into(), b"Unsupported client role");
                                            Ok(()) // Return Ok to end the task for this connection gracefully.
                                        }
                                    };

                                    if let Err(e) = handle_result {
                                        error!("Connection handler failed: {}", e);
                                    }
                                }.instrument(span)
                                .await;
                            }
                            Err(e) => {
                                error!("Failed to establish connection: {}", e);
                            }
                        }
                    });
                }
                mode = shutdown_rx.recv() => {
                    let mode = mode.unwrap_or(ShutdownMode::Immediate);
                    match mode {
                        ShutdownMode::Graceful => {
                            info!("Shutdown signal received (Graceful), starting graceful shutdown.");

                            // Send notify_shutdown to all providers
                            {
                                let providers = self.provider_connections.read().await;
                                for (service_name, provider_map) in providers.iter() {
                            for entry in provider_map.values() {
                                info!("Sending notify_shutdown to provider: {} ({})", entry.uri, service_name);
                                        let _ = entry.connection.send_datagram(b"notify_shutdown".to_vec().into());
                                    }
                                }
                            }

                            // Send notify_shutdown to all consumers
                            {
                                let consumers = self.consumer_connections.read().await;
                                for (uri, consumer_map) in consumers.iter() {
                                    for (id, entry) in consumer_map.iter() {
                                        info!("Sending notify_shutdown to consumer: {} (ID: {})", uri, id);
                                        let _ = entry.connection.send_datagram(b"notify_shutdown".to_vec().into());
                                    }
                                }
                            }

                            // Wait for connections to drain
                            let timeout = GRACEFUL_SHUTDOWN_DRAIN_TIMEOUT;
                            let start = Instant::now();
                            info!("Waiting for connections to drain (timeout: {:?})", timeout);

                            loop {
                                if start.elapsed() >= timeout {
                                    warn!("Graceful shutdown timeout reached. Forcing close.");
                                    break;
                                }

                                let p_count = self.provider_connections.read().await.values().map(|m| m.len()).sum::<usize>();
                                let c_count = self.consumer_connections.read().await.values().map(|m| m.len()).sum::<usize>();

                                if p_count == 0 && c_count == 0 {
                                    info!("All connections drained.");
                                    break;
                                }
                                time::sleep(GRACEFUL_SHUTDOWN_POLL_INTERVAL).await;
                            }
                        }
                        ShutdownMode::Immediate => {
                            info!("Shutdown signal received (Immediate), shutting down.");
                        }
                    }
                    break;
                }
            }
        }
        // Close the endpoint to stop accepting new connections.
        // The integer code is an application-defined reason for closing. 0 is a generic "going away".
        self.endpoint.close(0u32.into(), b"server shutting down");

        // Wait for all connections to be gracefully shut down.
        self.endpoint.wait_idle().await;
        info!(
            "Shutdown complete (Realm: {}, Hub: {}).",
            self.realm_name, self.hub_name
        );
    }

    /// Periodically updates provider idle status and reports statistics for all connections.
    async fn update_provider_idle_and_report_connection_stats(
        realm_name: &str,
        hub_name: &str,
        providers: &Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
        consumers: &Arc<RwLock<HashMap<String, HashMap<usize, ConsumerEntry>>>>,
        service_map: &Arc<ArcSwap<HashMap<String, ServiceInfo>>>,
        shared_config: &Arc<ArcSwap<AppConfig>>,
    ) {
        // 1. Create snapshots to minimize lock duration

        // Snapshot Providers
        let (provider_snapshot, provider_count) = {
            // Use a read lock on the map. The idle_since field is updated via atomics.
            let providers_lock = providers.read().await;
            let provider_count: usize = providers_lock.values().map(|v| v.len()).sum();

            let mut snapshot = Vec::with_capacity(provider_count);
            for (service, map) in providers_lock.iter() {
                for entry in map.values() {
                    let opened = entry.total_opened_streams.load(Ordering::Relaxed);
                    let closed = entry.total_closed_streams.load(Ordering::Relaxed);

                    // Atomically update and read the idle status using atomics to avoid locks.
                    let current_idle_since = {
                        if opened > closed {
                            // Busy: clear state.
                            entry.idle_since.store(0, Ordering::Relaxed);
                            None
                        } else {
                            // Idle: check for state changes.
                            let stored_since = entry.idle_since.load(Ordering::Relaxed);
                            let stored_opened = entry.streams_at_idle_start.load(Ordering::Relaxed);

                            if stored_since != 0 && stored_opened == opened {
                                // Continuously idle. Keep timestamp.
                                DateTime::from_timestamp(stored_since, 0)
                            } else {
                                // State changed or was busy. Reset timer.
                                let now = Utc::now().timestamp();
                                entry.streams_at_idle_start.store(opened, Ordering::Relaxed);
                                entry.idle_since.store(now, Ordering::Relaxed);
                                DateTime::from_timestamp(now, 0)
                            }
                        }
                    };

                    snapshot.push((
                        service.clone(),
                        entry.uri.clone(),
                        entry.connection.clone(),
                        entry.status.clone(),
                        opened,
                        closed,
                        current_idle_since,
                    ));
                }
            }
            (snapshot, provider_count)
        };

        // Snapshot Consumers
        let (consumer_snapshot, consumer_count) = {
            let consumers_lock = consumers.read().await;
            let consumer_count: usize = consumers_lock.values().map(|v| v.len()).sum();

            let snapshot: Vec<_> = consumers_lock
                .iter()
                .flat_map(|(uri, conns)| {
                    conns
                        .values()
                        .map(|entry| (uri.clone(), entry.connection.clone()))
                })
                .collect();
            (snapshot, consumer_count)
        };

        // 2. Identify and stop idle providers
        let config = shared_config.load();
        if let Some(hub_config) = config
            .realms
            .iter()
            .find(|r| r.realm_name == *realm_name)
            .and_then(|r| r.hubs.iter().find(|h| h.name == *hub_name))
        {
            for (service, _cn, conn, _status, _opened, _closed, idle_since) in &provider_snapshot {
                if let Some(since) = idle_since
                    && let Some(service_config) =
                        hub_config.services.iter().find(|s| &s.name == service)
                {
                    let am_config = &service_config.availability_management;
                    let idle_timeout = am_config.idle_timeout;

                    if idle_timeout > 0 {
                        let idle_duration = (Utc::now() - *since).num_seconds() as u64;
                        if idle_duration >= idle_timeout {
                            info!(
                                eventType = "autoLifecycleStopInitiated",
                                service = service,
                                urn = service_config.urn,
                                image = am_config.image,
                                idle_duration = idle_duration,
                                idle_timeout = idle_timeout,
                                "Idle provider timeout reached. Initiating stop."
                            );

                            // Close the QUIC connection. This will trigger its removal from the map in its handler.
                            conn.close(0u32.into(), b"idle timeout");

                            // Identify associated consumers to notify if stop succeeds
                            let consumers_to_notify: Vec<(String, quinn::Connection)> =
                                consumer_snapshot
                                    .iter()
                                    .filter(|(c_uri, _)| {
                                        service_map
                                            .load()
                                            .get(c_uri)
                                            .is_some_and(|info| info.name == *service)
                                    })
                                    .cloned()
                                    .collect();

                            // Stop the underlying microservice.
                            // Note: stop_provider only initiates the stop sequence (e.g., sending a command to Docker/Nomad)
                            // and does not guarantee that the process has completely terminated at the time of return.
                            let am_config_clone = am_config.clone();
                            let service_clone = service.clone();
                            let urn_clone = service_config.urn.clone();
                            tokio::spawn(async move {
                                match microservice::stop_provider(&am_config_clone).await {
                                    Ok(_) => {
                                        info!(
                                            eventType = "autoLifecycleStopSuccess",
                                            service = service_clone,
                                            urn = urn_clone,
                                            "Idle provider stopped successfully."
                                        );

                                        // Notify associated consumers via control datagram only on success
                                        for (c_uri, c_conn) in consumers_to_notify {
                                            info!(
                                                "Notifying consumer '{}' that provider for service '{}' is stopped.",
                                                c_uri, service_clone
                                            );
                                            let _ = c_conn.send_datagram(
                                                b"notify_provider_stopped".to_vec().into(),
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            eventType = "autoLifecycleStopFailed",
                                            service = service_clone,
                                            urn = urn_clone,
                                            error = %e,
                                            "Idle provider failed to stop."
                                        );
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }

        // Get tokio thread info (requires `tokio_unstable` feature).
        let tokio_workers = tokio::runtime::Handle::current().metrics().num_workers();
        let tokio_tasks = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();

        info!(
            message = "Stats",
            realm = realm_name,
            hub = hub_name,
            totalConnectionCount = provider_count + consumer_count,
            tokioWorkers = tokio_workers,
            tokioTasks = tokio_tasks,
            providerConnectionCount = provider_count,
            consumerConnectionCount = consumer_count,
        );

        // 3. Log stats
        for (service, cn, conn, status, opened, closed, idle_since) in provider_snapshot {
            let stats = conn.stats();
            let active_streams = opened.saturating_sub(closed);
            let idle_status = if let Some(since) = idle_since {
                format!("idle for {}s", (Utc::now() - since).num_seconds())
            } else {
                "busy".to_string()
            };

            info!(
                type = "provider",
                realm = realm_name,
                hub = hub_name,
                service,
                spnEndPoint = cn,
                spnSessionId = conn.stable_id(),
                status = ?status,
                activeStreams = active_streams,
                idleStatus = idle_status,
                rttMs = stats.path.rtt.as_millis(),
                lostPackets = stats.path.lost_packets,
                " -Prov"
            );
        }

        for (uri, conn) in consumer_snapshot {
            let stats = conn.stats();
            let service_map_ref = service_map.load();
            let service = service_map_ref
                .get(&uri)
                .map(|s| s.name.as_str())
                .unwrap_or("unknown");
            info!(
                type = "consumer",
                realm = realm_name,
                hub = hub_name,
                service,
                spnEndPoint = uri,
                spnSessionId = conn.stable_id(),
                rttMs = stats.path.rtt.as_millis(),
                lostPackets = stats.path.lost_packets,
                " -Cons"
            );
        }
    }
}

/// Holds contextual information for a single connection.
#[derive(Clone)]
struct ConnectionContext {
    connection: quinn::Connection,
    start_at: DateTime<Utc>,
    connection_id: usize,
    uri: String,
    endpoint_type: String,
    service: String,
    service_urn: String,
    total_opened_streams: Arc<AtomicUsize>,
    total_closed_streams: Arc<AtomicUsize>,
}

/// Represents the operational status of a provider.
#[derive(Clone, Debug, PartialEq)]
enum ProviderStatus {
    /// The provider is active and can accept new consumer streams.
    Active,
    /// The provider is shutting down and will not accept new consumer streams.
    ShuttingDown,
    /// The provider is waiting for the active provider to disconnect.
    StandBy,
}

/// Stores the provider's connection and its current status.
#[derive(Clone)]
struct ProviderEntry {
    connection: quinn::Connection,
    status: ProviderStatus,
    total_opened_streams: Arc<AtomicUsize>,
    total_closed_streams: Arc<AtomicUsize>,
    uri: String,
    created_at: DateTime<Utc>,
    /// Timestamp (seconds since epoch) when the provider became idle. 0 if busy (processing streams).
    idle_since: Arc<AtomicI64>,
    /// The number of total opened streams when the provider became idle.
    streams_at_idle_start: Arc<AtomicUsize>,
}

/// Stores the consumer's connection.
#[derive(Clone)]
struct ConsumerEntry {
    connection: quinn::Connection,
}

/// Handles connections from clients with the "provider" role.
/// Providers register themselves and wait for incoming requests (proxied streams).
struct ProviderHandler {
    context: ConnectionContext,
    provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
}

impl ProviderHandler {
    /// Creates a new provider handler.
    fn new(
        connection: quinn::Connection,
        cn: String,
        provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
        service_map: Arc<ArcSwap<HashMap<String, ServiceInfo>>>,
        _shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
    ) -> Self {
        let now = Utc::now();
        let conn_id = connection.stable_id();
        let service_info = service_map
            .load() // Load the latest service map
            .get(&cn) // Get from the loaded map
            .cloned()
            .unwrap_or_else(|| ServiceInfo {
                name: "unknown".to_string(),
                urn: "unknown".to_string(),
            });

        let endpoint_type = "serviceProvider".to_string();
        let context = ConnectionContext {
            connection: connection.clone(),
            start_at: now,
            connection_id: conn_id,
            uri: cn.clone(),
            endpoint_type: endpoint_type.clone(),
            service: service_info.name.clone(),
            service_urn: service_info.urn.clone(),
            total_opened_streams: Arc::new(AtomicUsize::new(0)),
            total_closed_streams: Arc::new(AtomicUsize::new(0)),
        };
        info!(
            eventType = "startSpnSession",
            timestamp = %context.start_at,
            spnSessionId = context.connection_id,
            spnEndPoint = &context.uri,
            endPointType = &context.endpoint_type,
            serviceUrn = &context.service_urn,
            remote = %context.connection.remote_address(),
            "SPN session (QUIC Connection) started"
        );
        Self {
            context,
            provider_connections,
        }
    }

    /// Spawns a background task to listen for control datagrams.
    ///
    /// Supported control messages:
    /// - `notify_shutdown`: Notifies that the provider is starting a graceful shutdown.
    fn spawn_control_datagram_handler(&self) {
        let datagram_conn = self.context.connection.clone();
        let provider_uri = self.context.uri.clone();
        let connection_id = self.context.connection_id;
        let service_name = self.context.service.clone();
        let provider_connections = self.provider_connections.clone();

        tokio::spawn(async move {
            while let Ok(bytes) = datagram_conn.read_datagram().await {
                let message = String::from_utf8_lossy(&bytes);
                info!(
                    "Received control datagram from provider '{}': {:?}",
                    provider_uri, message
                );

                match message.trim() {
                    "notify_shutdown" => {
                        info!(
                            "Provider '{}' notified graceful shutdown. Marking as ShuttingDown.",
                            provider_uri
                        );
                        let mut providers_by_service = provider_connections.write().await;
                        if let Some(providers_for_service) =
                            providers_by_service.get_mut(&service_name)
                            && let Some(provider_entry) =
                                providers_for_service.get_mut(&connection_id)
                        {
                            provider_entry.status = ProviderStatus::ShuttingDown;
                            info!(
                                "Provider '{}' status set to ShuttingDown. It will no longer accept new consumers.",
                                provider_uri
                            );
                        }
                        // The provider client is expected to close the connection after its own grace period.
                        // The connection.closed().await in the run() loop will handle the final cleanup.
                    }
                    _ => {
                        warn!(
                            "Unknown control message from provider '{}': {}",
                            provider_uri, message
                        );
                    }
                }
            }
        });
    }

    /// Runs a loop on the connection to accept streams from the provider.
    async fn run(&self) -> Result<(), quinn::ConnectionError> {
        // Start a background task to listen for control datagrams
        self.spawn_control_datagram_handler();

        // Register the connection.
        {
            let mut providers_by_service = self.provider_connections.write().await;
            let service_map = providers_by_service
                .entry(self.context.service.clone())
                .or_default();

            // Check if there is ANY Active provider for this service
            let has_active = service_map
                .values()
                .any(|v| v.status == ProviderStatus::Active);
            let status = if has_active {
                ProviderStatus::StandBy
            } else {
                ProviderStatus::Active
            };

            let entry = ProviderEntry {
                connection: self.context.connection.clone(),
                status: status.clone(),
                total_opened_streams: self.context.total_opened_streams.clone(),
                total_closed_streams: self.context.total_closed_streams.clone(),
                uri: self.context.uri.clone(),
                created_at: self.context.start_at,
                // A new provider starts with 0 streams, so it is considered idle.
                idle_since: Arc::new(AtomicI64::new(self.context.start_at.timestamp())),
                streams_at_idle_start: Arc::new(AtomicUsize::new(0)),
            };
            service_map.insert(self.context.connection_id, entry);

            let total_services = providers_by_service.len();
            let total_providers: usize = providers_by_service.values().map(|v| v.len()).sum();
            info!(
                "Provider '{}' registered as {:?}. (Total services: {}, Total providers: {})",
                self.context.uri, status, total_services, total_providers
            );
            info!("Current provider connections state:");
            for (service, providers) in providers_by_service.iter() {
                for (conn_id, entry) in providers.iter() {
                    info!(
                        service = service.as_str(),
                        provider_cn = entry.uri.as_str(),
                        connection_id = conn_id,
                        status = ?entry.status
                    );
                }
            }
        }

        // Wait for the connection to be closed for any reason. This is the main lifetime of the handler.
        let reason = self.context.connection.closed().await;
        let stats = self.context.connection.stats();

        // Remove the connection from the shared map upon disconnection.
        {
            let mut providers_by_service = self.provider_connections.write().await;
            if let Some(providers_for_service) = providers_by_service.get_mut(&self.context.service)
            {
                // Check if the disconnecting provider was active before removing it.
                let was_active = providers_for_service
                    .get(&self.context.connection_id)
                    .is_some_and(|e| e.status == ProviderStatus::Active);

                // Remove the provider from the map.
                if providers_for_service
                    .remove(&self.context.connection_id)
                    .is_some()
                {
                    info!(
                        "Provider '{}' removed from connection map.",
                        self.context.uri
                    );

                    // If an active provider was removed and no other active provider exists for this service,
                    // promote the oldest standby provider to maintain service availability.
                    if was_active
                        && !providers_for_service
                            .values()
                            .any(|e| e.status == ProviderStatus::Active)
                    {
                        let to_promote_key = providers_for_service
                            .iter()
                            .filter(|(_, e)| e.status == ProviderStatus::StandBy)
                            .min_by_key(|(_, e)| e.created_at)
                            .map(|(k, _)| *k);

                        if let Some(key) = to_promote_key
                            && let Some(entry) = providers_for_service.get_mut(&key)
                        {
                            entry.status = ProviderStatus::Active;
                            info!(
                                "Promoted standby provider '{}' to Active for service '{}' due to active provider disconnection.",
                                entry.uri, self.context.service
                            );
                        }
                    }

                    // Clean up the service entry if no providers are left.
                    if providers_for_service.is_empty() {
                        providers_by_service.remove(&self.context.service);
                    }
                }
            }
        }

        log_connection_close(&self.context, &reason, stats);

        Ok(())
    }
}

/// Handles connections from clients with the "consumer" role.
/// Consumers initiate bidirectional streams to request data from providers.
struct ConsumerHandler {
    context: ConnectionContext,
    target_provider: Option<(quinn::Connection, Arc<AtomicUsize>, Arc<AtomicUsize>)>,
    provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
    consumer_connections: Arc<RwLock<HashMap<String, HashMap<usize, ConsumerEntry>>>>,
    /// Provider URN
    provider_urn: Option<String>,
    /// Availability management configuration for provider.
    availability_config: Option<crate::config::AvailabilityManagementConfig>,
}

/// Represents the outcome of the stream proxying loop.
enum ProxyLoopResult {
    /// A recoverable error related to the provider occurred (e.g., connection lost). The handler should attempt to find a new provider.
    ProviderError,
    /// A fatal error occurred, or the consumer connection was closed. The handler should terminate.
    ConnectionClosed(quinn::ConnectionError),
}

impl ConsumerHandler {
    /// Creates a new consumer handler.
    fn new(
        connection: quinn::Connection,
        cn: String,
        realm_name: String,
        hub_name: String,
        provider_connections: Arc<RwLock<HashMap<String, HashMap<usize, ProviderEntry>>>>,
        consumer_connections: Arc<RwLock<HashMap<String, HashMap<usize, ConsumerEntry>>>>,
        service_map: Arc<ArcSwap<HashMap<String, ServiceInfo>>>,
        shared_config: Arc<ArcSwap<crate::config::AppConfig>>,
    ) -> Self {
        let now = Utc::now();
        let conn_id = connection.stable_id();
        let service_info = service_map
            .load() // Load the latest service map
            .get(&cn) // Get from the loaded map
            .cloned()
            .unwrap_or_else(|| ServiceInfo {
                name: "unknown".to_string(),
                urn: "unknown".to_string(),
            });
        let endpoint_type = "serviceConsumer".to_string();
        let context = ConnectionContext {
            connection: connection.clone(),
            start_at: now,
            connection_id: conn_id,
            uri: cn.clone(),
            endpoint_type: endpoint_type.clone(),
            service: service_info.name.clone(),
            service_urn: service_info.urn.clone(),
            total_opened_streams: Arc::new(AtomicUsize::new(0)),
            total_closed_streams: Arc::new(AtomicUsize::new(0)),
        };
        info!(
            eventType = "startSpnSession",
            timestamp = %context.start_at,
            spnSessionId = context.connection_id,
            spnEndPoint = &context.uri,
            endPointType = &context.endpoint_type,
            serviceUrn = &context.service_urn,
            remote = %context.connection.remote_address(),
            "SPN session (QUIC Connection) started"
        );

        // Extract configuration needed for consumer handling
        let config = shared_config.load();
        let service_config = config
            .realms
            .iter()
            .find(|r| r.realm_name == realm_name)
            .and_then(|r| r.hubs.iter().find(|h| h.name == hub_name))
            .and_then(|h| h.services.iter().find(|s| s.name == context.service));

        let (provider_urn, availability_config) = match service_config {
            Some(s) => (
                Some(s.provider.clone()),
                Some(s.availability_management.clone()),
            ),
            None => (None, None),
        };

        Self {
            context,
            target_provider: None,
            provider_connections,
            consumer_connections,
            provider_urn,
            availability_config,
        }
    }

    /// Executes the on-demand start logic for a provider.
    async fn execute_ondemand_start(
        urn: &str,
        am_config: &crate::config::AvailabilityManagementConfig,
        service_name: &str,
        trigger: &str,
    ) {
        let should_start = match trigger {
            "consumer" => am_config.ondemand_start_on_consumer,
            "payload" => am_config.ondemand_start_on_payload,
            _ => false,
        };

        if should_start {
            info!(
                eventType = "autoLifecycleStartInitiated",
                trigger = trigger,
                service = service_name,
                urn = urn,
                image = am_config.image,
                idle_timeout = am_config.idle_timeout,
                "On-demand provider start initiated."
            );
            match crate::microservice::start_provider(am_config).await {
                Ok(handle) => {
                    info!(
                        eventType = "autoLifecycleStartSuccess",
                        trigger = trigger,
                        service = service_name,
                        urn = urn,
                        id = handle.id,
                        "On-demand provider started successfully."
                    );
                }
                Err(e) => {
                    warn!(
                        eventType = "autoLifecycleStartFailed",
                        trigger = trigger,
                        service = service_name,
                        urn = urn,
                        error = %e,
                        "On-demand provider start failed."
                    );
                }
            }
        } else {
            info!(
                eventType = "autoLifecycleStartSkipped",
                trigger = trigger,
                service = service_name,
                urn = urn,
                "On-demand provider start is disabled for this service."
            );
        }
    }

    /// Spawns a background task to listen for control datagrams.
    ///
    /// Supported control messages:
    /// - `request_provider_start`: Triggers on-demand provider start.
    /// - `notify_shutdown`: Notifies that the consumer is starting a graceful shutdown.
    fn spawn_control_datagram_handler(&self) {
        let datagram_conn = self.context.connection.clone();
        let provider_urn = self.provider_urn.clone();
        let availability_config = self.availability_config.clone();
        let service_name = self.context.service.clone();
        let consumer_uri = self.context.uri.clone();

        tokio::spawn(async move {
            // Tracks the timestamp of the last processed "request_provider_start" signal from this specific connection.
            let mut last_ondemand_service_start_request_at: Option<Instant> = None;

            // Wait for datagrams (signals) from the consumer in a loop
            while let Ok(bytes) = datagram_conn.read_datagram().await {
                let message = String::from_utf8_lossy(&bytes);
                info!(
                    "Received control datagram from consumer '{}': {:?}",
                    consumer_uri, message
                );

                match message.trim() {
                    "request_provider_start" => {
                        if let (Some(urn), Some(am_config)) = (&provider_urn, &availability_config)
                        {
                            // -- Rate limit logic to prevent abuse --
                            let now = Instant::now();

                            if let Some(last) = last_ondemand_service_start_request_at
                                && now.duration_since(last)
                                    < ONDEMAND_SERVICE_START_RATE_LIMIT_PER_CONSUMER
                            {
                                warn!(
                                    service = %service_name,
                                    consumer = %consumer_uri,
                                    "On-demand start request ignored due to rate limiting (per-connection)."
                                );
                                continue;
                            }
                            last_ondemand_service_start_request_at = Some(now);
                            // --- End rate limit logic ---

                            let urn = urn.clone();
                            let am_config = am_config.clone();
                            let service_name = service_name.clone();
                            tokio::spawn(async move {
                                Self::execute_ondemand_start(
                                    &urn,
                                    &am_config,
                                    &service_name,
                                    "payload",
                                )
                                .await;
                            });
                        }
                    }
                    "notify_shutdown" => {
                        info!(
                            "Consumer '{}' notified graceful shutdown start.",
                            consumer_uri
                        );
                    }
                    _ => {
                        warn!(
                            "Unknown control message from consumer '{}': {}",
                            consumer_uri, message
                        );
                    }
                }
            }
        });
    }

    /// Finds a provider with the same service and sets it as the target,
    /// retrying periodically until one is found or the timeout is reached.
    async fn find_and_set_target_provider(&mut self, interval: Duration, timeout: Duration) {
        self.target_provider = None;
        let start_time = Instant::now();
        info!(
            "Searching for provider for service '{}' (timeout: {:?}, interval: {:?})",
            self.context.service, timeout, interval
        );
        let mut start_attempted = false;

        loop {
            // 1. Try to find an Active provider (Read Lock)
            // Also check if there are any StandBy providers to avoid unnecessary write locks.
            let (found_active, has_standby) = {
                let providers = self.provider_connections.read().await;
                if let Some(map) = providers.get(&self.context.service) {
                    let active = map
                        .values()
                        .find(|e| e.status == ProviderStatus::Active)
                        .map(|e| {
                            (
                                e.uri.clone(),
                                e.connection.clone(),
                                e.total_opened_streams.clone(),
                                e.total_closed_streams.clone(),
                            )
                        });
                    let standby = map.values().any(|e| e.status == ProviderStatus::StandBy);
                    (active, standby)
                } else {
                    (None, false)
                }
            };

            if let Some((cn, conn, opened, closed)) = found_active {
                info!(
                    "Found matching provider '{}' for service '{}'.",
                    cn, self.context.service
                );
                self.target_provider = Some((conn, opened, closed));
                return;
            }

            // 2. If no Active found, try to promote a StandBy provider (Write Lock)
            let promoted = if has_standby {
                let mut providers = self.provider_connections.write().await;
                let service_map = providers.entry(self.context.service.clone()).or_default();

                // Double check Active (race condition)
                if let Some(active) = service_map
                    .values()
                    .find(|e| e.status == ProviderStatus::Active)
                {
                    Some((
                        active.uri.clone(),
                        active.connection.clone(),
                        active.total_opened_streams.clone(),
                        active.total_closed_streams.clone(),
                    ))
                } else {
                    // Find a StandBy provider to promote
                    let standby_key = service_map
                        .iter()
                        .filter(|(_, e)| e.status == ProviderStatus::StandBy)
                        .min_by_key(|(_, e)| e.created_at)
                        .map(|(k, _)| *k);

                    if let Some(key) = standby_key {
                        if let Some(entry) = service_map.get_mut(&key) {
                            entry.status = ProviderStatus::Active;
                            info!(
                                "Promoted provider '{}' to Active for service '{}'",
                                entry.uri, self.context.service
                            );
                            Some((
                                entry.uri.clone(),
                                entry.connection.clone(),
                                entry.total_opened_streams.clone(),
                                entry.total_closed_streams.clone(),
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            } else {
                None
            };

            if let Some((_, conn, opened, closed)) = promoted {
                self.target_provider = Some((conn, opened, closed));
                return;
            }

            // Attempt on-demand provider start on first consumer connected
            if !start_attempted {
                start_attempted = true;
                if let (Some(urn), Some(am_config)) =
                    (&self.provider_urn, &self.availability_config)
                {
                    let urn = urn.clone();
                    let am_config = am_config.clone();
                    let service = self.context.service.clone();
                    tokio::spawn(async move {
                        Self::execute_ondemand_start(&urn, &am_config, &service, "consumer").await;
                    });
                }
            }

            // Check for timeout
            if start_time.elapsed() >= timeout {
                warn!(
                    "Timed out waiting for a provider for service '{}' after {:?}",
                    self.context.service,
                    start_time.elapsed()
                );
                break; // Timeout reached, exit the loop.
            }

            // Wait for the next interval
            time::sleep(interval).await;
        }
    }

    /// Manages the proxying of streams for a single, established provider connection.
    ///
    /// This function contains the primary `select!` loop that accepts new streams from the consumer
    /// and monitors for errors reported by the individual stream proxy tasks.
    async fn proxy_streams_with_provider(
        &mut self,
        provider_conn: quinn::Connection,
        total_opened_streams: Arc<AtomicUsize>,
        total_closed_streams: Arc<AtomicUsize>,
    ) -> ProxyLoopResult {
        /// Internal enum to distinguish between different kinds of stream proxy errors,
        /// allowing the loop to decide how to react.
        #[derive(Debug)]
        enum ProxyError {
            /// Indicates a problem with the provider connection, suggesting a retry might be needed.
            ProviderConnection(String),
            /// Indicates an error during data transfer for a specific stream.
            DataTransfer {
                msg: String,
                stream_id: quinn::StreamId,
            },
        }

        info!(
            "Starting to proxy streams to provider {}",
            provider_conn.stable_id()
        );
        // Channel for spawned tasks to signal errors back to this loop.
        let (error_tx, mut error_rx) = mpsc::channel::<ProxyError>(ERROR_CHANNEL_CAPACITY);

        loop {
            tokio::select! {
                biased; // Prioritize checking for error signals.

                // An error was reported by a spawned stream proxy task.
                Some(proxy_error) = error_rx.recv() => {
                    match proxy_error {
                        ProxyError::ProviderConnection(msg) => {
                            warn!("Provider-side error detected: {}. Will try to find a new provider.", msg);
                            return ProxyLoopResult::ProviderError;
                        }
                        ProxyError::DataTransfer {msg, stream_id} => {
                            //ProxyError::DataTransfer(msg, stream_id) => {
                            // An error occurred on an individual stream (e.g., client closed it).
                            // This is not fatal to the connection. Log it and continue.
                            // The task handling that specific stream has already terminated.
                            warn!(
                                stream_id = %stream_id,
                                "Data transfer error on a stream: {}. The stream has been closed.", msg);
                        }
                    }
                }

                // Accept a new stream from the consumer.
                result = self.context.connection.accept_bi() => {
                    match result {
                        Ok((send, recv)) => {
                            debug!("Bidirectional stream accepted from consumer '{}'", self.context.uri);
                            self.context.total_opened_streams.fetch_add(1, Ordering::Relaxed);
                            let consumer_context = self.context.clone();
                            let tx_clone = error_tx.clone();
                            let provider_conn_clone = provider_conn.clone();
                            let total_opened_streams_clone = total_opened_streams.clone();
                            let total_closed_streams_clone = total_closed_streams.clone();
                            tokio::spawn(async move {
                                let stream_id = recv.id();
                                let connection_id = consumer_context.connection_id;

                                if let Err(e) = proxy_consumer_stream_to_provider(
                                    send,
                                    recv,
                                    provider_conn_clone,
                                    total_opened_streams_clone,
                                    total_closed_streams_clone,
                                    consumer_context,
                                )
                                .instrument(info_span!(
                                    "consumer_stream",
                                    conn_id = connection_id,
                                    stream_id = %stream_id
                                ))
                                .await
                                {
                                    // Downcast the error to check its type
                                    if e.downcast_ref::<quinn::ConnectionError>().is_some() {
                                        // This is a provider-side connection error
                                        let _ = tx_clone
                                            .send(ProxyError::ProviderConnection(e.to_string()))
                                            .await;
                                    } else {
                                        // This is likely a data transfer (I/O) error
                                        let _ = tx_clone
                                            .send(ProxyError::DataTransfer {
                                                msg: e.to_string(),
                                                stream_id,
                                            })
                                            .await;
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            // The consumer connection itself was closed.
                            return ProxyLoopResult::ConnectionClosed(e);
                        }
                    }
                }
            }
        }
    }

    /// Executes the main logic for handling a consumer connection.
    ///
    /// This method orchestrates finding a provider and then handing off to the stream
    /// proxying loop. It will re-attempt to find a provider if the connection to an
    /// existing one fails.
    async fn run(mut self) -> Result<(), quinn::ConnectionError> {
        info!(
            "Consumer handler is running for '{}'. Searching for a provider with service '{}'.",
            self.context.uri, self.context.service
        );

        // Start a background task to listen for control datagram
        self.spawn_control_datagram_handler();

        // Add the connection to the shared map.
        {
            let mut consumers_by_uri = self.consumer_connections.write().await;
            let entry = ConsumerEntry {
                connection: self.context.connection.clone(),
            };
            consumers_by_uri
                .entry(self.context.uri.clone())
                .or_default()
                .insert(self.context.connection_id, entry);
            let total_consumers: usize = consumers_by_uri.values().map(|v| v.len()).sum();
            info!(
                "Consumer '{}' added to connection map. (Total: {})",
                self.context.uri, total_consumers
            );
        }

        let reason = 'main_loop: loop {
            // 1. Find a provider.
            let search_interval = Duration::from_secs(PROVIDER_SEARCH_INTERVAL_SECS);
            let search_timeout = Duration::from_secs(PROVIDER_SEARCH_TIMEOUT_SECS);
            self.find_and_set_target_provider(search_interval, search_timeout)
                .await;

            let (provider_conn, total_opened_streams, total_closed_streams) =
                match self.target_provider.clone() {
                    Some(val) => val,
                    None => {
                        warn!(
                            "No active provider found for service '{}'. Closing connection.",
                            self.context.service
                        );
                        let app_close = quinn::ApplicationClose {
                            error_code: APP_ERR_CODE_NO_PROVIDER_FOUND.into(),
                            reason: b"No provider available for the requested service"
                                .to_vec()
                                .into(),
                        };
                        break 'main_loop quinn::ConnectionError::ApplicationClosed(app_close);
                    }
                };

            // 2. Start proxying streams with the found provider.
            match self
                .proxy_streams_with_provider(
                    provider_conn,
                    total_opened_streams,
                    total_closed_streams,
                )
                .await
            {
                ProxyLoopResult::ProviderError => {
                    // A recoverable provider error occurred, loop again to find a new one.
                    // Brief pause to avoid busy loop if the broken provider is not yet removed from the map.
                    time::sleep(CONSUMER_PROVIDER_RETRY_DELAY).await;
                    continue 'main_loop;
                }
                ProxyLoopResult::ConnectionClosed(e) => {
                    // A fatal error or normal connection closure occurred.
                    break 'main_loop e;
                }
            }
        };

        // Remove the connection from the shared map upon disconnection.
        {
            let mut consumers_by_uri = self.consumer_connections.write().await;
            if let Some(conns_for_uri) = consumers_by_uri.get_mut(&self.context.uri) {
                conns_for_uri.remove(&self.context.connection_id);
                if conns_for_uri.is_empty() {
                    consumers_by_uri.remove(&self.context.uri);
                }
            }
            let total_consumers: usize = consumers_by_uri.values().map(|v| v.len()).sum();
            info!(
                "Consumer '{}' removed from connection map. (Total remaining: {})",
                self.context.uri, total_consumers
            );
        }

        let stats = self.context.connection.stats();
        log_connection_close(&self.context, &reason, stats);

        Ok(())
    }
}

/// RAII guard to ensure the provider's closed stream count is always incremented.
struct ProviderStreamCounterGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ProviderStreamCounterGuard {
    fn drop(&mut self) {
        self.counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Forwards data between a consumer's stream and a new stream opened to a provider.
/// This function acts as a proxy for a single request/response interaction.
async fn proxy_consumer_stream_to_provider(
    mut consumer_send: quinn::SendStream,
    mut consumer_recv: quinn::RecvStream,
    provider_conn: quinn::Connection,
    total_opened_streams: Arc<AtomicUsize>,
    total_closed_streams: Arc<AtomicUsize>,
    consumer_context: ConnectionContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Consumer-side identifiers
    let consumer_connection_id = consumer_context.connection_id;
    let consumer_stream_id = consumer_recv.id();

    // Provider-side identifiers
    let provider_connection_id = provider_conn.stable_id();
    let (mut provider_send, mut provider_recv) = provider_conn.open_bi().await?;
    let provider_stream_id = provider_send.id();

    // Increment open stream count and ensure close count is incremented on scope exit.
    total_opened_streams.fetch_add(1, Ordering::Relaxed);
    let _closed_stream_guard = ProviderStreamCounterGuard {
        counter: total_closed_streams,
    };

    let spn_connection_id = format!("{}-{}", consumer_stream_id, provider_stream_id);
    let start_at = Utc::now();

    info!(
        eventType = "startSpnConnection",
        timestamp = %start_at,
        spnConnectionId = &spn_connection_id,
        consumerSideSpnSessionId = consumer_connection_id,
        providerSideSpnSessionId = provider_connection_id,
        "SPN connection (QUIC stream) started"
    );

    // Proxy data in both directions concurrently.
    let consumer_to_provider = async {
        let bytes = tokio::io::copy(&mut consumer_recv, &mut provider_send)
            .await
            .map_err(|e| (e, "Consumer->Provider copy"))?;
        provider_send.finish().map_err(|e| {
            let io_err = std::io::Error::other(e);
            (io_err, "Consumer->Provider finish")
        })?;
        Ok(bytes)
    };
    let provider_to_consumer = async {
        let bytes = tokio::io::copy(&mut provider_recv, &mut consumer_send)
            .await
            .map_err(|e| (e, "Provider->Consumer copy"))?;
        consumer_send.finish().map_err(|e| {
            let io_err = std::io::Error::other(e);
            (io_err, "Provider->Consumer finish")
        })?;
        Ok(bytes)
    };

    let result = tokio::try_join!(consumer_to_provider, provider_to_consumer);
    let duration = Utc::now() - start_at;

    match result {
        Ok((bytes_c2p, bytes_p2c)) => {
            info!(
                eventType = "endSpnConnection",
                timestamp = %Utc::now(),
                spnConnectionId = &spn_connection_id,
                consumerSideSpnSessionId = consumer_connection_id,
                providerSideSpnSessionId = provider_connection_id,
                totalSentBytes = bytes_c2p,
                totalReceiveBytes = bytes_p2c,
                elapsedTime = duration.num_milliseconds(),
                disconnectReason = "closed",
                "SPN connection (QUIC stream) ended"
            );
            // The streams will be closed automatically when they are dropped.
            Ok(())
        }
        Err((e, direction)) => {
            // This is (std::io::Error, &str)
            let reason = match e.kind() {
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
                    "closedByPeer"
                }
                _ => "error",
            };

            info!(
                eventType = "endSpnConnection",
                timestamp = %Utc::now(),
                spnConnectionId = &spn_connection_id,
                consumerSideSpnSessionId = consumer_connection_id,
                providerSideSpnSessionId = provider_connection_id,
                elapsedTime = duration.num_milliseconds(),
                disconnectReason = reason,
                errorDirection = direction,
                errorDetails = %e,
                "SPN connection (QUIC stream) ended"
            );
            Err(e.into())
        }
    }
}

/// Maps a quinn::ConnectionError to a reason string defined in the spec.
fn map_reason_to_string(reason: &quinn::ConnectionError) -> &str {
    match reason {
        quinn::ConnectionError::ApplicationClosed(_) => "terminatedByPeer",
        quinn::ConnectionError::ConnectionClosed(_) => "terminatedByPeer",
        quinn::ConnectionError::LocallyClosed => "shutdown",
        _ => "error",
    }
}

/// Logs the details of a connection closure.
fn log_connection_close(
    context: &ConnectionContext,
    reason: &quinn::ConnectionError,
    _stats: quinn::ConnectionStats,
) {
    // Log the detailed reason for connection closure.
    match reason {
        quinn::ConnectionError::ApplicationClosed(app_close) => {
            info!(
                "{} connection for '{}' closed by the application. Code: {}, Reason: '{}'",
                context.endpoint_type,
                context.uri,
                app_close.error_code,
                String::from_utf8_lossy(&app_close.reason)
            );
        }
        quinn::ConnectionError::ConnectionClosed(conn_close) => {
            info!(
                "{} connection for '{}' closed by the peer. Code: {}, Reason: '{}'",
                context.endpoint_type,
                context.uri,
                conn_close.error_code,
                String::from_utf8_lossy(&conn_close.reason)
            );
        }
        quinn::ConnectionError::TimedOut => {
            warn!(
                "{} connection for '{}' timed out.",
                context.endpoint_type, context.uri
            );
        }
        quinn::ConnectionError::LocallyClosed => {
            info!(
                "{} connection for '{}' was closed locally.",
                context.endpoint_type, context.uri
            );
        }
        quinn::ConnectionError::TransportError(transport_error) => {
            error!(
                "{} connection for '{}' failed due to a transport error. Code: {:?}, Reason: '{}'",
                context.endpoint_type, context.uri, transport_error.code, transport_error.reason
            );
        }
        other_error => {
            error!(
                "{} connection for '{}' closed with an unexpected error: {:?}",
                context.endpoint_type, context.uri, other_error
            );
        }
    }

    let duration = Utc::now() - context.start_at;
    let total_connections = context.total_opened_streams.load(Ordering::Relaxed);
    let terminate_reason = map_reason_to_string(reason);

    info!(
        eventType = "endSpnSession",
        timestamp = %Utc::now(),
        spnSessionId = context.connection_id,
        spnEndPoint = &context.uri,
        endPointType = &context.endpoint_type,
        serviceUrn = &context.service_urn,
        totalConnectionCount = total_connections,
        elapsedTime = duration.num_milliseconds(),
        terminateReason = terminate_reason,
        "SPN session (QUIC Connection) ended"
    );
}
