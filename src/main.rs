mod api;
mod app;
mod mesh;
mod model;
mod netid;
mod state;
mod stream_relay;
mod udp_relay;

use crate::api::{
    admin_nodes, admin_topology, approve_node, approve_node_secret, audit_log, create_network,
    create_token, delete_network, delete_node, get_acl, get_key_policy, heartbeat, list_tokens,
    netmap, netmap_longpoll, node_keys, register, register_url, revoke_node, revoke_token,
    rotate_keys, update_acl, update_key_policy, update_node,
};
use crate::app::{AppState, MeshPeerMeta};
use crate::mesh::{MeshConfig, MeshTransport};
use crate::model::RelayConfig;
use axum::routing::{delete, get, post, put};
use axum::Router;
use clap::Parser;
use state::StateStore;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "lightscale-server")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,
    #[arg(long, default_value = "state.json")]
    state: PathBuf,
    #[arg(long, env = "LIGHTSCALE_DB_URL")]
    db_url: Option<String>,
    #[arg(long)]
    db_url_file: Option<PathBuf>,
    #[arg(long, env = "LIGHTSCALE_ADMIN_TOKEN")]
    admin_token: Option<String>,
    #[arg(long, value_delimiter = ',')]
    stun: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    turn: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    stream_relay: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    udp_relay: Vec<String>,
    #[arg(long)]
    udp_relay_listen: Option<String>,
    #[arg(long)]
    stream_relay_listen: Option<String>,
    #[arg(long)]
    mesh_server_id: Option<String>,
    #[arg(long)]
    mesh_listen: Option<String>,
    #[arg(long, value_name = "ID=HOST:PORT", value_delimiter = ',')]
    mesh_peer: Vec<String>,
    #[arg(long)]
    mesh_ca_cert: Option<PathBuf>,
    #[arg(long)]
    mesh_cert: Option<PathBuf>,
    #[arg(long)]
    mesh_key: Option<PathBuf>,
    #[arg(long, default_value_t = 4)]
    mesh_max_hops: u8,
    #[arg(long, value_delimiter = ',')]
    control_url: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    install_rustls_provider();

    let args = Args::parse();
    if args.admin_token.is_none() {
        anyhow::bail!("admin token is required; set --admin-token or LIGHTSCALE_ADMIN_TOKEN");
    }
    if args.db_url.is_some() && args.db_url_file.is_some() {
        anyhow::bail!("set only one of --db-url and --db-url-file");
    }
    let resolved_db_url = if let Some(path) = args.db_url_file.as_ref() {
        let raw = tokio::fs::read_to_string(path).await?;
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            anyhow::bail!("db url file is empty: {}", path.display());
        }
        Some(trimmed)
    } else {
        args.db_url.clone()
    };

    let store = if let Some(db_url) = resolved_db_url.as_deref() {
        StateStore::load_db(db_url).await?
    } else {
        StateStore::load(Some(args.state.clone())).await?
    };
    let mesh_config = build_mesh_config(&args)?;
    let relay = RelayConfig {
        stun_servers: args.stun,
        turn_servers: args.turn,
        stream_relay_servers: args.stream_relay,
        udp_relay_servers: args.udp_relay,
    };
    let control_urls = normalize_control_urls(&args.control_url)?;
    let mesh_peer_meta: Vec<MeshPeerMeta> = parse_mesh_peers(&args.mesh_peer)?
        .into_iter()
        .map(|peer| MeshPeerMeta {
            id: peer.id,
            addr: peer.addr,
        })
        .collect();
    let app_state = AppState {
        store,
        relay,
        admin_token: args.admin_token.clone(),
        control_urls,
        mesh_server_id: args.mesh_server_id.clone(),
        mesh_peers: mesh_peer_meta,
    };
    let mut mesh_dispatch_rx = None;
    let mut relay_to_mesh_tx = None;
    if let Some(mesh_config) = mesh_config.clone() {
        let (tx_to_mesh, rx_from_relay) = tokio::sync::mpsc::unbounded_channel();
        let (tx_to_relay, rx_from_mesh) = tokio::sync::mpsc::unbounded_channel();
        mesh::start(mesh_config, rx_from_relay, tx_to_relay).await?;
        relay_to_mesh_tx = Some(tx_to_mesh);
        mesh_dispatch_rx = Some(rx_from_mesh);
    }

    let mut stream_mesh_rx = None;
    let mut udp_mesh_rx = None;
    if let Some(mut dispatch_rx) = mesh_dispatch_rx.take() {
        let (stream_tx, stream_rx) = tokio::sync::mpsc::unbounded_channel();
        let (udp_tx, udp_rx) = tokio::sync::mpsc::unbounded_channel();
        stream_mesh_rx = Some(stream_rx);
        udp_mesh_rx = Some(udp_rx);
        tokio::spawn(async move {
            while let Some(packet) = dispatch_rx.recv().await {
                let send_result = match packet.transport {
                    MeshTransport::Stream => stream_tx.send(packet),
                    MeshTransport::Udp => udp_tx.send(packet),
                };
                if let Err(err) = send_result {
                    let _ = err.0.delivered.send(false);
                }
            }
        });
    }

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/networks", post(create_network))
        .route("/v1/networks/:network_id", delete(delete_network))
        .route(
            "/v1/networks/:network_id/tokens",
            get(list_tokens).post(create_token),
        )
        .route("/v1/networks/:network_id/acl", get(get_acl).put(update_acl))
        .route(
            "/v1/networks/:network_id/key-policy",
            get(get_key_policy).put(update_key_policy),
        )
        .route("/v1/tokens/:token_id/revoke", post(revoke_token))
        .route("/v1/register", post(register))
        .route("/v1/register-url", post(register_url))
        .route(
            "/v1/register/approve/:node_id/:secret",
            get(approve_node_secret),
        )
        .route("/v1/admin/nodes/:node_id/approve", post(approve_node))
        .route("/v1/nodes/:node_id/rotate-keys", post(rotate_keys))
        .route("/v1/nodes/:node_id/revoke", post(revoke_node))
        .route("/v1/nodes/:node_id", delete(delete_node))
        .route("/v1/nodes/:node_id/keys", get(node_keys))
        .route("/v1/admin/networks/:network_id/nodes", get(admin_nodes))
        .route("/v1/admin/topology", get(admin_topology))
        .route("/v1/admin/nodes/:node_id", put(update_node))
        .route("/v1/audit", get(audit_log))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/netmap/:node_id", get(netmap))
        .route("/v1/netmap/:node_id/longpoll", get(netmap_longpoll))
        .layer(axum::Extension(app_state));

    let addr: SocketAddr = args.listen.parse()?;
    tracing::info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let udp_relay_listen = args.udp_relay_listen.clone();
    let stream_relay_listen = args.stream_relay_listen.clone();

    if let Some(listen) = udp_relay_listen.clone() {
        let udp_addr: SocketAddr = listen.parse()?;
        let mesh_tx = relay_to_mesh_tx.clone();
        let mesh_rx = udp_mesh_rx.take();
        tokio::spawn(async move {
            if let Err(err) = udp_relay::run_with_mesh(udp_addr, mesh_tx, mesh_rx).await {
                tracing::error!("udp relay error: {}", err);
            }
        });
        tracing::info!("udp relay listening on {}", udp_addr);
    }

    if let Some(listen) = stream_relay_listen.clone() {
        let stream_addr: SocketAddr = listen.parse()?;
        let mesh_tx = relay_to_mesh_tx.clone();
        let mesh_rx = stream_mesh_rx.take();
        tokio::spawn(async move {
            if let Err(err) = stream_relay::run_with_mesh(stream_addr, mesh_tx, mesh_rx).await {
                tracing::error!("stream relay error: {}", err);
            }
        });
        tracing::info!("stream relay listening on {}", stream_addr);
    }

    if mesh_config.is_some() && stream_relay_listen.is_none() && udp_relay_listen.is_none() {
        tracing::warn!("mesh configured but neither stream nor udp relay listener is enabled");
    }

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn install_rustls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn healthz() -> &'static str {
    "ok"
}

fn build_mesh_config(args: &Args) -> anyhow::Result<Option<MeshConfig>> {
    let enabled = args.mesh_server_id.is_some()
        || args.mesh_listen.is_some()
        || !args.mesh_peer.is_empty()
        || args.mesh_ca_cert.is_some()
        || args.mesh_cert.is_some()
        || args.mesh_key.is_some();

    if !enabled {
        return Ok(None);
    }

    let server_id = args
        .mesh_server_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("mesh requires --mesh-server-id"))?;
    let listen = args
        .mesh_listen
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("mesh requires --mesh-listen"))?
        .parse()?;
    let ca_cert_path = args
        .mesh_ca_cert
        .clone()
        .ok_or_else(|| anyhow::anyhow!("mesh requires --mesh-ca-cert"))?;
    let cert_path = args
        .mesh_cert
        .clone()
        .ok_or_else(|| anyhow::anyhow!("mesh requires --mesh-cert"))?;
    let key_path = args
        .mesh_key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("mesh requires --mesh-key"))?;
    let peers = parse_mesh_peers(&args.mesh_peer)?;
    if peers.is_empty() {
        anyhow::bail!("mesh requires at least one --mesh-peer");
    }
    if args.mesh_max_hops == 0 {
        anyhow::bail!("--mesh-max-hops must be > 0");
    }

    Ok(Some(MeshConfig {
        server_id,
        listen,
        peers,
        ca_cert_path,
        cert_path,
        key_path,
        max_hops: args.mesh_max_hops,
    }))
}

fn parse_mesh_peers(values: &[String]) -> anyhow::Result<Vec<mesh::MeshPeer>> {
    let mut peers = Vec::new();
    for value in values {
        let mut parts = value.splitn(2, '=');
        let id = parts.next().unwrap_or("").trim();
        let addr = parts.next().unwrap_or("").trim();
        if id.is_empty() || addr.is_empty() {
            anyhow::bail!("invalid --mesh-peer value {}; expected ID=HOST:PORT", value);
        }
        peers.push(mesh::MeshPeer {
            id: id.to_string(),
            addr: addr.to_string(),
        });
    }
    Ok(peers)
}

fn normalize_control_urls(values: &[String]) -> anyhow::Result<Vec<String>> {
    let mut urls = Vec::new();
    for value in values {
        for candidate in value.split(',') {
            let trimmed = candidate.trim().trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
                anyhow::bail!(
                    "invalid --control-url value {}; expected http:// or https:// URL",
                    candidate
                );
            }
            urls.push(trimmed.to_string());
        }
    }
    urls.sort();
    urls.dedup();
    Ok(urls)
}
