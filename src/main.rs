mod api;
mod app;
mod model;
mod netid;
mod stream_relay;
mod udp_relay;
mod state;

use crate::api::{
    admin_nodes, approve_node, approve_node_secret, audit_log, create_network, create_token,
    get_acl, get_key_policy, heartbeat, netmap, netmap_longpoll, node_keys, register,
    register_url, revoke_node, revoke_token, rotate_keys, update_acl, update_key_policy,
    update_node,
};
use crate::app::AppState;
use crate::model::RelayConfig;
use axum::routing::{get, post, put};
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
    #[arg(long)]
    db_url: Option<String>,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let store = if let Some(db_url) = args.db_url.as_deref() {
        StateStore::load_db(db_url).await?
    } else {
        StateStore::load(Some(args.state)).await?
    };
    let relay = RelayConfig {
        stun_servers: args.stun,
        turn_servers: args.turn,
        stream_relay_servers: args.stream_relay,
        udp_relay_servers: args.udp_relay,
    };
    if args.admin_token.is_none() {
        tracing::warn!("admin token not set; admin endpoints are unsecured");
    }
    let app_state = AppState {
        store,
        relay,
        admin_token: args.admin_token,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/networks", post(create_network))
        .route("/v1/networks/:network_id/tokens", post(create_token))
        .route(
            "/v1/networks/:network_id/acl",
            get(get_acl).put(update_acl),
        )
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
        .route("/v1/nodes/:node_id/keys", get(node_keys))
        .route(
            "/v1/admin/networks/:network_id/nodes",
            get(admin_nodes),
        )
        .route("/v1/admin/nodes/:node_id", put(update_node))
        .route("/v1/audit", get(audit_log))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/netmap/:node_id", get(netmap))
        .route("/v1/netmap/:node_id/longpoll", get(netmap_longpoll))
        .layer(axum::Extension(app_state));

    let addr: SocketAddr = args.listen.parse()?;
    tracing::info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    if let Some(listen) = args.udp_relay_listen {
        let udp_addr: SocketAddr = listen.parse()?;
        tokio::spawn(async move {
            if let Err(err) = udp_relay::run(udp_addr).await {
                tracing::error!("udp relay error: {}", err);
            }
        });
        tracing::info!("udp relay listening on {}", udp_addr);
    }

    if let Some(listen) = args.stream_relay_listen {
        let stream_addr: SocketAddr = listen.parse()?;
        tokio::spawn(async move {
            if let Err(err) = stream_relay::run(stream_addr).await {
                tracing::error!("stream relay error: {}", err);
            }
        });
        tracing::info!("stream relay listening on {}", stream_addr);
    }

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}
