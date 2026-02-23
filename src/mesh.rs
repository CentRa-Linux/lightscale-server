use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader as StdBufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};
use uuid::Uuid;

const RECONNECT_DELAY: Duration = Duration::from_secs(2);
const LOCAL_DELIVER_TIMEOUT: Duration = Duration::from_millis(250);
const SEEN_TTL: Duration = Duration::from_secs(120);
const MAX_SEEN_IDS: usize = 8192;
const ROUTE_TTL: Duration = Duration::from_secs(300);
const MAX_ROUTE_HINTS: usize = 16384;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct MeshPeer {
    pub id: String,
    pub addr: String,
}

#[derive(Clone, Debug)]
pub struct MeshConfig {
    pub server_id: String,
    pub listen: SocketAddr,
    pub peers: Vec<MeshPeer>,
    pub ca_cert_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub max_hops: u8,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MeshTransport {
    Stream,
    Udp,
}

#[derive(Debug)]
pub struct MeshOutgoingPacket {
    pub transport: MeshTransport,
    pub from_id: String,
    pub to_id: String,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct MeshIncomingPacket {
    pub transport: MeshTransport,
    pub from_id: String,
    pub to_id: String,
    pub payload: Vec<u8>,
    pub delivered: oneshot::Sender<bool>,
}

#[derive(Clone)]
struct PeerSender {
    conn_id: u64,
    tx: mpsc::UnboundedSender<MeshFrame>,
}

#[derive(Clone)]
struct RouteHint {
    peer_id: String,
    updated_at: Instant,
}

#[derive(Clone)]
struct MeshContext {
    server_id: String,
    max_hops: u8,
    allowed_peers: Arc<HashSet<String>>,
    peers: Arc<RwLock<HashMap<String, PeerSender>>>,
    seen_ids: Arc<Mutex<HashMap<String, Instant>>>,
    route_hints: Arc<Mutex<HashMap<String, RouteHint>>>,
    to_local: mpsc::UnboundedSender<MeshIncomingPacket>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum MeshFrame {
    Hello {
        server_id: String,
    },
    Relay {
        message_id: String,
        transport: MeshTransport,
        from_id: String,
        to_id: String,
        payload_b64: String,
        hops_left: u8,
    },
}

pub async fn start(
    config: MeshConfig,
    mut from_local_rx: mpsc::UnboundedReceiver<MeshOutgoingPacket>,
    to_local_tx: mpsc::UnboundedSender<MeshIncomingPacket>,
) -> Result<()> {
    if config.server_id.trim().is_empty() {
        return Err(anyhow!("mesh server id must be non-empty"));
    }
    if config.max_hops == 0 {
        return Err(anyhow!("mesh max hops must be > 0"));
    }

    let allowed_peers: HashSet<String> = config.peers.iter().map(|peer| peer.id.clone()).collect();
    let context = MeshContext {
        server_id: config.server_id.clone(),
        max_hops: config.max_hops,
        allowed_peers: Arc::new(allowed_peers),
        peers: Arc::new(RwLock::new(HashMap::new())),
        seen_ids: Arc::new(Mutex::new(HashMap::new())),
        route_hints: Arc::new(Mutex::new(HashMap::new())),
        to_local: to_local_tx,
    };

    let server_tls = Arc::new(build_server_tls_config(&config)?);
    let client_tls = Arc::new(build_client_tls_config(&config)?);
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("mesh bind failed: {}", config.listen))?;
    let acceptor = TlsAcceptor::from(server_tls);

    let listen_ctx = context.clone();
    tokio::spawn(async move {
        if let Err(err) = run_listener(listener, acceptor, listen_ctx).await {
            warn!("mesh listener stopped: {}", err);
        }
    });

    let peer_count = config.peers.len();
    for peer in config.peers {
        let peer_ctx = context.clone();
        let connector = TlsConnector::from(client_tls.clone());
        tokio::spawn(async move {
            run_outbound_peer(peer, connector, peer_ctx).await;
        });
    }

    let local_ctx = context.clone();
    tokio::spawn(async move {
        while let Some(packet) = from_local_rx.recv().await {
            let message_id = Uuid::new_v4().to_string();
            remember_message(&local_ctx, &message_id).await;
            let frame = MeshFrame::Relay {
                message_id,
                transport: packet.transport,
                from_id: packet.from_id,
                to_id: packet.to_id.clone(),
                payload_b64: STANDARD.encode(packet.payload),
                hops_left: local_ctx.max_hops,
            };
            forward_to_target(&local_ctx, None, &packet.to_id, frame).await;
        }
    });

    info!(
        "mesh enabled as {} on {} with {} configured peers",
        config.server_id, config.listen, peer_count
    );

    Ok(())
}

async fn run_listener(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    context: MeshContext,
) -> Result<()> {
    loop {
        let (tcp, remote) = listener.accept().await.context("mesh accept failed")?;
        let acceptor = acceptor.clone();
        let ctx = context.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(tcp).await {
                Ok(stream) => stream,
                Err(err) => {
                    warn!("mesh tls accept failed from {}: {}", remote, err);
                    return;
                }
            };
            if let Err(err) = run_connection(stream, None, ctx).await {
                warn!("mesh inbound connection closed from {}: {}", remote, err);
            }
        });
    }
}

async fn run_outbound_peer(peer: MeshPeer, connector: TlsConnector, context: MeshContext) {
    let server_name = match ServerName::try_from(peer.id.clone()) {
        Ok(name) => name,
        Err(_) => {
            warn!(
                "mesh peer {} has invalid tls server name; expected DNS-like identifier",
                peer.id
            );
            return;
        }
    };

    loop {
        match TcpStream::connect(&peer.addr).await {
            Ok(stream) => match connector.connect(server_name.clone(), stream).await {
                Ok(tls) => {
                    info!("mesh connected to peer {} at {}", peer.id, peer.addr);
                    if let Err(err) =
                        run_connection(tls, Some(peer.id.clone()), context.clone()).await
                    {
                        warn!("mesh peer {} disconnected: {}", peer.id, err);
                    }
                }
                Err(err) => {
                    warn!(
                        "mesh tls connect failed to {} ({}): {}",
                        peer.id, peer.addr, err
                    );
                }
            },
            Err(err) => {
                warn!(
                    "mesh tcp connect failed to {} ({}): {}",
                    peer.id, peer.addr, err
                );
            }
        }
        sleep(RECONNECT_DELAY).await;
    }
}

async fn run_connection<S>(
    stream: S,
    expected_peer: Option<String>,
    context: MeshContext,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    write_frame(
        &mut writer,
        &MeshFrame::Hello {
            server_id: context.server_id.clone(),
        },
    )
    .await
    .context("mesh hello write failed")?;

    let mut lines = BufReader::new(reader).lines();
    let hello_line = lines
        .next_line()
        .await
        .context("mesh hello read failed")?
        .ok_or_else(|| anyhow!("mesh connection closed before hello"))?;
    let hello: MeshFrame = serde_json::from_str(&hello_line).context("mesh hello parse failed")?;
    let peer_id = match hello {
        MeshFrame::Hello { server_id } => server_id,
        _ => return Err(anyhow!("mesh expected hello frame")),
    };
    validate_peer(&context, expected_peer.as_deref(), &peer_id)?;

    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::unbounded_channel::<MeshFrame>();
    {
        let mut guard = context.peers.write().await;
        guard.insert(
            peer_id.clone(),
            PeerSender {
                conn_id,
                tx: tx.clone(),
            },
        );
    }

    let writer_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if let Err(err) = write_frame(&mut writer, &frame).await {
                warn!("mesh write failed: {}", err);
                break;
            }
        }
    });

    while let Some(line) = lines.next_line().await.context("mesh read failed")? {
        let frame: MeshFrame = match serde_json::from_str(&line) {
            Ok(frame) => frame,
            Err(err) => {
                warn!("mesh parse error from {}: {}", peer_id, err);
                continue;
            }
        };
        if let Err(err) = handle_frame(&context, &peer_id, frame).await {
            warn!("mesh frame handling failed from {}: {}", peer_id, err);
        }
    }

    writer_task.abort();
    {
        let mut guard = context.peers.write().await;
        if guard
            .get(&peer_id)
            .map(|entry| entry.conn_id == conn_id)
            .unwrap_or(false)
        {
            guard.remove(&peer_id);
        }
    }
    Ok(())
}

fn validate_peer(context: &MeshContext, expected_peer: Option<&str>, peer_id: &str) -> Result<()> {
    if peer_id.is_empty() {
        return Err(anyhow!("mesh peer id is empty"));
    }
    if peer_id == context.server_id {
        return Err(anyhow!("mesh peer id matched local server id"));
    }
    if let Some(expected) = expected_peer {
        if expected != peer_id {
            return Err(anyhow!(
                "mesh peer id mismatch: expected {}, got {}",
                expected,
                peer_id
            ));
        }
    }
    if context.allowed_peers.is_empty() {
        return Err(anyhow!("mesh peer allowlist is empty"));
    }
    if !context.allowed_peers.contains(peer_id) {
        return Err(anyhow!("mesh peer {} is not in allowlist", peer_id));
    }
    Ok(())
}

async fn handle_frame(context: &MeshContext, source_peer: &str, frame: MeshFrame) -> Result<()> {
    match frame {
        MeshFrame::Hello { .. } => Ok(()),
        MeshFrame::Relay {
            message_id,
            transport,
            from_id,
            to_id,
            payload_b64,
            hops_left,
        } => {
            if !remember_message(context, &message_id).await {
                return Ok(());
            }
            learn_route(context, &from_id, source_peer).await;
            let payload = STANDARD
                .decode(payload_b64.as_bytes())
                .context("mesh payload decode failed")?;
            let delivered = deliver_local(
                context,
                transport,
                from_id.clone(),
                to_id.clone(),
                payload.clone(),
            )
            .await;
            if delivered || hops_left == 0 {
                return Ok(());
            }
            let forwarded = MeshFrame::Relay {
                message_id,
                transport,
                from_id,
                to_id: to_id.clone(),
                payload_b64: STANDARD.encode(payload),
                hops_left: hops_left.saturating_sub(1),
            };
            forward_to_target(context, Some(source_peer), &to_id, forwarded).await;
            Ok(())
        }
    }
}

async fn deliver_local(
    context: &MeshContext,
    transport: MeshTransport,
    from_id: String,
    to_id: String,
    payload: Vec<u8>,
) -> bool {
    let (tx, rx) = oneshot::channel();
    if context
        .to_local
        .send(MeshIncomingPacket {
            transport,
            from_id,
            to_id,
            payload,
            delivered: tx,
        })
        .is_err()
    {
        return false;
    }
    match timeout(LOCAL_DELIVER_TIMEOUT, rx).await {
        Ok(Ok(delivered)) => delivered,
        _ => false,
    }
}

async fn broadcast(context: &MeshContext, exclude_peer: Option<&str>, frame: MeshFrame) {
    let targets: Vec<(String, mpsc::UnboundedSender<MeshFrame>)> = {
        let guard = context.peers.read().await;
        guard
            .iter()
            .map(|(peer_id, sender)| (peer_id.clone(), sender.tx.clone()))
            .collect()
    };
    for (peer_id, tx) in targets {
        if exclude_peer == Some(peer_id.as_str()) {
            continue;
        }
        let _ = tx.send(frame.clone());
    }
}

async fn forward_to_target(
    context: &MeshContext,
    exclude_peer: Option<&str>,
    target_node_id: &str,
    frame: MeshFrame,
) {
    if let Some(peer_id) = lookup_route(context, target_node_id).await {
        if exclude_peer != Some(peer_id.as_str()) && send_to_peer(context, &peer_id, &frame).await {
            return;
        }
    }
    broadcast(context, exclude_peer, frame).await;
}

async fn send_to_peer(context: &MeshContext, peer_id: &str, frame: &MeshFrame) -> bool {
    let tx = {
        let guard = context.peers.read().await;
        guard.get(peer_id).map(|sender| sender.tx.clone())
    };
    let Some(tx) = tx else {
        return false;
    };
    tx.send(frame.clone()).is_ok()
}

async fn learn_route(context: &MeshContext, node_id: &str, peer_id: &str) {
    if node_id.is_empty() || peer_id.is_empty() {
        return;
    }
    let now = Instant::now();
    let mut guard = context.route_hints.lock().await;
    guard.insert(
        node_id.to_string(),
        RouteHint {
            peer_id: peer_id.to_string(),
            updated_at: now,
        },
    );
    if guard.len() > MAX_ROUTE_HINTS {
        guard.retain(|_, route| now.duration_since(route.updated_at) <= ROUTE_TTL);
        if guard.len() > MAX_ROUTE_HINTS {
            let mut entries: Vec<(String, Instant)> = guard
                .iter()
                .map(|(node_id, route)| (node_id.clone(), route.updated_at))
                .collect();
            entries.sort_by_key(|(_, ts)| *ts);
            let remove_count = guard.len().saturating_sub(MAX_ROUTE_HINTS);
            for (node_id, _) in entries.into_iter().take(remove_count) {
                guard.remove(&node_id);
            }
        }
    }
}

async fn lookup_route(context: &MeshContext, node_id: &str) -> Option<String> {
    let now = Instant::now();
    let mut guard = context.route_hints.lock().await;
    let route = guard.get(node_id).cloned();
    match route {
        Some(route) if now.duration_since(route.updated_at) <= ROUTE_TTL => Some(route.peer_id),
        Some(_) => {
            guard.remove(node_id);
            None
        }
        None => None,
    }
}

async fn remember_message(context: &MeshContext, message_id: &str) -> bool {
    let mut guard = context.seen_ids.lock().await;
    let now = Instant::now();
    if let Some(seen_at) = guard.get(message_id) {
        if now.duration_since(*seen_at) < SEEN_TTL {
            return false;
        }
    }
    guard.insert(message_id.to_string(), now);
    if guard.len() > MAX_SEEN_IDS {
        guard.retain(|_, seen_at| now.duration_since(*seen_at) <= SEEN_TTL);
        if guard.len() > MAX_SEEN_IDS {
            let mut entries: Vec<(String, Instant)> = guard
                .iter()
                .map(|(id, seen_at)| (id.clone(), *seen_at))
                .collect();
            entries.sort_by_key(|(_, seen_at)| *seen_at);
            let remove_count = guard.len().saturating_sub(MAX_SEEN_IDS);
            for (id, _) in entries.into_iter().take(remove_count) {
                guard.remove(&id);
            }
        }
    }
    true
}

fn build_server_tls_config(config: &MeshConfig) -> Result<ServerConfig> {
    let certs = load_certs(&config.cert_path)?;
    let key = load_private_key(&config.key_path)?;

    let mut roots = RootCertStore::empty();
    for cert in load_certs(&config.ca_cert_path)? {
        roots
            .add(cert)
            .context("failed to add mesh CA cert to trust store")?;
    }

    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("failed to build mesh client cert verifier")?;
    let tls = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("failed to build mesh server tls config")?;
    Ok(tls)
}

fn build_client_tls_config(config: &MeshConfig) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&config.ca_cert_path)? {
        roots
            .add(cert)
            .context("failed to add mesh CA cert to trust store")?;
    }

    let certs = load_certs(&config.cert_path)?;
    let key = load_private_key(&config.key_path)?;
    let tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("failed to build mesh client tls config")?;
    Ok(tls)
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = StdBufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read certs from {}", path.display()))?;
    if certs.is_empty() {
        return Err(anyhow!("no certs in {}", path.display()));
    }
    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = StdBufReader::new(file);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read private key from {}", path.display()))?;
    if let Some(key) = keys.pop() {
        return Ok(key.into());
    }

    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = StdBufReader::new(file);
    let mut keys = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read rsa private key from {}", path.display()))?;
    if let Some(key) = keys.pop() {
        return Ok(key.into());
    }

    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = StdBufReader::new(file);
    let mut keys = rustls_pemfile::ec_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read ec private key from {}", path.display()))?;
    if let Some(key) = keys.pop() {
        return Ok(key.into());
    }

    Err(anyhow!("no private key found in {}", path.display()))
}

async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &MeshFrame,
) -> Result<()> {
    let body = serde_json::to_vec(frame).context("mesh serialize failed")?;
    writer
        .write_all(&body)
        .await
        .context("mesh frame write failed")?;
    writer
        .write_all(b"\n")
        .await
        .context("mesh newline write failed")?;
    writer.flush().await.context("mesh flush failed")?;
    Ok(())
}
