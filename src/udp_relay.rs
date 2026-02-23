use crate::mesh::{MeshIncomingPacket, MeshOutgoingPacket, MeshTransport};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration, Instant};
use tracing::warn;

const MAGIC: &[u8; 4] = b"LSR1";
const TYPE_REGISTER: u8 = 1;
const TYPE_SEND: u8 = 2;
const TYPE_DELIVER: u8 = 3;
const HEADER_LEN: usize = 8;
const MAX_ID_LEN: usize = 64;
const PEER_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct Peer {
    addr: SocketAddr,
    last_seen: Instant,
}

enum RelayPacket {
    Register {
        node_id: String,
    },
    Send {
        from_id: String,
        to_id: String,
        payload: Vec<u8>,
    },
}

pub async fn run_with_mesh(
    listen: SocketAddr,
    mesh_tx: Option<mpsc::UnboundedSender<MeshOutgoingPacket>>,
    mesh_rx: Option<mpsc::UnboundedReceiver<MeshIncomingPacket>>,
) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(listen)
            .await
            .map_err(|err| anyhow!("udp relay bind failed: {}", err))?,
    );
    let peers: Arc<RwLock<HashMap<String, Peer>>> = Arc::new(RwLock::new(HashMap::new()));

    let cleanup_peers = peers.clone();
    tokio::spawn(async move { cleanup_loop(cleanup_peers).await });

    if let Some(mesh_rx) = mesh_rx {
        let peers = peers.clone();
        let socket = socket.clone();
        tokio::spawn(async move { handle_mesh_deliveries(mesh_rx, socket, peers).await });
    }

    let mut buf = vec![0u8; 2048];
    loop {
        let (len, addr) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|err| anyhow!("udp relay recv failed: {}", err))?;
        let packet = match parse_packet(&buf[..len]) {
            Some(packet) => packet,
            None => {
                warn!("udp relay: invalid packet from {}", addr);
                continue;
            }
        };

        match packet {
            RelayPacket::Register { node_id } => {
                upsert_peer(&peers, node_id, addr).await;
            }
            RelayPacket::Send {
                from_id,
                to_id,
                payload,
            } => {
                upsert_peer(&peers, from_id.clone(), addr).await;
                let delivered = deliver_local(&socket, &peers, &from_id, &to_id, &payload).await?;
                if !delivered {
                    if let Some(mesh_tx) = mesh_tx.as_ref() {
                        let _ = mesh_tx.send(MeshOutgoingPacket {
                            transport: MeshTransport::Udp,
                            from_id,
                            to_id,
                            payload,
                        });
                    } else {
                        warn!("udp relay: unknown target {}", to_id);
                    }
                }
            }
        }
    }
}

async fn handle_mesh_deliveries(
    mut mesh_rx: mpsc::UnboundedReceiver<MeshIncomingPacket>,
    socket: Arc<UdpSocket>,
    peers: Arc<RwLock<HashMap<String, Peer>>>,
) {
    while let Some(incoming) = mesh_rx.recv().await {
        let MeshIncomingPacket {
            transport,
            from_id,
            to_id,
            payload,
            delivered,
        } = incoming;
        if transport != MeshTransport::Udp {
            let _ = delivered.send(false);
            continue;
        }
        let result = deliver_local(&socket, &peers, &from_id, &to_id, &payload).await;
        let delivered_flag = matches!(result, Ok(true));
        let _ = delivered.send(delivered_flag);
    }
}

async fn deliver_local(
    socket: &Arc<UdpSocket>,
    peers: &Arc<RwLock<HashMap<String, Peer>>>,
    from_id: &str,
    to_id: &str,
    payload: &[u8],
) -> Result<bool> {
    let target = peers.read().await.get(to_id).cloned();
    if let Some(peer) = target {
        let deliver = build_packet(TYPE_DELIVER, from_id, "", payload)?;
        if let Err(err) = socket.send_to(&deliver, peer.addr).await {
            warn!("udp relay send failed: {}", err);
            Ok(false)
        } else {
            Ok(true)
        }
    } else {
        Ok(false)
    }
}

async fn upsert_peer(
    peers: &Arc<RwLock<HashMap<String, Peer>>>,
    node_id: String,
    addr: SocketAddr,
) {
    let mut guard = peers.write().await;
    guard.insert(
        node_id,
        Peer {
            addr,
            last_seen: Instant::now(),
        },
    );
}

async fn cleanup_loop(peers: Arc<RwLock<HashMap<String, Peer>>>) {
    loop {
        sleep(Duration::from_secs(60)).await;
        let now = Instant::now();
        let mut guard = peers.write().await;
        guard.retain(|_, peer| now.duration_since(peer.last_seen) < PEER_TTL);
    }
}

fn parse_packet(buf: &[u8]) -> Option<RelayPacket> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    if &buf[0..4] != MAGIC {
        return None;
    }
    let msg_type = buf[4];
    let from_len = buf[5] as usize;
    let to_len = buf[6] as usize;
    if from_len > MAX_ID_LEN || to_len > MAX_ID_LEN {
        return None;
    }
    let offset = HEADER_LEN;
    if buf.len() < offset + from_len + to_len {
        return None;
    }
    let from_end = offset + from_len;
    let to_end = from_end + to_len;
    let from_id = std::str::from_utf8(&buf[offset..from_end])
        .ok()?
        .to_string();
    let to_id = std::str::from_utf8(&buf[from_end..to_end])
        .ok()?
        .to_string();
    let payload = buf[to_end..].to_vec();

    match msg_type {
        TYPE_REGISTER => {
            if from_id.is_empty() || !to_id.is_empty() {
                None
            } else {
                Some(RelayPacket::Register { node_id: from_id })
            }
        }
        TYPE_SEND => {
            if from_id.is_empty() || to_id.is_empty() {
                None
            } else {
                Some(RelayPacket::Send {
                    from_id,
                    to_id,
                    payload,
                })
            }
        }
        _ => None,
    }
}

fn build_packet(msg_type: u8, from_id: &str, to_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
    if from_id.len() > MAX_ID_LEN || to_id.len() > MAX_ID_LEN {
        return Err(anyhow!("relay id too long"));
    }
    let mut buf = Vec::with_capacity(HEADER_LEN + from_id.len() + to_id.len() + payload.len());
    buf.extend_from_slice(MAGIC);
    buf.push(msg_type);
    buf.push(from_id.len() as u8);
    buf.push(to_id.len() as u8);
    buf.push(0);
    buf.extend_from_slice(from_id.as_bytes());
    buf.extend_from_slice(to_id.as_bytes());
    buf.extend_from_slice(payload);
    Ok(buf)
}
