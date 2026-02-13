use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::warn;

const MAGIC: &[u8; 4] = b"LSR2";
const TYPE_REGISTER: u8 = 1;
const TYPE_SEND: u8 = 2;
const TYPE_DELIVER: u8 = 3;
const HEADER_LEN: usize = 8;
const MAX_ID_LEN: usize = 64;
const MAX_FRAME_LEN: usize = 64 * 1024;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct PeerConn {
    id: u64,
    sender: mpsc::UnboundedSender<Vec<u8>>,
}

enum RelayPacket {
    Register { node_id: String },
    Send {
        from_id: String,
        to_id: String,
        payload: Vec<u8>,
    },
}

pub async fn run(listen: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|err| anyhow!("stream relay bind failed: {}", err))?;
    let peers: Arc<RwLock<HashMap<String, Vec<PeerConn>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|err| anyhow!("stream relay accept failed: {}", err))?;
        let peers = peers.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peers).await {
                warn!("stream relay connection error: {}", err);
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    peers: Arc<RwLock<HashMap<String, Vec<PeerConn>>>>,
) -> Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);

    let writer_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if let Err(err) = write_frame(&mut writer, &frame).await {
                warn!("stream relay write failed: {}", err);
                break;
            }
        }
    });

    let register = read_frame(&mut reader).await?;
    let packet = parse_packet(&register).ok_or_else(|| anyhow!("invalid register frame"))?;
    let node_id = match packet {
        RelayPacket::Register { node_id } => node_id,
        _ => return Err(anyhow!("expected register frame")),
    };

    {
        let mut guard = peers.write().await;
        guard
            .entry(node_id.clone())
            .or_default()
            .push(PeerConn { id: conn_id, sender: tx });
    }

    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(frame) => frame,
            Err(_) => break,
        };
        let Some(packet) = parse_packet(&frame) else {
            warn!("stream relay: invalid frame from {}", node_id);
            continue;
        };
        match packet {
            RelayPacket::Register { .. } => {
                warn!("stream relay: unexpected register from {}", node_id);
            }
            RelayPacket::Send {
                from_id,
                to_id,
                payload,
            } => {
                if from_id != node_id {
                    warn!("stream relay: spoofed from_id {} for {}", from_id, node_id);
                    continue;
                }
                let targets = peers.read().await.get(&to_id).cloned();
                if let Some(targets) = targets {
                    let deliver = build_packet(TYPE_DELIVER, &from_id, "", &payload)?;
                    for target in targets {
                        let _ = target.sender.send(deliver.clone());
                    }
                }
            }
        }
    }

    {
        let mut guard = peers.write().await;
        if let Some(list) = guard.get_mut(&node_id) {
            list.retain(|conn| conn.id != conn_id);
            if list.is_empty() {
                guard.remove(&node_id);
            }
        }
    }
    writer_task.abort();
    Ok(())
}

async fn read_frame(reader: &mut tokio::net::tcp::OwnedReadHalf) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_LEN {
        return Err(anyhow!("invalid frame length {}", len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    body: &[u8],
) -> Result<()> {
    if body.is_empty() || body.len() > MAX_FRAME_LEN {
        return Err(anyhow!("invalid frame length {}", body.len()));
    }
    let len = body.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(body).await?;
    Ok(())
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
    let from_id = std::str::from_utf8(&buf[offset..from_end]).ok()?.to_string();
    let to_id = std::str::from_utf8(&buf[from_end..to_end]).ok()?.to_string();
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
