use crate::state::StateStore;
use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;

const DNS_TTL_SECONDS: u32 = 30;

#[derive(Default)]
struct DnsSnapshot {
    records: HashMap<String, Vec<IpAddr>>,
    domains: HashSet<String>,
}

pub async fn run(listen: SocketAddr, store: StateStore) -> Result<()> {
    let socket = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("dns listen {} failed", listen))?;
    let mut buf = vec![0u8; 2048];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let request = match Message::from_vec(&buf[..len]) {
            Ok(msg) => msg,
            Err(_) => continue,
        };
        let response = match build_response(&request, &store).await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!("dns query handling failed: {}", err);
                continue;
            }
        };
        let out = response.to_vec()?;
        let _ = socket.send_to(&out, peer).await;
    }
}

async fn snapshot(store: &StateStore) -> Result<DnsSnapshot> {
    store
        .read(|state| {
            let mut snapshot = DnsSnapshot::default();
            for network in state.networks.values() {
                snapshot.domains.insert(normalize_name(&network.dns_domain));
            }

            for node in state.nodes.values() {
                if node.revoked_at.is_some() || !node.approved {
                    continue;
                }
                let Some(network) = state.networks.get(&node.network_id) else {
                    continue;
                };
                let dns_name = normalize_name(&format!("{}.{}", node.name, network.dns_domain));
                let ipv4: IpAddr = match node.ipv4.parse() {
                    Ok(ip) => ip,
                    Err(_) => continue,
                };
                let ipv6: IpAddr = match node.ipv6.parse() {
                    Ok(ip) => ip,
                    Err(_) => continue,
                };
                snapshot.records.insert(dns_name, vec![ipv4, ipv6]);
            }
            Ok(snapshot)
        })
        .await
}

async fn build_response(request: &Message, store: &StateStore) -> Result<Message> {
    let snapshot = snapshot(store).await?;
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(false);

    let mut answered = false;
    let mut any_within_domain = false;
    for query in request.queries() {
        response.add_query(query.clone());
        let query_name = normalize_name(&query.name().to_ascii());
        if is_within_domains(&query_name, &snapshot.domains) {
            any_within_domain = true;
        }
        let Some(addresses) = snapshot.records.get(&query_name) else {
            continue;
        };
        for address in addresses {
            match (query.query_type(), address) {
                (RecordType::A, IpAddr::V4(_)) | (RecordType::ANY, IpAddr::V4(_)) => {
                    response.add_answer(build_record(query.name(), *address));
                    answered = true;
                }
                (RecordType::AAAA, IpAddr::V6(_)) | (RecordType::ANY, IpAddr::V6(_)) => {
                    response.add_answer(build_record(query.name(), *address));
                    answered = true;
                }
                _ => {}
            }
        }
    }

    response.set_response_code(if answered {
        ResponseCode::NoError
    } else if any_within_domain {
        ResponseCode::NXDomain
    } else {
        ResponseCode::Refused
    });
    response.set_authoritative(true);
    Ok(response)
}

fn is_within_domains(name: &str, domains: &HashSet<String>) -> bool {
    domains
        .iter()
        .any(|domain| name == domain || name.ends_with(&format!(".{}", domain)))
}

fn build_record(name: &Name, addr: IpAddr) -> Record {
    let rdata = match addr {
        IpAddr::V4(v4) => RData::A(A(v4)),
        IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
    };
    Record::from_rdata(name.clone(), DNS_TTL_SECONDS, rdata)
}

fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}
