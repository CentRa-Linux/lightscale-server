use crate::app::AppState;
use crate::model::{
    AclAction, AclPolicy, AclSelector, AdminNodesResponse, AuditEntry, AuditLogResponse,
    ControlPlaneMeshPeer, ControlPlaneTopologyResponse, CreateNetworkRequest,
    CreateNetworkResponse, CreateTokenRequest, CreateTokenResponse, DeleteNodeResponse,
    EnrollmentToken, HeartbeatRequest, HeartbeatResponse, KeyHistoryResponse, KeyPolicyResponse,
    KeyRecord, KeyRotationPolicy, KeyRotationRequest, KeyRotationResponse, KeyType,
    ListTokensResponse, NetMap, NetworkInfo, NetworkState, NodeInfo, NodeState, PeerInfo,
    ProbeRequest, RegisterRequest, RegisterResponse, RegisterUrlRequest, RegisterUrlResponse,
    RelayConfig, TokenState, UpdateAclRequest, UpdateAclResponse, UpdateNodeRequest,
    UpdateNodeResponse,
};
use crate::netid::derive_overlay_prefixes;
use crate::state::State;
use anyhow::Error;
use axum::extract::{ConnectInfo, Extension, Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ipnet::{Ipv4Net, Ipv6Net};
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::time::{sleep, Instant};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error("invalid request: {0}")]
    BadRequest(&'static str),
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("internal error")]
    Internal,
}

#[derive(Deserialize)]
pub struct NetmapLongpollParams {
    pub since: Option<u64>,
    pub timeout_seconds: Option<u64>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

fn map_store_err(err: Error) -> ApiError {
    match err.downcast::<ApiError>() {
        Ok(api_err) => api_err,
        Err(_) => ApiError::Internal,
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let header = headers.get(axum::http::header::AUTHORIZATION)?;
    let value = header.to_str().ok()?;
    let prefix = "Bearer ";
    if value.starts_with(prefix) {
        Some(value[prefix.len()..].trim())
    } else {
        None
    }
}

fn require_admin(headers: &HeaderMap, admin_token: &Option<String>) -> Result<(), ApiError> {
    let Some(expected) = admin_token.as_deref() else {
        return Ok(());
    };
    match bearer_token(headers) {
        Some(token) if token == expected => Ok(()),
        _ => Err(ApiError::Unauthorized("admin token required")),
    }
}

pub async fn admin_topology(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<Json<ControlPlaneTopologyResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let mut control_urls = state.control_urls.clone();
    if let Some(inferred) = infer_control_url_from_headers(&headers) {
        if !control_urls.iter().any(|existing| existing == &inferred) {
            control_urls.insert(0, inferred);
        }
    }
    dedup_strings(&mut control_urls);

    let mesh_peers = state
        .mesh_peers
        .iter()
        .map(|peer| ControlPlaneMeshPeer {
            id: peer.id.clone(),
            addr: peer.addr.clone(),
        })
        .collect();

    Ok(Json(ControlPlaneTopologyResponse {
        control_urls,
        mesh_server_id: state.mesh_server_id.clone(),
        mesh_peers,
        generated_at: now_unix(),
    }))
}

fn infer_control_url_from_headers(headers: &HeaderMap) -> Option<String> {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(axum::http::header::HOST))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;

    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("http");
    let scheme = if proto.eq_ignore_ascii_case("https") {
        "https"
    } else {
        "http"
    };
    Some(format!("{scheme}://{}", host.trim_end_matches('/')))
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn require_node(
    headers: &HeaderMap,
    admin_token: &Option<String>,
    node: &NodeState,
) -> Result<(), ApiError> {
    let Some(expected) = node.node_token.as_deref() else {
        return Ok(());
    };
    let token = bearer_token(headers);
    if let Some(token) = token {
        if token == expected {
            return Ok(());
        }
        if let Some(admin) = admin_token.as_deref() {
            if token == admin {
                return Ok(());
            }
        }
    }
    Err(ApiError::Unauthorized("node token required"))
}

pub async fn create_network(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateNetworkRequest>,
) -> Result<Json<CreateNetworkResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let CreateNetworkRequest {
        name,
        overlay_v4: requested_overlay_v4,
        overlay_v6: requested_overlay_v6,
        dns_domain,
        requires_approval,
        key_rotation_max_age_seconds,
        bootstrap_token_ttl_seconds,
        bootstrap_token_uses,
        bootstrap_token_tags,
    } = req;

    let network_id = Uuid::new_v4();
    let (default_overlay_v4, default_overlay_v6) = derive_overlay_prefixes(&network_id);
    let overlay_v4 = requested_overlay_v4.unwrap_or(default_overlay_v4);
    let overlay_v6 = requested_overlay_v6.unwrap_or(default_overlay_v6);
    let overlay_v4_net: Ipv4Net = overlay_v4
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid overlay_v4 cidr"))?;
    let overlay_v6_net: Ipv6Net = overlay_v6
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid overlay_v6 cidr"))?;
    let next_ipv4 = initial_ipv4_offset(&overlay_v4_net).ok_or(ApiError::BadRequest(
        "overlay_v4 must provide usable host addresses",
    ))?;
    let next_ipv6 = initial_ipv6_offset(&overlay_v6_net);
    let dns_domain =
        dns_domain.unwrap_or_else(|| format!("net-{}.lightscale", short_id(&network_id)));
    let now = now_unix();

    let mut bootstrap_token: Option<EnrollmentToken> = None;

    let network_state = NetworkState {
        id: network_id.to_string(),
        name,
        overlay_v4,
        overlay_v6,
        dns_domain,
        requires_approval: requires_approval.unwrap_or(false),
        acl: AclPolicy::default(),
        key_policy: KeyRotationPolicy {
            max_age_seconds: key_rotation_max_age_seconds,
        },
        created_at: now,
        next_ipv4,
        next_ipv6,
    };

    state
        .store
        .write(|state| {
            if state.networks.contains_key(&network_state.id) {
                return Err(ApiError::Conflict("network already exists").into());
            }
            for existing in state.networks.values() {
                let existing_v4: Ipv4Net = existing
                    .overlay_v4
                    .parse()
                    .map_err(|_| ApiError::Internal)?;
                if ipv4_nets_overlap(&overlay_v4_net, &existing_v4) {
                    return Err(ApiError::Conflict("overlay_v4 overlaps existing network").into());
                }
                let existing_v6: Ipv6Net = existing
                    .overlay_v6
                    .parse()
                    .map_err(|_| ApiError::Internal)?;
                if ipv6_nets_overlap(&overlay_v6_net, &existing_v6) {
                    return Err(ApiError::Conflict("overlay_v6 overlaps existing network").into());
                }
            }
            state
                .networks
                .insert(network_state.id.clone(), network_state.clone());
            state.audit_log.push(build_audit_entry(
                "network.create",
                Some(network_state.id.clone()),
                None,
                Some(serde_json::json!({
                    "name": network_state.name,
                    "requires_approval": network_state.requires_approval,
                    "key_rotation_max_age_seconds": network_state.key_policy.max_age_seconds,
                })),
            ));

            if let Some(ttl) = bootstrap_token_ttl_seconds {
                let uses = bootstrap_token_uses.unwrap_or(1);
                let tags = bootstrap_token_tags.unwrap_or_default();
                let token = build_token(&network_state.id, ttl, uses, tags, None, None, true)?;
                state.tokens.insert(token.token.clone(), token.clone());
                bootstrap_token = Some(token.into());
            }

            Ok(())
        })
        .await
        .map_err(map_store_err)?;

    let response = CreateNetworkResponse {
        network: NetworkInfo::from(&network_state),
        bootstrap_token,
    };

    Ok(Json(response))
}

pub async fn create_token(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<String>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let token = state
        .store
        .write(|state| {
            let network = state
                .networks
                .get(&network_id)
                .ok_or(ApiError::NotFound("network"))?;
            let token = build_token(
                &network.id,
                req.ttl_seconds,
                req.uses,
                req.tags,
                req.owner_user_id.clone(),
                req.owner_email.clone(),
                req.owner_is_admin.unwrap_or(true),
            )?;
            state.tokens.insert(token.token.clone(), token.clone());
            state.audit_log.push(build_audit_entry(
                "token.create",
                Some(network.id.clone()),
                None,
                Some(serde_json::json!({
                    "expires_at": token.expires_at,
                    "uses": token.uses_left,
                    "tags": token.tags,
                    "owner_user_id": token.owner_user_id,
                    "owner_email": token.owner_email,
                    "owner_is_admin": token.owner_is_admin,
                })),
            ));
            Ok(token)
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(CreateTokenResponse {
        token: token.into(),
    }))
}

pub async fn list_tokens(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<String>,
) -> Result<Json<ListTokensResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let tokens = state
        .store
        .read(|state| {
            if !state.networks.contains_key(&network_id) {
                return Err(ApiError::NotFound("network").into());
            }
            let mut tokens: Vec<EnrollmentToken> = state
                .tokens
                .values()
                .filter(|token| token.network_id == network_id)
                .map(EnrollmentToken::from)
                .collect();
            tokens.sort_by_key(|token| token.expires_at);
            tokens.reverse();
            Ok(tokens)
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(ListTokensResponse { tokens }))
}

pub async fn revoke_token(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Result<Json<EnrollmentToken>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let now = now_unix();
    let token = state
        .store
        .write(|state| {
            let token = state
                .tokens
                .get_mut(&token_id)
                .ok_or(ApiError::NotFound("token"))?;
            token.revoked_at = Some(now);
            state.audit_log.push(build_audit_entry(
                "token.revoke",
                Some(token.network_id.clone()),
                None,
                Some(serde_json::json!({
                    "revoked_at": token.revoked_at,
                })),
            ));
            Ok(token.clone())
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(token.into()))
}

pub async fn register(
    Extension(state): Extension<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let now = now_unix();
    let relay = relay_or_none(&state.relay);
    let node_token = random_secret();
    let node_name = normalize_node_name(&req.node_name)?;

    let node_id = state
        .store
        .write(|state| {
            let token = state
                .tokens
                .get(&req.token)
                .ok_or(ApiError::Unauthorized("token not found"))?;

            if token.expires_at <= now {
                return Err(ApiError::Unauthorized("token expired").into());
            }

            if token.revoked_at.is_some() {
                return Err(ApiError::Unauthorized("token revoked").into());
            }

            if token.uses_left == 0 {
                return Err(ApiError::Unauthorized("token used up").into());
            }

            ensure_unique_node_name(state, &token.network_id, &node_name, None)?;

            let network = state
                .networks
                .get_mut(&token.network_id)
                .ok_or(ApiError::NotFound("network"))?;

            let (ipv4, ipv6) = allocate_node_ips(network)?;

            let node_id = Uuid::new_v4().to_string();
            let approved = !network.requires_approval;
            let key_history = vec![
                KeyRecord {
                    key_type: KeyType::Machine,
                    public_key: req.machine_public_key.clone(),
                    created_at: now,
                    revoked_at: None,
                },
                KeyRecord {
                    key_type: KeyType::WireGuard,
                    public_key: req.wg_public_key.clone(),
                    created_at: now,
                    revoked_at: None,
                },
            ];
            let node = NodeState {
                id: node_id.clone(),
                network_id: network.id.clone(),
                name: node_name.clone(),
                machine_public_key: req.machine_public_key.clone(),
                wg_public_key: req.wg_public_key.clone(),
                ipv4,
                ipv6,
                endpoints: Vec::new(),
                tags: token.tags.clone(),
                owner_user_id: token.owner_user_id.clone(),
                owner_email: token.owner_email.clone(),
                owner_is_admin: token.owner_is_admin,
                routes: Vec::new(),
                created_at: now,
                last_seen: now,
                probe_requested_at: None,
                approved,
                approved_at: approved.then_some(now),
                auth_secret: None,
                auth_expires_at: None,
                node_token: Some(node_token.clone()),
                revoked_at: None,
                key_history,
            };

            state.nodes.insert(node.id.clone(), node.clone());
            state.audit_log.push(build_audit_entry(
                "node.register",
                Some(network.id.clone()),
                Some(node.id.clone()),
                Some(serde_json::json!({
                    "approved": node.approved,
                    "owner_user_id": node.owner_user_id,
                    "owner_email": node.owner_email,
                    "owner_is_admin": node.owner_is_admin,
                })),
            ));

            let token = state
                .tokens
                .get_mut(&req.token)
                .ok_or(ApiError::Unauthorized("token not found"))?;
            token.uses_left = token.uses_left.saturating_sub(1);
            if token.uses_left == 0 {
                state.tokens.remove(&req.token);
            }

            Ok(node.id.clone())
        })
        .await
        .map_err(map_store_err)?;

    let netmap = state
        .store
        .read(|state| Ok(build_netmap(state, &node_id, relay.clone())?))
        .await
        .map_err(map_store_err)?;

    Ok(Json(RegisterResponse { node_token, netmap }))
}

pub async fn register_url(
    Extension(state): Extension<AppState>,
    Json(req): Json<RegisterUrlRequest>,
) -> Result<Json<RegisterUrlResponse>, ApiError> {
    let now = now_unix();
    let ttl_seconds = req.ttl_seconds.unwrap_or(600);
    if ttl_seconds == 0 {
        return Err(ApiError::BadRequest("ttl_seconds must be > 0"));
    }
    let expires_at = now + ttl_seconds as i64;
    let node_name = normalize_node_name(&req.node_name)?;

    let node_token = random_secret();
    let (node, auth_path) = state
        .store
        .write(|state| {
            ensure_unique_node_name(state, &req.network_id, &node_name, None)?;
            let network = state
                .networks
                .get_mut(&req.network_id)
                .ok_or(ApiError::NotFound("network"))?;

            let (ipv4, ipv6) = allocate_node_ips(network)?;
            let node_id = Uuid::new_v4().to_string();
            let auth_secret = random_secret();

            let key_history = vec![
                KeyRecord {
                    key_type: KeyType::Machine,
                    public_key: req.machine_public_key.clone(),
                    created_at: now,
                    revoked_at: None,
                },
                KeyRecord {
                    key_type: KeyType::WireGuard,
                    public_key: req.wg_public_key.clone(),
                    created_at: now,
                    revoked_at: None,
                },
            ];
            let node = NodeState {
                id: node_id.clone(),
                network_id: network.id.clone(),
                name: node_name.clone(),
                machine_public_key: req.machine_public_key.clone(),
                wg_public_key: req.wg_public_key.clone(),
                ipv4,
                ipv6,
                endpoints: Vec::new(),
                tags: Vec::new(),
                owner_user_id: None,
                owner_email: None,
                owner_is_admin: true,
                routes: Vec::new(),
                created_at: now,
                last_seen: now,
                probe_requested_at: None,
                approved: false,
                approved_at: None,
                auth_secret: Some(auth_secret.clone()),
                auth_expires_at: Some(expires_at),
                node_token: Some(node_token.clone()),
                revoked_at: None,
                key_history,
            };

            state.nodes.insert(node.id.clone(), node.clone());
            state.audit_log.push(build_audit_entry(
                "node.register_url",
                Some(network.id.clone()),
                Some(node.id.clone()),
                Some(serde_json::json!({
                    "expires_at": expires_at,
                })),
            ));

            let auth_path = format!("/v1/register/approve/{}/{}", node_id, auth_secret);
            Ok((node, auth_path))
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(RegisterUrlResponse {
        node_id: node.id,
        network_id: node.network_id,
        ipv4: node.ipv4,
        ipv6: node.ipv6,
        auth_path,
        expires_at,
        node_token,
    }))
}

pub async fn approve_node_secret(
    Extension(state): Extension<AppState>,
    Path((node_id, secret)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let now = now_unix();
    let node = state
        .store
        .write(|state| {
            let node = state
                .nodes
                .get_mut(&node_id)
                .ok_or(ApiError::NotFound("node"))?;

            if node.approved {
                return Ok(node.clone());
            }

            let auth_secret = node
                .auth_secret
                .as_ref()
                .ok_or(ApiError::Unauthorized("approval not allowed"))?;
            if auth_secret != &secret {
                return Err(ApiError::Unauthorized("invalid approval secret").into());
            }
            if let Some(expires_at) = node.auth_expires_at {
                if expires_at <= now {
                    return Err(ApiError::Unauthorized("approval expired").into());
                }
            }

            node.approved = true;
            node.approved_at = Some(now);
            node.auth_secret = None;
            node.auth_expires_at = None;
            state.audit_log.push(build_audit_entry(
                "node.approve",
                Some(node.network_id.clone()),
                Some(node.id.clone()),
                Some(serde_json::json!({
                    "approved_at": node.approved_at,
                    "via": "auth_url",
                })),
            ));
            Ok(node.clone())
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(serde_json::json!({
        "node_id": node.id,
        "approved": node.approved,
        "approved_at": node.approved_at,
    })))
}

pub async fn approve_node(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let now = now_unix();
    let node = state
        .store
        .write(|state| {
            let node = state
                .nodes
                .get_mut(&node_id)
                .ok_or(ApiError::NotFound("node"))?;
            if node.approved {
                return Ok(node.clone());
            }
            node.approved = true;
            node.approved_at = Some(now);
            node.auth_secret = None;
            node.auth_expires_at = None;
            state.audit_log.push(build_audit_entry(
                "node.approve",
                Some(node.network_id.clone()),
                Some(node.id.clone()),
                Some(serde_json::json!({
                    "approved_at": node.approved_at,
                    "via": "admin",
                })),
            ));
            Ok(node.clone())
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(serde_json::json!({
        "node_id": node.id,
        "approved": node.approved,
        "approved_at": node.approved_at,
    })))
}

pub async fn admin_nodes(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<String>,
) -> Result<Json<AdminNodesResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let now = now_unix();
    let nodes = state
        .store
        .read(|state| {
            let network = state
                .networks
                .get(&network_id)
                .ok_or(ApiError::NotFound("network"))?;
            let nodes = state
                .nodes
                .values()
                .filter(|node| node.network_id == network_id)
                .map(|node| {
                    let (approved, key_rotation_required) =
                        effective_node_status(node, &network.key_policy, now);
                    NodeInfo::from_state(
                        node,
                        network.dns_domain.as_str(),
                        approved,
                        key_rotation_required,
                    )
                })
                .collect();
            Ok(nodes)
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(AdminNodesResponse { nodes }))
}

pub async fn update_node(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
    Json(req): Json<UpdateNodeRequest>,
) -> Result<Json<UpdateNodeResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    if req.name.is_none() && req.tags.is_none() {
        return Err(ApiError::BadRequest("no fields to update"));
    }
    let now = now_unix();
    let node = state
        .store
        .write(|state| {
            let existing = state
                .nodes
                .get(&node_id)
                .ok_or(ApiError::NotFound("node"))?
                .clone();
            let mut detail = serde_json::Map::new();
            let mut next_name: Option<String> = None;
            let mut next_tags: Option<Vec<String>> = None;

            if let Some(name) = req.name.as_ref() {
                let normalized = normalize_node_name(name)?;
                if normalized != existing.name {
                    ensure_unique_node_name(
                        state,
                        &existing.network_id,
                        &normalized,
                        Some(&existing.id),
                    )?;
                    detail.insert("name".to_string(), serde_json::json!(normalized));
                    next_name = Some(normalized);
                }
            }

            if let Some(tags) = req.tags.as_ref() {
                let mut unique = Vec::new();
                let mut seen = HashSet::new();
                for tag in tags {
                    let tag = tag.trim();
                    if tag.is_empty() {
                        continue;
                    }
                    if seen.insert(tag.to_string()) {
                        unique.push(tag.to_string());
                    }
                }
                if unique != existing.tags {
                    detail.insert("tags".to_string(), serde_json::json!(&unique));
                    next_tags = Some(unique);
                }
            }

            let node = state
                .nodes
                .get_mut(&node_id)
                .ok_or(ApiError::NotFound("node"))?;
            if let Some(name) = next_name {
                node.name = name;
            }
            if let Some(tags) = next_tags {
                node.tags = tags;
            }

            let network_id = node.network_id.clone();
            let node_snapshot = node.clone();
            let network = state
                .networks
                .get(&network_id)
                .ok_or(ApiError::NotFound("network"))?;
            let (approved, key_rotation_required) =
                effective_node_status(&node_snapshot, &network.key_policy, now);
            if !detail.is_empty() {
                state.audit_log.push(build_audit_entry(
                    "node.update",
                    Some(network.id.clone()),
                    Some(node_snapshot.id.clone()),
                    Some(serde_json::Value::Object(detail)),
                ));
            }

            Ok(NodeInfo::from_state(
                &node_snapshot,
                network.dns_domain.as_str(),
                approved,
                key_rotation_required,
            ))
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(UpdateNodeResponse { node }))
}

pub async fn get_acl(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<String>,
) -> Result<Json<AclPolicy>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let policy = state
        .store
        .read(|state| {
            let network = state
                .networks
                .get(&network_id)
                .ok_or(ApiError::NotFound("network"))?;
            Ok(network.acl.clone())
        })
        .await
        .map_err(map_store_err)?;
    Ok(Json(policy))
}

pub async fn update_acl(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<String>,
    Json(req): Json<UpdateAclRequest>,
) -> Result<Json<UpdateAclResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let policy = state
        .store
        .write(|state| {
            let network = state
                .networks
                .get_mut(&network_id)
                .ok_or(ApiError::NotFound("network"))?;
            network.acl = req.policy.clone();
            state.audit_log.push(build_audit_entry(
                "acl.update",
                Some(network.id.clone()),
                None,
                None,
            ));
            Ok(network.acl.clone())
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(UpdateAclResponse { policy }))
}

pub async fn get_key_policy(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<String>,
) -> Result<Json<KeyPolicyResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let policy = state
        .store
        .read(|state| {
            let network = state
                .networks
                .get(&network_id)
                .ok_or(ApiError::NotFound("network"))?;
            Ok(network.key_policy.clone())
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(KeyPolicyResponse { policy }))
}

pub async fn update_key_policy(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<String>,
    Json(req): Json<KeyRotationPolicy>,
) -> Result<Json<KeyPolicyResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let policy = state
        .store
        .write(|state| {
            let network = state
                .networks
                .get_mut(&network_id)
                .ok_or(ApiError::NotFound("network"))?;
            network.key_policy = req.clone();
            state.audit_log.push(build_audit_entry(
                "key_policy.update",
                Some(network.id.clone()),
                None,
                Some(serde_json::json!({
                    "max_age_seconds": network.key_policy.max_age_seconds,
                })),
            ));
            Ok(network.key_policy.clone())
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(KeyPolicyResponse { policy }))
}

pub async fn rotate_keys(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
    Json(req): Json<KeyRotationRequest>,
) -> Result<Json<KeyRotationResponse>, ApiError> {
    if req.machine_public_key.is_none() && req.wg_public_key.is_none() {
        return Err(ApiError::BadRequest("no keys provided"));
    }
    let now = now_unix();
    let admin_token = state.admin_token.clone();
    let node = state
        .store
        .write(|state| {
            let node = state
                .nodes
                .get_mut(&node_id)
                .ok_or(ApiError::NotFound("node"))?;
            require_node(&headers, &admin_token, node)?;

            let mut rotated = serde_json::Map::new();

            if let Some(new_machine) = req.machine_public_key.as_ref() {
                if node.machine_public_key == *new_machine {
                    return Err(ApiError::BadRequest("machine_public_key unchanged").into());
                }
                revoke_key_record(
                    &mut node.key_history,
                    KeyType::Machine,
                    &node.machine_public_key,
                    now,
                );
                node.machine_public_key = new_machine.clone();
                node.key_history.push(KeyRecord {
                    key_type: KeyType::Machine,
                    public_key: new_machine.clone(),
                    created_at: now,
                    revoked_at: None,
                });
                rotated.insert("machine".to_string(), serde_json::json!(new_machine));
            }

            if let Some(new_wg) = req.wg_public_key.as_ref() {
                if node.wg_public_key == *new_wg {
                    return Err(ApiError::BadRequest("wg_public_key unchanged").into());
                }
                revoke_key_record(
                    &mut node.key_history,
                    KeyType::WireGuard,
                    &node.wg_public_key,
                    now,
                );
                node.wg_public_key = new_wg.clone();
                node.key_history.push(KeyRecord {
                    key_type: KeyType::WireGuard,
                    public_key: new_wg.clone(),
                    created_at: now,
                    revoked_at: None,
                });
                rotated.insert("wireguard".to_string(), serde_json::json!(new_wg));
            }

            node.revoked_at = None;

            state.audit_log.push(build_audit_entry(
                "keys.rotate",
                Some(node.network_id.clone()),
                Some(node.id.clone()),
                Some(serde_json::Value::Object(rotated)),
            ));

            Ok(node.clone())
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(KeyRotationResponse {
        node_id: node.id,
        machine_public_key: node.machine_public_key,
        wg_public_key: node.wg_public_key,
    }))
}

pub async fn revoke_node(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let now = now_unix();
    let node = state
        .store
        .write(|state| {
            let node = state
                .nodes
                .get_mut(&node_id)
                .ok_or(ApiError::NotFound("node"))?;
            node.revoked_at = Some(now);
            revoke_key_record(
                &mut node.key_history,
                KeyType::Machine,
                &node.machine_public_key,
                now,
            );
            revoke_key_record(
                &mut node.key_history,
                KeyType::WireGuard,
                &node.wg_public_key,
                now,
            );
            state.audit_log.push(build_audit_entry(
                "keys.revoke",
                Some(node.network_id.clone()),
                Some(node.id.clone()),
                Some(serde_json::json!({
                    "revoked_at": node.revoked_at,
                })),
            ));
            Ok(node.clone())
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(serde_json::json!({
        "node_id": node.id,
        "revoked_at": node.revoked_at,
    })))
}

pub async fn delete_node(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> Result<Json<DeleteNodeResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let deleted = state
        .store
        .write(|state| {
            let node = state
                .nodes
                .remove(&node_id)
                .ok_or(ApiError::NotFound("node"))?;
            state.audit_log.push(build_audit_entry(
                "node.delete",
                Some(node.network_id.clone()),
                Some(node.id.clone()),
                Some(serde_json::json!({
                    "name": node.name,
                    "ipv4": node.ipv4,
                    "ipv6": node.ipv6,
                })),
            ));
            Ok(node.id)
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(DeleteNodeResponse { node_id: deleted }))
}

pub async fn delete_network(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin(&headers, &state.admin_token)?;

    state
        .store
        .write(|state| {
            // ネットワークの存在確認
            if !state.networks.contains_key(&network_id) {
                return Err(ApiError::NotFound("network").into());
            }

            // ネットワークに接続中のノードがあるか確認
            let connected_nodes: Vec<_> = state
                .nodes
                .values()
                .filter(|node| node.network_id == network_id)
                .map(|node| node.id.clone())
                .collect();

            if !connected_nodes.is_empty() {
                return Err(ApiError::Conflict(
                    "network has connected nodes; revoke or delete nodes first",
                )
                .into());
            }

            // 関連するトークンを削除
            state
                .tokens
                .retain(|_, token| token.network_id != network_id);

            // ネットワークを削除
            state.networks.remove(&network_id);

            state.audit_log.push(build_audit_entry(
                "network.delete",
                Some(network_id.clone()),
                None,
                None,
            ));

            Ok(())
        })
        .await
        .map_err(map_store_err)?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn node_keys(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> Result<Json<KeyHistoryResponse>, ApiError> {
    let admin_token = state.admin_token.clone();
    let history = state
        .store
        .read(|state| {
            let node = state
                .nodes
                .get(&node_id)
                .ok_or(ApiError::NotFound("node"))?;
            require_node(&headers, &admin_token, node)?;
            Ok(node.key_history.clone())
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(KeyHistoryResponse {
        node_id,
        keys: history,
    }))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub network_id: Option<String>,
    pub node_id: Option<String>,
    pub limit: Option<usize>,
}

pub async fn audit_log(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuditQuery>,
) -> Result<Json<AuditLogResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let entries = state
        .store
        .read(|state| {
            let mut entries: Vec<AuditEntry> = state
                .audit_log
                .iter()
                .filter(|entry| {
                    if let Some(ref network_id) = params.network_id {
                        if entry.network_id.as_deref() != Some(network_id.as_str()) {
                            return false;
                        }
                    }
                    if let Some(ref node_id) = params.node_id {
                        if entry.node_id.as_deref() != Some(node_id.as_str()) {
                            return false;
                        }
                    }
                    true
                })
                .cloned()
                .collect();
            if let Some(limit) = params.limit {
                if entries.len() > limit {
                    entries = entries[entries.len() - limit..].to_vec();
                }
            }
            Ok(entries)
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(AuditLogResponse { entries }))
}

pub async fn heartbeat(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    let now = now_unix();
    let relay = relay_or_none(&state.relay);
    let admin_token = state.admin_token.clone();
    let HeartbeatRequest {
        node_id,
        endpoints,
        listen_port,
        routes,
        probe,
    } = req;
    let observed_endpoint = listen_port.map(|port| SocketAddr::new(remote.ip(), port).to_string());
    let endpoints = merge_endpoints(endpoints, observed_endpoint);

    state
        .store
        .write(|state| {
            let node = state
                .nodes
                .get_mut(&node_id)
                .ok_or(ApiError::NotFound("node"))?;
            require_node(&headers, &admin_token, node)?;
            node.endpoints = endpoints;
            node.routes = routes;
            node.last_seen = now;
            if probe.unwrap_or(false) {
                node.probe_requested_at = Some(now);
            }
            Ok(())
        })
        .await
        .map_err(map_store_err)?;

    let netmap = state
        .store
        .read(|state| Ok(build_netmap(state, &node_id, relay.clone())?))
        .await
        .map_err(map_store_err)?;

    Ok(Json(HeartbeatResponse { netmap }))
}

pub async fn netmap(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> Result<Json<NetMap>, ApiError> {
    let relay = relay_or_none(&state.relay);
    let admin_token = state.admin_token.clone();
    let netmap = state
        .store
        .read(|state| {
            let node = state
                .nodes
                .get(&node_id)
                .ok_or(ApiError::NotFound("node"))?;
            require_node(&headers, &admin_token, node)?;
            Ok(build_netmap(state, &node_id, relay.clone())?)
        })
        .await
        .map_err(map_store_err)?;

    Ok(Json(netmap))
}

pub async fn netmap_longpoll(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
    Query(params): Query<NetmapLongpollParams>,
) -> Result<Json<NetMap>, ApiError> {
    let relay = relay_or_none(&state.relay);
    let since = params.since.unwrap_or(0);
    let timeout = params.timeout_seconds.unwrap_or(30).min(300);
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let admin_token = state.admin_token.clone();

    loop {
        let snapshot = state
            .store
            .read(|state| {
                let node = state
                    .nodes
                    .get(&node_id)
                    .ok_or(ApiError::NotFound("node"))?;
                require_node(&headers, &admin_token, node)?;
                Ok(build_netmap(state, &node_id, relay.clone())
                    .map(|netmap| (state.revision, netmap))?)
            })
            .await
            .map_err(map_store_err)?;

        if snapshot.0 > since || Instant::now() >= deadline {
            return Ok(Json(snapshot.1));
        }

        sleep(Duration::from_millis(500)).await;
    }
}

fn build_netmap(
    state: &State,
    node_id: &str,
    relay: Option<RelayConfig>,
) -> Result<NetMap, ApiError> {
    let node = state.nodes.get(node_id).ok_or(ApiError::NotFound("node"))?;
    let network = state
        .networks
        .get(&node.network_id)
        .ok_or(ApiError::NotFound("network"))?;
    let now = now_unix();
    let (approved, key_rotation_required) = effective_node_status(node, &network.key_policy, now);
    let peers = if approved {
        collect_peers(
            &network.id,
            network.dns_domain.as_str(),
            &state.nodes,
            Some(&node_id),
            node,
            &network.acl,
            &network.key_policy,
            now,
        )
    } else {
        Vec::new()
    };

    let probe_requests = collect_probe_requests(state, &peers, now);

    Ok(NetMap {
        network: NetworkInfo::from(network),
        node: NodeInfo::from_state(
            node,
            network.dns_domain.as_str(),
            approved,
            key_rotation_required,
        ),
        peers,
        relay,
        probe_requests,
        generated_at: now_unix(),
        revision: state.revision,
    })
}

const PROBE_TTL_SECONDS: i64 = 30;

fn collect_probe_requests(state: &State, peers: &[PeerInfo], now: i64) -> Vec<ProbeRequest> {
    peers
        .iter()
        .filter_map(|peer| {
            let node = state.nodes.get(&peer.id)?;
            let requested_at = node.probe_requested_at?;
            if now.saturating_sub(requested_at) > PROBE_TTL_SECONDS {
                return None;
            }
            Some(ProbeRequest {
                peer_id: peer.id.clone(),
                endpoints: peer.endpoints.clone(),
                ipv4: peer.ipv4.clone(),
                ipv6: peer.ipv6.clone(),
                requested_at,
            })
        })
        .collect()
}

fn collect_peers(
    network_id: &str,
    dns_domain: &str,
    nodes: &std::collections::HashMap<String, NodeState>,
    exclude_id: Option<&str>,
    src_node: &NodeState,
    acl: &AclPolicy,
    key_policy: &KeyRotationPolicy,
    now: i64,
) -> Vec<PeerInfo> {
    nodes
        .values()
        .filter(|node| node.network_id == network_id)
        .filter(|node| {
            let (approved, _) = effective_node_status(node, key_policy, now);
            approved
        })
        .filter(|node| exclude_id.map_or(true, |id| node.id != id))
        .filter(|node| acl_allows(acl, src_node, node))
        .map(|node| PeerInfo::from((node, dns_domain)))
        .collect()
}

fn effective_node_status(
    node: &NodeState,
    key_policy: &KeyRotationPolicy,
    now: i64,
) -> (bool, bool) {
    let mut key_rotation_required = false;
    if let Some(max_age) = key_policy.max_age_seconds {
        let max_age = max_age as i64;
        if let Some(created_at) = current_key_created_at(node, KeyType::Machine) {
            if now.saturating_sub(created_at) > max_age {
                key_rotation_required = true;
            }
        }
        if let Some(created_at) = current_key_created_at(node, KeyType::WireGuard) {
            if now.saturating_sub(created_at) > max_age {
                key_rotation_required = true;
            }
        }
    }
    let revoked = node.revoked_at.is_some();
    let approved = node.approved && !revoked && !key_rotation_required;
    (approved, key_rotation_required)
}

fn current_key_created_at(node: &NodeState, key_type: KeyType) -> Option<i64> {
    node.key_history
        .iter()
        .find(|record| {
            record.key_type == key_type
                && record.revoked_at.is_none()
                && match key_type {
                    KeyType::Machine => record.public_key == node.machine_public_key,
                    KeyType::WireGuard => record.public_key == node.wg_public_key,
                }
        })
        .map(|record| record.created_at)
}

fn revoke_key_record(history: &mut Vec<KeyRecord>, key_type: KeyType, public_key: &str, now: i64) {
    for record in history.iter_mut() {
        if record.key_type == key_type && record.public_key == public_key {
            record.revoked_at = Some(now);
        }
    }
}

fn acl_allows(policy: &AclPolicy, src: &NodeState, dst: &NodeState) -> bool {
    for rule in &policy.rules {
        if selector_matches(src, &rule.src) && selector_matches(dst, &rule.dst) {
            return matches!(rule.action, AclAction::Allow);
        }
    }
    matches!(policy.default_action, AclAction::Allow)
}

fn selector_matches(node: &NodeState, selector: &AclSelector) -> bool {
    let empty =
        selector.tags.is_empty() && selector.node_ids.is_empty() && selector.names.is_empty();
    if selector.any || empty {
        return true;
    }
    if selector.node_ids.iter().any(|id| id == &node.id) {
        return true;
    }
    if selector.names.iter().any(|name| name == &node.name) {
        return true;
    }
    selector
        .tags
        .iter()
        .any(|tag| node.tags.iter().any(|node_tag| node_tag == tag))
}

fn normalize_node_name(name: &str) -> Result<String, ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("node name must be non-empty"));
    }
    Ok(trimmed.to_string())
}

fn ensure_unique_node_name(
    state: &State,
    network_id: &str,
    name: &str,
    exclude_node_id: Option<&str>,
) -> Result<(), ApiError> {
    let conflict = state.nodes.values().any(|node| {
        if node.network_id != network_id {
            return false;
        }
        if node.revoked_at.is_some() {
            return false;
        }
        if exclude_node_id.is_some_and(|id| node.id == id) {
            return false;
        }
        node.name.eq_ignore_ascii_case(name)
    });
    if conflict {
        return Err(ApiError::Conflict("node name already exists"));
    }
    Ok(())
}

fn relay_or_none(relay: &RelayConfig) -> Option<RelayConfig> {
    if relay.stun_servers.is_empty()
        && relay.turn_servers.is_empty()
        && relay.stream_relay_servers.is_empty()
        && relay.udp_relay_servers.is_empty()
        && relay.dns_servers.is_empty()
    {
        None
    } else {
        Some(relay.clone())
    }
}

fn build_token(
    network_id: &str,
    ttl_seconds: u64,
    uses: u32,
    tags: Vec<String>,
    owner_user_id: Option<String>,
    owner_email: Option<String>,
    owner_is_admin: bool,
) -> Result<TokenState, ApiError> {
    if ttl_seconds == 0 || uses == 0 {
        return Err(ApiError::BadRequest("ttl_seconds and uses must be > 0"));
    }

    let owner_user_id = owner_user_id.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });
    let owner_email = owner_email.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });

    let token = random_secret();
    let expires_at = now_unix() + ttl_seconds as i64;

    Ok(TokenState {
        token,
        network_id: network_id.to_string(),
        expires_at,
        uses_left: uses,
        tags,
        owner_user_id,
        owner_email,
        owner_is_admin,
        revoked_at: None,
    })
}

fn random_secret() -> String {
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    URL_SAFE_NO_PAD.encode(random)
}

fn ipv4_nets_overlap(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

fn ipv6_nets_overlap(a: &Ipv6Net, b: &Ipv6Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

fn initial_ipv4_offset(net: &Ipv4Net) -> Option<u32> {
    let max = max_ipv4_offset(net)?;
    if max >= 10 {
        Some(10)
    } else if max >= 1 {
        Some(1)
    } else {
        None
    }
}

fn max_ipv4_offset(net: &Ipv4Net) -> Option<u32> {
    let prefix_len = net.prefix_len();
    if prefix_len >= 31 {
        return None;
    }
    let host_bits = (32 - prefix_len) as u32;
    let total = 1u64 << host_bits;
    let last_usable = total.saturating_sub(2);
    u32::try_from(last_usable).ok()
}

fn initial_ipv6_offset(net: &Ipv6Net) -> u128 {
    let max = max_ipv6_offset(net);
    if max >= 10 {
        10
    } else if max >= 1 {
        1
    } else {
        0
    }
}

fn max_ipv6_offset(net: &Ipv6Net) -> u128 {
    let host_bits = (128 - net.prefix_len()) as u32;
    if host_bits == 128 {
        u128::MAX
    } else if host_bits == 0 {
        0
    } else {
        (1u128 << host_bits) - 1
    }
}

fn allocate_node_ips(network: &mut NetworkState) -> Result<(String, String), ApiError> {
    let v4_net: Ipv4Net = network.overlay_v4.parse().map_err(|_| ApiError::Internal)?;
    let v6_net: Ipv6Net = network.overlay_v6.parse().map_err(|_| ApiError::Internal)?;

    let Some(max_ipv4) = max_ipv4_offset(&v4_net) else {
        return Err(ApiError::Conflict(
            "ipv4 subnet has no usable host addresses",
        ));
    };
    if network.next_ipv4 > max_ipv4 {
        return Err(ApiError::Conflict("ipv4 address space exhausted"));
    }

    let base_v4 = u32::from(v4_net.network());
    let ip4 = Ipv4Addr::from(base_v4 + network.next_ipv4);
    network.next_ipv4 += 1;

    let max_ipv6 = max_ipv6_offset(&v6_net);
    if network.next_ipv6 > max_ipv6 {
        return Err(ApiError::Conflict("ipv6 address space exhausted"));
    }
    let base_v6 = u128::from(v6_net.network());
    let ip6 = Ipv6Addr::from(base_v6 + network.next_ipv6);
    network.next_ipv6 += 1;

    Ok((ip4.to_string(), ip6.to_string()))
}

fn merge_endpoints(provided: Vec<String>, observed: Option<String>) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = HashSet::new();
    if let Some(endpoint) = observed {
        if seen.insert(endpoint.clone()) {
            merged.push(endpoint);
        }
    }
    for endpoint in provided {
        if seen.insert(endpoint.clone()) {
            merged.push(endpoint);
        }
    }
    merged
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn short_id(id: &Uuid) -> String {
    let text = id.to_string();
    text.split('-').next().unwrap_or(&text).to_string()
}

fn build_audit_entry(
    action: &str,
    network_id: Option<String>,
    node_id: Option<String>,
    detail: Option<serde_json::Value>,
) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4().to_string(),
        timestamp: now_unix(),
        network_id,
        node_id,
        action: action.to_string(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_node(name: &str, tags: Vec<String>, created_at: i64) -> NodeState {
        let machine_key = format!("machine-{}", name);
        let wg_key = format!("wg-{}", name);
        NodeState {
            id: format!("node-{}", name),
            network_id: "net-1".to_string(),
            name: name.to_string(),
            machine_public_key: machine_key.clone(),
            wg_public_key: wg_key.clone(),
            ipv4: "100.64.0.1".to_string(),
            ipv6: "fd00::1".to_string(),
            endpoints: Vec::new(),
            tags,
            owner_user_id: Some(format!("user-{}", name)),
            owner_email: Some(format!("{}@example.test", name)),
            owner_is_admin: false,
            routes: Vec::new(),
            created_at,
            last_seen: created_at,
            probe_requested_at: None,
            approved: true,
            approved_at: Some(created_at),
            auth_secret: None,
            auth_expires_at: None,
            node_token: Some(format!("token-{}", name)),
            revoked_at: None,
            key_history: vec![
                KeyRecord {
                    key_type: KeyType::Machine,
                    public_key: machine_key,
                    created_at,
                    revoked_at: None,
                },
                KeyRecord {
                    key_type: KeyType::WireGuard,
                    public_key: wg_key,
                    created_at,
                    revoked_at: None,
                },
            ],
        }
    }

    #[test]
    fn acl_default_allows() {
        let policy = AclPolicy::default();
        let src = sample_node("src", vec!["dev".to_string()], 0);
        let dst = sample_node("dst", vec!["prod".to_string()], 0);
        assert!(acl_allows(&policy, &src, &dst));
    }

    #[test]
    fn acl_rule_denies_tag_pair() {
        let policy = AclPolicy {
            default_action: AclAction::Allow,
            rules: vec![crate::model::AclRule {
                action: AclAction::Deny,
                src: AclSelector {
                    tags: vec!["dev".to_string()],
                    ..Default::default()
                },
                dst: AclSelector {
                    tags: vec!["prod".to_string()],
                    ..Default::default()
                },
            }],
        };
        let src = sample_node("src", vec!["dev".to_string()], 0);
        let dst = sample_node("dst", vec!["prod".to_string()], 0);
        assert!(!acl_allows(&policy, &src, &dst));
    }

    #[test]
    fn key_rotation_required_blocks_peer() {
        let now = 100;
        let node = sample_node("old", vec![], now - 100);
        let policy = KeyRotationPolicy {
            max_age_seconds: Some(30),
        };
        let (approved, required) = effective_node_status(&node, &policy, now);
        assert!(!approved);
        assert!(required);
    }

    fn sample_network(overlay_v4: &str, overlay_v6: &str) -> NetworkState {
        let v4_net: Ipv4Net = overlay_v4.parse().expect("valid v4 cidr");
        let v6_net: Ipv6Net = overlay_v6.parse().expect("valid v6 cidr");
        NetworkState {
            id: "net-1".to_string(),
            name: "net".to_string(),
            overlay_v4: overlay_v4.to_string(),
            overlay_v6: overlay_v6.to_string(),
            dns_domain: "net.test".to_string(),
            requires_approval: false,
            acl: AclPolicy::default(),
            key_policy: KeyRotationPolicy {
                max_age_seconds: None,
            },
            created_at: 0,
            next_ipv4: initial_ipv4_offset(&v4_net).unwrap_or(0),
            next_ipv6: initial_ipv6_offset(&v6_net),
        }
    }

    #[test]
    fn initial_offsets_follow_subnet_size() {
        let v4_large: Ipv4Net = "100.64.0.0/24".parse().unwrap();
        let v4_small: Ipv4Net = "100.64.0.0/30".parse().unwrap();
        let v4_tiny: Ipv4Net = "100.64.0.0/31".parse().unwrap();
        let v6_large: Ipv6Net = "fd00::/48".parse().unwrap();
        let v6_small: Ipv6Net = "fd00::/128".parse().unwrap();

        assert_eq!(initial_ipv4_offset(&v4_large), Some(10));
        assert_eq!(initial_ipv4_offset(&v4_small), Some(1));
        assert_eq!(initial_ipv4_offset(&v4_tiny), None);
        assert_eq!(initial_ipv6_offset(&v6_large), 10);
        assert_eq!(initial_ipv6_offset(&v6_small), 0);
    }

    #[test]
    fn ipv4_allocator_respects_configured_cidr_bounds() {
        let mut network = sample_network("100.64.0.0/30", "fd00::/126");

        let (ip1, _) = allocate_node_ips(&mut network).unwrap();
        let (ip2, _) = allocate_node_ips(&mut network).unwrap();
        assert_eq!(ip1, "100.64.0.1");
        assert_eq!(ip2, "100.64.0.2");

        let exhausted = allocate_node_ips(&mut network);
        assert!(matches!(
            exhausted,
            Err(ApiError::Conflict("ipv4 address space exhausted"))
        ));
    }

    #[test]
    fn cidr_overlap_detection_works() {
        let a: Ipv4Net = "100.64.0.0/24".parse().unwrap();
        let b: Ipv4Net = "100.64.0.128/25".parse().unwrap();
        let c: Ipv4Net = "100.65.0.0/24".parse().unwrap();
        assert!(ipv4_nets_overlap(&a, &b));
        assert!(!ipv4_nets_overlap(&a, &c));
    }
}
