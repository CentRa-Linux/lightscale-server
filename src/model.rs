use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkState {
    pub id: String,
    pub name: String,
    pub overlay_v4: String,
    pub overlay_v6: String,
    pub dns_domain: String,
    #[serde(default)]
    pub requires_approval: bool,
    #[serde(default)]
    pub acl: AclPolicy,
    #[serde(default)]
    pub key_policy: KeyRotationPolicy,
    pub created_at: i64,
    pub next_ipv4: u32,
    pub next_ipv6: u128,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub machine_public_key: String,
    pub wg_public_key: String,
    pub ipv4: String,
    pub ipv6: String,
    pub endpoints: Vec<String>,
    pub tags: Vec<String>,
    pub routes: Vec<Route>,
    #[serde(default)]
    pub created_at: i64,
    pub last_seen: i64,
    #[serde(default)]
    pub probe_requested_at: Option<i64>,
    #[serde(default = "default_true")]
    pub approved: bool,
    #[serde(default)]
    pub approved_at: Option<i64>,
    #[serde(default)]
    pub auth_secret: Option<String>,
    #[serde(default)]
    pub auth_expires_at: Option<i64>,
    #[serde(default)]
    pub node_token: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<i64>,
    #[serde(default)]
    pub key_history: Vec<KeyRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenState {
    pub token: String,
    pub network_id: String,
    pub expires_at: i64,
    pub uses_left: u32,
    pub tags: Vec<String>,
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Route {
    pub prefix: String,
    pub kind: RouteKind,
    pub enabled: bool,
    #[serde(default)]
    pub mapped_prefix: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    Subnet,
    Exit,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub id: String,
    pub name: String,
    pub overlay_v4: String,
    pub overlay_v6: String,
    pub dns_domain: String,
    pub requires_approval: bool,
    #[serde(default)]
    pub key_rotation_max_age_seconds: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub name: String,
    pub dns_name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub wg_public_key: String,
    pub machine_public_key: String,
    pub endpoints: Vec<String>,
    pub tags: Vec<String>,
    pub routes: Vec<Route>,
    pub last_seen: i64,
    pub approved: bool,
    #[serde(default)]
    pub key_rotation_required: bool,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub dns_name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub wg_public_key: String,
    pub endpoints: Vec<String>,
    pub tags: Vec<String>,
    pub routes: Vec<Route>,
    pub last_seen: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NetMap {
    pub network: NetworkInfo,
    pub node: NodeInfo,
    pub peers: Vec<PeerInfo>,
    pub relay: Option<RelayConfig>,
    #[serde(default)]
    pub probe_requests: Vec<ProbeRequest>,
    pub generated_at: i64,
    #[serde(default)]
    pub revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub peer_id: String,
    pub endpoints: Vec<String>,
    pub ipv4: String,
    pub ipv6: String,
    pub requested_at: i64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AclPolicy {
    #[serde(default)]
    pub default_action: AclAction,
    #[serde(default)]
    pub rules: Vec<AclRule>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    Allow,
    Deny,
}

impl Default for AclAction {
    fn default() -> Self {
        Self::Allow
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AclSelector {
    #[serde(default)]
    pub any: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub node_ids: Vec<String>,
    #[serde(default)]
    pub names: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub action: AclAction,
    #[serde(default)]
    pub src: AclSelector,
    #[serde(default)]
    pub dst: AclSelector,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct KeyRotationPolicy {
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    Machine,
    WireGuard,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub key_type: KeyType,
    pub public_key: String,
    pub created_at: i64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct RelayConfig {
    pub stun_servers: Vec<String>,
    pub turn_servers: Vec<String>,
    pub stream_relay_servers: Vec<String>,
    #[serde(default)]
    pub udp_relay_servers: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub token: String,
    pub expires_at: i64,
    pub uses_left: u32,
    pub tags: Vec<String>,
    pub revoked_at: Option<i64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateNetworkRequest {
    pub name: String,
    pub dns_domain: Option<String>,
    pub requires_approval: Option<bool>,
    pub key_rotation_max_age_seconds: Option<u64>,
    pub bootstrap_token_ttl_seconds: Option<u64>,
    pub bootstrap_token_uses: Option<u32>,
    pub bootstrap_token_tags: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateNetworkResponse {
    pub network: NetworkInfo,
    pub bootstrap_token: Option<EnrollmentToken>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub ttl_seconds: u64,
    pub uses: u32,
    pub tags: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateTokenResponse {
    pub token: EnrollmentToken,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AdminNodesResponse {
    pub nodes: Vec<NodeInfo>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateAclRequest {
    pub policy: AclPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateAclResponse {
    pub policy: AclPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateNodeRequest {
    pub name: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateNodeResponse {
    pub node: NodeInfo,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPolicyResponse {
    pub policy: KeyRotationPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    pub machine_public_key: Option<String>,
    pub wg_public_key: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRotationResponse {
    pub node_id: String,
    pub machine_public_key: String,
    pub wg_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyHistoryResponse {
    pub node_id: String,
    pub keys: Vec<KeyRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: i64,
    pub network_id: Option<String>,
    pub node_id: Option<String>,
    pub action: String,
    #[serde(default)]
    pub detail: Option<serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub token: String,
    pub node_name: String,
    pub machine_public_key: String,
    pub wg_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub node_token: String,
    pub netmap: NetMap,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterUrlRequest {
    pub network_id: String,
    pub node_name: String,
    pub machine_public_key: String,
    pub wg_public_key: String,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterUrlResponse {
    pub node_id: String,
    pub network_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub auth_path: String,
    pub expires_at: i64,
    pub node_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub endpoints: Vec<String>,
    pub listen_port: Option<u16>,
    pub routes: Vec<Route>,
    #[serde(default)]
    pub probe: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub netmap: NetMap,
}

impl From<&NetworkState> for NetworkInfo {
    fn from(state: &NetworkState) -> Self {
        Self {
            id: state.id.clone(),
            name: state.name.clone(),
            overlay_v4: state.overlay_v4.clone(),
            overlay_v6: state.overlay_v6.clone(),
            dns_domain: state.dns_domain.clone(),
            requires_approval: state.requires_approval,
            key_rotation_max_age_seconds: state.key_policy.max_age_seconds,
        }
    }
}

impl NodeInfo {
    pub fn from_state(node: &NodeState, dns_domain: &str, approved: bool, key_rotation_required: bool) -> Self {
        Self {
            id: node.id.clone(),
            name: node.name.clone(),
            dns_name: format!("{}.{}", node.name, dns_domain),
            ipv4: node.ipv4.clone(),
            ipv6: node.ipv6.clone(),
            wg_public_key: node.wg_public_key.clone(),
            machine_public_key: node.machine_public_key.clone(),
            endpoints: node.endpoints.clone(),
            tags: node.tags.clone(),
            routes: node.routes.clone(),
            last_seen: node.last_seen,
            approved,
            key_rotation_required,
            revoked: node.revoked_at.is_some(),
        }
    }
}

impl From<(&NodeState, &str)> for PeerInfo {
    fn from((node, dns_domain): (&NodeState, &str)) -> Self {
        Self {
            id: node.id.clone(),
            name: node.name.clone(),
            dns_name: format!("{}.{}", node.name, dns_domain),
            ipv4: node.ipv4.clone(),
            ipv6: node.ipv6.clone(),
            wg_public_key: node.wg_public_key.clone(),
            endpoints: node.endpoints.clone(),
            tags: node.tags.clone(),
            routes: node.routes.clone(),
            last_seen: node.last_seen,
        }
    }
}

impl From<TokenState> for EnrollmentToken {
    fn from(token: TokenState) -> Self {
        Self {
            token: token.token,
            expires_at: token.expires_at,
            uses_left: token.uses_left,
            tags: token.tags,
            revoked_at: token.revoked_at,
        }
    }
}

impl From<&TokenState> for EnrollmentToken {
    fn from(token: &TokenState) -> Self {
        Self {
            token: token.token.clone(),
            expires_at: token.expires_at,
            uses_left: token.uses_left,
            tags: token.tags.clone(),
            revoked_at: token.revoked_at,
        }
    }
}

fn default_true() -> bool {
    true
}
