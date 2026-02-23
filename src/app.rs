use crate::model::RelayConfig;
use crate::state::StateStore;

#[derive(Clone)]
pub struct MeshPeerMeta {
    pub id: String,
    pub addr: String,
}

#[derive(Clone)]
pub struct AppState {
    pub store: StateStore,
    pub relay: RelayConfig,
    pub admin_token: Option<String>,
    pub control_urls: Vec<String>,
    pub mesh_server_id: Option<String>,
    pub mesh_peers: Vec<MeshPeerMeta>,
}
