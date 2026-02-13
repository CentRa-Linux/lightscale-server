use crate::model::RelayConfig;
use crate::state::StateStore;

#[derive(Clone)]
pub struct AppState {
    pub store: StateStore,
    pub relay: RelayConfig,
    pub admin_token: Option<String>,
}
