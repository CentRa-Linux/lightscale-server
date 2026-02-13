use crate::model::{AuditEntry, NetworkState, NodeState, TokenState};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    #[serde(default)]
    pub revision: u64,
    pub networks: HashMap<String, NetworkState>,
    pub nodes: HashMap<String, NodeState>,
    pub tokens: HashMap<String, TokenState>,
    #[serde(default)]
    pub audit_log: Vec<AuditEntry>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            revision: 0,
            networks: HashMap::new(),
            nodes: HashMap::new(),
            tokens: HashMap::new(),
            audit_log: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct StateStore {
    backend: StoreBackend,
}

#[derive(Clone)]
enum StoreBackend {
    File(FileStore),
    Db(DbStore),
}

#[derive(Clone)]
struct FileStore {
    inner: Arc<RwLock<State>>,
    path: Option<PathBuf>,
}

#[derive(Clone)]
struct DbStore {
    pool: PgPool,
}

impl StateStore {
    pub async fn load(path: Option<PathBuf>) -> Result<Self> {
        let state = match &path {
            Some(path) => load_state(path).await.unwrap_or_default(),
            None => State::default(),
        };
        Ok(Self {
            backend: StoreBackend::File(FileStore {
                inner: Arc::new(RwLock::new(state)),
                path,
            }),
        })
    }

    pub async fn load_db(db_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(db_url)
            .await?;
        init_db(&pool).await?;
        Ok(Self {
            backend: StoreBackend::Db(DbStore { pool }),
        })
    }

    pub async fn read<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&State) -> Result<R>,
    {
        match &self.backend {
            StoreBackend::File(store) => {
                let guard = store.inner.read().await;
                f(&guard)
            }
            StoreBackend::Db(store) => {
                let state = load_state_db(&store.pool).await?;
                f(&state)
            }
        }
    }

    pub async fn write<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut State) -> Result<R>,
    {
        match &self.backend {
            StoreBackend::File(store) => {
                let mut guard = store.inner.write().await;
                let result = f(&mut guard)?;
                guard.revision = guard.revision.saturating_add(1);
                let snapshot = guard.clone();
                drop(guard);
                persist_file(store.path.as_deref(), snapshot).await?;
                Ok(result)
            }
            StoreBackend::Db(store) => write_state_db(&store.pool, f).await,
        }
    }
}

async fn load_state(path: &Path) -> Result<State> {
    match tokio::fs::read_to_string(path).await {
        Ok(contents) => Ok(serde_json::from_str(&contents)?),
        Err(_) => Ok(State::default()),
    }
}

async fn persist_file(path: Option<&Path>, state: State) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }

    let json = serde_json::to_string_pretty(&state)?;
    tokio::fs::write(path, json).await?;
    Ok(())
}

async fn init_db(pool: &PgPool) -> Result<()> {
    const INIT_LOCK_KEY: i64 = 0x4c53434c;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(INIT_LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS lightscale_state (id INT PRIMARY KEY, state JSONB NOT NULL)",
    )
    .execute(&mut *tx)
    .await?;

    let exists = sqlx::query("SELECT 1 FROM lightscale_state WHERE id = 1")
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        let state = State::default();
        sqlx::query("INSERT INTO lightscale_state (id, state) VALUES ($1, $2)")
            .bind(1i32)
            .bind(Json(&state))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn load_state_db(pool: &PgPool) -> Result<State> {
    let row = sqlx::query("SELECT state FROM lightscale_state WHERE id = 1")
        .fetch_one(pool)
        .await?;
    let Json(state): Json<State> = row.try_get("state")?;
    Ok(state)
}

async fn write_state_db<F, R>(pool: &PgPool, f: F) -> Result<R>
where
    F: FnOnce(&mut State) -> Result<R>,
{
    let mut tx = pool.begin().await?;
    let row = sqlx::query("SELECT state FROM lightscale_state WHERE id = 1 FOR UPDATE")
        .fetch_one(&mut *tx)
        .await?;
    let Json(mut state): Json<State> = row.try_get("state")?;
    let result = f(&mut state)?;
    state.revision = state.revision.saturating_add(1);
    sqlx::query("UPDATE lightscale_state SET state = $1 WHERE id = 1")
        .bind(Json(&state))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(result)
}
