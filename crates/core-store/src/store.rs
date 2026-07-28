//! Turso 数据库句柄和全异步读写 API。

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use tracing::{debug, info};
use turso::{Builder, Database, Error as TursoError, Value, params};

use crate::{blobs::*, schema::*};

const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_WRITE_ATTEMPTS: usize = 12;

const CREATE_KV_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS kv_entries (
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (namespace, key)
) STRICT
"#;

const CREATE_UPDATED_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS kv_entries_namespace_updated
ON kv_entries(namespace, updated_at)
"#;

const UPSERT_SQL: &str = r#"
INSERT INTO kv_entries(namespace, key, value, updated_at)
VALUES (?1, ?2, ?3, ?4)
ON CONFLICT(namespace, key) DO UPDATE SET
    value = excluded.value,
    updated_at = excluded.updated_at
"#;

const DELETE_SQL: &str = "DELETE FROM kv_entries WHERE namespace = ?1 AND key = ?2";

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("turso: {0}")]
    Db(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(String),
    #[error("数据库路径不是有效 UTF-8: {0}")]
    InvalidPath(String),
}

impl From<TursoError> for StoreError {
    fn from(error: TursoError) -> Self {
        Self::Db(error.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serde(error.to_string())
    }
}

#[derive(Debug)]
pub struct Store {
    db: Database,
    path: PathBuf,
    multiprocess_wal: bool,
    busy_timeout: Duration,
    max_write_attempts: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiprocessWal {
    Auto,
    Enabled,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct StoreOptions {
    pub path: PathBuf,
    pub busy_timeout: Duration,
    pub max_write_attempts: usize,
    pub multiprocess_wal: MultiprocessWal,
    pub experimental_vacuum: bool,
}

impl StoreOptions {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            busy_timeout: DEFAULT_BUSY_TIMEOUT,
            max_write_attempts: DEFAULT_MAX_WRITE_ATTEMPTS,
            multiprocess_wal: MultiprocessWal::Auto,
            experimental_vacuum: true,
        }
    }
}

impl Store {
    /// 异步打开或创建数据库，并初始化严格类型 schema。
    ///
    /// 每次操作从可克隆的 Turso `Database` 创建独立连接，因此读取可在
    /// Tokio 多线程运行时并发执行。写入使用短事务、预编译语句和 busy 重试。
    pub async fn open(path: impl AsRef<Path>) -> Result<Arc<Self>, StoreError> {
        Self::open_with_options(StoreOptions::new(path.as_ref())).await
    }

    pub async fn open_with_options(options: StoreOptions) -> Result<Arc<Self>, StoreError> {
        let path = options.path;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let (db, multiprocess_wal) =
            open_database(&path, options.multiprocess_wal, options.experimental_vacuum).await?;
        let store = Arc::new(Self {
            db,
            path,
            multiprocess_wal,
            busy_timeout: options.busy_timeout,
            max_write_attempts: options.max_write_attempts.max(1),
        });
        store.bootstrap().await?;
        info!(
            target: "store",
            path = %store.path.display(),
            engine = "turso",
            async_io = true,
            multiprocess_wal = store.multiprocess_wal,
            busy_timeout_ms = store.busy_timeout.as_millis(),
            max_write_attempts = store.max_write_attempts,
            "store opened"
        );
        Ok(store)
    }

    async fn bootstrap(&self) -> Result<(), StoreError> {
        let conn = self.connection()?;
        conn.execute(CREATE_KV_TABLE, ()).await?;
        conn.execute(CREATE_UPDATED_INDEX, ()).await?;
        self.put_raw(KV_META, SCHEMA_KEY, SCHEMA_VERSION.to_string().into_bytes())
            .await
    }

    fn connection(&self) -> Result<turso::Connection, StoreError> {
        let conn = self.db.connect()?;
        conn.busy_timeout(self.busy_timeout)?;
        Ok(conn)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 直接读取同一 Turso 文件中的持久流量。
    ///
    /// 此入口不会建表或写入，供独立 CLI 进程在核心运行时读取。
    pub async fn read_traffic_totals(
        path: impl AsRef<Path>,
    ) -> Result<Vec<(String, TrafficTotalBlob)>, StoreError> {
        Self::read_traffic_totals_with_options(StoreOptions::new(path.as_ref())).await
    }

    pub async fn read_traffic_totals_with_options(
        options: StoreOptions,
    ) -> Result<Vec<(String, TrafficTotalBlob)>, StoreError> {
        let path = options.path;
        let (db, _) =
            open_database(&path, options.multiprocess_wal, options.experimental_vacuum).await?;
        let conn = db.connect()?;
        conn.busy_timeout(options.busy_timeout)?;
        match query_json::<TrafficTotalBlob>(&conn, TRAFFIC_TOTALS).await {
            Ok(rows) => Ok(rows),
            Err(StoreError::Db(error)) if is_missing_schema(&error) => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    /// 异步读取单个 JSON 值。
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        table: Table,
        key: &str,
    ) -> Result<Option<T>, StoreError> {
        let conn = self.connection()?;
        let mut rows = conn
            .query(
                "SELECT value FROM kv_entries WHERE namespace = ?1 AND key = ?2",
                params![table.name(), key],
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let raw = row_blob(&row, 0)?;
        Ok(Some(serde_json::from_slice(&raw)?))
    }

    /// 异步写入单个 JSON 值。
    pub async fn put_json<T: Serialize>(
        &self,
        table: Table,
        key: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        self.put_raw(table, key, serde_json::to_vec(value)?).await
    }

    async fn put_raw(&self, table: Table, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
        self.write_encoded(&[EncodedOp::Put {
            table,
            key: key.to_string(),
            value,
        }])
        .await
    }

    pub async fn delete(&self, table: Table, key: &str) -> Result<(), StoreError> {
        self.write_encoded(&[EncodedOp::Delete {
            table,
            key: key.to_string(),
        }])
        .await
    }

    /// 把多个更新合并到一个原子事务。
    pub async fn write_batch(&self, ops: &[BatchOp]) -> Result<(), StoreError> {
        if ops.is_empty() {
            return Ok(());
        }
        let encoded = encode_ops(ops)?;
        self.write_encoded(&encoded).await?;
        debug!(target: "store", ops = ops.len(), "async batch committed");
        Ok(())
    }

    async fn write_encoded(&self, ops: &[EncodedOp]) -> Result<(), StoreError> {
        if ops.is_empty() {
            return Ok(());
        }

        let mut last_error = None;
        for attempt in 0..self.max_write_attempts {
            let conn = self.connection()?;
            match execute_transaction(&conn, ops).await {
                Ok(()) => return Ok(()),
                Err(error) if is_retryable(&error) && attempt + 1 < self.max_write_attempts => {
                    last_error = Some(error);
                    let millis = 1_u64 << attempt.min(7);
                    tokio::time::sleep(Duration::from_millis(millis)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(StoreError::Db(
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "write retry budget exhausted".to_string()),
        ))
    }

    /// 异步列出命名空间中所有 JSON 行。
    pub async fn iter_json<T: DeserializeOwned>(
        &self,
        table: Table,
    ) -> Result<Vec<(String, T)>, StoreError> {
        let conn = self.connection()?;
        query_json(&conn, table).await
    }

    /// 异步列出命名空间中所有原始 UTF-8 字符串。
    pub async fn iter_string(&self, table: Table) -> Result<Vec<(String, String)>, StoreError> {
        let conn = self.connection()?;
        let mut rows = conn
            .query(
                "SELECT key, value FROM kv_entries WHERE namespace = ?1 ORDER BY key",
                [table.name()],
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            let key = row.get::<String>(0)?;
            let value = String::from_utf8_lossy(&row_blob(&row, 1)?).into_owned();
            out.push((key, value));
        }
        Ok(out)
    }

    pub async fn approximate_stats(&self) -> Result<StoreStats, StoreError> {
        let conn = self.connection()?;
        let mut rows = conn
            .query(
                "SELECT namespace, COUNT(*) FROM kv_entries GROUP BY namespace",
                (),
            )
            .await?;
        let mut stats = StoreStats {
            path: self.path.display().to_string(),
            size_bytes: database_size(&self.path),
            ..StoreStats::default()
        };
        while let Some(row) = rows.next().await? {
            let namespace = row.get::<String>(0)?;
            let count = usize::try_from(row.get::<i64>(1)?.max(0)).unwrap_or(usize::MAX);
            match namespace.as_str() {
                "smart_node_stats" => stats.smart_node_stats = count,
                "smart_domain_best" => stats.smart_domain_best = count,
                "smart_negative" => stats.smart_negative = count,
                "smart_pin" => stats.smart_pin = count,
                "group_manual" => stats.group_manual = count,
                "feed_meta" => stats.feed_meta = count,
                "dns_cache" => stats.dns_cache = count,
                "traffic_totals" => stats.traffic_totals = count,
                _ => {}
            }
        }
        Ok(stats)
    }

    /// 删除所有学习数据，保留 schema 和通用面板存储。
    pub async fn reset(&self) -> Result<(), StoreError> {
        let conn = self.connection()?;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = conn
            .execute(
                "DELETE FROM kv_entries WHERE namespace <> ?1",
                [KV_META.name()],
            )
            .await;
        match result {
            Ok(_) => {
                conn.execute("COMMIT", ()).await?;
                Ok(())
            }
            Err(error) => {
                let _ = conn.execute("ROLLBACK", ()).await;
                Err(error.into())
            }
        }
    }

    /// 把连接脏页写入 WAL，并请求一次被动 checkpoint。
    pub async fn checkpoint(&self) -> Result<(), StoreError> {
        let conn = self.connection()?;
        conn.cacheflush()?;
        let mut rows = conn.query("PRAGMA wal_checkpoint(PASSIVE)", ()).await?;
        while rows.next().await?.is_some() {}
        Ok(())
    }
}

async fn open_database(
    path: &Path,
    multiprocess_wal: MultiprocessWal,
    experimental_vacuum: bool,
) -> Result<(Database, bool), StoreError> {
    let path = path
        .to_str()
        .ok_or_else(|| StoreError::InvalidPath(path.display().to_string()))?;
    match multiprocess_wal {
        MultiprocessWal::Disabled => {
            let database = Builder::new_local(path)
                .experimental_vacuum(experimental_vacuum)
                .build()
                .await?;
            Ok((database, false))
        }
        MultiprocessWal::Enabled => {
            let database = Builder::new_local(path)
                .experimental_multiprocess_wal(true)
                .experimental_vacuum(experimental_vacuum)
                .build()
                .await?;
            Ok((database, true))
        }
        MultiprocessWal::Auto => {
            let multiprocess = Builder::new_local(path)
                .experimental_multiprocess_wal(true)
                .experimental_vacuum(experimental_vacuum)
                .build()
                .await;
            match multiprocess {
                Ok(database) => Ok((database, true)),
                Err(error) if multiprocess_wal_unsupported(&error) => {
                    debug!(
                        target: "store",
                        %error,
                        "multiprocess WAL unavailable on active Turso IO backend; using process-local WAL"
                    );
                    let database = Builder::new_local(path)
                        .experimental_vacuum(experimental_vacuum)
                        .build()
                        .await?;
                    Ok((database, false))
                }
                Err(error) => Err(error.into()),
            }
        }
    }
}

async fn execute_transaction(
    conn: &turso::Connection,
    ops: &[EncodedOp],
) -> Result<(), TursoError> {
    conn.execute("BEGIN IMMEDIATE", ()).await?;
    let result = async {
        let mut upsert = conn.prepare_cached(UPSERT_SQL).await?;
        let mut delete = conn.prepare_cached(DELETE_SQL).await?;
        let now = unix_now_i64();
        for op in ops {
            match op {
                EncodedOp::Put { table, key, value } => {
                    upsert
                        .execute(params![table.name(), key.as_str(), value.as_slice(), now])
                        .await?;
                }
                EncodedOp::Delete { table, key } => {
                    delete.execute(params![table.name(), key.as_str()]).await?;
                }
            }
        }
        conn.execute("COMMIT", ()).await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = conn.execute("ROLLBACK", ()).await;
    }
    result
}

async fn query_json<T: DeserializeOwned>(
    conn: &turso::Connection,
    table: Table,
) -> Result<Vec<(String, T)>, StoreError> {
    let mut rows = conn
        .query(
            "SELECT key, value FROM kv_entries WHERE namespace = ?1 ORDER BY key",
            [table.name()],
        )
        .await?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        let key = row.get::<String>(0)?;
        let value = serde_json::from_slice(&row_blob(&row, 1)?)?;
        out.push((key, value));
    }
    Ok(out)
}

fn row_blob(row: &turso::Row, index: usize) -> Result<Vec<u8>, StoreError> {
    match row.get_value(index)? {
        Value::Blob(value) => Ok(value),
        Value::Text(value) => Ok(value.into_bytes()),
        value => Err(StoreError::Db(format!(
            "expected blob or text at column {index}, got {value:?}"
        ))),
    }
}

fn encode_ops(ops: &[BatchOp]) -> Result<Vec<EncodedOp>, StoreError> {
    ops.iter()
        .map(|op| match op {
            BatchOp::PutNodeStats(key, value) => encoded_json(SMART_NODE_STATS, key, value),
            BatchOp::PutDomainBest(key, value) => encoded_json(SMART_DOMAIN_BEST, key, value),
            BatchOp::PutNegative(key, value) => encoded_json(SMART_NEGATIVE, key, value),
            BatchOp::PutPin(key, value) => Ok(EncodedOp::Put {
                table: SMART_PIN,
                key: key.clone(),
                value: value.as_bytes().to_vec(),
            }),
            BatchOp::PutGroupManual(key, value) => Ok(EncodedOp::Put {
                table: GROUP_MANUAL,
                key: key.clone(),
                value: value.as_bytes().to_vec(),
            }),
            BatchOp::PutFeedMeta(key, value) => encoded_json(FEED_META, key, value),
            BatchOp::PutDnsCache(key, value) => encoded_json(DNS_CACHE, key, value),
            BatchOp::PutTrafficTotal(key, value) => encoded_json(TRAFFIC_TOTALS, key, value),
            BatchOp::Delete(table, key) => Ok(EncodedOp::Delete {
                table: Table::new(table),
                key: key.clone(),
            }),
        })
        .collect()
}

fn encoded_json<T: Serialize>(table: Table, key: &str, value: &T) -> Result<EncodedOp, StoreError> {
    Ok(EncodedOp::Put {
        table,
        key: key.to_string(),
        value: serde_json::to_vec(value)?,
    })
}

fn is_retryable(error: &TursoError) -> bool {
    matches!(error, TursoError::Busy(_) | TursoError::BusySnapshot(_))
        || error.to_string().to_ascii_lowercase().contains("locked")
        || error.to_string().to_ascii_lowercase().contains("conflict")
}

fn multiprocess_wal_unsupported(error: &TursoError) -> bool {
    let error = error.to_string().to_ascii_lowercase();
    error.contains("multiprocess wal") && error.contains("not supported")
}

fn is_missing_schema(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("no such table") || error.contains("does not exist")
}

fn database_size(path: &Path) -> u64 {
    let mut total = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
    for suffix in ["-wal", "-shm", ".tshm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        total = total.saturating_add(
            std::fs::metadata(sidecar)
                .map(|meta| meta.len())
                .unwrap_or(0),
        );
    }
    total
}

fn unix_now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[derive(Debug)]
enum EncodedOp {
    Put {
        table: Table,
        key: String,
        value: Vec<u8>,
    },
    Delete {
        table: Table,
        key: String,
    },
}

#[derive(Debug, Default, Clone)]
pub struct StoreStats {
    pub path: String,
    pub size_bytes: u64,
    pub smart_node_stats: usize,
    pub smart_domain_best: usize,
    pub smart_negative: usize,
    pub smart_pin: usize,
    pub group_manual: usize,
    pub feed_meta: usize,
    pub dns_cache: usize,
    pub traffic_totals: usize,
}

#[derive(Debug, Clone)]
pub enum BatchOp {
    PutNodeStats(String, NodeStatsBlob),
    PutDomainBest(String, DomainBestBlob),
    PutNegative(String, NegativeBlob),
    PutPin(String, String),
    PutGroupManual(String, String),
    PutFeedMeta(String, FeedMetaBlob),
    PutDnsCache(String, DnsCacheBlob),
    PutTrafficTotal(String, TrafficTotalBlob),
    Delete(&'static str, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wuthercore-store-{label}-{}.db",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn open_put_get_persists() {
        let path = tmp_path("roundtrip");
        let store = Store::open(&path).await.unwrap();
        let blob = NodeStatsBlob {
            samples: 42,
            success_ewma: 0.9,
            p50_latency_ms: 80.0,
            ..Default::default()
        };
        store
            .put_json(SMART_NODE_STATS, "HK-1", &blob)
            .await
            .unwrap();
        store.checkpoint().await.unwrap();
        drop(store);

        let reopened = Store::open(&path).await.unwrap();
        let got = reopened
            .get_json::<NodeStatsBlob>(SMART_NODE_STATS, "HK-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.samples, 42);
        assert!((got.p50_latency_ms - 80.0).abs() < 1e-6);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_write_atomic() {
        let path = tmp_path("batch");
        let store = Store::open(&path).await.unwrap();
        let ops = vec![
            BatchOp::PutNodeStats(
                "A".into(),
                NodeStatsBlob {
                    samples: 1,
                    ..Default::default()
                },
            ),
            BatchOp::PutNodeStats(
                "B".into(),
                NodeStatsBlob {
                    samples: 2,
                    ..Default::default()
                },
            ),
            BatchOp::PutDomainBest(
                "main|youtube.com".into(),
                DomainBestBlob {
                    node: "A".into(),
                    set_at_secs: 100,
                },
            ),
            BatchOp::PutPin("main|netflix.com".into(), "B".into()),
            BatchOp::PutGroupManual("main".into(), "A".into()),
        ];
        store.write_batch(&ops).await.unwrap();
        let stats = store.approximate_stats().await.unwrap();
        assert_eq!(stats.smart_node_stats, 2);
        assert_eq!(stats.smart_domain_best, 1);
        assert_eq!(stats.smart_pin, 1);
        assert_eq!(stats.group_manual, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_connections_write_without_loss() {
        let path = tmp_path("concurrent");
        let store = Store::open(&path).await.unwrap();
        let mut tasks = Vec::new();
        for worker in 0..8 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                for item in 0..32 {
                    let key = format!("{worker}-{item}");
                    store
                        .put_json(
                            SMART_NODE_STATS,
                            &key,
                            &NodeStatsBlob {
                                samples: 1,
                                ..NodeStatsBlob::default()
                            },
                        )
                        .await
                        .unwrap();
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            store
                .iter_json::<NodeStatsBlob>(SMART_NODE_STATS)
                .await
                .unwrap()
                .len(),
            256
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn direct_reader_can_open_while_writer_is_alive() {
        let path = tmp_path("reader");
        let store = Store::open(&path).await.unwrap();
        let total = TrafficTotalBlob {
            dimension: "total".into(),
            label: "all".into(),
            upload: "184467440737095516160000000000000000000".into(),
            download: "7".into(),
            connections: 1,
            first_seen_secs: 1,
            last_seen_secs: 2,
        };
        store
            .write_batch(&[BatchOp::PutTrafficTotal("total\0all".into(), total)])
            .await
            .unwrap();

        let rows = Store::read_traffic_totals(&path).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.upload, "184467440737095516160000000000000000000");
    }

    #[tokio::test]
    async fn opening_turso_does_not_touch_legacy_redb_file() {
        let path = tmp_path("legacy-untouched");
        let legacy = path.with_extension("redb");
        let marker = b"legacy database remains untouched";
        std::fs::write(&legacy, marker).unwrap();

        let _store = Store::open(&path).await.unwrap();

        assert_eq!(std::fs::read(legacy).unwrap(), marker);
    }

    #[tokio::test]
    async fn reset_clears_learning_data() {
        let path = tmp_path("reset");
        let store = Store::open(&path).await.unwrap();
        store
            .write_batch(&[BatchOp::PutNodeStats("A".into(), NodeStatsBlob::default())])
            .await
            .unwrap();
        assert_eq!(store.approximate_stats().await.unwrap().smart_node_stats, 1);
        store.reset().await.unwrap();
        assert_eq!(store.approximate_stats().await.unwrap().smart_node_stats, 0);
    }
}
