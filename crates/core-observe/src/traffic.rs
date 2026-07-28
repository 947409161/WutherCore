//! 任意精度持久流量汇总。
//!
//! 转发热路径只更新原子低位。只有跨越 2^64 边界时才锁定并扩展高位，
//! 因此数据库累计值没有固定宽度上限，也不会让常规流量承担大整数锁开销。

use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use core_store::{Store, TrafficTotalBlob, schema::TRAFFIC_TOTALS, store::BatchOp};
use dashmap::DashMap;
use num_bigint::BigUint;
use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const KEY_SEPARATOR: char = '\u{1f}';

#[derive(Debug)]
struct UnlimitedCounter {
    low: AtomicU64,
    /// 高位表示完整的 2^64 进位数，本身是任意精度整数。
    high: Mutex<BigUint>,
}

impl UnlimitedCounter {
    fn zero() -> Self {
        Self {
            low: AtomicU64::new(0),
            high: Mutex::new(BigUint::default()),
        }
    }

    fn from_decimal(value: &str) -> Self {
        let value = BigUint::parse_bytes(value.as_bytes(), 10).unwrap_or_default();
        let digits = value.to_u64_digits();
        let low = digits.first().copied().unwrap_or(0);
        let high = value >> 64usize;
        Self {
            low: AtomicU64::new(low),
            high: Mutex::new(high),
        }
    }

    fn add(&self, amount: u64) {
        if amount == 0 {
            return;
        }
        loop {
            let old = self.low.load(Ordering::Relaxed);
            let (next, overflow) = old.overflowing_add(amount);
            if !overflow {
                if self
                    .low
                    .compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
                continue;
            }

            // 跨 2^64 时才进入慢路径。snapshot 同样读取此锁，确保低位回绕和
            // 高位进位作为一个一致状态对外可见。
            let mut high = self.high.lock();
            if self
                .low
                .compare_exchange(old, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                *high += 1u8;
                return;
            }
        }
    }

    fn decimal(&self) -> String {
        let high = self.high.lock();
        ((high.clone() << 64usize) + self.low.load(Ordering::Relaxed)).to_str_radix(10)
    }
}

#[derive(Debug)]
struct TrafficCounters {
    dimension: String,
    label: String,
    upload: UnlimitedCounter,
    download: UnlimitedCounter,
    connections: AtomicU64,
    first_seen_secs: AtomicU64,
    last_seen_secs: AtomicU64,
    dirty: AtomicBool,
}

impl TrafficCounters {
    fn new(dimension: String, label: String, now: u64) -> Self {
        Self {
            dimension,
            label,
            upload: UnlimitedCounter::zero(),
            download: UnlimitedCounter::zero(),
            connections: AtomicU64::new(0),
            first_seen_secs: AtomicU64::new(now),
            last_seen_secs: AtomicU64::new(now),
            dirty: AtomicBool::new(true),
        }
    }

    fn from_blob(blob: TrafficTotalBlob) -> Self {
        Self {
            dimension: blob.dimension,
            label: blob.label,
            upload: UnlimitedCounter::from_decimal(&blob.upload),
            download: UnlimitedCounter::from_decimal(&blob.download),
            connections: AtomicU64::new(blob.connections),
            first_seen_secs: AtomicU64::new(blob.first_seen_secs),
            last_seen_secs: AtomicU64::new(blob.last_seen_secs),
            dirty: AtomicBool::new(false),
        }
    }

    fn mark_connection(&self, now: u64) {
        // 连接数只是辅助指标。即使达到极端上限也保持最大值，不影响任意精度
        // 字节累计。
        let _ = self
            .connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(1))
            });
        self.last_seen_secs.store(now, Ordering::Relaxed);
        self.dirty.store(true, Ordering::Release);
    }

    fn record_upload(&self, size: u64, now: u64) {
        self.upload.add(size);
        self.last_seen_secs.store(now, Ordering::Relaxed);
        self.dirty.store(true, Ordering::Release);
    }

    fn record_download(&self, size: u64, now: u64) {
        self.download.add(size);
        self.last_seen_secs.store(now, Ordering::Relaxed);
        self.dirty.store(true, Ordering::Release);
    }

    fn blob(&self) -> TrafficTotalBlob {
        TrafficTotalBlob {
            dimension: self.dimension.clone(),
            label: self.label.clone(),
            upload: self.upload.decimal(),
            download: self.download.decimal(),
            connections: self.connections.load(Ordering::Relaxed),
            first_seen_secs: self.first_seen_secs.load(Ordering::Relaxed),
            last_seen_secs: self.last_seen_secs.load(Ordering::Relaxed),
        }
    }
}

/// 一条连接对应的分类计数器集合。数据路径不做字符串查找。
#[derive(Debug, Clone, Default)]
pub struct TrafficSession {
    counters: Arc<[Arc<TrafficCounters>]>,
}

impl TrafficSession {
    pub fn record_upload(&self, size: u64) {
        if size == 0 {
            return;
        }
        let now = now_secs();
        for counter in self.counters.iter() {
            counter.record_upload(size, now);
        }
    }

    pub fn record_download(&self, size: u64) {
        if size == 0 {
            return;
        }
        let now = now_secs();
        for counter in self.counters.iter() {
            counter.record_download(size, now);
        }
    }
}

#[derive(Debug)]
pub struct TrafficLedger {
    store: Arc<Store>,
    rows: DashMap<String, Arc<TrafficCounters>>,
    stop: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl TrafficLedger {
    pub async fn open(store: Arc<Store>) -> Arc<Self> {
        let rows = DashMap::new();
        match store.iter_json::<TrafficTotalBlob>(TRAFFIC_TOTALS).await {
            Ok(saved) => {
                for (key, blob) in saved {
                    rows.insert(key, Arc::new(TrafficCounters::from_blob(blob)));
                }
            }
            Err(error) => {
                warn!(target: "traffic", %error, "failed to load persistent traffic totals");
            }
        }

        let ledger = Arc::new(Self {
            store,
            rows,
            stop: CancellationToken::new(),
            task: Mutex::new(None),
        });
        ledger.start_flush_task();
        ledger
    }

    fn start_flush_task(self: &Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            debug!(target: "traffic", "no Tokio runtime; periodic traffic flush disabled");
            return;
        };
        let weak = Arc::downgrade(self);
        let stop = self.stop.clone();
        let task = handle.spawn(async move {
            let mut interval = tokio::time::interval(FLUSH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = interval.tick() => {
                        let Some(ledger) = weak.upgrade() else {
                            break;
                        };
                        ledger.flush().await;
                    }
                }
            }
            if let Some(ledger) = weak.upgrade() {
                ledger.flush().await;
            }
        });
        *self.task.lock() = Some(task);
    }

    /// 为一条连接建立分类。重复的分类标签只计一次。
    pub fn begin<I, D, L>(&self, labels: I) -> TrafficSession
    where
        I: IntoIterator<Item = (D, L)>,
        D: Into<String>,
        L: Into<String>,
    {
        let now = now_secs();
        let mut unique = BTreeSet::new();
        unique.insert(("total".to_string(), "all".to_string()));
        for (dimension, label) in labels {
            let dimension = dimension.into();
            let label = label.into();
            if !dimension.trim().is_empty() && !label.trim().is_empty() {
                unique.insert((dimension, label));
            }
        }

        let counters = unique
            .into_iter()
            .map(|(dimension, label)| {
                let key = traffic_key(&dimension, &label);
                let counter = self
                    .rows
                    .entry(key)
                    .or_insert_with(|| {
                        Arc::new(TrafficCounters::new(dimension.clone(), label.clone(), now))
                    })
                    .clone();
                counter.mark_connection(now);
                counter
            })
            .collect::<Vec<_>>();
        TrafficSession {
            counters: counters.into(),
        }
    }

    pub async fn flush(&self) {
        let mut ops = Vec::new();
        for row in self.rows.iter() {
            let counters = row.value();
            if counters.dirty.swap(false, Ordering::AcqRel) {
                ops.push(BatchOp::PutTrafficTotal(row.key().clone(), counters.blob()));
            }
        }
        if ops.is_empty() {
            return;
        }
        if let Err(error) = self.store.write_batch(&ops).await {
            warn!(
                target: "traffic",
                %error,
                rows = ops.len(),
                "failed to persist traffic totals"
            );
            for op in ops {
                if let BatchOp::PutTrafficTotal(key, _) = op
                    && let Some(row) = self.rows.get(&key)
                {
                    row.dirty.store(true, Ordering::Release);
                }
            }
        }
    }

    pub fn snapshot(&self) -> Vec<TrafficTotalBlob> {
        let mut rows = self
            .rows
            .iter()
            .map(|row| row.value().blob())
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            a.dimension
                .cmp(&b.dimension)
                .then_with(|| a.label.cmp(&b.label))
        });
        rows
    }

    pub async fn shutdown(&self) {
        self.stop.cancel();
        let task = self.task.lock().take();
        if let Some(task) = task {
            let _ = task.await;
        } else {
            self.flush().await;
        }
    }
}

fn traffic_key(dimension: &str, label: &str) -> String {
    format!("{dimension}{KEY_SEPARATOR}{label}")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_counter_crosses_u64_without_wrapping() {
        let counter = UnlimitedCounter::from_decimal("18446744073709551610");
        counter.add(10);
        assert_eq!(counter.decimal(), "18446744073709551620");
    }

    #[test]
    fn unlimited_counter_accepts_values_far_beyond_u128() {
        let original = "999999999999999999999999999999999999999999999999999999";
        let counter = UnlimitedCounter::from_decimal(original);
        counter.add(1);
        assert_eq!(
            counter.decimal(),
            "1000000000000000000000000000000000000000000000000000000"
        );
    }

    #[tokio::test]
    async fn ledger_persists_total_beyond_u64() {
        let path = std::env::temp_dir().join(format!(
            "wuthercore-traffic-{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = Store::open(&path).await.unwrap();
        let ledger = TrafficLedger::open(store.clone()).await;
        let session = ledger.begin([("network", "tcp"), ("outbound", "node-a")]);
        session.record_upload(u64::MAX);
        session.record_upload(2);
        session.record_download(7);
        ledger.shutdown().await;

        let rows = store
            .iter_json::<TrafficTotalBlob>(TRAFFIC_TOTALS)
            .await
            .unwrap();
        let total = rows
            .into_iter()
            .map(|(_, blob)| blob)
            .find(|blob| blob.dimension == "total" && blob.label == "all")
            .unwrap();
        assert_eq!(total.upload, "18446744073709551617");
        assert_eq!(total.download, "7");
        drop(ledger);
        drop(store);
        let _ = std::fs::remove_file(path);
    }
}
