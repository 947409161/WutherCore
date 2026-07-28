//! 任意精度持久流量汇总。
//!
//! 转发热路径先在连接级原子中累计，达到批量阈值或周期刷新时才归并到分类。
//! 分类计数器只有跨越 2^64 边界时才锁定并扩展高位；数据库 writer 只消费
//! 无锁脏队列，不扫描全部历史行。

use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use core_store::{Store, TrafficTotalBlob, schema::TRAFFIC_TOTALS, store::BatchOp};
use crossbeam_queue::SegQueue;
use dashmap::DashMap;
use num_bigint::BigUint;
use parking_lot::Mutex;
use smallvec::SmallVec;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const SESSION_BATCH_BYTES: u64 = 1024 * 1024;
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
    queued: AtomicBool,
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
            queued: AtomicBool::new(false),
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
            queued: AtomicBool::new(false),
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
    }

    fn record_upload(&self, size: u64, now: u64) {
        self.upload.add(size);
        self.last_seen_secs.store(now, Ordering::Relaxed);
    }

    fn record_download(&self, size: u64, now: u64) {
        self.download.add(size);
        self.last_seen_secs.store(now, Ordering::Relaxed);
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

#[derive(Debug)]
struct TrafficSessionInner {
    counters: Arc<[Arc<TrafficCounters>]>,
    upload_pending: AtomicU64,
    download_pending: AtomicU64,
    queued: AtomicBool,
    dirty_sessions: Arc<SegQueue<Weak<TrafficSessionInner>>>,
    dirty_rows: Arc<SegQueue<Weak<TrafficCounters>>>,
}

impl TrafficSessionInner {
    fn record(self: &Arc<Self>, pending: &AtomicU64, size: u64) {
        if size == 0 {
            return;
        }
        if size >= SESSION_BATCH_BYTES {
            if std::ptr::eq(pending, &self.upload_pending) {
                self.apply(size, 0);
            } else {
                self.apply(0, size);
            }
            return;
        }

        let previous = pending.fetch_add(size, Ordering::Relaxed);
        self.enqueue();
        if previous >= SESSION_BATCH_BYTES - size {
            let drained = pending.swap(0, Ordering::AcqRel);
            if std::ptr::eq(pending, &self.upload_pending) {
                self.apply(drained, 0);
            } else {
                self.apply(0, drained);
            }
        }
    }

    fn enqueue(self: &Arc<Self>) {
        if !self.queued.load(Ordering::Relaxed)
            && self
                .queued
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.dirty_sessions.push(Arc::downgrade(self));
        }
    }

    fn flush_pending(&self) {
        let upload = self.upload_pending.swap(0, Ordering::AcqRel);
        let download = self.download_pending.swap(0, Ordering::AcqRel);
        self.apply(upload, download);
    }

    fn apply(&self, upload: u64, download: u64) {
        if upload == 0 && download == 0 {
            return;
        }
        let now = now_secs();
        for counter in self.counters.iter() {
            if upload != 0 {
                counter.record_upload(upload, now);
            }
            if download != 0 {
                counter.record_download(download, now);
            }
            enqueue_counter(&self.dirty_rows, counter);
        }
    }
}

/// 一条连接对应的分类计数器集合。
///
/// 热路径只更新连接级 pending 原子；达到 1 MiB、周期刷新或连接关闭时，
/// 才一次性归并到全部分类，避免每个 32 KiB 数据块都遍历十余个分类。
#[derive(Debug, Clone)]
pub struct TrafficSession {
    inner: Arc<TrafficSessionInner>,
}

impl Default for TrafficSession {
    fn default() -> Self {
        Self {
            inner: Arc::new(TrafficSessionInner {
                counters: Arc::from([]),
                upload_pending: AtomicU64::new(0),
                download_pending: AtomicU64::new(0),
                queued: AtomicBool::new(false),
                dirty_sessions: Arc::new(SegQueue::new()),
                dirty_rows: Arc::new(SegQueue::new()),
            }),
        }
    }
}

impl TrafficSession {
    pub fn record_upload(&self, size: u64) {
        self.inner.record(&self.inner.upload_pending, size);
    }

    pub fn record_download(&self, size: u64) {
        self.inner.record(&self.inner.download_pending, size);
    }
}

impl Drop for TrafficSession {
    fn drop(&mut self) {
        self.inner.flush_pending();
    }
}

#[derive(Debug)]
pub struct TrafficLedger {
    store: Arc<Store>,
    rows: DashMap<String, Arc<TrafficCounters>>,
    dirty_sessions: Arc<SegQueue<Weak<TrafficSessionInner>>>,
    dirty_rows: Arc<SegQueue<Weak<TrafficCounters>>>,
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
            dirty_sessions: Arc::new(SegQueue::new()),
            dirty_rows: Arc::new(SegQueue::new()),
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
        let mut unique = SmallVec::<[(String, String); 16]>::new();
        unique.push(("total".to_string(), "all".to_string()));
        for (dimension, label) in labels {
            let dimension = dimension.into();
            let label = label.into();
            if !dimension.trim().is_empty()
                && !label.trim().is_empty()
                && !unique
                    .iter()
                    .any(|item| item.0 == dimension && item.1 == label)
            {
                unique.push((dimension, label));
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
                enqueue_counter(&self.dirty_rows, &counter);
                counter
            })
            .collect::<Vec<_>>();
        TrafficSession {
            inner: Arc::new(TrafficSessionInner {
                counters: counters.into(),
                upload_pending: AtomicU64::new(0),
                download_pending: AtomicU64::new(0),
                queued: AtomicBool::new(false),
                dirty_sessions: Arc::clone(&self.dirty_sessions),
                dirty_rows: Arc::clone(&self.dirty_rows),
            }),
        }
    }

    pub async fn flush(&self) {
        self.drain_pending_sessions();

        let mut changed = Vec::with_capacity(self.dirty_rows.len().min(4096));
        let budget = self.dirty_rows.len();
        for _ in 0..budget {
            let Some(weak) = self.dirty_rows.pop() else {
                break;
            };
            if let Some(counters) = weak.upgrade() {
                // 先允许新的更新重新入队，再生成快照。并发更新要么被当前
                // blob 包含，要么留在下一批队列中，不会丢失。
                counters.queued.store(false, Ordering::Release);
                changed.push(counters);
            }
        }
        if changed.is_empty() {
            return;
        }
        let ops = changed
            .iter()
            .map(|counters| {
                BatchOp::PutTrafficTotal(
                    traffic_key(&counters.dimension, &counters.label),
                    counters.blob(),
                )
            })
            .collect::<Vec<_>>();
        if let Err(error) = self.store.write_batch(&ops).await {
            warn!(
                target: "traffic",
                %error,
                rows = ops.len(),
                "failed to persist traffic totals"
            );
            for counters in changed {
                enqueue_counter(&self.dirty_rows, &counters);
            }
        }
    }

    pub fn snapshot(&self) -> Vec<TrafficTotalBlob> {
        self.drain_pending_sessions();
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

    fn drain_pending_sessions(&self) {
        let budget = self.dirty_sessions.len();
        for _ in 0..budget {
            let Some(weak) = self.dirty_sessions.pop() else {
                break;
            };
            if let Some(session) = weak.upgrade() {
                // 与记录线程的顺序配合：记录先加 pending 再尝试入队。这里
                // 先清 queued 再 drain，竞态只会造成一次无害的重复入队。
                session.queued.store(false, Ordering::Release);
                session.flush_pending();
            }
        }
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

fn enqueue_counter(queue: &SegQueue<Weak<TrafficCounters>>, counters: &Arc<TrafficCounters>) {
    if !counters.queued.load(Ordering::Relaxed)
        && counters
            .queued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    {
        queue.push(Arc::downgrade(counters));
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

    #[tokio::test]
    async fn hot_path_batches_small_updates_and_snapshot_drains_them() {
        let path = std::env::temp_dir().join(format!(
            "wuthercore-traffic-batch-{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = Store::open(&path).await.unwrap();
        let ledger = TrafficLedger::open(store.clone()).await;
        let session = ledger.begin([
            ("network", "tcp"),
            ("outbound", "node-a"),
            ("destination", "example.com"),
        ]);

        for _ in 0..100_000 {
            session.record_upload(1);
        }
        assert_eq!(
            ledger.dirty_sessions.len(),
            1,
            "a session must enter the dirty queue once, not once per packet"
        );

        let rows = ledger.snapshot();
        let total = rows
            .iter()
            .find(|blob| blob.dimension == "total" && blob.label == "all")
            .unwrap();
        assert_eq!(total.upload, "100000");
        assert_eq!(ledger.dirty_sessions.len(), 0);
        assert!(
            ledger.dirty_rows.len() <= 4,
            "each changed classification should be queued at most once"
        );

        drop(session);
        ledger.shutdown().await;
        drop(ledger);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_session_batches_do_not_lose_bytes() {
        let path = std::env::temp_dir().join(format!(
            "wuthercore-traffic-concurrent-{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = Store::open(&path).await.unwrap();
        let ledger = TrafficLedger::open(store.clone()).await;
        let session = ledger.begin([("network", "tcp")]);
        let workers = (0..8)
            .map(|_| {
                let session = session.clone();
                tokio::task::spawn_blocking(move || {
                    for _ in 0..50_000 {
                        session.record_download(3);
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.await.unwrap();
        }

        let total = ledger
            .snapshot()
            .into_iter()
            .find(|blob| blob.dimension == "total" && blob.label == "all")
            .unwrap();
        assert_eq!(total.download, (8_u64 * 50_000 * 3).to_string());

        drop(session);
        ledger.shutdown().await;
        drop(ledger);
        drop(store);
        let _ = std::fs::remove_file(path);
    }
}
