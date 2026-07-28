use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use core_observe::ConnectionObserver;
use core_store::{HistoryEntry, NodeStatsBlob};
use parking_lot::RwLock;

const HISTORY_CAP: usize = 20;
const LATENCY_WINDOW: usize = 32;
const BASELINE_BOOTSTRAP: u32 = 3;
const BASELINE_ALPHA: f64 = 0.20;
const BASELINE_MAX_STEP: f64 = 1.25;
const SPIKE_FACTOR: f64 = 3.0;
const DEGRADE_FACTOR: f64 = 1.50;
const RECOVER_FACTOR: f64 = 1.20;
const RECOVER_SUCCESSES: u8 = 2;
const SPEED_WINDOW: Duration = Duration::from_secs(1);
const SPEED_CURRENT_TTL: Duration = Duration::from_secs(30);
const SPEED_PEAK_HALF_LIFE_SECS: f64 = 10.0 * 60.0;
const SPEED_CLOCK_GATE_BYTES: u64 = 256 * 1024;

/// 单节点运行时统计。
///
/// 探活和拨号结果走低频 `RwLock` 更新；连接数与数据面字节走原子字段，复制
/// 热路径不会获取锁。吞吐窗口最多每秒由一个竞争成功的线程汇总一次。
#[derive(Debug)]
pub struct NodeStats {
    inner: RwLock<Inner>,
    sample_count: AtomicU32,
    active_conn: AtomicU32,
    traffic_bytes: AtomicU64,
    /// 避免每个数据块都读取系统时钟。累计到阈值才尝试汇总一次；连接关闭和
    /// snapshot 会无条件刷新，因此低吞吐连接也不会丢数据。
    traffic_clock_gate: AtomicU64,
    traffic_window_started_ms: AtomicU64,
    throughput_hint_bits: AtomicU64,
    last_persist_ms: AtomicU64,
}

#[derive(Debug, Clone)]
struct Inner {
    samples: u32,
    success_ewma: f64,
    p50_latency_ms: f64,
    p90_latency_ms: f64,
    jitter_ms: f64,
    timeout_rate: f64,
    baseline_latency_ms: f64,
    baseline_samples: u32,
    high_latency_streak: u8,
    degraded: bool,
    recover_streak: u8,
    last_failure: Option<Instant>,
    last_error: Option<String>,
    last_used: Option<Instant>,
    latency_samples: VecDeque<u32>,
    history: VecDeque<HistoryEntry>,
    throughput_ewma_bps: f64,
    throughput_peak_bps: f64,
    throughput_updated: Option<Instant>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            samples: 0,
            success_ewma: 0.5,
            p50_latency_ms: 200.0,
            p90_latency_ms: 200.0,
            jitter_ms: 0.0,
            timeout_rate: 0.0,
            baseline_latency_ms: 0.0,
            baseline_samples: 0,
            high_latency_streak: 0,
            degraded: false,
            recover_streak: 0,
            last_failure: None,
            last_error: None,
            last_used: None,
            latency_samples: VecDeque::with_capacity(LATENCY_WINDOW),
            history: VecDeque::with_capacity(HISTORY_CAP),
            throughput_ewma_bps: 0.0,
            throughput_peak_bps: 0.0,
            throughput_updated: None,
        }
    }
}

impl Default for NodeStats {
    fn default() -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            sample_count: AtomicU32::new(0),
            active_conn: AtomicU32::new(0),
            traffic_bytes: AtomicU64::new(0),
            traffic_clock_gate: AtomicU64::new(0),
            traffic_window_started_ms: AtomicU64::new(0),
            throughput_hint_bits: AtomicU64::new(0.0f64.to_bits()),
            last_persist_ms: AtomicU64::new(0),
        }
    }
}

impl NodeStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_success(&self, latency: Duration) {
        self.record_success_inner(latency, false);
    }

    pub fn record_probe(&self, latency: Duration) {
        self.record_success_inner(latency, true);
    }

    fn record_success_inner(&self, latency: Duration, add_history: bool) {
        let latency_ms = latency.as_millis().min(u32::MAX as u128) as u32;
        let mut inner = self.inner.write();
        inner.samples = inner.samples.saturating_add(1);
        inner.success_ewma = ewma(inner.success_ewma, 1.0, 0.2);
        inner.timeout_rate = ewma(inner.timeout_rate, 0.0, 0.2);
        inner.last_used = Some(Instant::now());

        let previous_p50 = inner.p50_latency_ms;
        inner.latency_samples.push_back(latency_ms);
        while inner.latency_samples.len() > LATENCY_WINDOW {
            inner.latency_samples.pop_front();
        }
        let (p50, p90) = latency_quantiles(&inner.latency_samples);
        inner.p50_latency_ms = p50;
        inner.p90_latency_ms = p90;
        inner.jitter_ms = ewma(
            inner.jitter_ms,
            (latency_ms as f64 - previous_p50).abs(),
            0.20,
        );

        update_baseline(&mut inner, latency_ms as f64);
        update_recovery(&mut inner, latency_ms as f64);
        if !inner.degraded {
            inner.last_error = None;
        }

        if add_history {
            push_history(&mut inner.history, latency_ms);
        }
        self.sample_count.store(inner.samples, Ordering::Release);
    }

    pub fn record_failure(&self, reason: impl Into<String>) {
        self.record_failure_inner(reason.into(), false);
    }

    pub fn record_probe_failure(&self, reason: impl Into<String>) {
        self.record_failure_inner(reason.into(), true);
    }

    fn record_failure_inner(&self, reason: String, add_history: bool) {
        let mut inner = self.inner.write();
        inner.samples = inner.samples.saturating_add(1);
        inner.success_ewma = ewma(inner.success_ewma, 0.0, 0.2);
        inner.timeout_rate = ewma(inner.timeout_rate, 1.0, 0.2);
        inner.last_failure = Some(Instant::now());
        inner.last_error = Some(reason);
        inner.degraded = true;
        inner.recover_streak = 0;
        if add_history {
            push_history(&mut inner.history, 0);
        }
        self.sample_count.store(inner.samples, Ordering::Release);
    }

    pub fn history(&self) -> Vec<HistoryEntry> {
        self.inner.read().history.iter().cloned().collect()
    }

    pub fn should_persist(&self, interval: Duration) -> bool {
        let now = unix_now_ms();
        let previous = self.last_persist_ms.load(Ordering::Relaxed);
        if previous != 0
            && now.saturating_sub(previous) < interval.as_millis().min(u64::MAX as u128) as u64
        {
            return false;
        }
        self.last_persist_ms
            .compare_exchange(previous, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    pub fn open_connection(&self) {
        self.active_conn.fetch_add(1, Ordering::Relaxed);
    }

    pub fn close_connection(&self) {
        let _ = self
            .active_conn
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(1))
            });
    }

    /// 数据面热路径。绝大多数调用只执行两个 relaxed `fetch_add`，不读系统
    /// 时钟、不取锁。
    pub fn record_transfer(&self, bytes: u64) {
        if bytes > 0 {
            let previous_bytes = self.traffic_bytes.fetch_add(bytes, Ordering::Relaxed);
            let previous = self.traffic_clock_gate.fetch_add(bytes, Ordering::Relaxed);
            if previous_bytes == 0 && self.traffic_window_started_ms.load(Ordering::Relaxed) == 0 {
                self.flush_speed_window(unix_now_ms());
                return;
            }
            if previous.saturating_add(bytes) < SPEED_CLOCK_GATE_BYTES {
                return;
            }
            if self.traffic_clock_gate.swap(0, Ordering::AcqRel) < SPEED_CLOCK_GATE_BYTES {
                return;
            }
        }
        self.flush_speed_window(unix_now_ms());
    }

    fn flush_speed_window(&self, now_ms: u64) {
        let started = self.traffic_window_started_ms.load(Ordering::Relaxed);
        if started == 0 {
            let _ = self.traffic_window_started_ms.compare_exchange(
                0,
                now_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            return;
        }
        let elapsed_ms = now_ms.saturating_sub(started);
        if elapsed_ms < SPEED_WINDOW.as_millis() as u64 {
            return;
        }
        if self
            .traffic_window_started_ms
            .compare_exchange(started, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let bytes = self.traffic_bytes.swap(0, Ordering::AcqRel);
        if bytes == 0 || elapsed_ms == 0 {
            return;
        }
        let speed = bytes as f64 * 1000.0 / elapsed_ms as f64;
        let mut inner = self.inner.write();
        inner.throughput_ewma_bps = if inner.throughput_ewma_bps <= 0.0 {
            speed
        } else {
            ewma(inner.throughput_ewma_bps, speed, 0.35)
        };
        inner.throughput_peak_bps = inner.throughput_peak_bps.max(speed);
        inner.throughput_updated = Some(Instant::now());
        self.throughput_hint_bits.store(
            inner
                .throughput_ewma_bps
                .max(inner.throughput_peak_bps)
                .to_bits(),
            Ordering::Release,
        );
    }

    pub fn snapshot(&self) -> NodeStatSnapshot {
        self.snapshot_at(unix_now_ms())
    }

    /// Smart 一轮评分共享同一个墙钟值，避免海量候选逐节点读取系统时钟。
    pub fn snapshot_at(&self, now_ms: u64) -> NodeStatSnapshot {
        self.snapshot_for_scoring(now_ms, true)
    }

    /// `include_error=false` 用于数据面热路径，避免逐候选克隆错误字符串。
    pub fn snapshot_for_scoring(&self, now_ms: u64, include_error: bool) -> NodeStatSnapshot {
        self.flush_speed_window(now_ms);
        let inner = self.inner.read();
        let speed_age = inner
            .throughput_updated
            .map(|updated| updated.elapsed())
            .unwrap_or(Duration::MAX);
        let current_speed = if speed_age <= SPEED_CURRENT_TTL {
            inner.throughput_ewma_bps
        } else {
            0.0
        };
        let decayed_peak = if speed_age == Duration::MAX {
            0.0
        } else {
            inner.throughput_peak_bps
                * 0.5f64.powf(speed_age.as_secs_f64() / SPEED_PEAK_HALF_LIFE_SECS)
        };
        NodeStatSnapshot {
            samples: inner.samples,
            success_rate: inner.success_ewma,
            p50_latency_ms: inner.p50_latency_ms,
            p90_latency_ms: inner.p90_latency_ms,
            jitter_ms: inner.jitter_ms,
            timeout_rate: inner.timeout_rate,
            baseline_latency_ms: inner.baseline_latency_ms,
            degraded: inner.degraded,
            active_conn: self.active_conn.load(Ordering::Relaxed),
            throughput_bps: current_speed.max(decayed_peak),
            cooldown: inner
                .last_failure
                .map(|time| time.elapsed())
                .unwrap_or(Duration::MAX),
            last_error: include_error.then(|| inner.last_error.clone()).flatten(),
        }
    }

    pub fn sample_count(&self) -> u32 {
        self.sample_count.load(Ordering::Acquire)
    }

    pub fn throughput_hint_bps(&self) -> f64 {
        f64::from_bits(self.throughput_hint_bits.load(Ordering::Acquire))
    }

    pub fn to_blob(&self) -> NodeStatsBlob {
        self.flush_speed_window(unix_now_ms());
        let inner = self.inner.read();
        NodeStatsBlob {
            samples: inner.samples,
            success_ewma: inner.success_ewma,
            p50_latency_ms: inner.p50_latency_ms,
            p90_latency_ms: inner.p90_latency_ms,
            jitter_ms: inner.jitter_ms,
            timeout_rate: inner.timeout_rate,
            baseline_latency_ms: inner.baseline_latency_ms,
            degraded: inner.degraded,
            throughput_ewma_bps: inner.throughput_ewma_bps,
            throughput_peak_bps: inner.throughput_peak_bps,
            throughput_updated_secs: instant_to_unix(inner.throughput_updated),
            last_failure_secs: instant_to_unix(inner.last_failure),
            last_error: inner.last_error.clone(),
            last_used_secs: instant_to_unix(inner.last_used),
            history: inner.history.iter().cloned().collect(),
        }
    }

    pub fn from_blob(blob: &NodeStatsBlob) -> Self {
        let mut latency_samples = VecDeque::with_capacity(LATENCY_WINDOW);
        let recent: Vec<u32> = blob
            .history
            .iter()
            .rev()
            .filter(|entry| entry.delay_ms > 0)
            .take(LATENCY_WINDOW)
            .map(|entry| entry.delay_ms)
            .collect();
        for delay in recent.into_iter().rev() {
            latency_samples.push_back(delay);
        }
        let p50 = if blob.p50_latency_ms > 0.0 {
            blob.p50_latency_ms
        } else {
            200.0
        };
        let p90 = if blob.p90_latency_ms > 0.0 {
            blob.p90_latency_ms
        } else {
            p50
        };
        Self {
            inner: RwLock::new(Inner {
                samples: blob.samples,
                success_ewma: blob.success_ewma,
                p50_latency_ms: p50,
                p90_latency_ms: p90,
                jitter_ms: blob.jitter_ms,
                timeout_rate: blob.timeout_rate,
                baseline_latency_ms: blob.baseline_latency_ms,
                baseline_samples: blob.samples.min(BASELINE_BOOTSTRAP),
                high_latency_streak: 0,
                degraded: blob.degraded,
                recover_streak: 0,
                last_failure: restore_instant(blob.last_failure_secs),
                last_error: blob.last_error.clone(),
                last_used: restore_instant(blob.last_used_secs),
                latency_samples,
                history: blob.history.iter().cloned().collect(),
                throughput_ewma_bps: blob.throughput_ewma_bps,
                throughput_peak_bps: blob.throughput_peak_bps,
                throughput_updated: restore_instant(blob.throughput_updated_secs),
            }),
            sample_count: AtomicU32::new(blob.samples),
            active_conn: AtomicU32::new(0),
            traffic_bytes: AtomicU64::new(0),
            traffic_clock_gate: AtomicU64::new(0),
            traffic_window_started_ms: AtomicU64::new(0),
            throughput_hint_bits: AtomicU64::new(
                blob.throughput_ewma_bps
                    .max(blob.throughput_peak_bps)
                    .to_bits(),
            ),
            last_persist_ms: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeStatSnapshot {
    pub samples: u32,
    pub success_rate: f64,
    pub p50_latency_ms: f64,
    pub p90_latency_ms: f64,
    pub jitter_ms: f64,
    pub timeout_rate: f64,
    pub baseline_latency_ms: f64,
    pub degraded: bool,
    pub active_conn: u32,
    pub throughput_bps: f64,
    pub cooldown: Duration,
    pub last_error: Option<String>,
}

/// 每条连接持有一个观察器；关闭通过原子位保证只执行一次。
pub struct NodeFlowObserver {
    stats: Arc<NodeStats>,
    closed: AtomicBool,
}

impl NodeFlowObserver {
    pub fn new(stats: Arc<NodeStats>) -> Arc<Self> {
        stats.open_connection();
        Arc::new(Self {
            stats,
            closed: AtomicBool::new(false),
        })
    }
}

impl ConnectionObserver for NodeFlowObserver {
    fn on_upload(&self, bytes: u64) {
        self.stats.record_transfer(bytes);
    }

    fn on_download(&self, bytes: u64) {
        self.stats.record_transfer(bytes);
    }

    fn on_close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.stats.record_transfer(0);
            self.stats.close_connection();
        }
    }
}

fn update_baseline(inner: &mut Inner, latency_ms: f64) {
    if inner.baseline_samples < BASELINE_BOOTSTRAP {
        inner.baseline_samples += 1;
        let count = inner.baseline_samples as f64;
        inner.baseline_latency_ms =
            (inner.baseline_latency_ms * (count - 1.0) + latency_ms) / count;
        return;
    }
    if latency_ms > inner.baseline_latency_ms * SPIKE_FACTOR {
        inner.high_latency_streak = inner.high_latency_streak.saturating_add(1);
        if inner.high_latency_streak >= 5 {
            inner.baseline_latency_ms = inner.p50_latency_ms;
            inner.high_latency_streak = 0;
        }
        return;
    }
    inner.high_latency_streak = 0;
    let capped = latency_ms.min(inner.baseline_latency_ms * BASELINE_MAX_STEP);
    inner.baseline_latency_ms = ewma(inner.baseline_latency_ms, capped, BASELINE_ALPHA);
}

fn update_recovery(inner: &mut Inner, latency_ms: f64) {
    if inner.baseline_samples >= BASELINE_BOOTSTRAP
        && latency_ms > inner.baseline_latency_ms * DEGRADE_FACTOR
    {
        inner.degraded = true;
        inner.recover_streak = 0;
        return;
    }
    if inner.degraded
        && (inner.baseline_latency_ms <= 0.0
            || latency_ms <= inner.baseline_latency_ms * RECOVER_FACTOR)
    {
        inner.recover_streak = inner.recover_streak.saturating_add(1);
        if inner.recover_streak >= RECOVER_SUCCESSES {
            inner.degraded = false;
            inner.recover_streak = 0;
        }
    } else if inner.degraded {
        inner.recover_streak = 0;
    }
}

fn latency_quantiles(samples: &VecDeque<u32>) -> (f64, f64) {
    if samples.is_empty() {
        return (200.0, 200.0);
    }
    let mut values: Vec<u32> = samples.iter().copied().collect();
    values.sort_unstable();
    let p50 = values[(values.len() - 1) / 2] as f64;
    let p90_index = ((values.len() - 1) * 9).div_ceil(10);
    (p50, values[p90_index] as f64)
}

fn push_history(history: &mut VecDeque<HistoryEntry>, delay_ms: u32) {
    history.push_back(HistoryEntry {
        time_ms: unix_now_ms(),
        delay_ms,
    });
    while history.len() > HISTORY_CAP {
        history.pop_front();
    }
}

fn ewma(previous: f64, sample: f64, alpha: f64) -> f64 {
    previous * (1.0 - alpha) + sample * alpha
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn instant_to_unix(instant: Option<Instant>) -> Option<u64> {
    let instant = instant?;
    let elapsed = Instant::now().checked_duration_since(instant)?;
    SystemTime::now()
        .checked_sub(elapsed)?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn restore_instant(seconds: Option<u64>) -> Option<Instant> {
    let then = UNIX_EPOCH.checked_add(Duration::from_secs(seconds?))?;
    let elapsed = SystemTime::now().duration_since(then).ok()?;
    Instant::now().checked_sub(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_and_jitter_are_real_samples() {
        let stats = NodeStats::new();
        for delay in [10, 20, 30, 40, 100] {
            stats.record_probe(Duration::from_millis(delay));
        }
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.p50_latency_ms, 30.0);
        assert_eq!(snapshot.p90_latency_ms, 100.0);
        assert!(snapshot.jitter_ms > 0.0);
    }

    #[test]
    fn failures_degrade_and_successes_recover() {
        let stats = NodeStats::new();
        for _ in 0..3 {
            stats.record_probe(Duration::from_millis(50));
        }
        stats.record_probe_failure("timeout");
        assert!(stats.snapshot().degraded);
        stats.record_probe(Duration::from_millis(50));
        stats.record_probe(Duration::from_millis(50));
        assert!(!stats.snapshot().degraded);
    }
}
