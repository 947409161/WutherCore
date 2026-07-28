//! 多线程热路径使用的分片计数器。
//!
//! 单个全局 `AtomicU64::fetch_add` 会让所有 Tokio worker 争用同一缓存行。
//! 这里让每个线程稳定落到一个缓存行隔离的 shard，读取时才合并。流量写入
//! 是高频操作，读取只发生在 API 采样，因此这种布局显著减少 cache ping-pong。

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const SHARD_COUNT: usize = 64;
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static LOCAL_SHARD: usize = NEXT_SHARD.fetch_add(1, Ordering::Relaxed) % SHARD_COUNT;
}

#[derive(Debug, Default)]
#[repr(align(64))]
struct CounterShard {
    value: AtomicU64,
}

#[derive(Debug)]
pub(crate) struct StripedCounter {
    shards: Box<[CounterShard; SHARD_COUNT]>,
}

impl Default for StripedCounter {
    fn default() -> Self {
        Self {
            shards: Box::new(std::array::from_fn(|_| CounterShard::default())),
        }
    }
}

impl StripedCounter {
    #[inline]
    pub(crate) fn add(&self, value: u64) {
        if value == 0 {
            return;
        }
        LOCAL_SHARD.with(|index| {
            self.shards[*index]
                .value
                .fetch_add(value, Ordering::Relaxed);
        });
    }

    pub(crate) fn load(&self) -> u64 {
        self.shards.iter().fold(0_u64, |total, shard| {
            total.wrapping_add(shard.value.load(Ordering::Relaxed))
        })
    }

    pub(crate) fn reset(&self) {
        for shard in self.shards.iter() {
            shard.value.store(0, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn sums_updates_from_many_threads() {
        let counter = Arc::new(StripedCounter::default());
        let workers = (0..16)
            .map(|_| {
                let counter = Arc::clone(&counter);
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        counter.add(3);
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(counter.load(), 16 * 10_000 * 3);
        counter.reset();
        assert_eq!(counter.load(), 0);
    }
}
