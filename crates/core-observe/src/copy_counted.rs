//! 带流量统计 + 取消信号的双向 splice。
//!
//! 与 `tokio::io::copy_bidirectional` 的差异：
//! 1. 每读到一段 N 字节立刻 `up.fetch_add(N)` / `down.fetch_add(N)` —— per-conn
//!    流量计数实时更新（用于 dashboard 的 upload/download 列与速率列）。
//! 2. 同时把 N 透传给可选的全局 [`crate::Metrics`] —— 让 `/traffic` WS 的
//!    总上下行也增长。
//! 3. 接受一个粘性的 `CancellationToken`，外部（如 DELETE /connections/:id）触发
//!    时立刻 shutdown 双向 socket，让数据流尽快真正断开。
//!
//! 用法（与现有手写 split + try_join 等价，但少 30 行模板）：
//! ```ignore
//! let (up, down) = guard.counters();
//! let cancel = guard.cancel_token();
//! let metrics = Some(runtime.metrics.clone());
//! let (n_up, n_down) =
//!     copy_bidirectional_counted(&mut inbound, &mut outbound, up, down, cancel, metrics).await?;
//! ```

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::{ConnectionAccounting, Metrics};

const INITIAL_BUF_SIZE: usize = 8 * 1024;
const MAX_BUF_SIZE: usize = 64 * 1024;

#[inline]
fn grow_buffer_after_full_read(buffer: &mut Vec<u8>, bytes_read: usize) {
    if bytes_read == buffer.len() && buffer.len() < MAX_BUF_SIZE {
        buffer.resize((buffer.len() * 2).min(MAX_BUF_SIZE), 0);
    }
}

/// 把 `read` 结果归类为：拿到 N 字节继续 / 干净 EOF 该 break / 真错。
///
/// rustls 在 TLS 对端关 TCP 不发 close_notify 时返回 `UnexpectedEof`，RFC 8446
/// 上是 SHOULD 不是 MUST，实践中海量服务器都不发；mihomo / clash / sing-box
/// 一致把它当 clean EOF 吃掉，这里也对齐——HTTP 等应用层有自己的长度校验，
/// TLS-level 的截断攻击检测对代理场景没意义。
enum ReadOutcome {
    Data(usize),
    Eof,
    Err(io::Error),
}

fn classify_read(r: io::Result<usize>) -> ReadOutcome {
    match r {
        Ok(0) => ReadOutcome::Eof,
        Ok(n) => ReadOutcome::Data(n),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => ReadOutcome::Eof,
        Err(e) => ReadOutcome::Err(e),
    }
}

#[derive(Debug)]
struct DirectionResult {
    bytes: u64,
    error: Option<io::Error>,
}

async fn copy_direction<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    external_cancel: CancellationToken,
    relay_cancel: CancellationToken,
    mut record: F,
) -> DirectionResult
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
    F: FnMut(u64),
{
    let mut buffer = vec![0u8; INITIAL_BUF_SIZE];
    let mut total = 0u64;
    loop {
        let read = tokio::select! {
            biased;
            () = external_cancel.cancelled() => {
                let _ = writer.shutdown().await;
                return DirectionResult { bytes: total, error: None };
            }
            () = relay_cancel.cancelled() => {
                let _ = writer.shutdown().await;
                return DirectionResult { bytes: total, error: None };
            }
            result = reader.read(&mut buffer) => result,
        };
        let bytes_read = match classify_read(read) {
            ReadOutcome::Data(bytes_read) => bytes_read,
            ReadOutcome::Eof => {
                let _ = writer.shutdown().await;
                return DirectionResult {
                    bytes: total,
                    error: None,
                };
            }
            ReadOutcome::Err(error) => {
                relay_cancel.cancel();
                let _ = writer.shutdown().await;
                return DirectionResult {
                    bytes: total,
                    error: Some(error),
                };
            }
        };
        let write = tokio::select! {
            biased;
            () = external_cancel.cancelled() => {
                let _ = writer.shutdown().await;
                return DirectionResult { bytes: total, error: None };
            }
            () = relay_cancel.cancelled() => {
                let _ = writer.shutdown().await;
                return DirectionResult { bytes: total, error: None };
            }
            result = writer.write_all(&buffer[..bytes_read]) => result,
        };
        if let Err(error) = write {
            relay_cancel.cancel();
            let _ = writer.shutdown().await;
            return DirectionResult {
                bytes: total,
                error: Some(error),
            };
        }
        let bytes = bytes_read as u64;
        total = total.saturating_add(bytes);
        record(bytes);
        grow_buffer_after_full_read(&mut buffer, bytes_read);
    }
}

/// A TCP peer commonly closes a completed HTTP/download stream with RST
/// instead of a FIN. Once useful payload has crossed the relay, Linux
/// ECONNRESET, connection-aborted and the matching write-side errors are
/// terminal close signals rather than a failed transfer.
fn is_graceful_terminal_error(error: &io::Error, transferred: u64) -> bool {
    transferred > 0
        && matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
        )
}

fn finish_directions(upload: DirectionResult, download: DirectionResult) -> io::Result<(u64, u64)> {
    let transferred = upload.bytes.saturating_add(download.bytes);
    if let Some(error) = upload.error.or(download.error)
        && !is_graceful_terminal_error(&error, transferred)
    {
        return Err(error);
    }
    Ok((upload.bytes, download.bytes))
}

/// 双向拷贝 a ↔ b，每段透传到 per-conn + 全局 counter。
///
/// 返回 `(up_total, down_total)` —— 即便一方提前出错也会尽量返回到那一刻为止
/// 的流量统计（错误本身通过 `Result` 暴露）。
pub async fn copy_bidirectional_counted<A, B>(
    a: &mut A,
    b: &mut B,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    cancel: CancellationToken,
    metrics: Option<Arc<Metrics>>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let up_metrics = metrics.clone();
    let up_counter = up.clone();
    let cancel_up = cancel.clone();
    let relay_cancel = CancellationToken::new();
    let relay_cancel_up = relay_cancel.clone();
    let up_task = copy_direction(&mut ar, &mut bw, cancel_up, relay_cancel_up, move |bytes| {
        up_counter.fetch_add(bytes, Ordering::Relaxed);
        if let Some(metrics) = &up_metrics {
            metrics.add_up(bytes);
        }
    });

    let down_metrics = metrics.clone();
    let down_counter = down.clone();
    let cancel_down = cancel.clone();
    let down_task = copy_direction(&mut br, &mut aw, cancel_down, relay_cancel, move |bytes| {
        down_counter.fetch_add(bytes, Ordering::Relaxed);
        if let Some(metrics) = &down_metrics {
            metrics.add_down(bytes);
        }
    });

    let (upload, download) = tokio::join!(up_task, down_task);
    finish_directions(upload, download)
}

/// 双向拷贝并通过完整连接管理器计数。
///
/// 这个路径对应 mihomo `statistic.NewTCPTracker`/`NewUDPTracker` 的热路径：
/// 每段数据更新连接累计值、分片管理器总流量和 `/traffic` 全局指标。
/// 连接 max rate 在 dashboard 快照时按累计差值采样，复制循环不获取速率锁。
pub async fn copy_bidirectional_tracked<A, B>(
    a: &mut A,
    b: &mut B,
    accounting: ConnectionAccounting,
    metrics: Option<Arc<Metrics>>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let up_metrics = metrics.clone();
    let up_accounting = accounting.clone();
    let cancel_up = accounting.cancel_token();
    let relay_cancel = CancellationToken::new();
    let relay_cancel_up = relay_cancel.clone();
    let up_task = copy_direction(&mut ar, &mut bw, cancel_up, relay_cancel_up, move |bytes| {
        up_accounting.record_upload(bytes);
        if let Some(metrics) = &up_metrics {
            metrics.add_up(bytes);
        }
    });

    let down_metrics = metrics.clone();
    let down_accounting = accounting.clone();
    let cancel_down = accounting.cancel_token();
    let down_task = copy_direction(&mut br, &mut aw, cancel_down, relay_cancel, move |bytes| {
        down_accounting.record_download(bytes);
        if let Some(metrics) = &down_metrics {
            metrics.add_down(bytes);
        }
    });

    let (upload, download) = tokio::join!(up_task, down_task);
    finish_directions(upload, download)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// rustls 在 peer 关 TCP 不发 close_notify 时返回 `UnexpectedEof`；
    /// 该错误必须被归类为 clean EOF，否则 relay 层会 `warn!` 一条假错误。
    /// 这是 mihomo / clash / sing-box 的一致行为。
    #[test]
    fn classify_unexpected_eof_is_clean_eof() {
        let err = io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed without close_notify",
        );
        assert!(matches!(classify_read(Err(err)), ReadOutcome::Eof));
    }

    /// 真正的错误（连接重置等）继续按 Err 透传，不能被吃掉。
    #[test]
    fn classify_other_io_errors_propagate() {
        let err = io::Error::new(io::ErrorKind::ConnectionReset, "RST");
        assert!(matches!(classify_read(Err(err)), ReadOutcome::Err(_)));
    }

    #[test]
    fn reset_after_payload_is_a_graceful_terminal_close() {
        let result = finish_directions(
            DirectionResult {
                bytes: 1024,
                error: None,
            },
            DirectionResult {
                bytes: 40 * 1024 * 1024,
                error: Some(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "ECONNRESET (os error 104)",
                )),
            },
        );
        assert_eq!(result.unwrap(), (1024, 40 * 1024 * 1024));
    }

    #[test]
    fn reset_before_any_payload_still_reports_failure() {
        let result = finish_directions(
            DirectionResult {
                bytes: 0,
                error: None,
            },
            DirectionResult {
                bytes: 0,
                error: Some(io::Error::new(io::ErrorKind::ConnectionReset, "RST")),
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    }

    #[test]
    fn classify_normal_data_and_eof() {
        assert!(matches!(classify_read(Ok(0)), ReadOutcome::Eof));
        assert!(matches!(classify_read(Ok(42)), ReadOutcome::Data(42)));
    }

    #[test]
    fn relay_buffer_grows_for_bulk_traffic_but_stays_small_when_idle() {
        let mut buffer = vec![0_u8; INITIAL_BUF_SIZE];
        assert_eq!(buffer.len(), 8 * 1024);
        grow_buffer_after_full_read(&mut buffer, 1);
        assert_eq!(buffer.len(), INITIAL_BUF_SIZE);
        while buffer.len() < MAX_BUF_SIZE {
            let full = buffer.len();
            grow_buffer_after_full_read(&mut buffer, full);
        }
        assert_eq!(buffer.len(), 64 * 1024);
        grow_buffer_after_full_read(&mut buffer, MAX_BUF_SIZE);
        assert_eq!(buffer.len(), MAX_BUF_SIZE);
    }

    #[tokio::test]
    async fn round_trip_counts_bytes() {
        let (mut client_a, mut server_a) = tokio::io::duplex(8 * 1024);
        let (mut client_b, mut server_b) = tokio::io::duplex(8 * 1024);

        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let cancel = CancellationToken::new();

        let up_c = up.clone();
        let down_c = down.clone();
        let cancel_c = cancel.clone();
        let bridge = tokio::spawn(async move {
            copy_bidirectional_counted(&mut server_a, &mut server_b, up_c, down_c, cancel_c, None)
                .await
                .unwrap()
        });

        // client_a → bridge → client_b
        let payload = vec![7u8; 4 * 1024];
        client_a.write_all(&payload).await.unwrap();
        client_a.shutdown().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        client_b.read_exact(&mut got).await.unwrap();
        cancel.cancel();
        drop(client_a);
        drop(client_b);

        let (n_up, n_down) = tokio::time::timeout(std::time::Duration::from_millis(500), bridge)
            .await
            .expect("bridge timeout")
            .unwrap();
        assert_eq!(n_up, payload.len() as u64);
        assert!(n_down <= payload.len() as u64); // 可能为 0
        assert_eq!(up.load(Ordering::Relaxed), payload.len() as u64);
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn tracked_round_trip_updates_manager_totals() {
        let table = crate::ConnectionTable::new();
        let guard = table.open(crate::ConnectionMeta::default());
        let accounting = guard.accounting();
        let (mut client_a, mut server_a) = tokio::io::duplex(8 * 1024);
        let (mut client_b, mut server_b) = tokio::io::duplex(8 * 1024);

        let bridge = tokio::spawn(async move {
            copy_bidirectional_tracked(&mut server_a, &mut server_b, accounting, None).await
        });

        client_a.write_all(b"tracked").await.unwrap();
        let mut got = [0u8; 7];
        client_b.read_exact(&mut got).await.unwrap();
        guard.cancel.cancel();
        drop(client_a);
        drop(client_b);

        let result = tokio::time::timeout(std::time::Duration::from_millis(500), bridge)
            .await
            .expect("bridge timeout")
            .expect("bridge join");
        assert!(result.is_ok());
        assert_eq!(&got, b"tracked");
        assert_eq!(table.total(), (7, 0));
        let snap = table.manager_snapshot();
        assert_eq!(snap.upload_total, 7);
        assert_eq!(snap.connections[0].upload, 7);
        assert!(snap.connections[0].max_upload_rate >= 7);
    }

    #[tokio::test]
    async fn cancel_signals_shutdown() {
        let (mut client_a, mut server_a) = tokio::io::duplex(8 * 1024);
        let (mut client_b, mut server_b) = tokio::io::duplex(8 * 1024);

        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let cancel_c = cancel.clone();
        let bridge = tokio::spawn(async move {
            copy_bidirectional_counted(&mut server_a, &mut server_b, up, down, cancel_c, None).await
        });

        // 写一点数据但不关闭，让 splice 阻塞在下一次 read
        client_a.write_all(b"hello").await.unwrap();
        let _ = client_b.read_exact(&mut [0u8; 5]).await.unwrap();

        // 触发取消
        let start = std::time::Instant::now();
        cancel.cancel();

        // bridge 应在 200ms 内返回
        let r = tokio::time::timeout(std::time::Duration::from_millis(500), bridge)
            .await
            .expect("bridge timeout")
            .expect("bridge join");
        assert!(r.is_ok());
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
    }
}
