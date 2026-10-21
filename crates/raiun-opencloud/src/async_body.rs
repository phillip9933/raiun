//! Async content-body timeout primitives.
//!
//! A request may intentionally wait in the account rate limiter. That local
//! wait pauses the body inactivity clock, but it never pauses the hard total
//! deadline. Network/source work remains covered by the inactivity deadline.
//! The watchdog owns and polls the operation future directly; dropping it on a
//! timeout cancels the request without leaving a detached worker behind.

use bytes::Bytes;
use futures_util::{Stream, stream};
use raiun_core::backend::{CloudError, ErrorKind};
use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::watch,
    time::Instant,
};
use zeroize::Zeroizing;

use crate::transfer_budget::{TransferBudget, TransferDirection};

const BODY_CHUNK_BYTES: usize = 64 * 1024;
pub(crate) const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub(crate) struct BodyProgress {
    events: watch::Sender<ProgressState>,
    latest: Arc<Mutex<ProgressState>>,
}

pub(crate) struct BodyProgressReceiver {
    events: watch::Receiver<ProgressState>,
    latest: Arc<Mutex<ProgressState>>,
}

impl BodyProgressReceiver {
    #[cfg(test)]
    fn latest(&self) -> ProgressState {
        *self
            .latest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProgressState {
    last_progress_at: Instant,
    waited_since_progress: Duration,
    active_wait_since: Option<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BodyTimeout<E> {
    Operation(E),
    Inactive,
    Total,
    Cancelled,
}

impl BodyProgress {
    pub(crate) fn channel() -> (Self, BodyProgressReceiver) {
        let now = Instant::now();
        let initial = ProgressState {
            last_progress_at: now,
            waited_since_progress: Duration::ZERO,
            active_wait_since: None,
        };
        let latest = Arc::new(Mutex::new(initial));
        let (events, receiver) = watch::channel(initial);
        (
            Self {
                events,
                latest: Arc::clone(&latest),
            },
            BodyProgressReceiver {
                events: receiver,
                latest,
            },
        )
    }

    fn update(&self, modify: impl FnOnce(&mut ProgressState)) {
        let mut latest = self
            .latest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        modify(&mut latest);
        self.events.send_replace(*latest);
    }

    /// Mark only the local token-bucket wait. Source reads must not be wrapped
    /// in this marker, so a stalled source remains subject to inactivity.
    pub(crate) fn budget_wait_started(&self) {
        self.update(|state| {
            if state.active_wait_since.is_none() {
                state.active_wait_since = Some(Instant::now());
            }
        });
    }

    pub(crate) fn budget_wait_finished(&self) {
        self.update(|state| {
            if let Some(started) = state.active_wait_since.take() {
                state.waited_since_progress += started.elapsed();
            }
        });
    }

    /// Call after a body chunk makes progress through the request/response
    /// stream, not merely when a local source buffer is read.
    pub(crate) fn bytes_progressed(&self) {
        self.update(|state| {
            state.last_progress_at = Instant::now();
            state.waited_since_progress = Duration::ZERO;
            state.active_wait_since = None;
        });
    }
}

/// Build a fixed-size upload body stream. Token acquisition is async and
/// cancellable; only that local wait pauses the inactivity watchdog. Source
/// reads occur after the wait and therefore remain covered by the watchdog.
pub(crate) fn budgeted_upload_stream<R, C>(
    reader: R,
    expected_bytes: u64,
    budget: TransferBudget,
    is_cancelled: C,
    progress: BodyProgress,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    R: AsyncRead + Unpin + Send + 'static,
    C: Fn() -> bool + Send + Sync + 'static,
{
    let is_cancelled = Arc::new(is_cancelled);
    stream::try_unfold((reader, expected_bytes), move |(mut reader, remaining)| {
        let budget = budget.clone();
        let is_cancelled = Arc::clone(&is_cancelled);
        let progress = progress.clone();
        async move {
            if remaining == 0 {
                return Ok(None);
            }
            progress.budget_wait_started();
            let reservation = budget
                .acquire_cancellable_async(
                    TransferDirection::Upload,
                    BODY_CHUNK_BYTES.min(remaining.min(usize::MAX as u64) as usize),
                    || is_cancelled(),
                )
                .await;
            progress.budget_wait_finished();
            let reservation = reservation?;
            let mut bytes = vec![0; reservation.granted()];
            let count = reader.read(&mut bytes).await?;
            if is_cancelled() {
                drop(reservation);
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "content transfer was cancelled",
                ));
            }
            reservation.settle(count);
            if count == 0 {
                return Ok(None);
            }
            let remaining = remaining.saturating_sub(count as u64);
            bytes.truncate(count);
            progress.bytes_progressed();
            Ok(Some((Bytes::from(bytes), (reader, remaining))))
        }
    })
}

/// Copy a response body to an async sink in bounded chunks. A token
/// reservation is acquired before requesting the next network chunk; the
/// network read and local sink write remain visible to the inactivity timer.
pub(crate) async fn copy_response_body<W>(
    response: &mut reqwest::Response,
    output: &mut W,
    max_bytes: u64,
    budget: &TransferBudget,
    is_cancelled: impl Fn() -> bool,
    progress: &BodyProgress,
) -> Result<u64, CloudError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    copy_response_body_observed(
        response,
        output,
        max_bytes,
        budget,
        is_cancelled,
        progress,
        || {},
    )
    .await
}

pub(crate) async fn copy_response_body_observed<W>(
    response: &mut reqwest::Response,
    output: &mut W,
    max_bytes: u64,
    budget: &TransferBudget,
    is_cancelled: impl Fn() -> bool,
    progress: &BodyProgress,
    on_chunk_consumed: impl Fn(),
) -> Result<u64, CloudError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let mut copied = 0u64;
    let mut pending = Bytes::new();
    let mut pending_offset = 0usize;
    if max_bytes == 0 {
        return Ok(0);
    }
    loop {
        if copied == max_bytes {
            return Ok(copied);
        }
        if pending_offset == pending.len() {
            progress.budget_wait_started();
            let reservation = budget
                .acquire_cancellable_async(
                    TransferDirection::Download,
                    BODY_CHUNK_BYTES,
                    &is_cancelled,
                )
                .await;
            progress.budget_wait_finished();
            let reservation = reservation.map_err(crate::io_error)?;
            let Some(chunk) = response.chunk().await.map_err(crate::network)? else {
                reservation.settle(0);
                return Ok(copied);
            };
            if chunk.len() as u64 > max_bytes.saturating_sub(copied) {
                reservation.settle(0);
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "content body exceeded its advertised byte limit",
                ));
            }
            progress.bytes_progressed();
            on_chunk_consumed();
            pending = chunk;
            let take = pending.len().min(reservation.granted());
            output
                .write_all(&pending[..take])
                .await
                .map_err(crate::io_error)?;
            reservation.settle(take);
            pending_offset = take;
            copied = copied.saturating_add(take as u64);
        } else {
            progress.budget_wait_started();
            let reservation = budget
                .acquire_cancellable_async(
                    TransferDirection::Download,
                    pending.len() - pending_offset,
                    &is_cancelled,
                )
                .await;
            progress.budget_wait_finished();
            let reservation = reservation.map_err(crate::io_error)?;
            let take = reservation.granted();
            output
                .write_all(&pending[pending_offset..pending_offset + take])
                .await
                .map_err(crate::io_error)?;
            reservation.settle(take);
            pending_offset += take;
            copied = copied.saturating_add(take as u64);
        }
    }
}

#[derive(Default)]
pub(crate) struct VecAsyncWriter(Zeroizing<Vec<u8>>);

impl VecAsyncWriter {
    pub(crate) fn into_inner(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

impl tokio::io::AsyncWrite for VecAsyncWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        self.get_mut().0.extend_from_slice(bytes);
        std::task::Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Run the async body path on a bounded current-thread runtime. The runtime
/// and request future are owned by this synchronous worker call; timeout drops
/// the future and its socket/body stream instead of detaching a blocked task.
#[cfg(test)]
pub(crate) fn run_body_operation<T, F, Fut>(
    idle_timeout: Duration,
    total_timeout: Duration,
    operation: F,
) -> Result<T, CloudError>
where
    F: FnOnce(BodyProgress) -> Fut,
    Fut: Future<Output = Result<T, CloudError>>,
{
    run_body_operation_cancellable(idle_timeout, total_timeout, || false, operation)
}

pub(crate) fn run_body_operation_cancellable<T, F, Fut, C>(
    idle_timeout: Duration,
    total_timeout: Duration,
    is_cancelled: C,
    operation: F,
) -> Result<T, CloudError>
where
    F: FnOnce(BodyProgress) -> Fut,
    Fut: Future<Output = Result<T, CloudError>>,
    C: Fn() -> bool,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(CloudError::new(
            ErrorKind::Unsupported,
            "synchronous OpenCloud body API cannot run inside an async executor",
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| CloudError::new(ErrorKind::Offline, "body runtime is unavailable"))?;
    let (progress, events) = BodyProgress::channel();
    match runtime.block_on(with_body_watchdog_cancellable(
        operation(progress),
        events,
        idle_timeout,
        total_timeout,
        is_cancelled,
    )) {
        Ok(value) => Ok(value),
        Err(BodyTimeout::Operation(error)) => Err(error),
        Err(BodyTimeout::Inactive) => Err(CloudError::new(
            ErrorKind::Offline,
            "OpenCloud content transfer stalled",
        )),
        Err(BodyTimeout::Total) => Err(CloudError::new(
            ErrorKind::Offline,
            "OpenCloud content transfer exceeded its total deadline",
        )),
        Err(BodyTimeout::Cancelled) => Err(CloudError::new(
            ErrorKind::Offline,
            "OpenCloud content transfer was cancelled or paused",
        )),
    }
}

/// Run one body operation with an inactivity deadline and a non-pausable hard
/// total deadline. Intentional budget waits freeze only the remaining idle
/// allowance; progress restarts the idle clock. Dropping the future cancels its
/// transport operation and does not spawn a worker.
#[cfg(test)]
pub(crate) async fn with_body_watchdog<F, T, E>(
    operation: F,
    events: BodyProgressReceiver,
    idle_timeout: Duration,
    total_timeout: Duration,
) -> Result<T, BodyTimeout<E>>
where
    F: Future<Output = Result<T, E>>,
{
    with_body_watchdog_cancellable(operation, events, idle_timeout, total_timeout, || false).await
}

pub(crate) async fn with_body_watchdog_cancellable<F, T, E, C>(
    operation: F,
    events: BodyProgressReceiver,
    idle_timeout: Duration,
    total_timeout: Duration,
    is_cancelled: C,
) -> Result<T, BodyTimeout<E>>
where
    F: Future<Output = Result<T, E>>,
    C: Fn() -> bool,
{
    let started = Instant::now();
    let total_deadline = started + total_timeout;
    let mut idle_deadline = started + idle_timeout;
    let mut paused_idle = false;
    let mut events_open = true;
    let mut operation = Box::pin(operation);
    let mut total_sleep = Box::pin(tokio::time::sleep_until(total_deadline));
    let BodyProgressReceiver {
        mut events,
        latest: latest_progress,
    } = events;
    let mut changed = Box::pin(events.changed());

    loop {
        enum Wake<T, E> {
            Operation(Result<T, E>),
            Event(Result<(), watch::error::RecvError>),
            Total,
            Idle,
            Cancelled,
        }
        let mut idle_sleep = Box::pin(tokio::time::sleep_until(idle_deadline));
        let mut cancel_poll = Box::pin(tokio::time::sleep(Duration::from_millis(20)));
        let wake = std::future::poll_fn(|cx| {
            // Check deadlines before observing ready progress or success. A
            // late wake must not let an event mask an already expired clock.
            if total_sleep.as_mut().poll(cx).is_ready() {
                return std::task::Poll::Ready(Wake::Total);
            }
            if !paused_idle && idle_sleep.as_mut().poll(cx).is_ready() {
                // A coalesced watch update may not be polled until after this
                // timer becomes ready. Honor a budget wait that actually
                // began before the idle deadline, while still rejecting a
                // wait whose timestamp is at or beyond that deadline.
                if events_open
                    && latest_progress
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .active_wait_since
                        .is_some_and(|wait_started| wait_started < idle_deadline)
                {
                    return std::task::Poll::Ready(Wake::Event(Ok(())));
                }
                return std::task::Poll::Ready(Wake::Idle);
            }
            if is_cancelled() {
                return std::task::Poll::Ready(Wake::Cancelled);
            }
            if cancel_poll.as_mut().poll(cx).is_ready() {
                return std::task::Poll::Ready(Wake::Cancelled);
            }
            if events_open {
                if let std::task::Poll::Ready(event) = changed.as_mut().poll(cx) {
                    return std::task::Poll::Ready(Wake::Event(event));
                }
            }
            if let std::task::Poll::Ready(result) = operation.as_mut().poll(cx) {
                let now = Instant::now();
                if now >= total_deadline {
                    return std::task::Poll::Ready(Wake::Total);
                }
                if !paused_idle && now >= idle_deadline {
                    return std::task::Poll::Ready(Wake::Idle);
                }
                return std::task::Poll::Ready(Wake::Operation(result));
            }
            std::task::Poll::Pending
        })
        .await;
        match wake {
            Wake::Operation(result) => return result.map_err(BodyTimeout::Operation),
            Wake::Total => return Err(BodyTimeout::Total),
            Wake::Idle => return Err(BodyTimeout::Inactive),
            Wake::Cancelled => {
                if is_cancelled() {
                    return Err(BodyTimeout::Cancelled);
                }
            }
            Wake::Event(event) => {
                let now = Instant::now();
                if now >= total_deadline {
                    return Err(BodyTimeout::Total);
                }
                if event.is_err() {
                    // A closed progress producer has no effect on watchdog
                    // deadlines. Do not poll the closed channel in a loop.
                    events_open = false;
                    continue;
                }
                drop(changed);
                let state = *events.borrow_and_update();
                let latest_idle_deadline =
                    state.last_progress_at + idle_timeout + state.waited_since_progress;
                if let Some(wait_started) = state.active_wait_since {
                    idle_deadline = latest_idle_deadline;
                    if wait_started >= idle_deadline && !paused_idle {
                        return Err(BodyTimeout::Inactive);
                    }
                    paused_idle = true;
                } else {
                    paused_idle = false;
                    idle_deadline = latest_idle_deadline;
                    if now >= idle_deadline {
                        return Err(BodyTimeout::Inactive);
                    }
                }
                changed = Box::pin(events.changed());
            }
        }
    }
}

/// Combine an operation's hard timeout with an externally owned absolute
/// deadline such as a Cloud Files callback deadline.
pub(crate) fn bounded_total_timeout(
    hard_total: Duration,
    strict_remaining: Option<Duration>,
) -> Duration {
    strict_remaining.map_or(hard_total, |remaining| remaining.min(hard_total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer_budget::{TransferBudget, TransferDirection, TransferLimits};
    use std::{convert::Infallible, future::Future, num::NonZeroU64};

    fn run<F: Future<Output = ()>>(future: F) {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
            .block_on(future);
    }

    async fn stalled_http_server(
        respond_with_headers: bool,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut headers = Vec::new();
            let mut byte = [0u8; 1];
            while !headers.ends_with(b"\r\n\r\n") {
                if socket.read_exact(&mut byte).await.is_err() {
                    return;
                }
                headers.push(byte[0]);
                if headers.len() > 64 * 1024 {
                    return;
                }
            }
            if respond_with_headers {
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
            // Hold the connection open without consuming an upload or
            // producing a response body. The client watchdog must drop it.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        (format!("http://{address}/body"), task)
    }

    async fn upload_receiver(expected_bytes: usize) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut headers = Vec::new();
            let mut byte = [0u8; 1];
            while !headers.ends_with(b"\r\n\r\n") {
                if socket.read_exact(&mut byte).await.is_err() {
                    return;
                }
                headers.push(byte[0]);
            }
            let mut payload = vec![0; expected_bytes];
            if socket.read_exact(&mut payload).await.is_err() {
                return;
            }
            let _ = socket
                .write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        });
        (format!("http://{address}/body"), task)
    }

    async fn download_server(body: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut headers = Vec::new();
            let mut byte = [0u8; 1];
            while !headers.ends_with(b"\r\n\r\n") {
                if socket.read_exact(&mut byte).await.is_err() {
                    return;
                }
                headers.push(byte[0]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(&body).await;
        });
        (format!("http://{address}/body"), task)
    }

    #[test]
    fn stalled_network_operation_is_cancelled_at_idle_bound() {
        run(async {
            let (_progress, events) = BodyProgress::channel();
            let start = Instant::now();
            let result = with_body_watchdog::<_, (), Infallible>(
                std::future::pending(),
                events,
                Duration::from_millis(40),
                Duration::from_secs(2),
            )
            .await;
            assert_eq!(result, Err(BodyTimeout::Inactive));
            assert!(start.elapsed() < Duration::from_millis(500));
        });
    }

    #[test]
    fn async_http_download_body_stall_is_bounded() {
        run(async {
            let (url, server) = stalled_http_server(true).await;
            let (progress, events) = BodyProgress::channel();
            let operation = async move {
                let response = reqwest::Client::new()
                    .get(url)
                    .send()
                    .await
                    .map_err(|error| error.to_string())?;
                progress.bytes_progressed(); // response headers arrived
                response
                    .bytes()
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            };
            let started = Instant::now();
            let result = with_body_watchdog(
                operation,
                events,
                Duration::from_millis(80),
                Duration::from_secs(2),
            )
            .await;
            assert_eq!(result, Err(BodyTimeout::Inactive));
            assert!(started.elapsed() < Duration::from_secs(1));
            server.abort();
        });
    }

    #[test]
    fn async_http_upload_backpressure_is_bounded() {
        run(async {
            let (url, server) = stalled_http_server(false).await;
            let (_progress, events) = BodyProgress::channel();
            // Large enough to exceed local socket buffering while the fixture
            // reads only headers; the async send future must remain cancellable.
            let body = vec![0x5a; 64 * 1024 * 1024];
            let operation = async move {
                reqwest::Client::new()
                    .put(url)
                    .body(body)
                    .send()
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            };
            let started = Instant::now();
            let result = with_body_watchdog(
                operation,
                events,
                Duration::from_millis(120),
                Duration::from_secs(2),
            )
            .await;
            assert_eq!(result, Err(BodyTimeout::Inactive));
            assert!(started.elapsed() < Duration::from_secs(1));
            server.abort();
        });
    }

    #[test]
    fn real_async_budgeted_upload_pacing_does_not_trip_idle_watchdog() {
        run(async {
            let payload = vec![0x4c; 2 * 1024];
            let (url, server) = upload_receiver(payload.len()).await;
            let budget = TransferBudget::new();
            budget.set_limits(TransferLimits {
                upload_bytes_per_second: Some(NonZeroU64::new(1024).unwrap()),
                download_bytes_per_second: None,
            });
            budget
                .acquire_cancellable(TransferDirection::Upload, 1024, || false)
                .unwrap()
                .settle(1024);
            let cancellation = budget.cancellation();
            let operation_budget = budget.clone();
            let operation_payload = payload.clone();
            let (progress, events) = BodyProgress::channel();
            let start = Instant::now();
            let operation = async move {
                let stream = budgeted_upload_stream(
                    std::io::Cursor::new(operation_payload.clone()),
                    operation_payload.len() as u64,
                    operation_budget,
                    move || cancellation.is_cancelled(),
                    progress,
                );
                let response = reqwest::Client::new()
                    .put(url)
                    .header(reqwest::header::CONTENT_LENGTH, operation_payload.len())
                    .body(reqwest::Body::wrap_stream(stream))
                    .send()
                    .await
                    .map_err(|_| CloudError::new(ErrorKind::Offline, "synthetic upload failed"))?;
                if response.status() != reqwest::StatusCode::CREATED {
                    return Err(CloudError::new(
                        ErrorKind::InvalidResponse,
                        "unexpected response",
                    ));
                }
                Ok(())
            };
            let result = with_body_watchdog(
                operation,
                events,
                Duration::from_millis(40),
                Duration::from_secs(4),
            )
            .await;
            assert!(result.is_ok(), "paced upload should succeed: {result:?}");
            assert!(start.elapsed() >= Duration::from_millis(800));
            assert!(start.elapsed() < Duration::from_secs(3));
            server.await.unwrap();
        });
    }

    #[test]
    fn real_async_budgeted_download_pacing_does_not_trip_idle_watchdog() {
        run(async {
            use tokio::io::AsyncWriteExt;

            let payload = vec![0x2d; 2 * 1024];
            let payload_len = payload.len() as u64;
            let (url, server) = download_server(payload.clone()).await;
            let budget = TransferBudget::new();
            budget.set_limits(TransferLimits {
                upload_bytes_per_second: None,
                download_bytes_per_second: Some(NonZeroU64::new(1024).unwrap()),
            });
            budget
                .acquire_cancellable(TransferDirection::Download, 1024, || false)
                .unwrap()
                .settle(1024);
            let operation_budget = budget.clone();
            let cancellation = budget.cancellation();
            let (progress, events) = BodyProgress::channel();
            let start = Instant::now();
            let operation = async move {
                let mut response = reqwest::Client::new().get(url).send().await.map_err(|_| {
                    CloudError::new(ErrorKind::Offline, "synthetic download failed")
                })?;
                let mut output = tokio::io::sink();
                let copied = copy_response_body(
                    &mut response,
                    &mut output,
                    payload_len,
                    &operation_budget,
                    || cancellation.is_cancelled(),
                    &progress,
                )
                .await?;
                output.flush().await.map_err(crate::io_error)?;
                Ok::<u64, CloudError>(copied)
            };
            let result = with_body_watchdog(
                operation,
                events,
                Duration::from_millis(40),
                Duration::from_secs(4),
            )
            .await;
            assert_eq!(result.unwrap(), payload_len);
            assert!(start.elapsed() >= Duration::from_millis(800));
            assert!(start.elapsed() < Duration::from_secs(3));
            server.await.unwrap();
        });
    }

    #[test]
    fn lowered_rate_mid_transfer_keeps_paced_body_inside_hard_total() {
        run(async {
            let payload = vec![0x6a; 8 * 1024];
            let payload_len = payload.len();
            let (url, server) = upload_receiver(payload_len).await;
            let budget = TransferBudget::new();
            budget.set_limits(TransferLimits {
                upload_bytes_per_second: Some(NonZeroU64::new(4096).unwrap()),
                download_bytes_per_second: None,
            });
            budget
                .acquire_cancellable(TransferDirection::Upload, 4096, || false)
                .unwrap()
                .settle(4096);
            let operation_budget = budget.clone();
            let limit_budget = budget.clone();
            let cancellation = budget.cancellation();
            let (progress, events) = BodyProgress::channel();
            let operation_payload = payload;
            let operation = async move {
                let stream = budgeted_upload_stream(
                    std::io::Cursor::new(operation_payload.clone()),
                    operation_payload.len() as u64,
                    operation_budget,
                    move || cancellation.is_cancelled(),
                    progress,
                );
                let response = reqwest::Client::new()
                    .put(url)
                    .header(reqwest::header::CONTENT_LENGTH, operation_payload.len())
                    .body(reqwest::Body::wrap_stream(stream))
                    .send()
                    .await
                    .map_err(|_| CloudError::new(ErrorKind::Offline, "synthetic upload failed"))?;
                if response.status() != reqwest::StatusCode::CREATED {
                    return Err(CloudError::new(
                        ErrorKind::InvalidResponse,
                        "unexpected response",
                    ));
                }
                Ok::<_, CloudError>(())
            };
            let lower_rate = async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                limit_budget.set_limits(TransferLimits {
                    upload_bytes_per_second: Some(NonZeroU64::new(2048).unwrap()),
                    download_bytes_per_second: None,
                });
            };
            let started = Instant::now();
            tokio::spawn(lower_rate);
            let result = with_body_watchdog(
                operation,
                events,
                Duration::from_millis(60),
                Duration::from_secs(4),
            )
            .await;
            let elapsed = started.elapsed();
            assert!(result.is_ok(), "rate reduction failed: {result:?}");
            assert!(elapsed >= Duration::from_secs(1));
            assert!(elapsed < Duration::from_secs(4));
            server.await.unwrap();
        });
    }

    #[test]
    fn operation_ready_after_deadline_is_still_rejected() {
        let operation = std::future::poll_fn(|_| {
            std::thread::sleep(Duration::from_millis(35));
            std::task::Poll::Ready(Ok::<_, CloudError>(()))
        });
        let result = run_body_operation(
            Duration::from_millis(20),
            Duration::from_secs(1),
            move |_| operation,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ErrorKind::Offline,
            "a blocking poll must not bypass an expired inactivity bound"
        );
    }

    #[test]
    fn operation_ready_after_hard_total_deadline_is_rejected() {
        let operation = std::future::poll_fn(|_| {
            std::thread::sleep(Duration::from_millis(35));
            std::task::Poll::Ready(Ok::<_, CloudError>(()))
        });
        let result = run_body_operation(
            Duration::from_secs(1),
            Duration::from_millis(20),
            move |_| operation,
        );
        let error = result.unwrap_err();
        assert!(error.message.contains("total deadline"));
    }

    #[test]
    fn progress_updates_coalesce_in_a_bounded_watch_channel() {
        let (progress, mut events) = BodyProgress::channel();
        let initial = events.latest();
        for _ in 0..100_000 {
            progress.bytes_progressed();
        }
        assert!(events.events.has_changed().unwrap());
        let latest = events.latest();
        assert!(latest.last_progress_at >= initial.last_progress_at);
        assert_eq!(latest.waited_since_progress, Duration::ZERO);
        assert_eq!(latest.active_wait_since, None);
        let observed = *events.events.borrow_and_update();
        assert_eq!(observed.last_progress_at, latest.last_progress_at);
        assert!(!events.events.has_changed().unwrap());
    }

    #[test]
    fn external_cancellation_drops_a_stalled_http_operation_promptly() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancelled);
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            signal.store(true, Ordering::Release);
        });
        let started = Instant::now();
        let result = run_body_operation_cancellable(
            Duration::from_secs(3),
            Duration::from_secs(3),
            || cancelled.load(Ordering::Acquire),
            |_| std::future::pending::<Result<(), CloudError>>(),
        );
        canceller.join().unwrap();
        assert_eq!(result.unwrap_err().kind, ErrorKind::Offline);
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn closed_progress_channel_does_not_starve_the_idle_timer() {
        run(async {
            let (progress, events) = BodyProgress::channel();
            drop(progress);
            let result = with_body_watchdog::<_, (), Infallible>(
                std::future::pending(),
                events,
                Duration::from_millis(30),
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(result, Err(BodyTimeout::Inactive));
        });
    }

    #[test]
    fn late_rate_wait_event_cannot_resurrect_expired_idle_deadline() {
        run(async {
            let (progress, events) = BodyProgress::channel();
            let operation = std::future::poll_fn(move |_| {
                // Simulate a delayed executor poll: the event is emitted only
                // after the idle clock has elapsed, before the watchdog can
                // poll its timer branch again.
                std::thread::sleep(Duration::from_millis(35));
                progress.budget_wait_started();
                std::task::Poll::<Result<(), Infallible>>::Pending
            });
            let result = with_body_watchdog::<_, (), Infallible>(
                operation,
                events,
                Duration::from_millis(20),
                Duration::from_secs(2),
            )
            .await;
            assert_eq!(result, Err(BodyTimeout::Inactive));
        });
    }

    #[test]
    fn predeadline_rate_wait_survives_a_delayed_watchdog_poll() {
        run(async {
            let (progress, events) = BodyProgress::channel();
            let operation = async move {
                progress.budget_wait_started();
                // Block the current-thread executor beyond the idle deadline
                // after recording a wait start that was on time.
                std::thread::sleep(Duration::from_millis(35));
                tokio::time::sleep(Duration::from_millis(15)).await;
                progress.budget_wait_finished();
                progress.bytes_progressed();
                Ok::<_, Infallible>(())
            };
            let result = with_body_watchdog(
                operation,
                events,
                Duration::from_millis(20),
                Duration::from_secs(1),
            )
            .await;
            assert!(result.is_ok(), "on-time rate wait was rejected: {result:?}");
        });
    }

    #[test]
    fn intentional_rate_wait_pauses_idle_but_not_total_deadline() {
        run(async {
            let (progress, events) = BodyProgress::channel();
            let operation = async move {
                for _ in 0..3 {
                    progress.budget_wait_started();
                    tokio::time::sleep(Duration::from_millis(45)).await;
                    progress.budget_wait_finished();
                    progress.bytes_progressed();
                }
                Ok::<_, Infallible>(())
            };
            let start = Instant::now();
            let result = with_body_watchdog(
                operation,
                events,
                Duration::from_millis(25),
                Duration::from_secs(1),
            )
            .await;
            assert!(
                result.is_ok(),
                "paced budget wait should complete: {result:?}"
            );
            assert!(start.elapsed() >= Duration::from_millis(120));
        });
    }

    #[test]
    fn real_async_budget_wait_is_cancellable_and_excluded_from_idle_time() {
        run(async {
            let budget = TransferBudget::new();
            budget.set_limits(TransferLimits {
                upload_bytes_per_second: Some(NonZeroU64::new(5).unwrap()),
                download_bytes_per_second: None,
            });
            budget
                .acquire_cancellable(TransferDirection::Upload, 5, || false)
                .unwrap()
                .settle(5);
            let cancellation = budget.cancellation();
            let (progress, events) = BodyProgress::channel();
            let progress_for_body = progress.clone();
            let body = async move {
                progress_for_body.budget_wait_started();
                let reservation = budget
                    .acquire_cancellable_async(TransferDirection::Upload, 1, || {
                        cancellation.is_cancelled()
                    })
                    .await?;
                progress_for_body.budget_wait_finished();
                reservation.settle(1);
                progress_for_body.bytes_progressed();
                Ok::<_, std::io::Error>(())
            };
            let result = with_body_watchdog(
                body,
                events,
                Duration::from_millis(30),
                Duration::from_secs(2),
            )
            .await;
            assert!(
                result.is_ok(),
                "paced budget wait should complete: {result:?}"
            );
        });
    }

    #[test]
    fn cancelling_async_budget_wait_drops_it_without_a_worker() {
        run(async {
            let budget = TransferBudget::new();
            budget.set_limits(TransferLimits {
                upload_bytes_per_second: Some(NonZeroU64::new(1).unwrap()),
                download_bytes_per_second: None,
            });
            budget
                .acquire_cancellable(TransferDirection::Upload, 1, || false)
                .unwrap()
                .settle(1);
            let cancellation = budget.cancellation();
            let cancellation_for_task = cancellation.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(40)).await;
                cancellation_for_task.cancel();
            });
            let (progress, events) = BodyProgress::channel();
            let progress_for_body = progress.clone();
            let body = async move {
                progress_for_body.budget_wait_started();
                let reservation = budget
                    .acquire_cancellable_async(TransferDirection::Upload, 1, || {
                        cancellation.is_cancelled()
                    })
                    .await?;
                progress_for_body.budget_wait_finished();
                reservation.settle(1);
                Ok::<_, std::io::Error>(())
            };
            let result = with_body_watchdog(
                body,
                events,
                Duration::from_millis(20),
                Duration::from_secs(2),
            )
            .await;
            assert!(
                matches!(result, Err(BodyTimeout::Operation(error)) if error.kind() == std::io::ErrorKind::ConnectionAborted)
            );
        });
    }

    #[test]
    fn hard_total_deadline_still_expires_during_rate_wait() {
        run(async {
            let (progress, events) = BodyProgress::channel();
            let operation = async move {
                progress.budget_wait_started();
                tokio::time::sleep(Duration::from_secs(2)).await;
                progress.budget_wait_finished();
                Ok::<_, Infallible>(())
            };
            let result = with_body_watchdog(
                operation,
                events,
                Duration::from_millis(20),
                Duration::from_millis(50),
            )
            .await;
            assert_eq!(result, Err(BodyTimeout::Total));
        });
    }

    #[test]
    fn source_io_stall_is_not_misclassified_as_budget_wait() {
        run(async {
            let (_progress, events) = BodyProgress::channel();
            let operation = async {
                // Simulates an async source read. It is deliberately not marked as
                // a limiter wait, so it remains covered by inactivity timeout.
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok::<_, Infallible>(())
            };
            let result = with_body_watchdog(
                operation,
                events,
                Duration::from_millis(30),
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(result, Err(BodyTimeout::Inactive));
        });
    }

    #[test]
    fn strict_callback_deadline_remains_the_shorter_total_bound() {
        assert_eq!(
            bounded_total_timeout(Duration::from_secs(10), Some(Duration::from_millis(30))),
            Duration::from_millis(30)
        );
        assert_eq!(
            bounded_total_timeout(Duration::from_secs(10), Some(Duration::from_secs(20))),
            Duration::from_secs(10)
        );
        assert_eq!(
            bounded_total_timeout(Duration::from_secs(10), None),
            Duration::from_secs(10)
        );
    }
}
