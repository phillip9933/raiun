//! OpenCloud Graph and WebDAV client used by the desktop engine.
//!
//! The client is deliberately blocking: callers must run it on engine workers.
//! It never follows redirects, and keeps authorization values out of Debug output.

mod async_body;
pub mod transfer_budget;
pub mod vault;
pub mod vault_backend;
pub mod vault_cache;
pub mod vault_create;

use std::{
    cell::Cell,
    fs::File,
    io::{self, Read, Write},
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use percent_encoding::percent_decode_str;
use quick_xml::{NsReader, events::Event, name::ResolveResult};
use raiun_core::backend::{
    CloudBackend, CloudError, CloudSpace, ErrorKind, RemoteEntry, WriteCondition,
};
use reqwest::{
    Method, Proxy, StatusCode,
    blocking::{Client, Response},
    header::{
        ACCEPT_RANGES, AUTHORIZATION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG,
        HeaderValue, IF_MATCH, IF_NONE_MATCH, RANGE,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::NamedTempFile;
use transfer_budget::{TransferBudget, TransferDirection};
use url::Url;
use zeroize::Zeroizing;

const MAX_GRAPH_BODY: usize = 8 * 1024 * 1024;
const MAX_DAV_RESPONSE: u64 = 32 * 1024 * 1024;
const MAX_DAV_ENTRY: usize = 256 * 1024;
const MAX_ERROR_BODY: usize = 16 * 1024;
const MAX_RANGE_READ: usize = 64 * 1024;
/// Maximum atomic byte range staged by one Windows Cloud Files callback.
pub const MAX_CALLBACK_RANGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum body staged by the Cloud Files edit-recovery conditional uploader.
pub const MAX_RECOVERY_UPLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const NAMESPACE_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const NAMESPACE_PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_PAGES: usize = 1_000;
const MAX_VAULT_GUARD_DEPTH: usize = 64;
const VAULT_CONTENT_TYPE: &str = "application/vnd.opencloud.vault";
#[cfg(test)]
const TRANSFER_TIMEOUT_BASE_SECS: u64 = 120;
#[cfg(test)]
const TRANSFER_MIN_BYTES_PER_SECOND: u64 = 256 * 1024;
const TRANSFER_TIMEOUT_MAX_SECS: u64 = 24 * 60 * 60;

#[cfg(all(feature = "synthetic-test-ca", not(debug_assertions)))]
compile_error!("synthetic-test-ca is restricted to debug test builds");

/// Immutable account transport routing policy. `System` preserves reqwest's
/// existing proxy discovery behavior; `Direct` explicitly disables proxies.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProxyConfig {
    #[default]
    System,
    Direct,
    Explicit {
        url: String,
    },
}

impl ProxyConfig {
    /// Validate without returning or echoing the configured URL on failure.
    pub fn validate(&self) -> Result<(), CloudError> {
        if let Self::Explicit { url } = self {
            if url.is_empty()
                || url.len() > 2_048
                || url.trim() != url
                || url.chars().any(char::is_control)
                || url.chars().any(char::is_whitespace)
            {
                return Err(invalid("proxy URL is malformed"));
            }
            let parsed = Url::parse(url).map_err(|_| invalid("proxy URL is malformed"))?;
            let scheme = parsed.scheme();
            if !matches!(scheme, "http" | "https")
                || parsed.host_str().is_none_or(str::is_empty)
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || !matches!(parsed.path(), "" | "/")
                || authority_contains_userinfo(url)
            {
                return Err(invalid(
                    "proxy must be an HTTP(S) origin without credentials or URL components",
                ));
            }
        }
        Ok(())
    }

    /// Apply this route to a reqwest builder. Shared by authentication and
    /// cloud clients so discovery/token/Graph/DAV cannot silently diverge.
    pub fn apply_to_client_builder(
        &self,
        builder: reqwest::blocking::ClientBuilder,
    ) -> Result<reqwest::blocking::ClientBuilder, CloudError> {
        apply_proxy(builder, self)
    }

    fn apply_to_async_client_builder(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::ClientBuilder, CloudError> {
        apply_proxy_async(builder, self)
    }
}

fn authority_contains_userinfo(value: &str) -> bool {
    let Some((_, after_scheme)) = value.split_once("://") else {
        return true;
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    authority.contains('@')
}

/// Exact ordinary DAV identity and offset for a bounded range read.
#[derive(Clone, Copy)]
pub struct RemoteRangeRequest<'a> {
    pub space: &'a str,
    /// DAV resource ID of the Space root captured by the trusted provider.
    pub expected_root_id: &'a str,
    pub path: &'a str,
    pub expected_id: &'a str,
    pub expected_etag: &'a str,
    pub expected_size: u64,
    pub offset: u64,
}

/// One fixed deadline and bearer-token generation for a provider range read.
/// Created by the trusted adapter and never derived from callback data.
#[derive(Clone, Copy, Debug)]
pub struct RangeReadContext {
    pub deadline: Instant,
    pub token_generation: u64,
}

/// A token-generation lease held across a short local publish operation.
/// The credential itself is never exposed through this type.
pub struct TokenGenerationLease<'a> {
    _token: MutexGuard<'a, String>,
}

thread_local! {
    // Range reads are fully synchronous and all helper requests remain on the
    // calling worker thread. Thread-local scope lets the existing metadata
    // helpers share one absolute budget without storing request state on a
    // client that may be used concurrently by unrelated operations.
    static ACTIVE_RANGE_CONTEXT: Cell<Option<RangeReadContext>> = const { Cell::new(None) };
}

struct RangeContextGuard(Option<RangeReadContext>);

impl RangeContextGuard {
    fn enter(context: RangeReadContext) -> Self {
        let previous = ACTIVE_RANGE_CONTEXT.with(|slot| slot.replace(Some(context)));
        Self(previous)
    }
}

impl Drop for RangeContextGuard {
    fn drop(&mut self) {
        ACTIVE_RANGE_CONTEXT.with(|slot| slot.set(self.0));
    }
}

impl RangeReadContext {
    fn remaining(self) -> Result<Duration, CloudError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| CloudError::new(ErrorKind::Offline, "range request deadline elapsed"))
    }
}

// Metadata/control requests keep the 120-second client timeout. Content bodies
// use an async client with a separate inactivity watchdog; only time explicitly
// spent waiting for the local rate bucket pauses that idle clock. The total
// deadline remains active during pacing (and is strict for RangeReadContext),
// while cancellation drops the request future rather than leaving a worker
// blocked behind a synchronous body read. A configured cap uses a 24-hour hard
// ceiling because the account-wide rate may change or contend after request
// start; the 30-second body-idle bound independently catches stalled peers.
// Failed downloads discard staged output, and conditional uploads keep their
// existing exact-scope recovery behavior.
#[cfg(test)]
fn transfer_timeout(bytes: u64) -> Duration {
    let transfer_seconds =
        bytes.saturating_add(TRANSFER_MIN_BYTES_PER_SECOND - 1) / TRANSFER_MIN_BYTES_PER_SECOND;
    Duration::from_secs(
        TRANSFER_TIMEOUT_BASE_SECS
            .saturating_add(transfer_seconds)
            .min(TRANSFER_TIMEOUT_MAX_SECS),
    )
}

fn transfer_timeout_with_budget(
    _budget: &TransferBudget,
    _direction: TransferDirection,
    _bytes: u64,
) -> Duration {
    // The shared controller can change from unlimited to finite while a body
    // is active. Snapshotting an unlimited transfer's size estimate would
    // create an early deadline after such a change. Keep one hard ceiling for
    // every mutable-budget request; the independent inactivity watchdog
    // still bounds stalled peers, and callback contexts apply their stricter
    // absolute deadline below.
    Duration::from_secs(TRANSFER_TIMEOUT_MAX_SECS)
}

fn transfer_timeout_for_context(
    context: RangeReadContext,
    budget: &TransferBudget,
    direction: TransferDirection,
    bytes: u64,
) -> Result<Duration, CloudError> {
    Ok(async_body::bounded_total_timeout(
        transfer_timeout_with_budget(budget, direction, bytes),
        Some(context.remaining()?),
    ))
}

#[derive(Clone)]
pub struct OpenCloudClient {
    server: Url,
    http: Client,
    async_http: reqwest::Client,
    body_idle_timeout: Duration,
    token: Arc<Mutex<String>>,
    token_generation: Arc<AtomicU64>,
    initiator_id: String,
    transfer_budget: TransferBudget,
}

impl std::fmt::Debug for OpenCloudClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenCloudClient")
            .field("server", &self.server)
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl OpenCloudClient {
    fn validate_identity_addressed_root(
        &self,
        selected: &CloudSpace,
        expected_root: &str,
    ) -> Result<Url, CloudError> {
        let url = Url::parse(&selected.dav_url).map_err(|_| invalid("space DAV URL is invalid"))?;
        let mut segments = url
            .path_segments()
            .ok_or_else(|| invalid("space DAV URL has no path"))?
            .collect::<Vec<_>>();
        if segments.last() == Some(&"") {
            segments.pop();
        }
        let canonical = segments.len() >= 3
            && segments[segments.len() - 3] == "dav"
            && segments[segments.len() - 2] == "spaces"
            && decode_safe_segment(segments[segments.len() - 1])? == selected.id;
        // OpenCloud's /dav/spaces/{spaceID}/ endpoint selects a unique Space,
        // bypassing mutable user aliases. Keep the full fileid as a separate
        // pre/post identity proof; it is not a documented endpoint selector.
        if !canonical
            || !same_origin(&self.server, &url)
            || url.query().is_some()
            || url.fragment().is_some()
            || expected_root.split_once('!').map(|(space, _)| space) != Some(selected.id.as_str())
        {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "Space has no identity-addressed DAV root; local bytes were preserved",
            ));
        }
        append_logical_path(&url, "/")
    }

    /// Create a client for an HTTPS OpenCloud server. Plain HTTP is accepted
    /// only for literal IPv4 or IPv6 loopback addresses used by local fixtures.
    pub fn new(server: &str, bearer_token: String) -> Result<Self, CloudError> {
        Self::new_with_proxy(server, bearer_token, &ProxyConfig::System)
    }

    /// Create a client using the caller's immutable account proxy policy.
    pub fn new_with_proxy(
        server: &str,
        bearer_token: String,
        proxy: &ProxyConfig,
    ) -> Result<Self, CloudError> {
        Self::new_with_proxy_and_transfer_budget(server, bearer_token, proxy, TransferBudget::new())
    }

    /// Construct an authenticated account client with a caller-owned shared
    /// content-transfer budget. Pass the same budget to every rebuilt client
    /// for this account; clients cloned from it already share the budget.
    pub fn new_with_proxy_and_transfer_budget(
        server: &str,
        bearer_token: String,
        proxy: &ProxyConfig,
        transfer_budget: TransferBudget,
    ) -> Result<Self, CloudError> {
        Self::new_with_timeouts(
            server,
            bearer_token,
            Duration::from_secs(15),
            Duration::from_secs(120),
            proxy,
            transfer_budget,
        )
    }

    /// Create a client for one bounded startup namespace probe. This is
    /// intentionally separate from normal cloud operations, which keep their
    /// transfer-appropriate timeout. A server that accepts TCP but stalls
    /// must not leave a saved offline account indefinitely in `restoring`.
    pub fn new_for_namespace_probe(server: &str, bearer_token: String) -> Result<Self, CloudError> {
        Self::new_for_namespace_probe_with_proxy(server, bearer_token, &ProxyConfig::System)
    }

    /// Create a short-deadline probe client using the same proxy policy as
    /// ordinary account traffic.
    pub fn new_for_namespace_probe_with_proxy(
        server: &str,
        bearer_token: String,
        proxy: &ProxyConfig,
    ) -> Result<Self, CloudError> {
        Self::new_with_timeouts(
            server,
            bearer_token,
            NAMESPACE_PROBE_CONNECT_TIMEOUT,
            NAMESPACE_PROBE_TIMEOUT,
            proxy,
            TransferBudget::new(),
        )
    }

    /// Apply the short namespace-probe deadline to one synchronous operation
    /// using this client's existing backend and token generation. This keeps
    /// recovery probes bounded without replacing the long-timeout client used
    /// for ordinary listing and file transfers. Every Graph page shares the
    /// same absolute deadline, and the request fails if authentication rotates
    /// while the probe is in flight.
    pub fn with_bounded_namespace_probe<T>(
        &self,
        probe: impl FnOnce() -> Result<T, CloudError>,
    ) -> Result<T, CloudError> {
        let deadline = Instant::now()
            .checked_add(NAMESPACE_PROBE_TIMEOUT)
            .ok_or_else(|| invalid("namespace probe deadline is invalid"))?;
        let context = RangeReadContext {
            deadline,
            token_generation: self.token_generation.load(Ordering::Acquire),
        };
        let _guard = RangeContextGuard::enter(context);
        let result = probe()?;
        if self.token_generation.load(Ordering::Acquire) != context.token_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(result)
    }

    fn new_with_timeouts(
        server: &str,
        bearer_token: String,
        connect_timeout: Duration,
        request_timeout: Duration,
        proxy: &ProxyConfig,
        transfer_budget: TransferBudget,
    ) -> Result<Self, CloudError> {
        let server = Url::parse(server).map_err(|_| invalid("server URL is invalid"))?;
        validate_server(&server)?;
        if bearer_token.trim().is_empty() || bearer_token.chars().any(char::is_control) {
            return Err(invalid("bearer token is empty or malformed"));
        }
        let builder = apply_proxy(Client::builder(), proxy)?
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(connect_timeout)
            .timeout(request_timeout);
        #[cfg(feature = "synthetic-test-ca")]
        let builder = add_synthetic_test_ca(builder, &server)?;
        #[cfg(not(feature = "synthetic-test-ca"))]
        let _ = &server;
        let http = builder.build().map_err(|_| {
            CloudError::new(ErrorKind::Offline, "could not initialize HTTPS client")
        })?;
        let async_builder = proxy
            .apply_to_async_client_builder(reqwest::Client::builder())?
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(connect_timeout)
            .read_timeout(async_body::BODY_IDLE_TIMEOUT)
            .timeout(request_timeout);
        #[cfg(feature = "synthetic-test-ca")]
        let async_builder = add_synthetic_test_ca_async(async_builder, &server)?;
        #[cfg(not(feature = "synthetic-test-ca"))]
        let _ = &server;
        let async_http = async_builder.build().map_err(|_| {
            CloudError::new(ErrorKind::Offline, "could not initialize HTTPS body client")
        })?;
        Ok(Self {
            server: normalized_server(server),
            http,
            async_http,
            body_idle_timeout: async_body::BODY_IDLE_TIMEOUT,
            token: Arc::new(Mutex::new(bearer_token)),
            token_generation: Arc::new(AtomicU64::new(1)),
            initiator_id: format!("raiun-{}", std::process::id()),
            transfer_budget,
        })
    }

    /// Clone the account's shared transfer controller for configuration and
    /// pause/cancel coordination. Ordinary clones use this same controller.
    pub fn transfer_budget(&self) -> TransferBudget {
        self.transfer_budget.clone()
    }

    pub(crate) fn body_idle_timeout(&self) -> Duration {
        self.body_idle_timeout
    }

    #[cfg(test)]
    fn with_body_idle_timeout_for_test(mut self, timeout: Duration) -> Self {
        self.body_idle_timeout = timeout;
        self
    }

    /// Rebind a freshly authenticated client to its account's retained
    /// controller before publishing it to engine, mount, and vault services.
    pub fn with_transfer_budget(mut self, transfer_budget: TransferBudget) -> Self {
        self.transfer_budget = transfer_budget;
        self
    }

    /// Replace the in-memory bearer token after an external auth layer refreshes it.
    pub fn set_bearer_token(&self, bearer_token: String) -> Result<(), CloudError> {
        if bearer_token.trim().is_empty() || bearer_token.chars().any(char::is_control) {
            return Err(invalid("bearer token is empty or malformed"));
        }
        let mut token = self
            .token
            .lock()
            .map_err(|_| invalid("authentication state unavailable"))?;
        let current = self.token_generation.load(Ordering::Acquire);
        let next = current
            .checked_add(1)
            .ok_or_else(|| invalid("authentication generation exhausted"))?;
        *token = bearer_token;
        self.token_generation.store(next, Ordering::Release);
        Ok(())
    }

    /// Current in-memory bearer generation, captured when a provider lease is
    /// created. Replacing the token invalidates every prior lease.
    pub fn token_generation(&self) -> u64 {
        self.token_generation.load(Ordering::Acquire)
    }

    /// Canonical configured server URL without credentials, query, or fragment.
    /// This is for trusted account-identity derivation; callback data must not
    /// choose or alter the server.
    pub fn configured_server_url(&self) -> String {
        self.server.as_str().trim_end_matches('/').to_owned()
    }

    /// Run a short local publication step only while the captured token
    /// generation remains current. The token lock makes this check and the
    /// caller's output copy atomic with respect to `set_bearer_token`.
    pub fn with_token_generation<T>(
        &self,
        expected: u64,
        publish: impl FnOnce() -> T,
    ) -> Result<T, CloudError> {
        let _token = self
            .token
            .lock()
            .map_err(|_| invalid("authentication state unavailable"))?;
        if self.token_generation.load(Ordering::Acquire) != expected {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(publish())
    }

    /// Run a local completion step while both account clients retain the
    /// captured bearer generations. Token refresh/logout through
    /// `set_bearer_token` blocks until the closure returns. The locks are
    /// acquired in stable pointer order; clones sharing one token lock are
    /// handled without attempting to lock that mutex twice.
    pub(crate) fn with_token_generations<T>(
        &self,
        other: &Self,
        self_expected: u64,
        other_expected: u64,
        publish: impl FnOnce() -> T,
    ) -> Result<T, CloudError> {
        let generation_matches =
            |client: &Self, expected| client.token_generation.load(Ordering::Acquire) == expected;
        if Arc::ptr_eq(&self.token, &other.token) {
            let _token = self
                .token
                .lock()
                .map_err(|_| invalid("authentication state unavailable"))?;
            if self_expected != other_expected
                || !generation_matches(self, self_expected)
                || !generation_matches(other, other_expected)
            {
                return Err(CloudError::new(
                    ErrorKind::Unauthorized,
                    "authenticated provider generation changed",
                ));
            }
            return Ok(publish());
        }

        let self_first = (Arc::as_ptr(&self.token) as usize) < (Arc::as_ptr(&other.token) as usize);
        let (_first, _second) = if self_first {
            let first = self
                .token
                .lock()
                .map_err(|_| invalid("authentication state unavailable"))?;
            let second = other
                .token
                .lock()
                .map_err(|_| invalid("authentication state unavailable"))?;
            (first, second)
        } else {
            let first = other
                .token
                .lock()
                .map_err(|_| invalid("authentication state unavailable"))?;
            let second = self
                .token
                .lock()
                .map_err(|_| invalid("authentication state unavailable"))?;
            (first, second)
        };
        if !generation_matches(self, self_expected) || !generation_matches(other, other_expected) {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(publish())
    }

    /// Non-blocking counterpart for callback publication, whose absolute
    /// request deadline must include waiting for the short auth-state lock.
    pub fn try_lock_token_generation(
        &self,
        expected: u64,
    ) -> Result<Option<TokenGenerationLease<'_>>, CloudError> {
        let token = match self.token.try_lock() {
            Ok(token) => token,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(invalid("authentication state unavailable"));
            }
        };
        if self.token_generation.load(Ordering::Acquire) != expected {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(Some(TokenGenerationLease { _token: token }))
    }

    fn request(
        &self,
        method: Method,
        url: &Url,
    ) -> Result<(reqwest::blocking::RequestBuilder, String), CloudError> {
        let context = ACTIVE_RANGE_CONTEXT.with(Cell::get);
        self.request_with_context(method, url, context)
    }

    fn request_with_context(
        &self,
        method: Method,
        url: &Url,
        context: Option<RangeReadContext>,
    ) -> Result<(reqwest::blocking::RequestBuilder, String), CloudError> {
        let context = context.or_else(|| ACTIVE_RANGE_CONTEXT.with(Cell::get));
        if !same_origin(&self.server, url) {
            return Err(invalid(
                "server returned a URL outside the configured origin",
            ));
        }
        let token_guard = self
            .token
            .lock()
            .map_err(|_| invalid("authentication state unavailable"))?;
        if context.is_some_and(|context| {
            self.token_generation.load(Ordering::Acquire) != context.token_generation
        }) {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        let token = token_guard.clone();
        let mut request = self
            .http
            .request(method, url.clone())
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header("Initiator-ID", &self.initiator_id)
            .header("X-Requested-With", "XMLHttpRequest");
        if let Some(context) = context {
            request = request.timeout(context.remaining()?);
        }
        Ok((request, token))
    }

    fn request_async(
        &self,
        method: Method,
        url: &Url,
    ) -> Result<(reqwest::RequestBuilder, String), CloudError> {
        self.request_async_with_context(method, url, ACTIVE_RANGE_CONTEXT.with(Cell::get))
    }

    fn request_async_with_context(
        &self,
        method: Method,
        url: &Url,
        context: Option<RangeReadContext>,
    ) -> Result<(reqwest::RequestBuilder, String), CloudError> {
        let context = context.or_else(|| ACTIVE_RANGE_CONTEXT.with(Cell::get));
        if !same_origin(&self.server, url) {
            return Err(invalid(
                "server returned a URL outside the configured origin",
            ));
        }
        let token_guard = self
            .token
            .lock()
            .map_err(|_| invalid("authentication state unavailable"))?;
        if context.is_some_and(|context| {
            self.token_generation.load(Ordering::Acquire) != context.token_generation
        }) {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        let token = token_guard.clone();
        let mut request = self
            .async_http
            .request(method, url.clone())
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header("Initiator-ID", &self.initiator_id)
            .header("X-Requested-With", "XMLHttpRequest");
        if let Some(context) = context {
            request = request.timeout(context.remaining()?);
        }
        Ok((request, token))
    }

    fn graph_get_with_context(
        &self,
        url: &Url,
        context: Option<RangeReadContext>,
    ) -> Result<Vec<u8>, CloudError> {
        let (request, token) = self.request_with_context(Method::GET, url, context)?;
        let response = request
            .header("Accept", "application/json")
            .send()
            .map_err(network)?;
        let mut response = checked(response, &[StatusCode::OK], &token)?;
        read_bounded(&mut response, MAX_GRAPH_BODY)
    }

    fn resolve_dav(&self, space: &str, path: &str) -> Result<(CloudSpace, Url), CloudError> {
        self.resolve_dav_with_context(space, path, None)
    }

    fn resolve_dav_with_context(
        &self,
        space: &str,
        path: &str,
        context: Option<RangeReadContext>,
    ) -> Result<(CloudSpace, Url), CloudError> {
        let spaces = self.discover_spaces(context, MAX_ENTRIES)?;
        let selected = spaces
            .into_iter()
            .find(|candidate| candidate.id == space)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud space was not found"))?;
        if selected.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted Spaces are unavailable to ordinary DAV operations",
            ));
        }
        if is_vault_path(path) {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted vault folders are unavailable to ordinary DAV operations",
            ));
        }
        let url = append_logical_path(
            &Url::parse(&selected.dav_url).map_err(|_| invalid("space DAV URL is invalid"))?,
            path,
        )?;
        if !same_origin(&self.server, &url) {
            return Err(invalid("space DAV URL is outside the configured origin"));
        }
        Ok((selected, url))
    }

    fn propfind(
        &self,
        url: &Url,
        depth: &str,
        logical_path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        self.propfind_with_context(url, depth, logical_path, visit, None)
    }

    fn propfind_with_context(
        &self,
        url: &Url,
        depth: &str,
        logical_path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
        context: Option<RangeReadContext>,
    ) -> Result<(), CloudError> {
        let body = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><d:propfind xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" xmlns:lg=\"http://graph.opencloud.eu/ns\" xmlns:ocrclone=\"ocrclone\"><d:prop><d:resourcetype/><d:getcontentlength/><d:getetag/><d:getlastmodified/><d:getcontenttype/><oc:fileid/><oc:permissions/><lg:encrypted/><lg:contentType/><ocrclone:integrity-id/></d:prop></d:propfind>";
        let (request, token) = self.request_with_context(
            Method::from_bytes(b"PROPFIND").expect("static method"),
            url,
            context,
        )?;
        let response = request
            .header("Depth", depth)
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .header("Initiator-ID", &self.initiator_id)
            .body(body.as_slice())
            .send()
            .map_err(network)?;
        let mut response = checked(response, &[StatusCode::MULTI_STATUS], &token)?;
        let bytes = read_bounded(&mut response, MAX_DAV_RESPONSE as usize)?;
        parse_multistatus(&bytes, url, logical_path, visit)
    }

    fn ensure_writable_target(
        &self,
        space: &CloudSpace,
        target_url: &Url,
        logical_path: &str,
    ) -> Result<(), CloudError> {
        if space.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted Spaces do not accept plaintext writes",
            ));
        }
        if !space.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "OpenCloud Space is read only",
            ));
        }
        self.ensure_plain_ancestors(space, logical_path, false)?;
        let mut entry = None;
        let target_result = self.propfind(target_url, "0", logical_path, &mut |value| {
            if entry.is_some() {
                return Err(invalid("DAV write check returned multiple entries"));
            }
            if value.path.trim_end_matches('/') != logical_path.trim_end_matches('/') {
                return Err(invalid(
                    "DAV write check returned an item other than the requested path",
                ));
            }
            entry = Some(value);
            Ok(())
        });
        let target = match target_result {
            Ok(()) => entry,
            Err(error) if error.kind == ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let checked_entry = if let Some(target) = target {
            target
        } else {
            let parent_path = logical_parent(logical_path);
            let root_url =
                Url::parse(&space.dav_url).map_err(|_| invalid("space DAV URL is invalid"))?;
            let parent_logical = if parent_path == "/" {
                parent_path.clone()
            } else {
                format!("{}/", parent_path)
            };
            let parent_url = append_logical_path(&root_url, &parent_logical)?;
            let mut parent = None;
            self.propfind(&parent_url, "0", &parent_path, &mut |value| {
                if parent.is_some() {
                    return Err(invalid("DAV parent check returned multiple entries"));
                }
                parent = Some(value);
                Ok(())
            })?;
            parent.ok_or_else(|| {
                CloudError::new(ErrorKind::NotFound, "remote parent folder was not found")
            })?
        };
        if checked_entry.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted remote content does not accept plaintext writes",
            ));
        }
        if !checked_entry.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "remote folder or item is read only",
            ));
        }
        Ok(())
    }

    /// Freshly inspect each ancestor because encryption metadata can appear
    /// without a `.vault` path suffix, and cached negative checks are unsafe.
    /// List callers include the requested directory itself; file operations
    /// check the root and parent chain while their target check handles leaf.
    fn ensure_plain_ancestors(
        &self,
        space: &CloudSpace,
        logical_path: &str,
        include_self: bool,
    ) -> Result<(), CloudError> {
        self.ensure_plain_ancestors_with_context(space, logical_path, include_self, None)
            .map(|_| ())
    }

    fn ensure_plain_ancestors_with_context(
        &self,
        space: &CloudSpace,
        logical_path: &str,
        include_self: bool,
        context: Option<RangeReadContext>,
    ) -> Result<String, CloudError> {
        self.ordinary_ancestor_root_entry_with_context(space, logical_path, include_self, context)
            .map(|root| root.id)
    }

    fn ordinary_ancestor_root_entry_with_context(
        &self,
        space: &CloudSpace,
        logical_path: &str,
        include_self: bool,
        context: Option<RangeReadContext>,
    ) -> Result<RemoteEntry, CloudError> {
        validate_logical_path(logical_path)?;
        let parts: Vec<_> = logical_path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        if parts.len() > MAX_VAULT_GUARD_DEPTH {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "remote path exceeds the vault metadata guard depth limit",
            ));
        }

        let ancestors = if include_self {
            parts.len()
        } else {
            parts.len().saturating_sub(1)
        };
        let root_url =
            Url::parse(&space.dav_url).map_err(|_| invalid("space DAV URL is invalid"))?;
        let mut paths = vec!["/".to_owned()];
        let mut prefix = String::new();
        for part in parts.iter().take(ancestors) {
            prefix.push('/');
            prefix.push_str(part);
            paths.push(prefix.clone());
        }

        let mut root_resource_id = None;
        for path in paths {
            let url = append_logical_path(&root_url, &path)?;
            let mut found = None;
            self.propfind_with_context(
                &url,
                "0",
                &path,
                &mut |entry| {
                    if found.is_some() {
                        return Err(invalid("vault ancestor check returned multiple entries"));
                    }
                    found = Some(entry);
                    Ok(())
                },
                context,
            )?;
            let entry = found.ok_or_else(|| {
                CloudError::new(
                    ErrorKind::Unsupported,
                    "could not confirm that the remote parent is ordinary content",
                )
            })?;
            if entry.path.trim_end_matches('/') != path.trim_end_matches('/') {
                return Err(invalid(
                    "vault ancestor check returned an item other than the requested path",
                ));
            }
            if entry.encrypted {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "encrypted vault folders are unavailable to ordinary DAV operations",
                ));
            }
            if path == "/" {
                if entry.id.is_empty() || entry.id.chars().any(char::is_control) {
                    return Err(invalid("Space root identity is invalid"));
                }
                root_resource_id = Some(entry.clone());
            }
            if !entry.directory {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "remote path ancestor is not a directory",
                ));
            }
        }
        root_resource_id.ok_or_else(|| invalid("Space root identity was not checked"))
    }

    fn transfer_url(&self, space: &str, path: &str) -> Result<(CloudSpace, Url), CloudError> {
        self.resolve_dav(space, path)
    }

    /// Read one bounded byte range from an ordinary file without staging the
    /// whole object. The caller supplies metadata captured when it registered
    /// an opaque provider identity; every invocation revalidates that exact
    /// file identity, entity tag, and length before and after the conditional
    /// range request. Encrypted Spaces and vault ancestors are rejected by the
    /// same DAV resolution and ancestor checks used by ordinary transfers.
    pub fn read_range(
        &self,
        request: RemoteRangeRequest<'_>,
        output: &mut [u8],
    ) -> Result<usize, CloudError> {
        self.read_range_cancellable(request, output, || false)
    }

    /// Cancellable form of [`OpenCloudClient::read_range`]. Cancellation is
    /// checked before and between metadata, response, and bounded body-read
    /// steps. The blocking HTTP request itself remains bounded by its timeout.
    pub fn read_range_cancellable<F>(
        &self,
        request: RemoteRangeRequest<'_>,
        output: &mut [u8],
        is_cancelled: F,
    ) -> Result<usize, CloudError>
    where
        F: Fn() -> bool,
    {
        self.read_range_cancellable_inner(
            request,
            output,
            None,
            MAX_RANGE_READ,
            is_cancelled,
            || {},
        )
    }

    /// Deadline- and token-generation-bound form for the Windows provider
    /// seam. The same absolute deadline is applied to every Graph/DAV request
    /// and body read in the operation; a changed bearer generation fails
    /// before another request is sent.
    pub fn read_range_cancellable_with_context<F>(
        &self,
        request: RemoteRangeRequest<'_>,
        output: &mut [u8],
        context: RangeReadContext,
        is_cancelled: F,
    ) -> Result<usize, CloudError>
    where
        F: Fn() -> bool,
    {
        let _guard = RangeContextGuard::enter(context);
        self.read_range_cancellable_inner(
            request,
            output,
            Some(context),
            MAX_RANGE_READ,
            is_cancelled,
            || {},
        )
    }

    #[cfg(test)]
    fn read_range_cancellable_with_context_and_body_hook<F, H>(
        &self,
        request: RemoteRangeRequest<'_>,
        output: &mut [u8],
        context: RangeReadContext,
        is_cancelled: F,
        on_body_chunk_consumed: H,
    ) -> Result<usize, CloudError>
    where
        F: Fn() -> bool,
        H: Fn() + Send + Sync + 'static,
    {
        let _guard = RangeContextGuard::enter(context);
        self.read_range_cancellable_inner(
            request,
            output,
            Some(context),
            MAX_RANGE_READ,
            is_cancelled,
            on_body_chunk_consumed,
        )
    }

    /// Fetch and validate one whole Cloud Files callback range. Unlike the
    /// small range API, this stages up to 16 MiB and performs one conditional
    /// GET so file/root metadata is not revalidated for every 64 KiB native
    /// transfer slice. The caller must reserve memory before allocating
    /// `output` and retain its authorization/revocation lease until publish.
    pub fn read_callback_range_cancellable_with_context<F>(
        &self,
        request: RemoteRangeRequest<'_>,
        output: &mut [u8],
        context: RangeReadContext,
        is_cancelled: F,
    ) -> Result<usize, CloudError>
    where
        F: Fn() -> bool,
    {
        let _guard = RangeContextGuard::enter(context);
        self.read_range_cancellable_inner(
            request,
            output,
            Some(context),
            MAX_CALLBACK_RANGE_BYTES,
            is_cancelled,
            || {},
        )
    }

    /// Callback form that owns its staging buffer and returns it only after
    /// complete response, post-metadata, and token-generation validation.
    /// This avoids keeping a second 16 MiB temporary alongside the provider's
    /// staging permit.
    pub fn read_callback_range_to_vec_cancellable_with_context<F>(
        &self,
        request: RemoteRangeRequest<'_>,
        length: usize,
        context: RangeReadContext,
        is_cancelled: F,
    ) -> Result<Vec<u8>, CloudError>
    where
        F: Fn() -> bool,
    {
        if length > MAX_CALLBACK_RANGE_BYTES {
            return Err(invalid("callback range exceeds its bounded size"));
        }
        let mut bytes = vec![0; length];
        let _guard = RangeContextGuard::enter(context);
        self.read_range_cancellable_inner(
            request,
            &mut bytes,
            Some(context),
            MAX_CALLBACK_RANGE_BYTES,
            is_cancelled,
            || {},
        )?;
        Ok(bytes)
    }

    fn read_range_cancellable_inner<F>(
        &self,
        request: RemoteRangeRequest<'_>,
        output: &mut [u8],
        context: Option<RangeReadContext>,
        max_range_read: usize,
        is_cancelled: F,
        on_body_chunk_consumed: impl Fn() + Send + Sync + 'static,
    ) -> Result<usize, CloudError>
    where
        F: Fn() -> bool,
    {
        let RemoteRangeRequest {
            space,
            expected_root_id,
            path,
            expected_id,
            expected_etag,
            expected_size,
            offset,
        } = request;
        let transfer_cancellation = self.transfer_budget.cancellation();
        let expected_token_generation = context.map(|context| context.token_generation);
        let token_generation = Arc::clone(&self.token_generation);
        let cancelled = || {
            is_cancelled()
                || transfer_cancellation.is_cancelled()
                || expected_token_generation
                    .is_some_and(|expected| token_generation.load(Ordering::Acquire) != expected)
        };
        ensure_not_cancelled(&cancelled)?;
        if output.len() > max_range_read
            || expected_id.is_empty()
            || expected_etag.is_empty()
            || expected_id.len() > MAX_DAV_ENTRY
            || expected_etag.len() > MAX_DAV_ENTRY
            || expected_id.chars().any(char::is_control)
            || expected_etag.chars().any(char::is_control)
            || !is_strong_etag(expected_etag)
            || HeaderValue::from_str(expected_etag).is_err()
            || offset > expected_size
            || expected_root_id.is_empty()
            || expected_root_id.len() > MAX_DAV_ENTRY
            || expected_root_id.chars().any(char::is_control)
        {
            return Err(invalid("range request metadata is invalid"));
        }
        let (selected, url) = self.transfer_url(space, path)?;
        ensure_not_cancelled(&cancelled)?;
        self.ensure_plain_ancestors(&selected, path, false)?;
        ensure_not_cancelled(&cancelled)?;
        let root_before =
            self.ensure_plain_ancestors_with_context(&selected, path, false, context)?;
        ensure_not_cancelled(&cancelled)?;
        if root_before != expected_root_id {
            return Err(conflict("Space root identity changed"));
        }
        let before = self.stat(space, path)?;
        ensure_not_cancelled(&cancelled)?;
        validate_range_identity(&before, expected_id, expected_etag, expected_size)?;
        if before.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted remote content cannot be read through ordinary DAV",
            ));
        }
        if before.directory {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "directories do not have readable file ranges",
            ));
        }
        if output.is_empty() || offset == expected_size {
            return Ok(0);
        }
        let length = output
            .len()
            .min((expected_size - offset).min(usize::MAX as u64) as usize);
        let end = offset
            .checked_add(length as u64)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| invalid("range request bounds overflow"))?;

        let transfer_timeout = match context {
            Some(context) => transfer_timeout_for_context(
                context,
                &self.transfer_budget,
                TransferDirection::Download,
                length as u64,
            )?,
            None => transfer_timeout_with_budget(
                &self.transfer_budget,
                TransferDirection::Download,
                length as u64,
            ),
        };
        let (request, token) = self.request_async(Method::GET, &url)?;
        let budget = self.transfer_budget.clone();
        let operation_cancellation = transfer_cancellation.clone();
        let watchdog_cancellation = operation_cancellation.clone();
        let watchdog_token_generation = Arc::clone(&token_generation);
        let body_token_generation = Arc::clone(&token_generation);
        let caller_cancelled = &is_cancelled;
        let range_header = format!("bytes={offset}-{end}");
        let expected_etag_owned = expected_etag.to_owned();
        let expected_size_for_body = expected_size;
        let length_for_body = length;
        let body_result = async_body::run_body_operation_cancellable(
            self.body_idle_timeout,
            transfer_timeout,
            || {
                caller_cancelled()
                    || watchdog_cancellation.is_cancelled()
                    || expected_token_generation.is_some_and(|expected| {
                        watchdog_token_generation.load(Ordering::Acquire) != expected
                    })
            },
            move |progress| async move {
                let response = request
                    .header(RANGE, range_header)
                    .header(IF_MATCH, expected_etag_owned.as_str())
                    .timeout(transfer_timeout)
                    .send()
                    .await
                    .map_err(network)?;
                let mut response = checked_async(response, &[StatusCode::PARTIAL_CONTENT], &token)?;
                if response.headers().get(ACCEPT_RANGES).is_some_and(|value| {
                    value
                        .to_str()
                        .ok()
                        .is_some_and(|text| !text.eq_ignore_ascii_case("bytes"))
                }) {
                    return Err(invalid("server returned an unsupported range unit"));
                }
                let response_etag = response
                    .headers()
                    .get(ETAG)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| invalid("range response omitted its entity tag"))?;
                if response_etag != expected_etag_owned {
                    return Err(conflict("remote item changed during range read"));
                }
                let content_range = response
                    .headers()
                    .get(CONTENT_RANGE)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| invalid("range response omitted Content-Range"))?;
                validate_content_range(content_range, offset, end, expected_size_for_body)?;
                let advertised = response
                    .content_length()
                    .ok_or_else(|| invalid("range response omitted Content-Length"))?;
                if advertised != length_for_body as u64 {
                    return Err(invalid(
                        "range response length does not match the requested range",
                    ));
                }
                let mut staged = async_body::VecAsyncWriter::default();
                let copied = async_body::copy_response_body_observed(
                    &mut response,
                    &mut staged,
                    length_for_body as u64,
                    &budget,
                    || {
                        caller_cancelled()
                            || operation_cancellation.is_cancelled()
                            || expected_token_generation.is_some_and(|expected| {
                                body_token_generation.load(Ordering::Acquire) != expected
                            })
                    },
                    &progress,
                    on_body_chunk_consumed,
                )
                .await?;
                if copied != length_for_body as u64 {
                    return Err(invalid("range response body is shorter than requested"));
                }
                Ok(staged.into_inner())
            },
        );
        let body = match body_result {
            Ok(body) => body,
            Err(_)
                if expected_token_generation.is_some_and(|expected| {
                    token_generation.load(Ordering::Acquire) != expected
                }) =>
            {
                return Err(CloudError::new(
                    ErrorKind::Unauthorized,
                    "authenticated provider generation changed during range read",
                ));
            }
            Err(error) => return Err(error),
        };
        ensure_not_cancelled(&cancelled)?;

        // Re-stat after the body is received to reject path replacement or a
        // revision/identity change that raced the conditional GET.
        let after = self.stat(space, path)?;
        ensure_not_cancelled(&cancelled)?;
        validate_range_identity(&after, expected_id, expected_etag, expected_size)?;
        if after.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted remote content cannot be read through ordinary DAV",
            ));
        }
        if after.directory {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "directories do not have readable file ranges",
            ));
        }
        let (selected_after, _) = self.resolve_dav_with_context(space, path, context)?;
        let root_after =
            self.ensure_plain_ancestors_with_context(&selected_after, path, false, context)?;
        ensure_not_cancelled(&is_cancelled)?;
        if root_after != expected_root_id {
            return Err(conflict("Space root identity changed"));
        }
        if context.is_some_and(|context| {
            self.token_generation.load(Ordering::Acquire) != context.token_generation
        }) {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        if let Some(context) = context {
            self.with_token_generation(context.token_generation, || {
                output[..length].copy_from_slice(&body);
                length
            })
        } else {
            output[..length].copy_from_slice(&body);
            Ok(length)
        }
    }
}

fn apply_proxy(
    builder: reqwest::blocking::ClientBuilder,
    proxy: &ProxyConfig,
) -> Result<reqwest::blocking::ClientBuilder, CloudError> {
    proxy.validate()?;
    match proxy {
        ProxyConfig::System => Ok(builder),
        ProxyConfig::Direct => Ok(builder.no_proxy()),
        ProxyConfig::Explicit { url } => {
            let proxy = Proxy::all(url).map_err(|_| invalid("proxy URL is malformed"))?;
            Ok(builder.no_proxy().proxy(proxy))
        }
    }
}

fn apply_proxy_async(
    builder: reqwest::ClientBuilder,
    proxy: &ProxyConfig,
) -> Result<reqwest::ClientBuilder, CloudError> {
    proxy.validate()?;
    match proxy {
        ProxyConfig::System => Ok(builder),
        ProxyConfig::Direct => Ok(builder.no_proxy()),
        ProxyConfig::Explicit { url } => {
            let proxy = Proxy::all(url).map_err(|_| invalid("proxy URL is malformed"))?;
            Ok(builder.no_proxy().proxy(proxy))
        }
    }
}

#[cfg(feature = "synthetic-test-ca")]
fn add_synthetic_test_ca(
    builder: reqwest::blocking::ClientBuilder,
    server: &Url,
) -> Result<reqwest::blocking::ClientBuilder, CloudError> {
    let origin = std::env::var("RAIUN_SYNTHETIC_TEST_CA_ORIGIN").ok();
    let pem_path = std::env::var_os("RAIUN_SYNTHETIC_TEST_CA_PEM");
    let (origin, pem_path) = match (origin, pem_path) {
        (None, None) => return Ok(builder),
        (Some(origin), Some(path)) => (normalize_synthetic_ca_origin(&origin)?, path),
        _ => return Err(invalid("synthetic test CA requires origin and PEM path")),
    };
    if server.origin().ascii_serialization() != origin
        || server.scheme() != "https"
        || !server.host_str().is_some_and(|host| {
            host.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        })
    {
        return Err(invalid(
            "synthetic test CA is limited to its exact HTTPS loopback origin",
        ));
    }
    let pem = std::fs::read(pem_path)
        .map_err(|_| invalid("could not read explicit synthetic test CA"))?;
    if pem.is_empty() || pem.len() > 65_536 {
        return Err(invalid("synthetic test CA exceeds the size limit"));
    }
    let certificate = reqwest::Certificate::from_pem(&pem)
        .map_err(|_| invalid("synthetic test CA certificate is invalid"))?;
    Ok(builder.add_root_certificate(certificate))
}

#[cfg(feature = "synthetic-test-ca")]
fn add_synthetic_test_ca_async(
    builder: reqwest::ClientBuilder,
    server: &Url,
) -> Result<reqwest::ClientBuilder, CloudError> {
    let origin = std::env::var("RAIUN_SYNTHETIC_TEST_CA_ORIGIN").ok();
    let pem_path = std::env::var_os("RAIUN_SYNTHETIC_TEST_CA_PEM");
    let (origin, pem_path) = match (origin, pem_path) {
        (None, None) => return Ok(builder),
        (Some(origin), Some(path)) => (normalize_synthetic_ca_origin(&origin)?, path),
        _ => return Err(invalid("synthetic test CA requires origin and PEM path")),
    };
    if server.origin().ascii_serialization() != origin
        || server.scheme() != "https"
        || !server.host_str().is_some_and(|host| {
            host.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        })
    {
        return Err(invalid(
            "synthetic test CA is limited to its exact HTTPS loopback origin",
        ));
    }
    let pem = std::fs::read(pem_path)
        .map_err(|_| invalid("could not read explicit synthetic test CA"))?;
    if pem.is_empty() || pem.len() > 65_536 {
        return Err(invalid("synthetic test CA exceeds the size limit"));
    }
    let certificate = reqwest::Certificate::from_pem(&pem)
        .map_err(|_| invalid("synthetic test CA certificate is invalid"))?;
    Ok(builder.add_root_certificate(certificate))
}

#[cfg(feature = "synthetic-test-ca")]
fn normalize_synthetic_ca_origin(origin: &str) -> Result<String, CloudError> {
    let parsed = Url::parse(origin).map_err(|_| invalid("synthetic CA origin is invalid"))?;
    let loopback = parsed.host_str().is_some_and(|host| {
        host.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if parsed.scheme() != "https"
        || !loopback
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return Err(invalid(
            "synthetic CA origin must be an HTTPS literal loopback origin",
        ));
    }
    let normalized = parsed.origin().ascii_serialization();
    if origin.trim_end_matches('/') != normalized {
        return Err(invalid("synthetic CA origin must not include a path"));
    }
    Ok(normalized)
}

fn validate_range_identity(
    entry: &RemoteEntry,
    expected_id: &str,
    expected_etag: &str,
    expected_size: u64,
) -> Result<(), CloudError> {
    if entry.id != expected_id || entry.etag != expected_etag || entry.size != expected_size {
        return Err(conflict("remote item identity or revision changed"));
    }
    Ok(())
}

fn is_strong_etag(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2
        && bytes.first() == Some(&b'"')
        && bytes.last() == Some(&b'"')
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte))
}

fn recovery_target_path(root: &str, relative: &str) -> Result<String, CloudError> {
    const MAX_RECOVERY_PATH: usize = 32 * 1024;
    if root.is_empty()
        || root.len() > MAX_RECOVERY_PATH
        || !root.starts_with('/')
        || root.contains('\\')
        || root.contains('?')
        || root.contains('#')
        || root.chars().any(char::is_control)
        || root.split('/').any(|part| matches!(part, "." | ".."))
        || relative.is_empty()
        || relative.len() > MAX_RECOVERY_PATH
        || relative.starts_with('/')
        || relative.ends_with('/')
        || relative.contains('\\')
        || relative.contains('?')
        || relative.contains('#')
        || relative.chars().any(char::is_control)
        || relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(invalid("recovery target path is invalid"));
    }
    let normalized_root = root.trim_end_matches('/');
    let target = if normalized_root.is_empty() {
        format!("/{relative}")
    } else {
        format!("{normalized_root}/{relative}")
    };
    if target.len() > MAX_RECOVERY_PATH {
        return Err(invalid("recovery target path exceeds its limit"));
    }
    Ok(target)
}

fn validate_recovery_entry(entry: &RemoteEntry, expected_path: &str) -> Result<(), CloudError> {
    if entry.id.is_empty()
        || entry.id.len() > MAX_DAV_ENTRY
        || entry.id.chars().any(char::is_control)
        || entry.path.trim_end_matches('/') != expected_path.trim_end_matches('/')
    {
        return Err(conflict(
            "recovery lookup returned a different remote object",
        ));
    }
    Ok(())
}

fn ensure_not_cancelled(is_cancelled: &impl Fn() -> bool) -> Result<(), CloudError> {
    if is_cancelled() {
        Err(CloudError::new(ErrorKind::Offline, "range read cancelled"))
    } else {
        Ok(())
    }
}

fn validate_content_range(
    value: &str,
    expected_start: u64,
    expected_end: u64,
    expected_size: u64,
) -> Result<(), CloudError> {
    let (unit, range) = value
        .split_once(' ')
        .ok_or_else(|| invalid("range response Content-Range is malformed"))?;
    let (bounds, total) = range
        .split_once('/')
        .ok_or_else(|| invalid("range response Content-Range is malformed"))?;
    let (start, end) = bounds
        .split_once('-')
        .ok_or_else(|| invalid("range response Content-Range is malformed"))?;
    let parsed = (
        start.parse::<u64>(),
        end.parse::<u64>(),
        total.parse::<u64>(),
    );
    let (Ok(start), Ok(end), Ok(total)) = parsed else {
        return Err(invalid("range response Content-Range is malformed"));
    };
    if !unit.eq_ignore_ascii_case("bytes")
        || start != expected_start
        || end != expected_end
        || total != expected_size
        || end < start
    {
        return Err(invalid(
            "range response Content-Range does not match the request",
        ));
    }
    Ok(())
}

impl OpenCloudClient {
    /// Perform one bounded direct-child listing under the captured provider
    /// deadline and bearer generation. Visitors must stage entries until this
    /// returns successfully; an error means the listing is incomplete.
    pub fn list_with_context(
        &self,
        space: &str,
        path: &str,
        context: RangeReadContext,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        let _guard = RangeContextGuard::enter(context);
        CloudBackend::list(self, space, path, visit)?;
        if self.token_generation.load(Ordering::Acquire) != context.token_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(())
    }

    /// Perform one metadata lookup under a fixed provider-operation deadline
    /// and captured bearer generation. Intended for trusted provider setup,
    /// not general user-facing DAV operations.
    pub fn stat_with_context(
        &self,
        space: &str,
        path: &str,
        context: RangeReadContext,
    ) -> Result<RemoteEntry, CloudError> {
        let _guard = RangeContextGuard::enter(context);
        let entry = CloudBackend::stat(self, space, path)?;
        if self.token_generation.load(Ordering::Acquire) != context.token_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(entry)
    }

    /// Stat one recovered edit target beneath an exact configured remote root.
    /// The root resource ID, relative path, and auth generation are all
    /// revalidated for this request; this API does not accept callback URLs.
    pub fn recovery_stat_with_context(
        &self,
        space: &str,
        remote_root_path: &str,
        expected_root_id: &str,
        relative_path: &str,
        context: RangeReadContext,
    ) -> Result<RemoteEntry, CloudError> {
        let _guard = RangeContextGuard::enter(context);
        let path = recovery_target_path(remote_root_path, relative_path)?;
        self.validate_recovery_root(space, remote_root_path, expected_root_id)?;
        let entry = CloudBackend::stat(self, space, &path)?;
        validate_recovery_entry(&entry, &path)?;
        self.validate_recovery_root(space, remote_root_path, expected_root_id)?;
        self.ensure_context_current(context)?;
        Ok(entry)
    }

    /// Conditionally upload a bounded recovered edit directly from memory.
    /// No plaintext staging file is created. Root and target identity/version
    /// are checked immediately before the PUT and again afterward. The
    /// client's redirect policy is `none`, and `request` rejects cross-origin
    /// URLs before attaching authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn recovery_upload_bytes_with_context(
        &self,
        space: &str,
        remote_root_path: &str,
        expected_root_id: &str,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: &str,
        expected_size: u64,
        content: &[u8],
        context: RangeReadContext,
    ) -> Result<RemoteEntry, CloudError> {
        if content.len() > MAX_RECOVERY_UPLOAD_BYTES
            || expected_resource_id.is_empty()
            || !is_strong_etag(expected_etag)
            || HeaderValue::from_str(expected_etag).is_err()
        {
            return Err(invalid("recovery upload metadata is invalid"));
        }
        let _guard = RangeContextGuard::enter(context);
        let path = recovery_target_path(remote_root_path, relative_path)?;
        self.validate_recovery_root(space, remote_root_path, expected_root_id)?;
        let before = CloudBackend::stat(self, space, &path)?;
        validate_recovery_entry(&before, &path)?;
        if before.id != expected_resource_id
            || before.etag != expected_etag
            || before.size != expected_size
            || !before.writable
        {
            return Err(conflict(
                "recovery target changed before conditional upload",
            ));
        }
        let (selected, url) = self.transfer_url(space, &path)?;
        self.ensure_writable_target(&selected, &url, &path)?;
        let (request, token) = self.request_async(Method::PUT, &url)?;
        let budget = self.transfer_budget.clone();
        let cancellation = budget.cancellation();
        let watchdog_cancellation = cancellation.clone();
        let watchdog_generation = Arc::clone(&self.token_generation);
        let body_generation = Arc::clone(&self.token_generation);
        let expected_generation = context.token_generation;
        let total_timeout = transfer_timeout_for_context(
            context,
            &budget,
            TransferDirection::Upload,
            content.len() as u64,
        )?;
        let content_size = content.len() as u64;
        let content = content.to_vec();
        let upload_result = async_body::run_body_operation_cancellable(
            self.body_idle_timeout,
            total_timeout,
            || {
                watchdog_cancellation.is_cancelled()
                    || watchdog_generation.load(Ordering::Acquire) != expected_generation
            },
            move |progress| async move {
                let body = async_body::budgeted_upload_stream(
                    tokio::io::BufReader::new(io::Cursor::new(content)),
                    content_size,
                    budget,
                    move || {
                        cancellation.is_cancelled()
                            || body_generation.load(Ordering::Acquire) != expected_generation
                    },
                    progress,
                );
                let response = request
                    .header(CONTENT_LENGTH, content_size)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .header(IF_MATCH, expected_etag)
                    .timeout(total_timeout)
                    .body(reqwest::Body::wrap_stream(body))
                    .send()
                    .await
                    .map_err(network)?;
                checked_async(
                    response,
                    &[StatusCode::CREATED, StatusCode::NO_CONTENT],
                    &token,
                )?;
                Ok(())
            },
        );
        if let Err(error) = upload_result {
            self.ensure_context_current(context)?;
            return Err(error);
        }
        self.validate_recovery_root(space, remote_root_path, expected_root_id)?;
        let after = CloudBackend::stat(self, space, &path)?;
        validate_recovery_entry(&after, &path)?;
        if after.id != expected_resource_id
            || !is_strong_etag(&after.etag)
            || after.size != content_size
        {
            return Err(conflict("recovery upload could not be verified"));
        }
        self.ensure_context_current(context)?;
        Ok(after)
    }

    /// Read back one exact target into a bounded in-memory buffer and verify
    /// the same root/resource/revision before returning it to the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn recovery_read_bytes_with_context(
        &self,
        space: &str,
        remote_root_path: &str,
        expected_root_id: &str,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: &str,
        max_bytes: usize,
        context: RangeReadContext,
    ) -> Result<(RemoteEntry, Zeroizing<Vec<u8>>), CloudError> {
        if max_bytes > MAX_RECOVERY_UPLOAD_BYTES
            || expected_resource_id.is_empty()
            || !is_strong_etag(expected_etag)
            || HeaderValue::from_str(expected_etag).is_err()
        {
            return Err(invalid("recovery read metadata is invalid"));
        }
        let _guard = RangeContextGuard::enter(context);
        let path = recovery_target_path(remote_root_path, relative_path)?;
        self.validate_recovery_root(space, remote_root_path, expected_root_id)?;
        let before = CloudBackend::stat(self, space, &path)?;
        validate_recovery_entry(&before, &path)?;
        if before.id != expected_resource_id || before.etag != expected_etag {
            return Err(conflict("recovery target changed before readback"));
        }
        if before.size > max_bytes as u64 {
            return Err(invalid("recovery readback exceeds its byte limit"));
        }
        let (_, url) = self.transfer_url(space, &path)?;
        let (request, token) = self.request_async(Method::GET, &url)?;
        let budget = self.transfer_budget.clone();
        let total_timeout = transfer_timeout_for_context(
            context,
            &budget,
            TransferDirection::Download,
            before.size,
        )?;
        let cancellation = budget.cancellation();
        let watchdog_cancellation = cancellation.clone();
        let watchdog_generation = Arc::clone(&self.token_generation);
        let body_generation = Arc::clone(&self.token_generation);
        let expected_generation = context.token_generation;
        let expected_etag_owned = expected_etag.to_owned();
        let expected_size = before.size;
        let read_result = async_body::run_body_operation_cancellable(
            self.body_idle_timeout,
            total_timeout,
            || {
                watchdog_cancellation.is_cancelled()
                    || watchdog_generation.load(Ordering::Acquire) != expected_generation
            },
            move |progress| async move {
                let response = request
                    .header(IF_MATCH, expected_etag_owned.as_str())
                    .timeout(total_timeout)
                    .send()
                    .await
                    .map_err(network)?;
                let mut response = checked_async(response, &[StatusCode::OK], &token)?;
                let advertised = response
                    .content_length()
                    .ok_or_else(|| invalid("recovery readback omitted Content-Length"))?;
                if advertised != expected_size || advertised > max_bytes as u64 {
                    return Err(conflict("recovery readback size changed"));
                }
                let response_etag = response
                    .headers()
                    .get(ETAG)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| invalid("recovery readback omitted its entity tag"))?;
                if response_etag != expected_etag_owned {
                    return Err(conflict("recovery readback revision changed"));
                }
                let mut output = async_body::VecAsyncWriter::default();
                let copied = async_body::copy_response_body(
                    &mut response,
                    &mut output,
                    max_bytes as u64,
                    &budget,
                    || body_generation.load(Ordering::Acquire) != expected_generation,
                    &progress,
                )
                .await?;
                if copied != advertised {
                    return Err(invalid("recovery readback body length is inconsistent"));
                }
                Ok(output.into_inner())
            },
        );
        let bytes = match read_result {
            Ok(bytes) => bytes,
            Err(error) => {
                self.ensure_context_current(context)?;
                return Err(error);
            }
        };
        let bytes = bytes;
        if bytes.len() as u64 != before.size {
            return Err(invalid("recovery readback body length is inconsistent"));
        }
        self.validate_recovery_root(space, remote_root_path, expected_root_id)?;
        let after = CloudBackend::stat(self, space, &path)?;
        validate_recovery_entry(&after, &path)?;
        if after.id != expected_resource_id
            || !is_strong_etag(&after.etag)
            || after.size != before.size
        {
            return Err(conflict("recovery target changed during readback"));
        }
        self.ensure_context_current(context)?;
        Ok((after, bytes))
    }

    fn validate_recovery_root(
        &self,
        space: &str,
        remote_root_path: &str,
        expected_root_id: &str,
    ) -> Result<(), CloudError> {
        if expected_root_id.is_empty()
            || expected_root_id.len() > MAX_DAV_ENTRY
            || expected_root_id.chars().any(char::is_control)
            || !remote_root_path.starts_with('/')
            || remote_root_path.contains('\\')
            || remote_root_path.chars().any(char::is_control)
            || remote_root_path
                .split('/')
                .any(|part| matches!(part, "." | ".."))
            || (remote_root_path != "/"
                && remote_root_path
                    .trim_end_matches('/')
                    .split('/')
                    .skip(1)
                    .any(str::is_empty))
        {
            return Err(invalid("recovery root identity is invalid"));
        }
        let root = CloudBackend::stat(self, space, remote_root_path)?;
        if root.id != expected_root_id || !root.directory || root.encrypted {
            return Err(conflict("recovery root identity changed"));
        }
        Ok(())
    }

    fn ensure_context_current(&self, context: RangeReadContext) -> Result<(), CloudError> {
        if context.remaining().is_err()
            || self.token_generation.load(Ordering::Acquire) != context.token_generation
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed or expired",
            ));
        }
        Ok(())
    }

    /// Inspect the root of a Space returned by this client's immediately
    /// preceding `spaces_with_context` call. This metadata-only operation
    /// deliberately returns encryption markers instead of routing through
    /// ordinary plaintext DAV guards, so a trusted provider can exclude an
    /// encrypted Space without ever listing its contents.
    pub fn stat_discovered_space_root_with_context(
        &self,
        space: &CloudSpace,
        context: RangeReadContext,
    ) -> Result<RemoteEntry, CloudError> {
        let _guard = RangeContextGuard::enter(context);
        if self.token_generation.load(Ordering::Acquire) != context.token_generation
            || space.id.is_empty()
            || space.id.len() > MAX_DAV_ENTRY
            || space.id.chars().any(char::is_control)
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation or Space identity is invalid",
            ));
        }
        let root_url =
            Url::parse(&space.dav_url).map_err(|_| invalid("Graph drive WebDAV URL is invalid"))?;
        validate_server(&root_url)?;
        if !same_origin(&self.server, &root_url)
            || !root_url.username().is_empty()
            || root_url.password().is_some()
            || root_url.query().is_some()
            || root_url.fragment().is_some()
        {
            return Err(invalid(
                "Graph drive WebDAV URL is outside the configured origin",
            ));
        }
        let mut found = None;
        self.propfind_with_context(
            &root_url,
            "0",
            "/",
            &mut |entry| {
                if found.is_some() {
                    return Err(invalid("Space root inspection returned multiple entries"));
                }
                if !entry.path.trim_end_matches('/').is_empty() {
                    return Err(invalid("Space root inspection returned a different path"));
                }
                found = Some(entry);
                Ok(())
            },
            Some(context),
        )?;
        let root = found
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "Space root was not found"))?;
        if !root.directory || root.id.is_empty() || root.id.chars().any(char::is_control) {
            return Err(invalid("Space root identity is invalid"));
        }
        if self.token_generation.load(Ordering::Acquire) != context.token_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(root)
    }

    /// Discover the authenticated account's Spaces under one deadline and
    /// bearer generation. Provider namespace construction uses this to bind
    /// Personal and Spaces routes to a verified account identity.
    pub fn spaces_with_context(
        &self,
        context: RangeReadContext,
    ) -> Result<Vec<CloudSpace>, CloudError> {
        self.spaces_with_context_limited(context, MAX_ENTRIES)
    }

    /// As above, with a caller-selected smaller response cap for bounded
    /// provider namespace construction.
    pub fn spaces_with_context_limited(
        &self,
        context: RangeReadContext,
        max_spaces: usize,
    ) -> Result<Vec<CloudSpace>, CloudError> {
        if max_spaces == 0 || max_spaces > MAX_ENTRIES {
            return Err(invalid("Space discovery limit is invalid"));
        }
        let _guard = RangeContextGuard::enter(context);
        let spaces = self.discover_spaces(Some(context), max_spaces)?;
        if self.token_generation.load(Ordering::Acquire) != context.token_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(spaces)
    }

    fn discover_spaces(
        &self,
        context: Option<RangeReadContext>,
        max_spaces: usize,
    ) -> Result<Vec<CloudSpace>, CloudError> {
        let start = self
            .server
            .join("graph/v1.0/me/drives")
            .map_err(|_| invalid("Graph endpoint is invalid"))?;
        let mut next = Some(start.clone());
        let mut visited = std::collections::HashSet::new();
        let mut ids = std::collections::HashSet::new();
        let mut result = Vec::new();
        while let Some(url) = next.take() {
            if !same_origin(&start, &url)
                || !visited.insert(url.as_str().to_owned())
                || visited.len() > MAX_PAGES
            {
                return Err(invalid("Graph pagination is invalid or exceeds its limit"));
            }
            let payload: Value =
                serde_json::from_slice(&self.graph_get_with_context(&url, context)?)
                    .map_err(|_| invalid("Graph response is invalid JSON"))?;
            let records = payload
                .get("value")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("Graph response has no drive list"))?;
            for record in records {
                let id = required_string(record, "id")?;
                if !ids.insert(id.clone()) || ids.len() > max_spaces {
                    return Err(invalid(
                        "Graph drive list contains duplicate IDs or exceeds its limit",
                    ));
                }
                let name = required_string(record, "name")?;
                let drive_type = record
                    .get("driveType")
                    .and_then(Value::as_str)
                    .unwrap_or("project");
                let root = record
                    .get("root")
                    .and_then(Value::as_object)
                    .ok_or_else(|| invalid("Graph drive root is missing"))?;
                let dav_url = root
                    .get("webDavUrl")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("Graph drive WebDAV URL is missing"))?;
                let dav_url = Url::parse(dav_url)
                    .map_err(|_| invalid("Graph drive WebDAV URL is invalid"))?;
                validate_server(&dav_url)?;
                if !same_origin(&self.server, &dav_url) {
                    return Err(invalid(
                        "Graph drive WebDAV URL is outside the configured origin",
                    ));
                }
                let permission_value = root
                    .get("permissions")
                    .or_else(|| root.get("@libre.graph.permissions"))
                    .or_else(|| record.get("@libre.graph.permissions"));
                let encrypted = record
                    .get("@libre.graph.contentType")
                    .and_then(Value::as_str)
                    .is_some_and(is_vault_content_type)
                    || root
                        .get("@libre.graph.contentType")
                        .and_then(Value::as_str)
                        .is_some_and(is_vault_content_type)
                    || record
                        .get("@libre.graph.encrypted")
                        .and_then(Value::as_bool)
                        == Some(true)
                    || root.get("@libre.graph.encrypted").and_then(Value::as_bool) == Some(true)
                    || record.get("encrypted").and_then(Value::as_bool) == Some(true)
                    || root.get("encrypted").and_then(Value::as_bool) == Some(true)
                    || root
                        .get("contentType")
                        .and_then(Value::as_str)
                        .is_some_and(is_vault_content_type)
                    || record
                        .get("contentType")
                        .and_then(Value::as_str)
                        .is_some_and(is_vault_content_type)
                    || is_vault_name(&name);
                result.push(CloudSpace {
                    id,
                    name: name.clone(),
                    dav_url: dav_url.to_string(),
                    personal: drive_type == "personal",
                    writable: permission_value
                        .map(graph_permissions_writable)
                        .unwrap_or(true),
                    encrypted,
                });
            }
            if let Some(link) = payload.get("@odata.nextLink").and_then(Value::as_str) {
                let url = url
                    .join(link)
                    .map_err(|_| invalid("Graph pagination link is invalid"))?;
                if !same_origin(&start, &url) {
                    return Err(invalid(
                        "Graph pagination link leaves the configured origin",
                    ));
                }
                next = Some(url);
            }
        }
        if !result.iter().any(|space| space.personal) {
            return Err(invalid("Graph response did not include the personal drive"));
        }
        result.sort_by(|a, b| {
            a.personal
                .cmp(&b.personal)
                .reverse()
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(result)
    }
}

impl OpenCloudClient {
    fn check_transfer_root(
        &self,
        selected: &CloudSpace,
        path: &str,
        expected_root: Option<&str>,
    ) -> Result<(), CloudError> {
        let actual = self.ensure_plain_ancestors_with_context(selected, path, false, None)?;
        if expected_root.is_some_and(|expected| expected != actual) {
            return Err(conflict(
                "Space root changed before transfer; local bytes were preserved",
            ));
        }
        Ok(())
    }
    fn root_write_condition(
        &self,
        selected: &CloudSpace,
        path: &str,
        expected_root: &str,
    ) -> Result<String, CloudError> {
        let root = self.ordinary_ancestor_root_entry_with_context(selected, path, false, None)?;
        if root.id != expected_root {
            return Err(conflict(
                "Space root changed before transfer; local bytes were preserved",
            ));
        }
        let etag = root.etag.as_bytes();
        if etag.len() < 2
            || etag.len() > 4096
            || etag[0] != b'"'
            || etag[etag.len() - 1] != b'"'
            || etag[1..etag.len() - 1]
                .iter()
                .any(|byte| *byte < 0x21 || *byte > 0x7e || *byte == b'"')
        {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "Space root has no strong revision for conditional creation; local bytes were preserved",
            ));
        }
        let root_url =
            Url::parse(&selected.dav_url).map_err(|_| invalid("space DAV URL is invalid"))?;
        if !same_origin(&self.server, &root_url)
            || root_url.query().is_some()
            || root_url.fragment().is_some()
        {
            return Err(invalid(
                "Space root URL cannot be used for a conditional creation",
            ));
        }
        // RFC 4918 tagged If condition: the server checks the root revision
        // atomically with the leaf's If-None-Match condition when applying PUT.
        Ok(format!("<{}> ([{}])", root_url, root.etag))
    }

    fn stat_at_dav(&self, url: &Url, path: &str) -> Result<RemoteEntry, CloudError> {
        let mut found = None;
        self.propfind(url, "0", path, &mut |entry| {
            if found.is_some() {
                return Err(invalid("DAV stat returned multiple entries"));
            }
            found = Some(entry);
            Ok(())
        })?;
        let entry = found
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "remote item was not found"))?;
        if entry.path.trim_end_matches('/') != path.trim_end_matches('/') {
            return Err(invalid(
                "DAV stat returned an item other than the requested path",
            ));
        }
        Ok(entry)
    }
    fn download_with_root(
        &self,
        space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
        expected_root: Option<&str>,
    ) -> Result<RemoteEntry, CloudError> {
        let (mut selected, url) = self.transfer_url(space, path)?;
        if let Some(root) = expected_root {
            selected.dav_url = self
                .validate_identity_addressed_root(&selected, root)?
                .to_string();
        }
        let before = if expected_root.is_some() {
            self.check_transfer_root(&selected, path, expected_root)?;
            self.stat_at_dav(&url, path)?
        } else {
            self.stat(space, path)?
        };
        if before.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted remote content cannot be downloaded as plaintext",
            ));
        }
        if let Some(expected) = expected_etag {
            if expected != before.etag {
                return Err(conflict("remote item changed before download"));
            }
        }
        let (mut request, token) = self.request_async(Method::GET, &url)?;
        if let Some(etag) = expected_etag {
            request = request.header(IF_MATCH, etag);
        }
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut staged = NamedTempFile::new_in(parent).map_err(io_error)?;
        let output = staged.as_file().try_clone().map_err(io_error)?;
        let budget = self.transfer_budget.clone();
        let cancellation = budget.cancellation();
        let watchdog_cancellation = cancellation.clone();
        let expected_size = before.size;
        let total_timeout =
            transfer_timeout_with_budget(&budget, TransferDirection::Download, expected_size);
        let copied = async_body::run_body_operation_cancellable(
            self.body_idle_timeout,
            total_timeout,
            || watchdog_cancellation.is_cancelled(),
            move |progress| async move {
                let response = request
                    .timeout(total_timeout)
                    .send()
                    .await
                    .map_err(network)?;
                let mut response = checked_async(response, &[StatusCode::OK], &token)?;
                let advertised = response
                    .content_length()
                    .ok_or_else(|| invalid("download response omitted Content-Length"))?;
                if advertised != expected_size {
                    return Err(conflict("download size changed during transfer"));
                }
                let mut output = tokio::fs::File::from_std(output);
                let copied = async_body::copy_response_body(
                    &mut response,
                    &mut output,
                    expected_size,
                    &budget,
                    || cancellation.is_cancelled(),
                    &progress,
                )
                .await?;
                use tokio::io::AsyncWriteExt;
                output.flush().await.map_err(io_error)?;
                output.sync_all().await.map_err(io_error)?;
                if copied != advertised {
                    return Err(invalid("download size did not match Content-Length"));
                }
                Ok(copied)
            },
        )?;
        if copied != expected_size {
            return Err(invalid("download size did not match Content-Length"));
        }
        staged.as_file_mut().flush().map_err(io_error)?;
        staged.as_file().sync_all().map_err(io_error)?;

        // Keep the caller's destination intact until the server confirms the
        // same revision is still present after the complete body is staged.
        let after = if expected_root.is_some() {
            self.check_transfer_root(&selected, path, expected_root)?;
            self.stat_at_dav(&url, path)?
        } else {
            self.stat(space, path)?
        };
        if after.etag != before.etag || after.size != copied {
            return Err(conflict("remote item changed during download"));
        }
        staged
            .persist(destination)
            .map_err(|error| io_error(error.error))?;
        Ok(after)
    }

    fn upload_with_root(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
        expected_root: Option<&str>,
    ) -> Result<RemoteEntry, CloudError> {
        let (mut selected, url) = self.transfer_url(space, path)?;
        if let Some(root) = expected_root {
            selected.dav_url = self
                .validate_identity_addressed_root(&selected, root)?
                .to_string();
        }
        self.ensure_writable_target(&selected, &url, path)?;
        let root_condition = expected_root
            .map(|root| self.root_write_condition(&selected, path, root))
            .transpose()?;
        let file = File::open(source).map_err(io_error)?;
        let size = file.metadata().map_err(io_error)?.len();
        let (mut request, token) = self.request_async(Method::PUT, &url)?;
        if let Some(condition) = root_condition {
            request = request
                .header("If", condition)
                .header("Cache-Control", "no-cache");
        }
        request = request
            .header(CONTENT_LENGTH, size)
            .header(CONTENT_TYPE, "application/octet-stream");
        request = match condition {
            WriteCondition::Absent => request.header(IF_NONE_MATCH, "*"),
            WriteCondition::Match(etag) => request.header(IF_MATCH, etag),
        };
        let budget = self.transfer_budget.clone();
        let cancellation = budget.cancellation();
        let watchdog_cancellation = cancellation.clone();
        let total_timeout = transfer_timeout_with_budget(&budget, TransferDirection::Upload, size);
        let response_token = token.clone();
        async_body::run_body_operation_cancellable(
            self.body_idle_timeout,
            total_timeout,
            || watchdog_cancellation.is_cancelled(),
            move |progress| async move {
                let body = async_body::budgeted_upload_stream(
                    tokio::fs::File::from_std(file),
                    size,
                    budget,
                    move || cancellation.is_cancelled(),
                    progress,
                );
                let response = request
                    .timeout(total_timeout)
                    .body(reqwest::Body::wrap_stream(body))
                    .send()
                    .await
                    .map_err(network)?;
                checked_async(
                    response,
                    &[StatusCode::CREATED, StatusCode::NO_CONTENT],
                    &response_token,
                )?;
                Ok(())
            },
        )?;
        let entry = if expected_root.is_some() {
            self.check_transfer_root(&selected, path, expected_root)?;
            self.stat_at_dav(&url, path)?
        } else {
            self.stat(space, path)?
        };
        if entry.size != size {
            return Err(invalid("uploaded file failed size verification"));
        }
        Ok(entry)
    }
}

impl CloudBackend for OpenCloudClient {
    fn server_origin(&self) -> Option<String> {
        Some(self.server.origin().ascii_serialization())
    }

    fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
        self.discover_spaces(None, MAX_ENTRIES)
    }

    fn list(
        &self,
        space: &str,
        path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        let (selected, url) = self.transfer_url(space, path)?;
        self.ensure_plain_ancestors(&selected, path, true)?;
        let scope = path.trim_end_matches('/');
        let mut response_entries = Vec::new();
        self.propfind(&url, "1", path, &mut |entry| {
            if response_entries.len() > MAX_ENTRIES {
                return Err(invalid("DAV listing exceeds its entry limit"));
            }
            response_entries.push(entry);
            Ok(())
        })?;
        for entry in &response_entries {
            if entry.path.trim_end_matches('/') == scope && entry.encrypted {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "encrypted vault folders are unavailable to ordinary DAV operations",
                ));
            }
        }
        let mut emitted = 0;
        for entry in response_entries {
            if entry.path.trim_end_matches('/') == scope {
                continue;
            }
            if !is_direct_child(scope, &entry.path) {
                return Err(invalid(
                    "DAV listing returned an item outside the requested directory",
                ));
            }
            emitted += 1;
            if emitted > MAX_ENTRIES {
                return Err(invalid("DAV listing exceeds its entry limit"));
            }
            visit(entry)?;
        }
        Ok(())
    }

    fn stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        let (selected, url) = self.transfer_url(space, path)?;
        self.ensure_plain_ancestors(&selected, path, false)?;
        let mut found = None;
        self.propfind(&url, "0", path, &mut |entry| {
            if found.is_some() {
                return Err(invalid("DAV stat returned multiple entries"));
            }
            found = Some(entry);
            Ok(())
        })?;
        let entry = found
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "remote item was not found"))?;
        if entry.path.trim_end_matches('/') != path.trim_end_matches('/') {
            return Err(invalid(
                "DAV stat returned an item other than the requested path",
            ));
        }
        Ok(entry)
    }

    fn download(
        &self,
        space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<RemoteEntry, CloudError> {
        self.download_with_root(space, path, expected_etag, destination, None)
    }
    fn upload(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        self.upload_with_root(space, path, source, condition, None)
    }
    fn upload_in_root(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
        expected_root: &str,
    ) -> Result<RemoteEntry, CloudError> {
        self.upload_with_root(space, path, source, condition, Some(expected_root))
    }
    fn download_in_root(
        &self,
        space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
        expected_root: &str,
    ) -> Result<RemoteEntry, CloudError> {
        self.download_with_root(space, path, expected_etag, destination, Some(expected_root))
    }

    fn mkdir(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        let (selected, url) = self.transfer_url(space, path)?;
        self.ensure_writable_target(&selected, &url, path)?;
        let (request, token) =
            self.request(Method::from_bytes(b"MKCOL").expect("static method"), &url)?;
        let response = request.send().map_err(network)?;
        checked(response, &[StatusCode::CREATED], &token)?;
        self.stat(space, path)
    }

    fn delete(&self, space: &str, path: &str, expected_etag: &str) -> Result<(), CloudError> {
        // Direct backend callers must not bypass the Engine's root guard.
        // Slash-only aliases resolve to the same Space DAV endpoint.
        if path.is_empty() || path.bytes().all(|byte| byte == b'/') {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot delete a cloud Space root",
            ));
        }
        let (selected, url) = self.transfer_url(space, path)?;
        self.ensure_writable_target(&selected, &url, path)?;
        let (request, token) = self.request(Method::DELETE, &url)?;
        let response = request
            .header(IF_MATCH, expected_etag)
            .send()
            .map_err(network)?;
        checked(response, &[StatusCode::NO_CONTENT, StatusCode::OK], &token)?;
        Ok(())
    }

    fn rename(
        &self,
        space: &str,
        from: &str,
        to: &str,
        expected_etag: &str,
    ) -> Result<RemoteEntry, CloudError> {
        let (selected, source) = self.transfer_url(space, from)?;
        let (_, destination) = self.transfer_url(space, to)?;
        if source == destination {
            return self.stat(space, from);
        }
        self.ensure_writable_target(&selected, &source, from)?;
        self.ensure_writable_target(&selected, &destination, to)?;
        let (request, token) =
            self.request(Method::from_bytes(b"MOVE").expect("static method"), &source)?;
        let response = request
            .header(IF_MATCH, expected_etag)
            .header("Destination", destination.as_str())
            .header("Overwrite", "F")
            .send()
            .map_err(network)?;
        checked(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            &token,
        )?;
        self.stat(space, to)
    }
}

fn validate_server(url: &Url) -> Result<(), CloudError> {
    let loopback = url.host_str().is_some_and(|host| {
        host.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "server must be HTTPS; HTTP is allowed only for literal loopback test hosts",
        ));
    }
    Ok(())
}

fn normalized_server(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url
}
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn append_logical_path(root: &Url, path: &str) -> Result<Url, CloudError> {
    validate_logical_path(path)?;
    let mut out = root.clone();
    {
        let mut segments = out
            .path_segments_mut()
            .map_err(|_| invalid("DAV URL cannot contain paths"))?;
        segments.pop_if_empty();
        for part in path.split('/').filter(|part| !part.is_empty()) {
            segments.push(part);
        }
        if path.ends_with('/') || path == "/" {
            segments.push("");
        }
    }
    Ok(out)
}

fn validate_logical_path(path: &str) -> Result<(), CloudError> {
    if !path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err(invalid(
            "remote path must be absolute and contain no traversal components",
        ));
    }
    Ok(())
}

#[derive(Default, Debug)]
struct DavItem {
    href: String,
    directory: bool,
    size: u64,
    etag: String,
    modified: i64,
    file_id: Option<String>,
    encrypted: bool,
    content_type: Option<String>,
    writable: Option<bool>,
}

fn parse_multistatus(
    bytes: &[u8],
    requested: &Url,
    logical_path: &str,
    visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
) -> Result<(), CloudError> {
    let mut reader = NsReader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut entries = 0usize;
    let mut item: Option<DavItem> = None;
    let mut prop_values = DavItem::default();
    let mut field = String::new();
    let mut depth = 0usize;
    let mut in_prop = false;
    let mut propstat_ok = false;
    let mut saw_root = false;
    loop {
        match reader.read_resolved_event_into(&mut buf) {
            Ok((namespace, Event::Start(e))) => {
                let name = local_name(e.local_name().as_ref()).to_ascii_lowercase();
                let namespace_ok = expected_namespace(&name)
                    .is_some_and(|expected| namespace_is(&namespace, expected));
                if name == "multistatus" {
                    if saw_root || !namespace_is(&namespace, b"DAV:") {
                        return Err(invalid("DAV response has an invalid root element"));
                    }
                    saw_root = true;
                }
                if name == "response" && !namespace_is(&namespace, b"DAV:") {
                    return Err(invalid("DAV response element uses an invalid namespace"));
                }
                depth += 1;
                if name == "response" {
                    if item.is_some() {
                        return Err(invalid("nested DAV response"));
                    }
                    item = Some(DavItem::default());
                    depth = 1;
                }
                if namespace_is(&namespace, b"DAV:") && name == "propstat" {
                    propstat_ok = false;
                    prop_values = DavItem::default();
                }
                if namespace_is(&namespace, b"DAV:") && name == "prop" {
                    in_prop = true;
                }
                if item.is_some() {
                    if depth > 32 {
                        return Err(invalid("DAV entry nesting exceeds its limit"));
                    }
                    field = if namespace_ok {
                        name.clone()
                    } else {
                        String::new()
                    };
                    if namespace_is(&namespace, b"DAV:") && in_prop && name == "collection" {
                        prop_values.directory = true;
                    }
                    if namespace_is(&namespace, b"http://graph.opencloud.eu/ns")
                        && in_prop
                        && name == "encrypted"
                    {
                        prop_values.encrypted = true;
                    }
                }
            }
            Ok((namespace, Event::Empty(e))) => {
                let name = local_name(e.local_name().as_ref()).to_ascii_lowercase();
                if item.is_some() {
                    if namespace_is(&namespace, b"DAV:") && in_prop && name == "collection" {
                        prop_values.directory = true;
                    }
                    if namespace_is(&namespace, b"http://graph.opencloud.eu/ns")
                        && in_prop
                        && name == "encrypted"
                    {
                        prop_values.encrypted = true;
                    }
                }
            }
            Ok((_, Event::Text(e))) => {
                if let Some(ref mut current) = item {
                    let text = e
                        .decode()
                        .map_err(|_| invalid("DAV response contains invalid text"))?;
                    if text.len() > MAX_DAV_ENTRY {
                        return Err(invalid("DAV property exceeds its size limit"));
                    }
                    let value = text.trim();
                    match field.as_str() {
                        "href" if current.href.is_empty() => current.href = value.to_owned(),
                        "getcontentlength" if in_prop => {
                            prop_values.size = value
                                .parse()
                                .map_err(|_| invalid("DAV content length is invalid"))?
                        }
                        "getetag" if in_prop => prop_values.etag = value.to_owned(),
                        "getlastmodified" if in_prop => {
                            prop_values.modified = parse_http_date(value).unwrap_or(0)
                        }
                        "fileid" if in_prop => prop_values.file_id = Some(value.to_owned()),
                        "integrity-id" if in_prop && !value.is_empty() => {
                            prop_values.encrypted = true
                        }
                        "permissions" if in_prop => {
                            prop_values.writable = Some(dav_permissions_writable(value))
                        }
                        "encrypted" if in_prop => {
                            prop_values.encrypted = value.eq_ignore_ascii_case("true")
                        }
                        "contenttype" if in_prop => {
                            prop_values.content_type = Some(value.to_owned())
                        }
                        "getcontenttype" if in_prop => {
                            prop_values.content_type = Some(value.to_owned())
                        }
                        "status" if value.split_whitespace().nth(1) == Some("200") => {
                            propstat_ok = true
                        }
                        _ => {}
                    }
                }
            }
            Ok((namespace, Event::End(e))) => {
                let name = local_name(e.local_name().as_ref()).to_ascii_lowercase();
                let dav_element = namespace_is(&namespace, b"DAV:");
                if dav_element && name == "prop" {
                    in_prop = false;
                }
                if dav_element && name == "propstat" && propstat_ok {
                    if let Some(ref mut current) = item {
                        current.directory |= prop_values.directory;
                        current.encrypted |= prop_values.encrypted;
                        current.size = prop_values.size;
                        if !prop_values.etag.is_empty() {
                            current.etag = std::mem::take(&mut prop_values.etag);
                        }
                        current.modified = prop_values.modified;
                        current.file_id = prop_values
                            .file_id
                            .take()
                            .or_else(|| current.file_id.take());
                        current.content_type = prop_values
                            .content_type
                            .take()
                            .or_else(|| current.content_type.take());
                        current.writable = prop_values.writable.or(current.writable);
                    }
                }
                if dav_element && name == "response" {
                    let finished = item
                        .take()
                        .ok_or_else(|| invalid("DAV response structure is invalid"))?;
                    if !finished.href.is_empty() {
                        visit(to_remote_entry(finished, requested, logical_path)?)?;
                        entries += 1;
                        if entries > MAX_ENTRIES {
                            return Err(invalid("DAV response exceeds the entry limit"));
                        }
                    }
                    depth = 0;
                } else if item.is_some() {
                    depth = depth.saturating_sub(1);
                }
                field.clear();
            }
            Ok((_, Event::DocType(_))) => {
                return Err(invalid("DAV response contains a document type declaration"));
            }
            Ok((_, Event::Eof)) => break,
            Err(_) => return Err(invalid("DAV response is malformed XML")),
            _ => {}
        }
        buf.clear();
    }
    if !saw_root || item.is_some() {
        return Err(invalid("DAV response ended inside an entry"));
    }
    Ok(())
}

fn to_remote_entry(
    item: DavItem,
    requested: &Url,
    logical_path: &str,
) -> Result<RemoteEntry, CloudError> {
    let actual = requested
        .join(&item.href)
        .map_err(|_| invalid("DAV response contains an invalid href"))?;
    if !same_origin(requested, &actual) || actual.query().is_some() || actual.fragment().is_some() {
        return Err(invalid("DAV response href leaves the requested origin"));
    }
    let requested_segments: Vec<_> = requested
        .path_segments()
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .map(decode_safe_segment)
        .collect::<Result<_, _>>()?;
    let actual_segments: Vec<_> = actual
        .path_segments()
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .map(decode_safe_segment)
        .collect::<Result<_, _>>()?;
    if actual_segments.len() < requested_segments.len()
        || !actual_segments
            .iter()
            .zip(&requested_segments)
            .all(|(a, b)| a == b)
    {
        return Err(invalid("DAV response href is outside requested scope"));
    }
    let relative = &actual_segments[requested_segments.len()..];
    if relative.len() > 1 {
        return Err(invalid("DAV depth-one response returned a nested item"));
    }
    let prefix = if logical_path == "/" {
        String::new()
    } else {
        logical_path.trim_end_matches('/').to_owned()
    };
    let path = if relative.is_empty() {
        if prefix.is_empty() {
            "/".to_owned()
        } else {
            prefix
        }
    } else {
        format!("{prefix}/{}", relative[0])
    };
    let name = relative
        .first()
        .cloned()
        .unwrap_or_else(|| "root".to_owned());
    let etag = item.etag.trim().to_owned();
    if etag.is_empty() {
        return Err(invalid("DAV response omitted an entity tag"));
    }
    let encrypted = item.encrypted
        || item
            .content_type
            .as_deref()
            .is_some_and(is_vault_content_type)
        || is_vault_name(&name);
    Ok(RemoteEntry {
        id: item
            .file_id
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| actual.to_string()),
        path,
        directory: item.directory,
        size: if item.directory { 0 } else { item.size },
        etag,
        modified_unix: item.modified,
        writable: item.writable.unwrap_or(true),
        encrypted,
    })
}

fn is_vault_content_type(value: &str) -> bool {
    value.eq_ignore_ascii_case(VAULT_CONTENT_TYPE)
}

fn is_vault_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".vault")
}

fn is_vault_path(path: &str) -> bool {
    path.split('/').any(is_vault_name)
}

fn graph_permissions_writable(value: &Value) -> bool {
    fn writable_role(value: &str) -> bool {
        let normalized = value.to_ascii_lowercase();
        matches!(
            normalized.as_str(),
            "w" | "c" | "write" | "writer" | "owner" | "editor" | "create" | "update"
        ) || normalized.contains('w')
            || normalized.contains('c')
    }
    match value {
        Value::String(value) => writable_role(value),
        Value::Array(values) => values.iter().any(|value| {
            value.as_str().is_some_and(writable_role)
                || value.get("roles").is_some_and(graph_permissions_writable)
        }),
        Value::Object(values) => values
            .get("roles")
            .or_else(|| values.get("permissions"))
            .is_some_and(graph_permissions_writable),
        _ => false,
    }
}

fn dav_permissions_writable(value: &str) -> bool {
    let value = value.trim();
    if value.eq_ignore_ascii_case("read") || value.eq_ignore_ascii_case("readonly") {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("write") || lower.contains("update") || lower.contains("create") {
        return true;
    }
    value.contains('W') || value.contains('C')
}

fn logical_parent(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some(("", _)) | None => "/".to_owned(),
        Some((parent, _)) => parent.to_owned(),
    }
}

fn local_name(name: &[u8]) -> &str {
    std::str::from_utf8(name)
        .unwrap_or("")
        .rsplit(':')
        .next()
        .unwrap_or("")
}

fn namespace_is(namespace: &ResolveResult<'_>, expected: &[u8]) -> bool {
    matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == expected)
}

fn expected_namespace(name: &str) -> Option<&'static [u8]> {
    match name {
        "multistatus" | "response" | "href" | "propstat" | "prop" | "status" | "resourcetype"
        | "collection" | "getcontentlength" | "getetag" | "getlastmodified" | "getcontenttype" => {
            Some(b"DAV:")
        }
        "fileid" | "permissions" => Some(b"http://owncloud.org/ns"),
        "encrypted" | "contenttype" => Some(b"http://graph.opencloud.eu/ns"),
        "integrity-id" => Some(b"ocrclone"),
        _ => None,
    }
}

fn decode_safe_segment(segment: &str) -> Result<String, CloudError> {
    let decoded = percent_decode_str(segment)
        .decode_utf8()
        .map_err(|_| invalid("DAV response href contains invalid UTF-8"))?
        .into_owned();
    if decoded.is_empty()
        || decoded == "."
        || decoded == ".."
        || decoded.contains('/')
        || decoded.contains('\\')
        || decoded.chars().any(char::is_control)
    {
        return Err(invalid("DAV response href contains an unsafe name"));
    }
    Ok(decoded)
}
fn is_direct_child(parent: &str, child: &str) -> bool {
    let parent = parent.trim_end_matches('/');
    let tail = child.strip_prefix(parent).unwrap_or("");
    tail.starts_with('/') && !tail[1..].is_empty() && !tail[1..].contains('/')
}
fn required_string(value: &Value, key: &str) -> Result<String, CloudError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid("Graph response omitted a required drive field"))
}
fn read_bounded(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, CloudError> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(response_body_error)?;
    if bytes.len() > limit {
        return Err(invalid("server response exceeds its size limit"));
    }
    Ok(bytes)
}

fn checked(
    mut response: Response,
    expected: &[StatusCode],
    bearer_token: &str,
) -> Result<Response, CloudError> {
    if expected.contains(&response.status()) {
        return Ok(response);
    }
    if response.status().is_redirection() {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            format!(
                "OpenCloud {} request returned redirect HTTP {}; redirects are not followed",
                endpoint_kind(response.url()),
                response.status().as_u16()
            ),
        ));
    }
    let status = response.status();
    let endpoint = endpoint_kind(response.url());
    let request_id = response_request_id(&response, Some(bearer_token));
    let error_code = response_error_code(&mut response, Some(bearer_token));
    let kind = match status {
        StatusCode::UNAUTHORIZED => ErrorKind::Unauthorized,
        StatusCode::FORBIDDEN => ErrorKind::Forbidden,
        StatusCode::NOT_FOUND => ErrorKind::NotFound,
        StatusCode::PRECONDITION_FAILED
        | StatusCode::CONFLICT
        | StatusCode::PRECONDITION_REQUIRED => ErrorKind::Conflict,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT => {
            ErrorKind::Offline
        }
        _ => ErrorKind::InvalidResponse,
    };
    let mut message = format!(
        "OpenCloud {endpoint} request failed with HTTP {}",
        status.as_u16()
    );
    let mut diagnostics = Vec::new();
    if let Some(code) = error_code {
        diagnostics.push(format!("code={code}"));
    }
    if let Some(request_id) = request_id {
        diagnostics.push(format!("request_id={request_id}"));
    }
    if !diagnostics.is_empty() {
        message.push_str(" (");
        message.push_str(&diagnostics.join(", "));
        message.push(')');
    }
    Err(CloudError::new(kind, message))
}

fn checked_async(
    response: reqwest::Response,
    expected: &[StatusCode],
    bearer_token: &str,
) -> Result<reqwest::Response, CloudError> {
    if expected.contains(&response.status()) {
        return Ok(response);
    }
    if response.status().is_redirection() {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            format!(
                "OpenCloud {} request returned redirect HTTP {}; redirects are not followed",
                endpoint_kind(response.url()),
                response.status().as_u16()
            ),
        ));
    }
    let status = response.status();
    let endpoint = endpoint_kind(response.url());
    let request_id = [
        "request-id",
        "x-request-id",
        "x-correlation-id",
        "oc-request-id",
        "x-ms-request-id",
    ]
    .iter()
    .find_map(|name| response.headers().get(*name)?.to_str().ok())
    .and_then(|value| safe_diagnostic_value(value, 128, Some(bearer_token)));
    let kind = match status {
        StatusCode::UNAUTHORIZED => ErrorKind::Unauthorized,
        StatusCode::FORBIDDEN => ErrorKind::Forbidden,
        StatusCode::NOT_FOUND => ErrorKind::NotFound,
        StatusCode::PRECONDITION_FAILED
        | StatusCode::CONFLICT
        | StatusCode::PRECONDITION_REQUIRED => ErrorKind::Conflict,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT => {
            ErrorKind::Offline
        }
        _ => ErrorKind::InvalidResponse,
    };
    let mut message = format!(
        "OpenCloud {endpoint} request failed with HTTP {}",
        status.as_u16()
    );
    if let Some(request_id) = request_id {
        message.push_str(&format!(" request_id={request_id}"));
    }
    Err(CloudError::new(kind, message))
}

fn endpoint_kind(url: &Url) -> &'static str {
    let segments: Vec<_> = url.path().split('/').collect();
    if segments
        .windows(2)
        .any(|pair| pair[0] == "graph" && pair[1] == "v1.0")
    {
        "Graph discovery"
    } else {
        "WebDAV"
    }
}

fn response_request_id(response: &Response, secret: Option<&str>) -> Option<String> {
    [
        "request-id",
        "x-request-id",
        "x-correlation-id",
        "oc-request-id",
        "x-ms-request-id",
    ]
    .iter()
    .find_map(|name| response.headers().get(*name)?.to_str().ok())
    .and_then(|value| safe_diagnostic_value(value, 128, secret))
}

fn response_error_code(response: &mut Response, secret: Option<&str>) -> Option<String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ERROR_BODY as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    (&mut *response)
        .take(MAX_ERROR_BODY as u64 + 1)
        .read_to_end(&mut body)
        .ok()?;
    if body.len() > MAX_ERROR_BODY {
        return None;
    }
    let payload: Value = serde_json::from_slice(&body).ok()?;
    [
        payload.pointer("/error/code"),
        payload.get("code"),
        payload.pointer("/ocs/error/code"),
        payload.pointer("/ocs/meta/code"),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_str)
    .and_then(|value| safe_diagnostic_value(value, 64, secret))
}

fn safe_diagnostic_value(value: &str, max_len: usize, secret: Option<&str>) -> Option<String> {
    if value.is_empty()
        || value.len() > max_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || secret.is_some_and(|secret| !secret.is_empty() && value.contains(secret))
    {
        return None;
    }
    Some(value.to_owned())
}

fn network(_: reqwest::Error) -> CloudError {
    CloudError::new(ErrorKind::Offline, "OpenCloud server could not be reached")
}
fn response_body_error(_: io::Error) -> CloudError {
    CloudError::new(ErrorKind::Offline, "OpenCloud response ended unexpectedly")
}
fn io_error(error: io::Error) -> CloudError {
    CloudError::new(
        ErrorKind::Io,
        format!("local file operation failed: {error}"),
    )
}
fn invalid(message: &str) -> CloudError {
    CloudError::new(ErrorKind::InvalidResponse, message)
}
fn conflict(message: &str) -> CloudError {
    CloudError::new(ErrorKind::Conflict, message)
}

fn parse_http_date(value: &str) -> Option<i64> {
    // HTTP-date parsing without an additional date dependency; invalid metadata is non-fatal.
    let parts: Vec<_> = value.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    let day: i64 = parts[1].parse().ok()?;
    let month = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[3].parse().ok()?;
    let mut time = parts[4].split(':');
    let h: i64 = time.next()?.parse().ok()?;
    let m: i64 = time.next()?.parse().ok()?;
    let s: i64 = time.next()?.parse().ok()?;
    if parts[5] != "GMT" {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + h * 3_600 + m * 60 + s)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    #[test]
    fn token_generation_completion_lease_serializes_rotation_and_shared_clients() {
        let client = OpenCloudClient::new("https://cloud.example", "token-v1".into()).unwrap();
        let same_client = client.clone();
        let worker_client = client.clone();
        let (admitted_tx, admitted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            worker_client
                .with_token_generations(&same_client, 1, 1, || {
                    admitted_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .unwrap();
        });
        admitted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let rotation_client = client.clone();
        let (rotation_started_tx, rotation_started_rx) = mpsc::channel();
        let (rotated_tx, rotated_rx) = mpsc::channel();
        let rotation = thread::spawn(move || {
            rotation_started_tx.send(()).unwrap();
            rotation_client.set_bearer_token("token-v2".into()).unwrap();
            rotated_tx.send(()).unwrap();
        });
        rotation_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert!(
            rotated_rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "token rotation must wait for an admitted completion"
        );
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        rotated_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        rotation.join().unwrap();
        assert_eq!(client.token_generation(), 2);
    }

    #[cfg(feature = "synthetic-test-ca")]
    #[test]
    fn synthetic_ca_origin_is_limited_to_https_ip_loopback() {
        assert_eq!(
            normalize_synthetic_ca_origin("https://127.0.0.1:18443")
                .unwrap()
                .as_str(),
            "https://127.0.0.1:18443"
        );
        assert!(normalize_synthetic_ca_origin("https://localhost:18443").is_err());
        assert!(normalize_synthetic_ca_origin("https://example.com").is_err());
        assert!(normalize_synthetic_ca_origin("http://127.0.0.1:18443").is_err());
        assert!(normalize_synthetic_ca_origin("https://127.0.0.1:18443/path").is_err());
    }

    #[test]
    fn range_etag_requires_a_strong_quoted_entity_tag() {
        assert!(is_strong_etag("\"revision-1\""));
        assert!(!is_strong_etag("W/\"revision-1\""));
        assert!(!is_strong_etag("*"));
        assert!(!is_strong_etag("revision-1"));
        assert!(!is_strong_etag("\"bad\"tag\""));
        assert!(!is_strong_etag("\"line\nfeed\""));
    }

    #[test]
    fn transfer_timeout_scales_and_saturates_safely() {
        assert_eq!(transfer_timeout(0).as_secs(), TRANSFER_TIMEOUT_BASE_SECS);
        assert_eq!(
            transfer_timeout(1).as_secs(),
            TRANSFER_TIMEOUT_BASE_SECS + 1
        );
        assert_eq!(
            transfer_timeout(TRANSFER_MIN_BYTES_PER_SECOND).as_secs(),
            TRANSFER_TIMEOUT_BASE_SECS + 1
        );
        assert_eq!(
            transfer_timeout(TRANSFER_MIN_BYTES_PER_SECOND + 1).as_secs(),
            TRANSFER_TIMEOUT_BASE_SECS + 2
        );
        let bytes_at_cap = (TRANSFER_TIMEOUT_MAX_SECS - TRANSFER_TIMEOUT_BASE_SECS)
            * TRANSFER_MIN_BYTES_PER_SECOND;
        assert_eq!(
            transfer_timeout(bytes_at_cap).as_secs(),
            TRANSFER_TIMEOUT_MAX_SECS
        );
        assert_eq!(
            transfer_timeout(bytes_at_cap + 1).as_secs(),
            TRANSFER_TIMEOUT_MAX_SECS
        );
        assert_eq!(
            transfer_timeout(u64::MAX).as_secs(),
            TRANSFER_TIMEOUT_MAX_SECS
        );
    }

    #[test]
    fn rate_limited_deadline_uses_hard_cap_while_range_context_stays_strict() {
        use std::num::NonZeroU64;

        let budget = TransferBudget::new();
        let unlimited_deadline =
            transfer_timeout_with_budget(&budget, TransferDirection::Upload, 10_000_000);
        assert_eq!(
            unlimited_deadline,
            Duration::from_secs(TRANSFER_TIMEOUT_MAX_SECS),
            "a request that starts unlimited must tolerate a later live cap"
        );
        budget.set_limits(crate::transfer_budget::TransferLimits {
            upload_bytes_per_second: Some(NonZeroU64::new(1).unwrap()),
            download_bytes_per_second: Some(NonZeroU64::new(1).unwrap()),
        });
        let upload_deadline =
            transfer_timeout_with_budget(&budget, TransferDirection::Upload, 10_000_000);
        let download_deadline =
            transfer_timeout_with_budget(&budget, TransferDirection::Download, 10_000_000);
        assert_eq!(
            upload_deadline,
            Duration::from_secs(TRANSFER_TIMEOUT_MAX_SECS)
        );
        assert_eq!(upload_deadline, unlimited_deadline);
        assert_eq!(
            download_deadline,
            Duration::from_secs(TRANSFER_TIMEOUT_MAX_SECS)
        );

        // A running request uses a fixed hard bound instead of a stale
        // estimate; lowering the shared cap cannot make it time out early.
        budget.set_limits(crate::transfer_budget::TransferLimits {
            upload_bytes_per_second: Some(NonZeroU64::new(1).unwrap()),
            download_bytes_per_second: Some(NonZeroU64::new(1).unwrap()),
        });
        assert_eq!(
            transfer_timeout_with_budget(&budget, TransferDirection::Upload, u64::MAX),
            upload_deadline
        );

        let context = RangeReadContext {
            deadline: Instant::now() + Duration::from_millis(30),
            token_generation: 1,
        };
        let callback_deadline =
            transfer_timeout_for_context(context, &budget, TransferDirection::Download, 10_000_000)
                .unwrap();
        assert!(callback_deadline <= Duration::from_millis(30));
        assert!(callback_deadline > Duration::ZERO);
        let expired = RangeReadContext {
            deadline: Instant::now() - Duration::from_millis(1),
            token_generation: 1,
        };
        assert!(
            transfer_timeout_for_context(expired, &budget, TransferDirection::Download, 1,)
                .is_err()
        );
    }

    #[test]
    fn proxy_config_is_bounded_and_never_accepts_url_credentials_or_components() {
        assert!(ProxyConfig::System.validate().is_ok());
        assert!(ProxyConfig::Direct.validate().is_ok());
        for url in [
            "http://proxy.example:8080",
            "https://proxy.example",
            "http://user@proxy.example:8080",
            "http://:pass@proxy.example:8080",
            "http://proxy.example:8080/path",
            "http://proxy.example:8080/?token=x",
            "ftp://proxy.example:21",
            " http://proxy.example:8080",
        ] {
            let proxy = ProxyConfig::Explicit { url: url.into() };
            let result = proxy.validate();
            if matches!(url, "http://proxy.example:8080" | "https://proxy.example") {
                assert!(result.is_ok(), "valid proxy rejected: {url}");
            } else {
                assert!(result.is_err(), "unsafe proxy accepted: {url}");
            }
            if let Err(error) = result {
                assert!(!error.to_string().contains(url));
            }
        }
        assert!(
            ProxyConfig::Explicit {
                url: "x".repeat(2_049)
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn explicit_proxy_receives_cloud_tls_connect_and_no_bearer_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy_server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            String::from_utf8(request).unwrap()
        });
        let proxy = ProxyConfig::Explicit {
            url: format!("http://{proxy_address}"),
        };
        let client = OpenCloudClient::new_with_proxy(
            "https://cloud.example",
            "never-forward-this-token".into(),
            &proxy,
        )
        .unwrap();
        assert!(client.spaces().is_err());
        let request = proxy_server.join().unwrap();
        assert!(
            request.starts_with("CONNECT cloud.example:443 "),
            "{request}"
        );
        assert!(!request.contains("never-forward-this-token"));
    }

    #[test]
    fn async_content_body_uses_the_configured_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy_server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16 * 1024);
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nproxied",
                )
                .unwrap();
            String::from_utf8(request).unwrap()
        });
        let proxy = ProxyConfig::Explicit {
            url: format!("http://{proxy_address}"),
        };
        let client = OpenCloudClient::new_with_proxy(
            "http://127.0.0.1:9",
            "synthetic-test-token".into(),
            &proxy,
        )
        .unwrap();
        let url = client.server.join("/objects/item").unwrap();
        let (request, token) = client.request_async(Method::GET, &url).unwrap();
        let budget = client.transfer_budget();
        let body = async_body::run_body_operation(
            Duration::from_secs(1),
            Duration::from_secs(2),
            move |progress| async move {
                let mut response = checked_async(
                    request.send().await.map_err(network)?,
                    &[StatusCode::OK],
                    &token,
                )?;
                let mut output = async_body::VecAsyncWriter::default();
                async_body::copy_response_body(
                    &mut response,
                    &mut output,
                    7,
                    &budget,
                    || false,
                    &progress,
                )
                .await?;
                Ok(output.into_inner())
            },
        )
        .unwrap();
        assert_eq!(&*body, b"proxied");
        let request = proxy_server.join().unwrap();
        assert!(
            request.starts_with("GET http://127.0.0.1:9/objects/item HTTP/1.1"),
            "{request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer synthetic-test-token")
        );
    }

    #[test]
    fn explicit_proxy_carries_graph_discovery_and_dav_listing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let graph = r#"{"value":[{"id":"drive-1","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"http://127.0.0.1:9/dav/personal/"}}]}"#;
            let root = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
            let empty_listing = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
            let mut requests = Vec::new();
            for index in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut headers = Vec::new();
                let mut byte = [0_u8; 1];
                while !headers.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                    assert!(headers.len() < 16 * 1024);
                }
                let header_text = String::from_utf8(headers).unwrap();
                let length = header_text
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                assert!(length < 4096);
                let mut body = vec![0; length];
                if length > 0 {
                    stream.read_exact(&mut body).unwrap();
                }
                requests.push(format!("{header_text}BODY_BYTES={}", body.len()));
                let (status, content_type, response_body) = match index {
                    0 | 1 => ("200 OK", "application/json", graph),
                    2 => ("207 Multi-Status", "application/xml", root),
                    _ => ("207 Multi-Status", "application/xml", empty_listing),
                };
                write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n", response_body.len()).unwrap();
                stream.write_all(response_body.as_bytes()).unwrap();
            }
            requests
        });
        let proxy = ProxyConfig::Explicit {
            url: format!("http://{proxy_address}"),
        };
        let client = OpenCloudClient::new_with_proxy(
            "http://127.0.0.1:9",
            "proxy-fixture-token".into(),
            &proxy,
        )
        .unwrap();
        let spaces = client.spaces().unwrap();
        assert_eq!(spaces.len(), 1);
        let mut entries = Vec::new();
        client
            .list("drive-1", "/", &mut |entry| {
                entries.push(entry);
                Ok(())
            })
            .unwrap();
        assert!(entries.is_empty());

        let requests = worker.join().unwrap();
        assert!(requests[0].starts_with("GET http://127.0.0.1:9/graph/v1.0/me/drives "));
        assert!(requests[1].starts_with("GET http://127.0.0.1:9/graph/v1.0/me/drives "));
        assert!(requests[2].starts_with("PROPFIND http://127.0.0.1:9/dav/personal/ "));
        assert!(requests[3].starts_with("PROPFIND http://127.0.0.1:9/dav/personal/ "));
        assert!(requests.iter().all(|request| {
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer proxy-fixture-token")
        }));
    }

    fn fixture(
        responses: Vec<(&'static str, String)>,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_authority = address.to_string();
        let worker = thread::spawn(move || {
            let mut seen = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut chunk).is_err() {
                        break;
                    }
                    request.push(chunk[0]);
                }
                let header = String::from_utf8_lossy(&request).to_string();
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let mut rest = vec![0; length];
                if length > 0 {
                    let _ = stream.read_exact(&mut rest);
                }
                seen.push(format!("{header}\nBODY_BYTES={}", rest.len()));
                if status == "STALL" {
                    if header.starts_with("PUT ") {
                        thread::sleep(Duration::from_millis(250));
                        break;
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                    // Keep the body incomplete long enough for the production
                    // client watchdog to cancel its request future.
                    thread::sleep(Duration::from_millis(250));
                    break;
                }
                let body = body.replace("127.0.0.1:PORT", &server_authority);
                let response_body = body.as_bytes();
                write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n", response_body.len()).unwrap();
                stream.write_all(response_body).unwrap();
            }
            seen
        });
        (format!("http://{address}"), worker)
    }

    #[test]
    fn namespace_probe_bounds_a_connected_server_that_never_responds() {
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled Graph fixture");
        let server = format!("http://{}", listener.local_addr().unwrap());
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("Graph probe request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set fixture read deadline");
            accepted_tx.send(()).expect("signal accepted request");
            let mut request = [0_u8; 1024];
            while stream.read(&mut request).unwrap_or(0) > 0 {}
            // Deliberately send no HTTP response. Reqwest closes the socket at
            // the namespace-probe deadline, allowing this fixture to exit.
        });
        let client = OpenCloudClient::new_for_namespace_probe(&server, "fixture-access".into())
            .expect("bounded namespace-probe client");

        let started = Instant::now();
        let error = client
            .spaces()
            .expect_err("stalled Graph endpoint must not block startup");
        let elapsed = started.elapsed();
        assert_eq!(error.kind, ErrorKind::Offline);
        assert!(accepted_rx.recv_timeout(Duration::from_secs(1)).is_ok());
        assert!(
            elapsed < Duration::from_secs(8),
            "startup namespace probe exceeded its bounded deadline: {elapsed:?}"
        );
        worker
            .join()
            .expect("stalled Graph fixture exits on client timeout");
    }

    const GRAPH: &str = r#"{"value":[{"id":"drive-1","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"http://127.0.0.1:PORT/dav/personal/"}}]}"#;

    #[test]
    fn client_rejects_non_loopback_http_and_redacts_debug() {
        assert!(OpenCloudClient::new("http://example.com", "secret-token".into()).is_err());
        let client = OpenCloudClient::new("http://127.0.0.1:1234", "secret-token".into()).unwrap();
        assert!(!format!("{client:?}").contains("secret-token"));
    }

    #[test]
    fn paths_reject_traversal_and_parser_rejects_hostile_href() {
        assert!(validate_logical_path("/../../etc").is_err());
        let xml = br#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>http://evil.example/x</d:href><d:propstat><d:prop><d:resourcetype/><d:getetag>\"x\"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
        let requested = Url::parse("https://cloud.example/dav/").unwrap();
        assert!(parse_multistatus(xml, &requested, "/", &mut |_| Ok(())).is_err());
    }

    #[test]
    fn redirects_are_not_followed_and_graph_pages_are_origin_bound() {
        let (server, worker) = fixture(vec![("302 Found", String::new())]);
        let client = OpenCloudClient::new(&server, "secret-token".into()).unwrap();
        assert_eq!(
            client.spaces().unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
        let requests = worker.join().unwrap();
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer secret-token")
        );
        assert!(requests[0].starts_with("GET /graph/v1.0/me/drives"));
    }

    #[test]
    fn list_stream_boundary_returns_only_direct_children_and_marks_vault_directory() {
        let xml = r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"root"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/personal/notes.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>3</d:getcontentlength><d:getetag>"a1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/personal/.vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"vault"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()),
            ("207 Multi-Status", xml),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let mut entries = Vec::new();
        client
            .list("drive-1", "/", &mut |entry| {
                entries.push(entry);
                Ok(())
            })
            .unwrap();
        worker.join().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/notes.txt");
        assert_eq!(entries[0].size, 3);
        assert!(entries[1].encrypted);
        assert_eq!(entries[1].path, "/.vault");
    }

    #[test]
    fn dav_vault_signals_cover_suffix_content_type_and_integrity_id() {
        let xml = r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:v="ocrclone"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/personal/Secret.VAULT/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>suffix</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/personal/Mime/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontenttype>Application/Vnd.OpenCloud.Vault</d:getcontenttype><d:getetag>mime</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/personal/Token/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><v:integrity-id>vault-key-token</v:integrity-id><d:getetag>token</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/personal/Ordinary/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontenttype>httpd/unix-directory</d:getcontenttype><v:integrity-id></v:integrity-id><d:getetag>ordinary</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
        let requested = Url::parse("https://cloud.example/dav/personal/").unwrap();
        let mut entries = Vec::new();
        parse_multistatus(xml.as_bytes(), &requested, "/", &mut |entry| {
            entries.push(entry);
            Ok(())
        })
        .unwrap();
        assert_eq!(entries.len(), 5);
        assert!(entries[1].encrypted, "case-insensitive .vault suffix");
        assert!(entries[2].encrypted, "DAV getcontenttype");
        assert!(entries[3].encrypted, "non-empty ocrclone integrity-id");
        assert!(!entries[4].encrypted, "empty integrity-id marks no vault");
    }

    #[test]
    fn ordinary_dav_requests_reject_vault_descendants_before_network_access() {
        let (server, worker) = fixture(vec![("200 OK", GRAPH.to_owned())]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let error = client
            .stat("drive-1", "/Ordinary/Secret.VaUlT/child.txt")
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1, "only Graph discovery should be sent");
        assert!(requests[0].starts_with("GET /graph/v1.0/me/drives"));
    }

    #[test]
    fn download_rejects_metadata_marked_ancestor_before_get() {
        let root = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let ordinary = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/Workspace/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>workspace</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let marked = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/Workspace/Secret/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><d:getetag>secret</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", root),
            ("207 Multi-Status", ordinary),
            ("207 Multi-Status", marked),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let destination = tempfile::NamedTempFile::new().unwrap();
        let error = client
            .download(
                "drive-1",
                "/Workspace/Secret/child.txt",
                None,
                destination.path(),
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported, "{error}");
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 5, "stop after marked ancestor metadata");
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with("GET /dav/"))
        );
    }

    #[test]
    fn upload_rejects_integrity_marked_ancestor_before_put() {
        let root = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let ordinary = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/Workspace/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>workspace</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let marked = r#"<d:multistatus xmlns:d="DAV:" xmlns:v="ocrclone"><d:response><d:href>/dav/personal/Workspace/Secret/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><v:integrity-id>vault-key</v:integrity-id><d:getetag>secret</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", root),
            ("207 Multi-Status", ordinary),
            ("207 Multi-Status", marked),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            client
                .upload(
                    "drive-1",
                    "/Workspace/Secret/child.txt",
                    source.path(),
                    WriteCondition::Absent,
                )
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 4, "stop after marked ancestor metadata");
        assert!(requests.iter().all(|request| !request.starts_with("PUT /")));
    }

    #[test]
    fn vault_ancestor_check_rejects_mismatched_depth_zero_href() {
        let wrong_root = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/innocent/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>wrong</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", wrong_root),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        assert_eq!(
            client
                .stat("drive-1", "/Workspace/file.txt")
                .unwrap_err()
                .kind,
            ErrorKind::InvalidResponse
        );
        let requests = worker.join().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "no transfer follows a mismatched ancestor href"
        );
    }

    #[test]
    fn list_rejects_encrypted_scope_from_depth_one_response_before_emitting() {
        let ordinary_root = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let changed_root = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><d:getetag>vault</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/personal/child.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>1</d:getcontentlength><d:getetag>child</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", ordinary_root),
            ("207 Multi-Status", changed_root),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let mut emitted = 0;
        assert_eq!(
            client
                .list("drive-1", "/", &mut |_| {
                    emitted += 1;
                    Ok(())
                })
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
        worker.join().unwrap();
        assert_eq!(emitted, 0);
    }

    #[test]
    fn graph_vault_space_name_and_root_markers_block_dav_operations() {
        let graph = r#"{"value":[{"id":"drive-1","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"http://127.0.0.1:PORT/dav/personal/"}},{"id":"vault","name":"Encrypted Space","root":{"id":"vault-root","webDavUrl":"http://127.0.0.1:PORT/dav/vault/","@libre.graph.contentType":"APPLICATION/VND.OPENCLOUD.VAULT"}},{"id":"suffix","name":"Archive.VAULT","root":{"id":"suffix-root","webDavUrl":"http://127.0.0.1:PORT/dav/suffix/"}}]}"#.to_owned();
        let (server, worker) = fixture(vec![("200 OK", graph.clone()), ("200 OK", graph)]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        assert!(client.stat("vault", "/file").unwrap_err().kind == ErrorKind::Unsupported);
        assert!(client.stat("suffix", "/file").unwrap_err().kind == ErrorKind::Unsupported);
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 2, "Graph discovery only; no DAV requests");
        assert!(
            requests
                .iter()
                .all(|request| request.starts_with("GET /graph/v1.0/me/drives"))
        );
    }

    #[test]
    fn failed_listing_does_not_report_a_complete_snapshot() {
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()),
            ("500 Internal Server Error", String::new()),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let mut emitted = 0;
        let result = client.list("drive-1", "/", &mut |_| {
            emitted += 1;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(emitted, 0);
        worker.join().unwrap();
    }

    #[test]
    fn direct_delete_rejects_root_aliases_without_network_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = format!("http://{}", listener.local_addr().unwrap());
        let client = OpenCloudClient::new(&server, "synthetic-token".into()).unwrap();
        for path in ["", "/", "//", "///"] {
            let error = client.delete("drive-1", path, "root-etag").unwrap_err();
            assert_eq!(error.kind, ErrorKind::Unsupported);
            assert!(error.message.contains("Space root"));
        }
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn rate_limited_http_response_is_not_classified_as_transport_offline() {
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("429 Too Many Requests", String::new()),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let error = client
            .list("drive-1", "/", &mut |_| Ok(()))
            .expect_err("rate limiting is a server response, not an offline transport failure");
        assert_eq!(error.kind, ErrorKind::InvalidResponse);
        assert!(error.message.contains("HTTP 429"));
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn http_error_reports_only_safe_graph_code_and_request_id() {
        let body = r#"{"error":{"code":"InternalServerError","message":"request failed for bearer secret-token"}}"#.to_owned();
        let (server, worker) = fixture(vec![(
            "500 Internal Server Error\r\nX-Request-ID: req-7a21",
            body,
        )]);
        let client = OpenCloudClient::new(&server, "secret-token".into()).unwrap();
        let error = client.spaces().unwrap_err();
        worker.join().unwrap();
        assert!(error.message.contains("Graph discovery"));
        assert!(error.message.contains("HTTP 500"));
        assert!(error.message.contains("code=InternalServerError"));
        assert!(error.message.contains("request_id=req-7a21"));
        assert!(!error.message.contains("secret-token"));
        assert!(!error.message.contains("for bearer"));
    }

    #[test]
    fn malformed_or_oversized_error_body_is_not_reflected() {
        let malformed = "not-json secret-token".to_owned();
        let (server, worker) = fixture(vec![("500 Internal Server Error", malformed)]);
        let client = OpenCloudClient::new(&server, "secret-token".into()).unwrap();
        let error = client.spaces().unwrap_err();
        worker.join().unwrap();
        assert!(error.message.contains("Graph discovery"));
        assert!(!error.message.contains("not-json"));
        assert!(!error.message.contains("secret-token"));
        assert!(!error.message.contains("code="));

        let oversized = format!(
            r#"{{"error":{{"code":"ShouldNotBeParsed"}},"padding":"{}"}}"#,
            "x".repeat(MAX_ERROR_BODY)
        );
        let (server, worker) = fixture(vec![("500 Internal Server Error", oversized)]);
        let client = OpenCloudClient::new(&server, "another-secret".into()).unwrap();
        let error = client.spaces().unwrap_err();
        worker.join().unwrap();
        assert!(!error.message.contains("ShouldNotBeParsed"));
        assert!(!error.message.contains("padding"));

        let body = r#"{"error":{"code":"another-secret"}}"#.to_owned();
        let (server, worker) = fixture(vec![(
            "500 Internal Server Error\r\nX-Request-ID: another-secret",
            body,
        )]);
        let client = OpenCloudClient::new(&server, "another-secret".into()).unwrap();
        let error = client.spaces().unwrap_err();
        worker.join().unwrap();
        assert!(!error.message.contains("another-secret"));
        assert!(!error.message.contains("code="));
        assert!(!error.message.contains("request_id="));
    }

    #[test]
    fn conditional_delete_maps_etag_mismatch_to_conflict() {
        let writable_target = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/stale.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>3</d:getcontentlength><d:getetag>"old"</d:getetag><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()),
            ("207 Multi-Status", writable_target),
            ("412 Precondition Failed", String::new()),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let error = client
            .delete("drive-1", "/stale.txt", "\"old\"")
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert!(
            error
                .message
                .contains("OpenCloud WebDAV request failed with HTTP 412")
        );
        let requests = worker.join().unwrap();
        assert!(
            requests[3]
                .to_ascii_lowercase()
                .contains("if-match: \"old\"")
        );
    }

    #[test]
    fn download_keeps_existing_destination_when_final_remote_stat_fails() {
        let stat = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/file.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>3</d:getcontentlength><d:getetag>"v1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()),
            ("207 Multi-Status", stat),
            ("200 OK", "new".to_owned()),
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()),
            ("500 Internal Server Error", String::new()),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("destination.txt");
        std::fs::write(&destination, b"keep").unwrap();
        assert!(
            client
                .download("drive-1", "/file.txt", Some("\"v1\""), &destination)
                .is_err()
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        worker.join().unwrap();
    }

    #[test]
    fn stat_rejects_a_dav_response_for_a_different_path() {
        let wrong = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/other.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>1</d:getcontentlength><d:getetag>"v1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()),
            ("207 Multi-Status", wrong),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        assert_eq!(
            client.stat("drive-1", "/requested.txt").unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
        worker.join().unwrap();
    }

    #[test]
    fn spaces_report_root_permissions_and_vault_markers() {
        let graph = r#"{"value":[{"id":"drive-1","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"http://127.0.0.1:PORT/dav/personal/","permissions":"R"}},{"id":"vault","name":"Vault","root":{"id":"vault-root","webDavUrl":"http://127.0.0.1:PORT/dav/vault/","@libre.graph.contentType":"application/vnd.opencloud.vault"}}]}"#.to_owned();
        let (server, worker) = fixture(vec![("200 OK", graph)]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let spaces = client.spaces().unwrap();
        worker.join().unwrap();
        let personal = spaces.iter().find(|space| space.id == "drive-1").unwrap();
        let vault = spaces.iter().find(|space| space.id == "vault").unwrap();
        assert!(!personal.writable);
        assert!(vault.encrypted);
    }

    #[test]
    fn upload_rejects_a_dav_stat_marked_read_only() {
        let readonly = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/upload.bin</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>0</d:getcontentlength><d:getetag>"old"</d:getetag><oc:permissions>R</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()),
            ("207 Multi-Status", readonly),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            client
                .upload(
                    "drive-1",
                    "/upload.bin",
                    source.path(),
                    WriteCondition::Match("old".into())
                )
                .unwrap_err()
                .kind,
            ErrorKind::Forbidden
        );
        worker.join().unwrap();
    }

    #[test]
    fn upload_rejects_a_read_only_space_before_webdav_mutation() {
        let graph = r#"{"value":[{"id":"drive-1","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"http://127.0.0.1:PORT/dav/personal/","permissions":"R"}}]}"#.to_owned();
        let (server, worker) = fixture(vec![("200 OK", graph)]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            client
                .upload(
                    "drive-1",
                    "/upload.bin",
                    source.path(),
                    WriteCondition::Absent
                )
                .unwrap_err()
                .kind,
            ErrorKind::Forbidden
        );
        worker.join().unwrap();
    }

    #[test]
    fn scoped_transfer_requires_matching_identity_addressed_space_url() {
        let client = OpenCloudClient::new("http://127.0.0.1:18448/", "token".into()).unwrap();
        let mut selected = CloudSpace {
            id: "storage$space".into(),
            name: "Personal".into(),
            dav_url: "http://127.0.0.1:18448/prefix/dav/spaces/storage%24space/".into(),
            personal: true,
            writable: true,
            encrypted: false,
        };
        client
            .validate_identity_addressed_root(&selected, "storage$space!root")
            .unwrap();
        selected.dav_url.pop();
        assert_eq!(
            client
                .validate_identity_addressed_root(&selected, "storage$space!root")
                .unwrap()
                .as_str(),
            "http://127.0.0.1:18448/prefix/dav/spaces/storage%24space/"
        );
        for url in [
            "http://127.0.0.1:18448/dav/personal/",
            "http://127.0.0.1:18448/dav/spaces/other/",
            "http://127.0.0.1:18448/dav/spaces/storage%24space/child/",
            "http://127.0.0.1:18448/dav/spaces/storage%24space/?alias=personal",
            "http://127.0.0.1:18449/dav/spaces/storage%24space/",
        ] {
            selected.dav_url = url.into();
            assert_eq!(
                client
                    .validate_identity_addressed_root(&selected, "storage$space!root")
                    .unwrap_err()
                    .kind,
                ErrorKind::Unsupported
            );
        }
        selected.dav_url = "http://127.0.0.1:18448/dav/spaces/storage%24space/".into();
        assert_eq!(
            client
                .validate_identity_addressed_root(&selected, "other!root")
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn root_bound_upload_sends_atomic_root_and_absent_leaf_preconditions() {
        let root = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/spaces/drive-1/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>"root-v1"</d:getetag><oc:fileid>drive-1!expected-root</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            (
                "200 OK",
                GRAPH.replace("/dav/personal/", "/dav/spaces/drive-1"),
            ),
            ("207 Multi-Status", root.clone()),
            ("404 Not Found", String::new()),
            ("207 Multi-Status", root.clone()),
            ("207 Multi-Status", root),
            ("412 Precondition Failed", String::new()),
        ]);
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"retained creation").unwrap();
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let error = client
            .upload_in_root(
                "drive-1",
                "/new.txt",
                source.path(),
                WriteCondition::Absent,
                "drive-1!expected-root",
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        let requests = worker.join().unwrap();
        let put = requests.last().unwrap().to_ascii_lowercase();
        assert!(put.starts_with("put /dav/spaces/drive-1/new.txt "));
        assert!(
            put.lines()
                .any(|line| line == format!(r#"if: <{server}/dav/spaces/drive-1/> (["root-v1"])"#)),
            "tagged root revision must be checked by the server"
        );
        assert!(put.lines().any(|line| line == "if-none-match: *"));
        assert_eq!(std::fs::read(source.path()).unwrap(), b"retained creation");
    }

    #[test]
    fn root_bound_transfers_reject_replaced_roots_before_sending_body_requests() {
        fn root(id: &str) -> String {
            format!(
                r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/spaces/drive-1/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
            )
        }
        let (server, worker) = fixture(vec![
            (
                "200 OK",
                GRAPH.replace("/dav/personal/", "/dav/spaces/drive-1/"),
            ),
            ("207 Multi-Status", root("drive-1!expected-root")),
            ("404 Not Found", String::new()),
            ("207 Multi-Status", root("drive-1!expected-root")),
            ("207 Multi-Status", root("drive-1!replacement-root")),
        ]);
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"retain local creation").unwrap();
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let error = client
            .upload_in_root(
                "drive-1",
                "/new.txt",
                source.path(),
                WriteCondition::Absent,
                "drive-1!expected-root",
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert!(
            worker
                .join()
                .unwrap()
                .iter()
                .all(|request| !request.starts_with("PUT "))
        );
        assert_eq!(
            std::fs::read(source.path()).unwrap(),
            b"retain local creation"
        );
        let (server, worker) = fixture(vec![
            (
                "200 OK",
                GRAPH.replace("/dav/personal/", "/dav/spaces/drive-1/"),
            ),
            ("207 Multi-Status", root("drive-1!replacement-root")),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let error = client
            .download_in_root(
                "drive-1",
                "/new.txt",
                Some("v1"),
                source.path(),
                "drive-1!expected-root",
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert!(
            worker
                .join()
                .unwrap()
                .iter()
                .all(|request| !request.starts_with("GET /dav/"))
        );
        assert_eq!(
            std::fs::read(source.path()).unwrap(),
            b"retain local creation"
        );
    }

    #[test]
    fn upload_streams_file_bytes_and_verifies_remote_size() {
        let xml = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/upload.bin</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>524288</d:getcontentlength><d:getetag>"new"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let writable_root = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"root"</d:getetag><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", writable_root.clone()),
            ("404 Not Found", String::new()),
            ("207 Multi-Status", writable_root),
            ("201 Created", String::new()),
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()),
            ("207 Multi-Status", xml),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        let payload = vec![0x5a; 512 * 1024];
        std::fs::write(file.path(), &payload).unwrap();
        let entry = client
            .upload(
                "drive-1",
                "/upload.bin",
                file.path(),
                WriteCondition::Absent,
            )
            .unwrap();
        assert_eq!(entry.size, payload.len() as u64);
        let requests = worker.join().unwrap();
        assert!(requests[4].starts_with("PUT /dav/personal/upload.bin"));
        assert!(
            requests[4]
                .to_ascii_lowercase()
                .contains("content-length: 524288")
        );
        assert!(requests[4].contains("BODY_BYTES=524288"));
    }

    #[test]
    fn production_download_with_finite_budget_cancels_a_stalled_body() {
        let root = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let target = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/slow.bin</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>2</d:getcontentlength><d:getetag>"v1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", root),
            ("207 Multi-Status", target),
            ("STALL", String::new()),
        ]);
        let budget = TransferBudget::new();
        budget.set_limits(transfer_budget::TransferLimits {
            upload_bytes_per_second: None,
            download_bytes_per_second: std::num::NonZeroU64::new(1),
        });
        let client = OpenCloudClient::new_with_proxy_and_transfer_budget(
            &server,
            "token".into(),
            &ProxyConfig::Direct,
            budget,
        )
        .unwrap()
        .with_body_idle_timeout_for_test(Duration::from_millis(80));
        let destination = tempfile::NamedTempFile::new().unwrap();
        let started = Instant::now();
        let error = client
            .download("drive-1", "/slow.bin", Some("\"v1\""), destination.path())
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Offline);
        assert!(started.elapsed() < Duration::from_secs(2));
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 5);
        assert!(requests[4].starts_with("GET /dav/personal/slow.bin "));
    }

    #[test]
    fn production_upload_with_finite_budget_paces_then_cancels_a_stalled_response() {
        let writable_root = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>\"root\"</d:getetag><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", writable_root.clone()),
            ("404 Not Found", String::new()),
            ("207 Multi-Status", writable_root),
            ("STALL", String::new()),
        ]);
        let budget = TransferBudget::new();
        budget.set_limits(transfer_budget::TransferLimits {
            upload_bytes_per_second: std::num::NonZeroU64::new(1),
            download_bytes_per_second: None,
        });
        let client = OpenCloudClient::new_with_proxy_and_transfer_budget(
            &server,
            "token".into(),
            &ProxyConfig::Direct,
            budget,
        )
        .unwrap()
        .with_body_idle_timeout_for_test(Duration::from_millis(80));
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"xy").unwrap();
        let started = Instant::now();
        let error = client
            .upload(
                "drive-1",
                "/slow.bin",
                source.path(),
                WriteCondition::Absent,
            )
            .unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(error.kind, ErrorKind::Offline);
        assert!(
            elapsed >= Duration::from_millis(800),
            "budget was not applied: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "stalled response was not bounded: {elapsed:?}"
        );
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 5);
        assert!(requests[4].starts_with("PUT /dav/personal/slow.bin "));
        assert!(requests[4].contains("BODY_BYTES=2"));
    }

    #[test]
    fn production_download_observes_cap_added_after_request_start() {
        use std::{num::NonZeroU64, sync::mpsc};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let authority = address.to_string();
        let (get_seen_tx, get_seen_rx) = mpsc::channel();
        let (release_body_tx, release_body_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let graph = GRAPH.replace("127.0.0.1:PORT", &authority);
            let root = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
            let target = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/live.bin</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>8</d:getcontentlength><d:getetag>"v1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
            let mut index = 0;
            'accept: while index < 8 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut headers = Vec::new();
                let mut byte = [0u8; 1];
                let mut incomplete = false;
                while !headers.ends_with(b"\r\n\r\n") {
                    if let Err(error) = stream.read_exact(&mut byte) {
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::UnexpectedEof
                        ) {
                            incomplete = true;
                            break;
                        }
                        panic!("fixture request read failed: {error}");
                    }
                    headers.push(byte[0]);
                    assert!(headers.len() < 16 * 1024);
                }
                if incomplete {
                    continue 'accept;
                }
                let request = String::from_utf8(headers).unwrap();
                let request_body_len = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let mut request_body = vec![0; request_body_len];
                stream.read_exact(&mut request_body).unwrap();
                if index == 4 {
                    assert!(request.starts_with("GET /dav/personal/live.bin "));
                    get_seen_tx.send(()).unwrap();
                    release_body_rx
                        .recv_timeout(Duration::from_secs(15))
                        .unwrap();
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nabcdefgh")
                        .unwrap();
                    stream.flush().unwrap();
                    index += 1;
                    continue 'accept;
                }
                let body = match index {
                    0 | 1 | 5 => graph.as_str(),
                    2 | 6 => root,
                    3 | 7 => target,
                    _ => unreachable!(),
                };
                let status = if matches!(index, 0 | 1 | 5) {
                    "200 OK"
                } else {
                    "207 Multi-Status"
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body.as_bytes()).unwrap();
                index += 1;
            }
        });

        let budget = TransferBudget::new();
        let client = OpenCloudClient::new_with_proxy_and_transfer_budget(
            &format!("http://{address}"),
            "live-cap-token".into(),
            &ProxyConfig::Direct,
            budget.clone(),
        )
        .unwrap()
        .with_body_idle_timeout_for_test(Duration::from_millis(500));
        // Use a new path rather than a still-open NamedTempFile as the
        // destination. On Windows the open handle does not permit replacing
        // the file, which tests filesystem sharing semantics instead of the
        // transfer-budget behavior this test covers.
        let destination_dir = tempfile::tempdir().unwrap();
        let destination = destination_dir.path().join("download.bin");
        let download_client = client.clone();
        let destination_path = destination.clone();
        let download = thread::spawn(move || {
            let started = Instant::now();
            let result =
                download_client.download("drive-1", "/live.bin", Some("\"v1\""), &destination_path);
            (started.elapsed(), result)
        });
        get_seen_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("download request should start with an unlimited budget");
        budget.set_limits(transfer_budget::TransferLimits {
            upload_bytes_per_second: None,
            download_bytes_per_second: NonZeroU64::new(4),
        });
        release_body_tx.send(()).unwrap();
        let (elapsed, result) = download.join().unwrap();
        result.expect("live cap change must not invalidate the running request deadline");
        assert!(
            elapsed >= Duration::from_millis(700),
            "download body did not observe the live cap: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "download stalled: {elapsed:?}"
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"abcdefgh");
        server.join().unwrap();
    }

    #[test]
    fn contextual_range_rotation_cancels_stalled_body_without_publishing_bytes() {
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let authority = address.to_string();
        let stop_server = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_server_in_thread = std::sync::Arc::clone(&stop_server);
        let server = thread::spawn(move || {
            let graph = GRAPH.replace("127.0.0.1:PORT", &authority);
            let root = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>root</d:getetag><oc:fileid>root</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
            let target = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/file.bin</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>2</d:getcontentlength><d:getetag>"v1"</d:getetag><oc:fileid>file-id</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
            let mut seen_get = false;
            'accept: loop {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut headers = Vec::new();
                let mut byte = [0u8; 1];
                while !headers.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).is_err() {
                        if stop_server_in_thread.load(std::sync::atomic::Ordering::Acquire) {
                            return seen_get;
                        }
                        // reqwest may open and abandon a pooled connection
                        // before sending a request. Treat an incomplete
                        // request as a discarded connection, not a fixture
                        // shutdown, so the actual request can be accepted.
                        continue 'accept;
                    }
                    headers.push(byte[0]);
                    assert!(headers.len() < 16 * 1024);
                }
                let request = String::from_utf8(headers).unwrap();
                let request_body_len = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let mut request_body = vec![0; request_body_len];
                stream.read_exact(&mut request_body).unwrap();
                let (status, body) = if request.starts_with("GET /graph/") {
                    ("200 OK", graph.as_str())
                } else if request.starts_with("PROPFIND /dav/personal/file.bin") {
                    ("207 Multi-Status", target)
                } else if request.starts_with("PROPFIND /dav/personal/") {
                    ("207 Multi-Status", root)
                } else if request.starts_with("GET /dav/personal/file.bin") {
                    stream
                        .write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 0-1/2\r\nAccept-Ranges: bytes\r\nETag: \"v1\"\r\nConnection: close\r\n\r\nx")
                        .unwrap();
                    stream.flush().unwrap();
                    seen_get = true;
                    let mut drain = [0u8; 64];
                    while stream.read(&mut drain).unwrap_or(0) > 0 {}
                    return seen_get;
                } else {
                    panic!("unexpected range fixture request: {request}");
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body.as_bytes()).unwrap();
            }
        });

        let client = OpenCloudClient::new(
            &format!("http://{address}"),
            "synthetic-token-before-rotation".into(),
        )
        .unwrap()
        .with_body_idle_timeout_for_test(Duration::from_secs(3));
        let context = RangeReadContext {
            deadline: Instant::now() + Duration::from_secs(5),
            token_generation: client.token_generation(),
        };
        let reader_client = client.clone();
        let (finished_tx, finished_rx) = mpsc::channel();
        let (body_started_tx, body_started_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut output = [0xa5; 2];
            let result = reader_client.read_range_cancellable_with_context_and_body_hook(
                RemoteRangeRequest {
                    space: "drive-1",
                    expected_root_id: "root",
                    path: "/file.bin",
                    expected_id: "file-id",
                    expected_etag: "\"v1\"",
                    expected_size: 2,
                    offset: 0,
                },
                &mut output,
                context,
                || false,
                move || {
                    let _ = body_started_tx.send(());
                },
            );
            finished_tx.send((result, output)).unwrap();
        });

        if body_started_rx
            .recv_timeout(Duration::from_secs(2))
            .is_err()
        {
            let completed = finished_rx.try_recv().ok();
            stop_server.store(true, std::sync::atomic::Ordering::Release);
            let _ = std::net::TcpStream::connect(address);
            let server_result = server.join();
            panic!(
                "client did not consume a response-body chunk (server={server_result:?}): {completed:?}"
            );
        }
        let rotated_at = Instant::now();
        client
            .set_bearer_token("synthetic-token-after-rotation".into())
            .unwrap();
        let (result, output) = finished_rx
            .recv_timeout(Duration::from_millis(500))
            .expect("generation rotation must cancel a stalled response promptly");
        assert_eq!(result.unwrap_err().kind, ErrorKind::Unauthorized);
        assert_eq!(output, [0xa5; 2], "no staged body bytes may be published");
        assert!(rotated_at.elapsed() < Duration::from_millis(500));
        reader.join().unwrap();
        assert!(
            server.join().unwrap(),
            "fixture observed the conditional GET"
        );
    }
}
