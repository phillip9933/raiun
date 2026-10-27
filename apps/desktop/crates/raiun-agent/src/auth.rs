//! OAuth authorization-code + PKCE and keyring-backed session storage.
//!
//! Tokens are deliberately not `Debug` values and are never passed on a
//! command line. The Secret Service helper receives them only over stdin and
//! returns them only over stdout.

#[cfg(any(unix, test))]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use raiun_opencloud::ProxyConfig;
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;

const MAX_BODY: u64 = 1_048_576;
const MAX_WEBFINGER_BODY: u64 = 65_536;
const MAX_SECRET: usize = 65_536;
#[cfg(unix)]
const SECRET_SERVICE: &str = "app.raiun.desktop";
const AUTH_CODE_GRANT: &str = "authorization_code";
const CALLBACK_LIMIT: usize = 8192;
#[cfg(any(unix, test))]
const MAX_JWT_PAYLOAD: usize = 8192;
#[cfg(any(unix, test))]
const ISSUER_MISMATCH_HINT: &str = "Token issuer differs from OpenCloud discovery; configure the desktop provider to use the same issuer and signing key as the existing OpenCloud provider.";
const WEBFINGER_ISSUER_REL: &str = "http://openid.net/specs/connect/1.0/issuer";
const LEGACY_WEBFINGER_ISSUER_REL: &str = "http://opencloud.eu/ns/oidc/issuer";
const WEBFINGER_CLIENT_ID: &str = "http://opencloud.eu/ns/oidc/client_id";
const WEBFINGER_SCOPES: &str = "http://opencloud.eu/ns/oidc/scopes";
const DEFAULT_CLIENT_ID: &str = "OpenCloudDesktop";
const DEFAULT_SCOPES: &[&str] = &["openid", "offline_access", "profile", "email"];

#[cfg(all(feature = "synthetic-test-ca", not(debug_assertions)))]
compile_error!("synthetic-test-ca is restricted to debug test builds");

#[derive(Debug)]
struct WebFingerConfig {
    issuer: Option<String>,
    client_id: Option<String>,
    scopes: Option<Vec<String>>,
}

/// A pending user authorization. PKCE credentials stay private to this
/// object and are never included in public status JSON or diagnostics.
pub struct AuthFlow {
    server: String,
    client_id: String,
    token_endpoint: String,
    expected_issuer: Option<String>,
    authorization_url: String,
    redirect_uri: String,
    state: String,
    code_verifier: String,
    expires_at: Instant,
    expires_in: u64,
    listener: TcpListener,
    client: Client,
    proxy: ProxyConfig,
}

/// An OAuth session. This type intentionally does not implement `Debug`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub server: String,
    pub client_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: u64,
    pub token_endpoint: String,
    #[serde(default)]
    pub expected_issuer: Option<String>,
    /// Timestamp of the last successful refresh, safe for local status output.
    #[serde(default)]
    pub last_refresh_at: Option<u64>,
    /// Snapshot of the account's transport route used by discovery, token,
    /// Graph, and DAV clients. Settings changes apply only after reconnect.
    #[serde(default)]
    pub proxy: ProxyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshError {
    Transport,
    Rejected(String),
    Other(String),
}

/// Classified failure while reading a saved OAuth session. Missing sessions
/// remain `Ok(None)`; only Secret Service process/availability failures are
/// retryable during startup restoration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(unix)]
pub enum SessionLoadError {
    Unavailable(String),
    Invalid(String),
}

#[cfg(unix)]
impl std::fmt::Display for SessionLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) | Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport => write!(
                formatter,
                "Could not contact the token endpoint to refresh the session"
            ),
            Self::Rejected(message) | Self::Other(message) => formatter.write_str(message),
        }
    }
}

impl AuthFlow {
    /// Discover OpenID configuration and prepare a loopback PKCE sign-in.
    #[cfg_attr(unix, allow(dead_code))]
    pub fn begin(server: &str, client_id: &str) -> Result<Self, String> {
        Self::begin_with_proxy(server, client_id, ProxyConfig::System)
    }

    /// Discover OpenID configuration using the selected immutable proxy route.
    pub fn begin_with_proxy(
        server: &str,
        client_id: &str,
        proxy: ProxyConfig,
    ) -> Result<Self, String> {
        proxy
            .validate()
            .map_err(|_| "Proxy configuration is invalid")?;
        let server_url = validate_url(server, true, "server")?;
        if server_url.query().is_some() {
            return Err("Server URL must not contain a query string".into());
        }
        let allow_loopback_http =
            server_url.scheme() == "http" && server_url.host_str().is_some_and(is_loopback);
        let manual_client_id = (!client_id.is_empty()).then_some(client_id);
        if let Some(client_id) = manual_client_id {
            validate_client_id(client_id)?;
        }
        let server = normalize_server(&server_url);
        let client = safe_client_for(Some(&server), &proxy)?;
        let webfinger = get_webfinger(&client, &server, &server_url)?;
        let discovered_issuer = webfinger.as_ref().and_then(|info| info.issuer.as_deref());
        let issuer_url = discovered_issuer.unwrap_or(&server);
        ensure_synthetic_test_ca_endpoint(issuer_url)?;
        let metadata_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let metadata = get_json(&client, &metadata_url, "OpenID discovery")?;
        let issuer = required_string(&metadata, "issuer")?;
        validate_url(issuer, allow_loopback_http, "OpenID issuer")?;
        ensure_synthetic_test_ca_endpoint(issuer)?;
        if discovered_issuer.is_some_and(|discovered| discovered != issuer) {
            return Err("OpenID discovery issuer does not match the WebFinger issuer".into());
        }
        let expected_issuer = Some(issuer.to_owned());
        let authorization_endpoint = required_string(&metadata, "authorization_endpoint")?;
        let token_endpoint = required_string(&metadata, "token_endpoint")?;
        validate_url(
            authorization_endpoint,
            allow_loopback_http,
            "authorization endpoint",
        )?;
        ensure_synthetic_test_ca_endpoint(authorization_endpoint)?;
        validate_url(token_endpoint, allow_loopback_http, "token endpoint")?;
        ensure_synthetic_test_ca_endpoint(token_endpoint)?;
        let advertised_client_id = webfinger
            .as_ref()
            .filter(|info| info.issuer.is_some())
            .and_then(|info| info.client_id.as_deref());
        let client_id = manual_client_id
            .or(advertised_client_id)
            .unwrap_or(DEFAULT_CLIENT_ID);
        validate_client_id(client_id)?;
        let mut scopes = webfinger
            .as_ref()
            .filter(|info| info.issuer.is_some())
            .and_then(|info| info.scopes.as_deref())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                DEFAULT_SCOPES
                    .iter()
                    .map(|scope| (*scope).to_owned())
                    .collect()
            });
        // A manually selected public desktop client traditionally requested
        // offline_access so the agent can refresh sessions. Keep honoring
        // server-advertised scopes, while preserving that behavior if a
        // deployment advertises a space-delimited list without the scope.
        if manual_client_id.is_some() && !scopes.iter().any(|scope| scope == "offline_access") {
            scopes.push("offline_access".to_owned());
        }
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|_| "Could not start the local OAuth callback listener".to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "Could not configure the local OAuth callback listener".to_string())?;
        let redirect_uri = format!(
            "http://127.0.0.1:{}",
            listener
                .local_addr()
                .map_err(|_| "Could not read the local OAuth callback address")?
                .port()
        );
        let state = random_url_token(32)?;
        let code_verifier = random_url_token(32)?;
        let code_challenge = base64_url(&Sha256::digest(code_verifier.as_bytes()));
        let mut authorization_url = Url::parse(authorization_endpoint)
            .map_err(|_| "Authorization endpoint URL is invalid".to_string())?;
        authorization_url
            .query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes.join(" "))
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("state", &state)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256");
        let expires_in = 600;

        Ok(Self {
            server,
            client_id: client_id.to_string(),
            token_endpoint: token_endpoint.to_string(),
            expected_issuer,
            authorization_url: authorization_url.to_string(),
            redirect_uri,
            state,
            code_verifier,
            expires_at: Instant::now() + Duration::from_secs(expires_in),
            expires_in,
            listener,
            client,
            proxy,
        })
    }

    /// Data safe for display in settings UI. It contains no verifier or token
    /// credentials.
    pub fn public_info(&self) -> Value {
        json!({
            "url": self.authorization_url,
            "expires_in": self.expires_in,
        })
    }

    /// Return the non-secret identity used for scoping local configuration.
    /// This is an issuer/client tuple, not a verified user subject.
    #[cfg(windows)]
    pub fn configured_identity(&self) -> (&str, &str) {
        (&self.server, &self.client_id)
    }

    /// The effective client ID selected from an explicit override, WebFinger,
    /// or the backward-compatible OpenCloud default.
    #[cfg(any(unix, test))]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Accept the bounded loopback callback until authorization expires.
    #[cfg(any(unix, test))]
    pub fn wait(self) -> Result<Session, String> {
        self.wait_with_cancel(|| false)
    }

    /// Accept the bounded loopback callback until authorization expires or a
    /// caller cancels the in-progress sign-in. The callback is checked on each
    /// nonblocking listener poll so platform control loops can stop promptly.
    pub fn wait_with_cancel(
        self,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Session, String> {
        loop {
            if is_cancelled() {
                return Err("Sign-in was cancelled".into());
            }
            if Instant::now() >= self.expires_at {
                return Err("Sign-in expired. Start sign-in again.".into());
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    // Windows may propagate the listener's nonblocking mode
                    // to accepted sockets. Callback parsing uses bounded
                    // read timeouts, so normalize the accepted stream before
                    // reading rather than treating WSAEWOULDBLOCK as a bad
                    // callback.
                    stream
                        .set_nonblocking(false)
                        .map_err(|_| "Could not configure OAuth callback mode")?;
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .map_err(|_| "Could not configure OAuth callback timeout")?;
                    let code = read_callback(&mut stream, &self.state)?;
                    return self.exchange_code(&code);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => return Err("Could not accept the local OAuth callback".into()),
            }
        }
    }

    fn exchange_code(&self, code: &str) -> Result<Session, String> {
        let response = self
            .client
            .post(&self.token_endpoint)
            .form(&[
                ("grant_type", AUTH_CODE_GRANT),
                ("code", code),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("code_verifier", self.code_verifier.as_str()),
                ("client_id", self.client_id.as_str()),
            ])
            .send()
            .map_err(|_| "Could not contact the token endpoint".to_string())?;
        let status = response.status();
        let body = read_bounded(response, "Authorization token response")?;
        if status.is_success() {
            return parse_session(
                &body,
                &self.server,
                &self.client_id,
                &self.token_endpoint,
                self.expected_issuer.as_deref(),
                self.proxy.clone(),
            );
        }
        let error = oauth_error(&body).unwrap_or("invalid_response");
        Err(match error {
            "access_denied" => "Sign-in was denied by the user or server".into(),
            "invalid_client" => "The server rejected this desktop OAuth client. Check its app registration and client ID.".into(),
            _ => format!("Authorization code exchange failed ({error})"),
        })
    }
}

impl Session {
    /// Refresh the access token without exposing token data in diagnostics.
    #[cfg(unix)]
    pub fn refresh(&mut self) -> Result<(), String> {
        self.refresh_classified().map_err(|error| error.to_string())
    }

    /// Refresh while preserving whether failure occurred before an HTTP
    /// response (transport) or came from validation/server response. Offline
    /// startup may use cached state only for the former.
    pub fn refresh_classified(&mut self) -> Result<(), RefreshError> {
        validate_session(self).map_err(RefreshError::Other)?;
        let refresh_token = self.refresh_token.as_deref().ok_or_else(|| {
            RefreshError::Other("This session has no refresh token; sign in again".into())
        })?;
        let client =
            safe_client_for(Some(&self.server), &self.proxy).map_err(RefreshError::Other)?;
        ensure_synthetic_test_ca_endpoint(&self.token_endpoint).map_err(RefreshError::Other)?;
        let response = client
            .post(&self.token_endpoint)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", self.client_id.as_str()),
            ])
            .send()
            .map_err(|_| RefreshError::Transport)?;
        let status = response.status();
        let body = read_bounded(response, "Token refresh response").map_err(RefreshError::Other)?;
        if !status.is_success() {
            let code = oauth_error(&body).unwrap_or("invalid_response");
            let message = format!("Session refresh failed ({code}); sign in again if needed");
            return Err(if status.as_u16() == 401 || code == "invalid_grant" {
                RefreshError::Rejected(message)
            } else {
                RefreshError::Other(message)
            });
        }
        let refreshed = parse_session(
            &body,
            &self.server,
            &self.client_id,
            &self.token_endpoint,
            self.expected_issuer.as_deref(),
            self.proxy.clone(),
        )
        .map_err(RefreshError::Other)?;
        self.access_token = refreshed.access_token;
        self.expires_at = refreshed.expires_at;
        if refreshed.refresh_token.is_some() {
            self.refresh_token = refreshed.refresh_token;
        }
        self.last_refresh_at = Some(now_unix());
        Ok(())
    }
}

/// Save a session to the user's Secret Service via `secret-tool`.
/// The serialized session is sent through stdin, never an argument or log.
#[cfg(unix)]
pub fn save_session(session: &Session) -> Result<(), String> {
    save_session_scoped(session, None)
}

#[cfg(unix)]
pub fn save_session_scoped(session: &Session, scope: Option<&str>) -> Result<(), String> {
    validate_session(session)?;
    let service = secret_service_name(scope)?;
    let secret = serde_json::to_vec(session)
        .map_err(|_| "Could not encode the session for secure storage".to_string())?;
    if secret.len() > MAX_SECRET {
        return Err("Session exceeds the secure storage size limit".into());
    }
    let mut child = Command::new("secret-tool")
        .args([
            "store",
            "--label=Raiun Desktop session",
            "service",
            &service,
            "server",
            &session.server,
            "client_id",
            &session.client_id,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            "Secret Service is unavailable; install or unlock a compatible keyring".to_string()
        })?;
    let input = child
        .stdin
        .take()
        .ok_or("Could not open Secret Service input")?;
    let writer = thread::spawn(move || {
        let mut input = input;
        input.write_all(&secret).map_err(|_| ())
    });
    let (status, _, _) =
        wait_bounded(child, Duration::from_secs(10)).map_err(|error| error.to_string())?;
    if writer
        .join()
        .map_err(|_| "Could not write the session to Secret Service")?
        .is_err()
    {
        return Err("Could not write the session to Secret Service".into());
    }
    if status.success() {
        Ok(())
    } else {
        Err("Secret Service could not store the session; unlock the keyring and retry".into())
    }
}

#[cfg(unix)]
pub fn load_session_scoped_classified(
    server: &str,
    client_id: &str,
    scope: Option<&str>,
) -> Result<Option<Session>, SessionLoadError> {
    let service = secret_service_name(scope).map_err(SessionLoadError::Invalid)?;
    let server_url = validate_url(server, true, "server").map_err(SessionLoadError::Invalid)?;
    if server_url.query().is_some() {
        return Err(SessionLoadError::Invalid(
            "Server URL must not contain a query string".into(),
        ));
    }
    if client_id.trim().is_empty() || client_id.len() > 512 {
        return Err(SessionLoadError::Invalid(
            "OAuth client ID is empty or too long".into(),
        ));
    }
    let server = normalize_server(&server_url);
    let child = Command::new("secret-tool")
        .args([
            "lookup",
            "service",
            &service,
            "server",
            &server,
            "client_id",
            client_id,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            SessionLoadError::Unavailable(
                "Secret Service is unavailable; install or unlock a compatible keyring".into(),
            )
        })?;
    let (status, output, stderr) =
        wait_bounded(child, Duration::from_secs(10)).map_err(SessionLoadError::from)?;
    if !status.success() {
        return if status.code() == Some(1) && stderr.is_empty() {
            Ok(None)
        } else {
            Err(SessionLoadError::Unavailable(
                "Secret Service could not read the session; unlock the keyring and retry".into(),
            ))
        };
    }
    let session: Session = serde_json::from_slice(&output).map_err(|_| {
        SessionLoadError::Invalid("Stored session is invalid; sign in again".into())
    })?;
    if session.server != server || session.client_id != client_id {
        return Err(SessionLoadError::Invalid(
            "Stored session does not match the requested account".into(),
        ));
    }
    validate_session(&session).map_err(SessionLoadError::Invalid)?;
    Ok(Some(session))
}

#[cfg(unix)]
pub fn remove_session(server: &str, client_id: &str) -> Result<(), String> {
    remove_session_scoped(server, client_id, None)
}

#[cfg(unix)]
pub fn remove_session_scoped(
    server: &str,
    client_id: &str,
    scope: Option<&str>,
) -> Result<(), String> {
    let service = secret_service_name(scope)?;
    let server_url = validate_url(server, true, "server")?;
    if server_url.query().is_some() {
        return Err("Server URL must not contain a query string".into());
    }
    if client_id.trim().is_empty() || client_id.len() > 512 {
        return Err("OAuth client ID is empty or too long".into());
    }
    let server = normalize_server(&server_url);
    let child = Command::new("secret-tool")
        .args([
            "clear",
            "service",
            &service,
            "server",
            &server,
            "client_id",
            client_id,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            "Secret Service is unavailable; install or unlock a compatible keyring".to_string()
        })?;
    let (status, _, _) =
        wait_bounded(child, Duration::from_secs(10)).map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(
            "Secret Service could not remove the saved session; unlock the keyring and retry"
                .into(),
        )
    }
}

#[cfg(unix)]
fn secret_service_name(scope: Option<&str>) -> Result<String, String> {
    match scope {
        None => Ok(SECRET_SERVICE.to_owned()),
        Some(scope)
            if !scope.is_empty()
                && scope.len() <= 64
                && scope.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                }) =>
        {
            Ok(format!("{SECRET_SERVICE}.profile.{scope}"))
        }
        Some(_) => Err("Secret Service profile scope is invalid".into()),
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum SecretToolError {
    Unavailable(String),
    ResponseTooLarge,
}

#[cfg(unix)]
impl std::fmt::Display for SecretToolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => formatter.write_str(message),
            Self::ResponseTooLarge => {
                formatter.write_str("Secret Service response exceeds the size limit")
            }
        }
    }
}

#[cfg(unix)]
impl From<SecretToolError> for SessionLoadError {
    fn from(error: SecretToolError) -> Self {
        match error {
            SecretToolError::Unavailable(message) => Self::Unavailable(message),
            SecretToolError::ResponseTooLarge => Self::Invalid(error.to_string()),
        }
    }
}

/// Run a Secret Service helper without allowing an unlocked/absent keyring to
/// hang startup forever. Both pipes are drained on helper threads so a full
/// pipe cannot prevent the timeout check. Diagnostic output is intentionally
/// discarded and never returned to callers.
#[cfg(unix)]
fn wait_bounded(
    mut child: Child,
    timeout: Duration,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), SecretToolError> {
    let stdout = child.stdout.take().ok_or_else(|| {
        SecretToolError::Unavailable("Could not read Secret Service output".into())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        SecretToolError::Unavailable("Could not read Secret Service diagnostics".into())
    })?;
    let out_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take((MAX_SECRET + 1) as u64).read_to_end(&mut bytes);
        bytes
    });
    let err_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.take(8193).read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err(SecretToolError::Unavailable(
                    "Secret Service timed out; unlock the keyring and retry".into(),
                ));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SecretToolError::Unavailable(
                    "Could not read the session from Secret Service".into(),
                ));
            }
        }
    };
    let output = out_reader
        .join()
        .map_err(|_| SecretToolError::Unavailable("Could not read Secret Service output".into()))?;
    let stderr = err_reader.join().map_err(|_| {
        SecretToolError::Unavailable("Could not read Secret Service diagnostics".into())
    })?;
    if output.len() > MAX_SECRET || stderr.len() > 8192 {
        return Err(SecretToolError::ResponseTooLarge);
    }
    Ok((status, output, stderr))
}

#[cfg(test)]
fn safe_client() -> Result<Client, String> {
    safe_client_for(None, &ProxyConfig::System)
}

fn safe_client_for(server: Option<&str>, proxy: &ProxyConfig) -> Result<Client, String> {
    let builder = proxy
        .apply_to_client_builder(Client::builder())
        .map_err(|_| "Proxy configuration is invalid")?
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20));
    #[cfg(feature = "synthetic-test-ca")]
    let builder = if let Some((origin, pem_path)) = synthetic_test_ca_config()? {
        let server = server.ok_or_else(|| {
            "Synthetic test CA requires an explicitly scoped loopback server".to_string()
        })?;
        let server_origin = url_origin(server)?;
        if server_origin != origin {
            return Err("Synthetic test CA is scoped to a different server origin".into());
        }
        let pem = std::fs::read(pem_path)
            .map_err(|_| "Could not read the explicit synthetic test CA certificate".to_string())?;
        if pem.is_empty() || pem.len() > 65_536 {
            return Err("Synthetic test CA certificate exceeds the size limit".into());
        }
        let certificate = reqwest::Certificate::from_pem(&pem)
            .map_err(|_| "Synthetic test CA certificate is invalid".to_string())?;
        builder.add_root_certificate(certificate)
    } else {
        builder
    };
    #[cfg(not(feature = "synthetic-test-ca"))]
    let _ = server;
    builder
        .build()
        .map_err(|_| "Could not create a secure OAuth HTTP client".into())
}

#[cfg(feature = "synthetic-test-ca")]
fn synthetic_test_ca_config() -> Result<Option<(String, std::ffi::OsString)>, String> {
    let origin = std::env::var("RAIUN_SYNTHETIC_TEST_CA_ORIGIN").ok();
    let pem_path = std::env::var_os("RAIUN_SYNTHETIC_TEST_CA_PEM");
    match (origin, pem_path) {
        (None, None) => Ok(None),
        (Some(origin), Some(pem_path)) => Ok(Some((
            normalize_synthetic_test_ca_origin(&origin)?,
            pem_path,
        ))),
        _ => Err("Synthetic test CA requires both origin and PEM path".into()),
    }
}

#[cfg(feature = "synthetic-test-ca")]
fn normalize_synthetic_test_ca_origin(origin: &str) -> Result<String, String> {
    let parsed =
        Url::parse(origin).map_err(|_| "Synthetic test CA origin is invalid".to_string())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none_or(|host| !is_loopback(host))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return Err("Synthetic test CA origin must be an HTTPS loopback origin".into());
    }
    let normalized = parsed.origin().ascii_serialization();
    if origin.trim_end_matches('/') != normalized {
        return Err("Synthetic test CA origin must not include a path".into());
    }
    Ok(normalized)
}

#[cfg(feature = "synthetic-test-ca")]
fn url_origin(value: &str) -> Result<String, String> {
    let parsed = Url::parse(value).map_err(|_| "Server URL is invalid".to_string())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none_or(|host| !is_loopback(host))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("Synthetic test CA is limited to HTTPS loopback URLs".into());
    }
    Ok(parsed.origin().ascii_serialization())
}

#[cfg(feature = "synthetic-test-ca")]
fn ensure_synthetic_test_ca_endpoint(value: &str) -> Result<(), String> {
    if let Some((origin, _)) = synthetic_test_ca_config()? {
        if url_origin(value)? != origin {
            return Err(
                "Synthetic test CA discovery endpoints must use the configured origin".into(),
            );
        }
    }
    Ok(())
}

#[cfg(not(feature = "synthetic-test-ca"))]
fn ensure_synthetic_test_ca_endpoint(_value: &str) -> Result<(), String> {
    Ok(())
}

fn get_json(client: &Client, url: &str, context: &str) -> Result<Value, String> {
    let response = client
        .get(url)
        .send()
        .map_err(|_| format!("Could not contact {context}"))?;
    bounded_json(response, context)
}

fn get_webfinger(
    client: &Client,
    server: &str,
    server_url: &Url,
) -> Result<Option<WebFingerConfig>, String> {
    let mut endpoint = Url::parse(&format!("{server}/.well-known/webfinger"))
        .map_err(|_| "OpenCloud WebFinger URL is invalid".to_string())?;
    endpoint
        .query_pairs_mut()
        .append_pair("resource", server)
        .append_pair("rel", WEBFINGER_ISSUER_REL)
        .append_pair("platform", "desktop");
    let response = client
        .get(endpoint)
        .send()
        .map_err(|_| "Could not contact OpenCloud WebFinger discovery".to_string())?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(format!(
            "OpenCloud WebFinger endpoint returned HTTP {}",
            response.status().as_u16()
        ));
    }
    let bytes = read_bounded_with_limit(response, "OpenCloud WebFinger", MAX_WEBFINGER_BODY)?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "OpenCloud WebFinger endpoint returned invalid JSON".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "OpenCloud WebFinger response is not a JSON object".to_string())?;

    let links = match object.get("links") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(links)) => links.as_slice(),
        _ => return Err("OpenCloud WebFinger links field is malformed".into()),
    };
    let mut standard_issuers = Vec::new();
    let mut legacy_issuers = Vec::new();
    for link in links {
        let link = link
            .as_object()
            .ok_or_else(|| "OpenCloud WebFinger link is malformed".to_string())?;
        let Some(rel) = link.get("rel").and_then(Value::as_str) else {
            continue;
        };
        if rel != WEBFINGER_ISSUER_REL && rel != LEGACY_WEBFINGER_ISSUER_REL {
            continue;
        }
        let href = link
            .get("href")
            .and_then(Value::as_str)
            .filter(|href| !href.trim().is_empty())
            .ok_or_else(|| "OpenCloud WebFinger issuer link has no href".to_string())?;
        let issuer = validate_url(
            href,
            is_loopback(server_url.host_str().unwrap_or("")),
            "WebFinger issuer",
        )?;
        if issuer.query().is_some() {
            return Err("WebFinger issuer URL must not contain a query string".into());
        }
        let list = if rel == WEBFINGER_ISSUER_REL {
            &mut standard_issuers
        } else {
            &mut legacy_issuers
        };
        list.push(href.to_owned());
    }
    let issuer_values = if standard_issuers.is_empty() {
        &legacy_issuers
    } else {
        &standard_issuers
    };
    if issuer_values.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err("OpenCloud WebFinger returned conflicting issuer links".into());
    }
    let issuer = issuer_values.first().cloned();

    let properties = match object.get("properties") {
        None | Some(Value::Null) => None,
        Some(Value::Object(properties)) => Some(properties),
        _ => return Err("OpenCloud WebFinger properties field is malformed".into()),
    };
    let client_id = properties
        .and_then(|properties| properties.get(WEBFINGER_CLIENT_ID))
        .map(|value| {
            let client_id = value
                .as_str()
                .ok_or_else(|| "OpenCloud WebFinger client ID property is malformed".to_string())?;
            validate_client_id(client_id)?;
            Ok::<String, String>(client_id.to_owned())
        })
        .transpose()?;
    let scopes = properties
        .and_then(|properties| properties.get(WEBFINGER_SCOPES))
        .map(|value| {
            let values = value
                .as_array()
                .ok_or_else(|| "OpenCloud WebFinger scopes property is malformed".to_string())?;
            if values.is_empty() || values.len() > 128 {
                return Err("OpenCloud WebFinger scopes are empty or exceed the limit".into());
            }
            let mut scopes = Vec::with_capacity(values.len());
            for value in values {
                let value = value
                    .as_str()
                    .ok_or_else(|| "OpenCloud WebFinger scope value is malformed".to_string())?;
                // OpenCloud's JRD example represents scopes as individual
                // array values, while some deployed servers return one
                // whitespace-separated value, e.g. ["openid profile email"].
                // Accept both representations, then validate every OAuth
                // scope token exactly as before.
                for scope in value.split_ascii_whitespace() {
                    if !valid_scope(scope) || scopes.iter().any(|old| old == scope) {
                        return Err("OpenCloud WebFinger scope value is invalid".into());
                    }
                    scopes.push(scope.to_owned());
                }
            }
            if scopes.is_empty() {
                return Err("OpenCloud WebFinger scopes are empty or exceed the limit".into());
            }
            if !scopes.iter().any(|scope| scope == "openid") {
                return Err("OpenCloud WebFinger OIDC scopes omit openid".into());
            }
            Ok::<Vec<String>, String>(scopes)
        })
        .transpose()?;

    Ok(Some(WebFingerConfig {
        issuer,
        client_id,
        scopes,
    }))
}

fn validate_client_id(client_id: &str) -> Result<(), String> {
    if client_id.trim().is_empty()
        || client_id.len() > 512
        || client_id.chars().any(char::is_control)
    {
        return Err("OAuth client ID is empty, invalid, or too long".into());
    }
    Ok(())
}

fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

fn bounded_json(response: Response, context: &str) -> Result<Value, String> {
    if !response.status().is_success() {
        return Err(format!(
            "{context} endpoint returned HTTP {}",
            response.status().as_u16()
        ));
    }
    let bytes = read_bounded(response, context)?;
    serde_json::from_slice(&bytes).map_err(|_| format!("{context} endpoint returned invalid JSON"))
}

fn read_bounded(response: Response, context: &str) -> Result<Vec<u8>, String> {
    read_bounded_with_limit(response, context, MAX_BODY)
}

fn read_bounded_with_limit(
    response: Response,
    context: &str,
    max_size: u64,
) -> Result<Vec<u8>, String> {
    if response.content_length().is_some_and(|len| len > max_size) {
        return Err(format!("{context} response exceeds the size limit"));
    }
    let mut body = Vec::new();
    response
        .take(max_size + 1)
        .read_to_end(&mut body)
        .map_err(|_| format!("Could not read {context} response"))?;
    if body.len() as u64 > max_size {
        return Err(format!("{context} response exceeds the size limit"));
    }
    Ok(body)
}

fn parse_session(
    body: &[u8],
    server: &str,
    client_id: &str,
    token_endpoint: &str,
    expected_issuer: Option<&str>,
    proxy: ProxyConfig,
) -> Result<Session, String> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| "Token endpoint returned invalid JSON".to_string())?;
    let access_token = required_string(&value, "access_token")?.to_string();
    if access_token.len() > MAX_SECRET {
        return Err("Token endpoint returned an oversized access token".into());
    }
    let expires_in = value
        .get("expires_in")
        .and_then(Value::as_u64)
        .filter(|seconds| (1..=31_536_000).contains(seconds))
        .ok_or_else(|| "Token endpoint returned an invalid token expiry".to_string())?;
    let refresh_token = value
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if refresh_token
        .as_ref()
        .is_some_and(|token| token.len() > MAX_SECRET)
    {
        return Err("Token endpoint returned an oversized refresh token".into());
    }
    Ok(Session {
        server: server.to_string(),
        client_id: client_id.to_string(),
        access_token,
        refresh_token,
        expires_at: now_unix().saturating_add(expires_in),
        token_endpoint: token_endpoint.to_string(),
        expected_issuer: expected_issuer.map(str::to_owned),
        last_refresh_at: None,
        proxy,
    })
}

pub(crate) fn validate_session(session: &Session) -> Result<(), String> {
    session
        .proxy
        .validate()
        .map_err(|_| "Stored proxy configuration is invalid".to_string())?;
    let server = validate_url(&session.server, true, "stored server")?;
    let allow_loopback_http =
        server.scheme() == "http" && server.host_str().is_some_and(is_loopback);
    validate_url(
        &session.token_endpoint,
        allow_loopback_http,
        "stored token endpoint",
    )?;
    if let Some(issuer) = &session.expected_issuer {
        validate_url(issuer, allow_loopback_http, "stored OpenID issuer")?;
    }
    if session.client_id.trim().is_empty()
        || session.client_id.len() > 512
        || session.access_token.is_empty()
        || session.access_token.len() > MAX_SECRET
        || session
            .refresh_token
            .as_ref()
            .is_some_and(|token| token.len() > MAX_SECRET)
        || session.expires_at == 0
    {
        return Err("Stored session is incomplete; sign in again".into());
    }
    if normalize_server(&server) != session.server {
        return Err("Stored session server is not normalized".into());
    }
    Ok(())
}

/// Add a narrowly scoped setup hint to Graph discovery failures when an
/// unverified JWT payload appears to name a different issuer than discovery.
/// The claim is diagnostic only; no token is rejected or treated as proof.
#[cfg(any(unix, test))]
pub fn graph_error_with_issuer_hint(error: &str, session: &Session) -> String {
    let mismatch = session.expected_issuer.as_deref().is_some_and(|expected| {
        unverified_token_issuer(session.access_token.as_str())
            .is_some_and(|actual| actual != expected)
    });
    if mismatch {
        format!("{error}. {ISSUER_MISMATCH_HINT}")
    } else {
        error.to_owned()
    }
}

#[cfg(any(unix, test))]
fn unverified_token_issuer(token: &str) -> Option<String> {
    if token.len() > MAX_SECRET {
        return None;
    }
    let mut segments = token.split('.');
    let header = segments.next()?;
    let payload = segments.next()?;
    let signature = segments.next()?;
    if header.is_empty()
        || payload.is_empty()
        || signature.is_empty()
        || segments.next().is_some()
        || payload.len() > MAX_JWT_PAYLOAD * 2
    {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    if decoded.len() > MAX_JWT_PAYLOAD {
        return None;
    }
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let issuer = claims.get("iss")?.as_str()?;
    if issuer.is_empty() || issuer.len() > 2048 || issuer.chars().any(char::is_control) {
        return None;
    }
    Some(issuer.to_owned())
}

fn validate_url(raw: &str, allow_loopback_http: bool, label: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| format!("Invalid {label} URL"))?;
    let loopback = url.host_str().is_some_and(is_loopback);
    let secure =
        url.scheme() == "https" || (allow_loopback_http && loopback && url.scheme() == "http");
    if !secure
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "http" && url.scheme() != "https")
    {
        return Err(format!(
            "{label} must use HTTPS (HTTP is allowed only for loopback tests)"
        ));
    }
    Ok(url)
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn normalize_server(url: &Url) -> String {
    let mut server = url.clone();
    server.set_query(None);
    server.set_fragment(None);
    while server.path().len() > 1 && server.path().ends_with('/') {
        let trimmed = server.path().trim_end_matches('/').to_string();
        server.set_path(&trimmed);
    }
    server.to_string().trim_end_matches('/').to_string()
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("OAuth response omitted {key}"))
}

fn oauth_error(body: &[u8]) -> Option<&'static str> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let raw = value.get("error")?.as_str()?;
    Some(match raw {
        "authorization_pending" => "authorization_pending",
        "slow_down" => "slow_down",
        "too_many_requests" => "too_many_requests",
        "access_denied" => "access_denied",
        "expired_token" => "expired_token",
        "temporarily_unavailable" => "temporarily_unavailable",
        "server_error" => "server_error",
        "invalid_client" => "invalid_client",
        "invalid_grant" => "invalid_grant",
        "invalid_scope" => "invalid_scope",
        "unsupported_grant_type" => "unsupported_grant_type",
        _ => "oauth_error",
    })
}

fn random_url_token(bytes: usize) -> Result<String, String> {
    let mut raw = vec![0u8; bytes];
    getrandom::fill(&mut raw)
        .map_err(|_| "Could not generate secure OAuth randomness".to_string())?;
    Ok(base64_url(&raw))
}

fn base64_url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    for chunk in input.chunks(3) {
        let a = chunk[0] as usize;
        let b = chunk.get(1).copied().unwrap_or(0) as usize;
        let c = chunk.get(2).copied().unwrap_or(0) as usize;
        out.push(TABLE[a >> 2] as char);
        out.push(TABLE[((a & 3) << 4) | (b >> 4)] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((b & 15) << 2) | (c >> 6)] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[c & 63] as char);
        }
    }
    out
}

fn read_callback(stream: &mut TcpStream, expected_state: &str) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut request = Vec::new();
    let mut line = Vec::new();
    read_callback_line(stream, &mut line, deadline)?;
    request.extend_from_slice(&line);
    if request.len() > CALLBACK_LIMIT || !line.ends_with(b"\r\n") {
        callback_reply(stream, false);
        return Err("OAuth callback was invalid or oversized".into());
    }
    let first = String::from_utf8_lossy(&line).into_owned();
    let mut parts = first.split_ascii_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("");
    if method != "GET" || version != "HTTP/1.1" {
        callback_reply(stream, false);
        return Err("OAuth callback request was invalid".into());
    }
    loop {
        line.clear();
        read_callback_line(stream, &mut line, deadline)?;
        request.extend_from_slice(&line);
        if request.len() > CALLBACK_LIMIT {
            callback_reply(stream, false);
            return Err("OAuth callback was oversized".into());
        }
        if line == b"\r\n" || line.is_empty() {
            break;
        }
    }
    let callback_url = Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|_| "OAuth callback URL was invalid")?;
    if callback_url.path() != "/" {
        callback_reply(stream, false);
        return Err("OAuth callback path was invalid".into());
    }
    let query: std::collections::HashMap<String, String> =
        callback_url.query_pairs().into_owned().collect();
    let state = query.get("state").map(String::as_str).unwrap_or("");
    if !constant_time_equal(state.as_bytes(), expected_state.as_bytes()) {
        callback_reply(stream, false);
        return Err("OAuth callback state did not match; sign-in was rejected".into());
    }
    if query.contains_key("error") {
        callback_reply(stream, false);
        let error = query
            .get("error")
            .map(String::as_str)
            .unwrap_or("invalid_response");
        return Err(match error {
            "access_denied" => "Sign-in was denied by the user or server".into(),
            "login_required" => "The server requires another sign-in method".into(),
            _ => "The authorization server did not complete sign-in".into(),
        });
    }
    let Some(code) = query
        .get("code")
        .filter(|code| !code.is_empty() && code.len() <= 8192)
    else {
        callback_reply(stream, false);
        let error = query
            .get("error")
            .map(String::as_str)
            .unwrap_or("invalid_response");
        return Err(match error {
            "access_denied" => "Sign-in was denied by the user or server".into(),
            "login_required" => "The server requires another sign-in method".into(),
            _ => "The authorization server returned no authorization code".into(),
        });
    };
    callback_reply(stream, true);
    Ok(code.clone())
}

fn read_callback_line(
    stream: &mut TcpStream,
    line: &mut Vec<u8>,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("OAuth callback timed out".into());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| "Could not configure OAuth callback timeout")?;
        let mut byte = [0u8; 1];
        let count = stream
            .read(&mut byte)
            .map_err(|_| "OAuth callback timed out")?;
        if count == 0 {
            return Err("OAuth callback ended unexpectedly".into());
        }
        line.push(byte[0]);
        if line.len() > CALLBACK_LIMIT {
            return Err("OAuth callback was oversized".into());
        }
        if byte[0] == b'\n' {
            return Ok(());
        }
    }
}

fn callback_reply(stream: &mut TcpStream, accepted: bool) {
    let (status, message) = if accepted {
        ("200 OK", "Sign-in received. You can close this tab.")
    } else {
        (
            "400 Bad Request",
            "Sign-in could not be completed. Return to Raiun Desktop.",
        )
    };
    let body = format!("<!doctype html><title>Raiun Desktop</title><p>{message}</p>");
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    #[cfg(unix)]
    #[test]
    fn secret_service_oversized_response_is_permanent_corrupt_data() {
        let child = Command::new("sh")
            .args(["-c", "head -c 65537 /dev/zero"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn synthetic output fixture");

        let error = wait_bounded(child, Duration::from_secs(3)).unwrap_err();

        assert_eq!(
            SessionLoadError::from(error),
            SessionLoadError::Invalid("Secret Service response exceeds the size limit".into())
        );
        assert_eq!(
            SessionLoadError::from(SecretToolError::Unavailable("timeout".into())),
            SessionLoadError::Unavailable("timeout".into())
        );
    }

    #[cfg(feature = "synthetic-test-ca")]
    #[test]
    fn synthetic_ca_origin_is_https_loopback_only() {
        assert_eq!(
            normalize_synthetic_test_ca_origin("https://127.0.0.1:18443").unwrap(),
            "https://127.0.0.1:18443"
        );
        assert!(normalize_synthetic_test_ca_origin("http://127.0.0.1:18443").is_err());
        assert!(normalize_synthetic_test_ca_origin("https://example.com").is_err());
        assert!(normalize_synthetic_test_ca_origin("https://127.0.0.1:18443/path").is_err());
    }

    fn read_http_request(stream: &TcpStream) -> (String, Vec<u8>, String) {
        // A server listener switched to nonblocking mode for bounded accept
        // polling can yield accepted sockets that retain that mode on Windows.
        // Test handlers intentionally consume complete request bodies, so use
        // blocking reads (the clients already have bounded request timeouts).
        stream.set_nonblocking(false).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let first = line.trim_end().to_owned();
        let mut headers = String::new();
        headers.push_str(&line);
        let mut length = 0usize;
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            headers.push_str(&line);
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        (first, body, headers)
    }

    fn response(stream: &mut TcpStream, status: u16, body: &str) {
        let text = if status == 200 {
            "OK"
        } else if status == 302 {
            "Found"
        } else {
            "Bad Request"
        };
        write!(stream, "HTTP/1.1 {status} {text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    }

    fn refresh_session(endpoint: &str) -> Session {
        let server = endpoint.trim_end_matches("/token").to_owned();
        Session {
            server: server.clone(),
            client_id: "synthetic-client".into(),
            access_token: "old-access-token".into(),
            refresh_token: Some("old-refresh-token".into()),
            expires_at: now_unix().saturating_sub(1),
            token_endpoint: endpoint.to_owned(),
            expected_issuer: Some(server),
            last_refresh_at: None,
            proxy: ProxyConfig::System,
        }
    }

    fn refresh_server(
        status: u16,
        body: &'static str,
    ) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let task = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (request, request_body, _) = read_http_request(&stream);
            assert!(request.starts_with("POST /token"));
            let form: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(&request_body)
                    .into_owned()
                    .collect();
            assert_eq!(
                form.get("grant_type").map(String::as_str),
                Some("refresh_token")
            );
            assert_eq!(
                form.get("refresh_token").map(String::as_str),
                Some("old-refresh-token")
            );
            assert_eq!(
                form.get("client_id").map(String::as_str),
                Some("synthetic-client")
            );
            response(&mut stream, status, body);
            String::from_utf8(request_body).unwrap()
        });
        (endpoint, task)
    }

    #[cfg(not(feature = "synthetic-test-ca"))]
    #[test]
    fn auth_discovery_and_refresh_share_explicit_proxy_without_echoing_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy_server = thread::spawn(move || {
            let mut requests = Vec::new();
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let (first, _body, headers) = read_http_request(&stream);
                requests.push(format!("{first}\n{headers}"));
                if index == 0 {
                    let body = "{}";
                    write!(stream, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                }
                // Closing the second connection without an HTTP response makes
                // the refresh failure a transport error independent of proxy
                // status-code classification.
            }
            requests
        });
        let proxy = ProxyConfig::Explicit {
            url: format!("http://{proxy_address}"),
        };
        let begin_result =
            AuthFlow::begin_with_proxy("http://127.0.0.1:9", "synthetic-client", proxy.clone());
        let begin_error = match begin_result {
            Ok(_) => panic!("the rejecting proxy must stop discovery"),
            Err(error) => error,
        };
        assert!(!begin_error.contains(&proxy_address.to_string()));

        let mut session = refresh_session("http://127.0.0.1:9/token");
        session.proxy = proxy;
        assert_eq!(session.refresh_classified(), Err(RefreshError::Transport));

        let requests = proxy_server.join().unwrap();
        assert!(requests[0].starts_with("GET http://127.0.0.1:9/.well-known/webfinger?"));
        assert!(requests[1].starts_with("POST http://127.0.0.1:9/token "));
        assert!(
            requests
                .iter()
                .all(|request| !request.contains("refresh_token"))
        );
    }

    #[cfg(not(feature = "synthetic-test-ca"))]
    #[test]
    fn explicit_proxy_carries_webfinger_oidc_code_exchange_and_refresh() {
        let target = "http://127.0.0.1:9";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy_url = format!("http://{proxy_address}");
        let target_for_thread = target.to_owned();
        let proxy_server = thread::spawn(move || {
            let mut captured = Vec::new();
            for index in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                let (first, body, headers) = read_http_request(&stream);
                captured.push((first.clone(), body.clone(), headers.clone()));
                match index {
                    0 => {
                        assert!(first.starts_with(&format!(
                            "GET {target_for_thread}/.well-known/webfinger?"
                        )));
                        let body = json!({
                            "links": [{"rel": WEBFINGER_ISSUER_REL, "href": target_for_thread}],
                            "properties": {
                                WEBFINGER_CLIENT_ID: "advertised-client",
                                WEBFINGER_SCOPES: ["openid", "profile"]
                            }
                        })
                        .to_string();
                        response(&mut stream, 200, &body);
                    }
                    1 => {
                        assert!(first.starts_with(&format!(
                            "GET {target_for_thread}/.well-known/openid-configuration "
                        )));
                        assert!(!headers.lines().any(|line| {
                            line.to_ascii_lowercase().starts_with("authorization:")
                        }));
                        let body = metadata_for_issuer(&target_for_thread, &target_for_thread);
                        response(&mut stream, 200, &body);
                    }
                    2 | 3 => {
                        assert!(first.starts_with(&format!("POST {target_for_thread}/token ")));
                        let form: std::collections::HashMap<String, String> =
                            url::form_urlencoded::parse(&body).into_owned().collect();
                        if index == 2 {
                            assert_eq!(
                                form.get("grant_type").map(String::as_str),
                                Some("authorization_code")
                            );
                            assert_eq!(
                                form.get("code").map(String::as_str),
                                Some("synthetic-code")
                            );
                            assert_eq!(
                                form.get("client_id").map(String::as_str),
                                Some("synthetic-client")
                            );
                            assert!(
                                form.get("code_verifier")
                                    .is_some_and(|value| !value.is_empty())
                            );
                        } else {
                            assert_eq!(
                                form.get("grant_type").map(String::as_str),
                                Some("refresh_token")
                            );
                            assert_eq!(
                                form.get("refresh_token").map(String::as_str),
                                Some("synthetic-refresh")
                            );
                        }
                        response(
                            &mut stream,
                            200,
                            if index == 2 {
                                r#"{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_in":3600}"#
                            } else {
                                r#"{"access_token":"synthetic-access-2","refresh_token":"synthetic-refresh-2","expires_in":3600}"#
                            },
                        );
                    }
                    _ => unreachable!(),
                }
            }
            captured
        });

        let flow = AuthFlow::begin_with_proxy(
            target,
            "synthetic-client",
            ProxyConfig::Explicit { url: proxy_url },
        )
        .unwrap();
        let info = flow.public_info();
        let authorization = Url::parse(info["url"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> =
            authorization.query_pairs().into_owned().collect();
        let redirect = Url::parse(params.get("redirect_uri").unwrap()).unwrap();
        let state = params.get("state").unwrap().clone();

        let waiter = thread::spawn(move || flow.wait());
        let mut callback = TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).unwrap();
        write!(
            callback,
            "GET /?code=synthetic-code&state={state} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        let mut session = waiter.join().unwrap().unwrap();
        session.expires_at = now_unix().saturating_sub(1);
        session.refresh_classified().unwrap();

        let captured = proxy_server.join().unwrap();
        assert_eq!(captured.len(), 4);
        assert!(captured.iter().all(|(request, _, _)| {
            request.starts_with(&format!("GET {target}/.well-known/"))
                || request.starts_with(&format!("POST {target}/token "))
        }));
        assert_eq!(session.access_token, "synthetic-access-2");
    }

    fn metadata_for_issuer(base: &str, issuer: &str) -> String {
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token")
        })
        .to_string()
    }

    fn start_server() -> (String, std::thread::JoinHandle<Vec<u8>>) {
        start_server_with_webfinger(404, "", None)
    }

    #[test]
    fn refresh_persists_rotation_fields_only_from_a_successful_response() {
        let (endpoint, server) = refresh_server(
            200,
            r#"{"access_token":"rotated-access-token","refresh_token":"rotated-refresh-token","expires_in":3600}"#,
        );
        let mut session = refresh_session(&endpoint);
        session.refresh_classified().unwrap();
        server.join().unwrap();
        assert_eq!(session.access_token, "rotated-access-token");
        assert_eq!(
            session.refresh_token.as_deref(),
            Some("rotated-refresh-token")
        );
        assert!(session.expires_at > now_unix() + 3500);
        assert!(session.last_refresh_at.is_some());
    }

    #[test]
    fn saved_session_keeps_its_proxy_snapshot() {
        let mut session = refresh_session("https://cloud.example/token");
        session.proxy = ProxyConfig::Explicit {
            url: "http://proxy.example:3128".into(),
        };
        let encoded = serde_json::to_vec(&session).unwrap();
        let restored: Session = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.proxy, session.proxy);

        let legacy = json!({
            "server": session.server,
            "client_id": session.client_id,
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_at": session.expires_at,
            "token_endpoint": session.token_endpoint,
            "expected_issuer": session.expected_issuer,
            "last_refresh_at": session.last_refresh_at,
        });
        let restored_legacy: Session = serde_json::from_value(legacy).unwrap();
        assert_eq!(restored_legacy.proxy, ProxyConfig::System);
    }

    #[test]
    fn refresh_rejection_is_distinct_from_transport_failure() {
        let (endpoint, server) = refresh_server(401, r#"{"error":"invalid_grant"}"#);
        let mut session = refresh_session(&endpoint);
        assert!(matches!(
            session.refresh_classified(),
            Err(RefreshError::Rejected(_))
        ));
        server.join().unwrap();
        assert_eq!(session.access_token, "old-access-token");
        assert_eq!(session.refresh_token.as_deref(), Some("old-refresh-token"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let unavailable = format!("http://{}/token", listener.local_addr().unwrap());
        drop(listener);
        let mut session = refresh_session(&unavailable);
        assert_eq!(session.refresh_classified(), Err(RefreshError::Transport));
        assert_eq!(session.access_token, "old-access-token");
        assert_eq!(session.refresh_token.as_deref(), Some("old-refresh-token"));
    }

    fn start_server_with_webfinger(
        webfinger_status: u16,
        webfinger_body: &str,
        metadata_issuer: Option<&str>,
    ) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let issuer = metadata_issuer
            .unwrap_or("https://issuer.example")
            .replace("{server}", &base);
        let discovery = metadata_for_issuer(&base, &issuer);
        let webfinger_body = webfinger_body.replace("{server}", &base);
        let base_for_thread = base.clone();
        let task = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let (request, _, headers) = read_http_request(&first);
            assert!(request.starts_with("GET /.well-known/webfinger?"));
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            );
            let url = Url::parse(&format!(
                "{base_for_thread}{}",
                request.split_whitespace().nth(1).unwrap()
            ))
            .unwrap();
            let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(
                params.get("resource").map(String::as_str),
                Some(base_for_thread.as_str())
            );
            assert_eq!(
                params.get("rel").map(String::as_str),
                Some(WEBFINGER_ISSUER_REL)
            );
            assert_eq!(params.get("platform").map(String::as_str), Some("desktop"));
            response(&mut first, webfinger_status, &webfinger_body);

            let (mut metadata_stream, _) = listener.accept().unwrap();
            let (request, _, _) = read_http_request(&metadata_stream);
            assert!(request.starts_with("GET /.well-known/openid-configuration"));
            response(&mut metadata_stream, 200, &discovery);
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            let (mut second, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        return Vec::new();
                    }
                    Err(error) => panic!("accept token request: {error}"),
                }
            };
            let (request, body, _) = read_http_request(&second);
            assert!(request.starts_with("POST /token"));
            response(
                &mut second,
                200,
                r#"{"access_token":"private-access-token","refresh_token":"private-refresh-token","expires_in":3600}"#,
            );
            body
        });
        (base, task)
    }

    fn start_discovery_only_server(
        webfinger_status: u16,
        webfinger_body: &str,
        metadata_issuer: &str,
    ) -> (String, std::thread::JoinHandle<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let webfinger_body = webfinger_body.replace("{server}", &base);
        let metadata_issuer = metadata_issuer.replace("{server}", &base);
        let discovery = metadata_for_issuer(&base, &metadata_issuer);
        let base_for_thread = base.clone();
        let task = thread::spawn(move || {
            let (mut webfinger_stream, _) = listener.accept().unwrap();
            let (request, _, headers) = read_http_request(&webfinger_stream);
            assert!(request.starts_with("GET /.well-known/webfinger?"));
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            );
            let request_url = Url::parse(&format!(
                "{base_for_thread}{}",
                request.split_whitespace().nth(1).unwrap()
            ))
            .unwrap();
            let params: std::collections::HashMap<_, _> =
                request_url.query_pairs().into_owned().collect();
            assert_eq!(
                params.get("resource").map(String::as_str),
                Some(base_for_thread.as_str())
            );
            assert_eq!(
                params.get("rel").map(String::as_str),
                Some(WEBFINGER_ISSUER_REL)
            );
            assert_eq!(params.get("platform").map(String::as_str), Some("desktop"));
            response(&mut webfinger_stream, webfinger_status, &webfinger_body);

            let (mut metadata_stream, _) = listener.accept().unwrap();
            let (metadata_request, _, _) = read_http_request(&metadata_stream);
            assert!(metadata_request.starts_with("GET /.well-known/openid-configuration"));
            response(&mut metadata_stream, 200, &discovery);
            (request, metadata_request)
        });
        (base, task)
    }

    fn start_webfinger_only_server(
        status: u16,
        body: String,
    ) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (request, _, headers) = read_http_request(&stream);
            assert!(request.starts_with("GET /.well-known/webfinger?"));
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            );
            response(&mut stream, status, &body);
            request
        });
        (base, task)
    }

    fn start_webfinger_disconnect_server() -> (String, std::thread::JoinHandle<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, _, _) = read_http_request(&stream);
            assert!(request.starts_with("GET /.well-known/webfinger?"));
            drop(stream);
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_millis(300);
            loop {
                match listener.accept() {
                    Ok(_) => return true,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return false,
                    Err(error) => panic!("accept unexpected fallback request: {error}"),
                }
            }
        });
        (base, task)
    }

    fn start_split_discovery_servers() -> (
        String,
        String,
        std::thread::JoinHandle<()>,
        std::thread::JoinHandle<()>,
    ) {
        let issuer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let issuer = format!("http://{}", issuer_listener.local_addr().unwrap());
        let server_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = format!("http://{}", server_listener.local_addr().unwrap());
        let webfinger_body = json!({
            "links": [{"rel": WEBFINGER_ISSUER_REL, "href": issuer}],
            "properties": {
                WEBFINGER_CLIENT_ID: "split-origin-client",
                WEBFINGER_SCOPES: ["openid", "profile"]
            }
        })
        .to_string();
        let issuer_discovery = metadata_for_issuer(&issuer, &issuer);
        let issuer_task = thread::spawn(move || {
            let (mut stream, _) = issuer_listener.accept().unwrap();
            let (request, _, headers) = read_http_request(&stream);
            assert!(request.starts_with("GET /.well-known/openid-configuration"));
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            );
            response(&mut stream, 200, &issuer_discovery);
        });
        let server_for_thread = server.clone();
        let server_task = thread::spawn(move || {
            let (mut stream, _) = server_listener.accept().unwrap();
            let (request, _, headers) = read_http_request(&stream);
            assert!(request.starts_with("GET /.well-known/webfinger?"));
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            );
            let url = Url::parse(&format!(
                "{server_for_thread}{}",
                request.split_whitespace().nth(1).unwrap()
            ))
            .unwrap();
            let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(params.get("platform").map(String::as_str), Some("desktop"));
            response(&mut stream, 200, &webfinger_body);
        });
        (server, issuer, server_task, issuer_task)
    }

    #[test]
    fn starts_pkce_authorization_and_exchanges_callback_code() {
        let (base, server) = start_server();
        let flow = AuthFlow::begin(&base, "OpenCloudDesktop").unwrap();
        let info = flow.public_info();
        let authorization = Url::parse(info["url"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> =
            authorization.query_pairs().into_owned().collect();
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid offline_access profile email")
        );
        assert!(!info.to_string().contains("user_code"));
        assert!(!info.to_string().contains("private-access-token"));
        let redirect = Url::parse(params.get("redirect_uri").unwrap()).unwrap();
        assert_eq!(redirect.path(), "/");
        let state = params.get("state").unwrap().clone();

        let waiter = thread::spawn(move || flow.wait());
        let mut callback = TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).unwrap();
        write!(
            callback,
            "GET /?code=auth-code&state={state} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        let session = waiter.join().unwrap().unwrap();
        let request_body = server.join().unwrap();
        let form: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(&request_body)
                .into_owned()
                .collect();
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some(AUTH_CODE_GRANT)
        );
        assert_eq!(form.get("code").map(String::as_str), Some("auth-code"));
        let verifier = form.get("code_verifier").unwrap();
        assert_eq!(
            params.get("code_challenge").unwrap(),
            &base64_url(&Sha256::digest(verifier.as_bytes()))
        );
        assert_eq!(session.server, base);
        assert_eq!(session.access_token, "private-access-token");
        assert_eq!(
            session.expected_issuer.as_deref(),
            Some("https://issuer.example")
        );
        assert_eq!(
            session.refresh_token.as_deref(),
            Some("private-refresh-token")
        );
    }

    #[test]
    fn webfinger_discovers_desktop_client_and_exact_scopes() {
        let body = json!({
            "links": [{"rel": WEBFINGER_ISSUER_REL, "href": "{server}"}],
            "properties": {
                WEBFINGER_CLIENT_ID: "advertised-desktop-client",
                WEBFINGER_SCOPES: ["openid", "profile", "groups"]
            }
        })
        .to_string();
        let (base, server) = start_discovery_only_server(200, &body, "{server}");
        let flow = AuthFlow::begin(&base, "").unwrap();
        let authorization = Url::parse(flow.public_info()["url"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> =
            authorization.query_pairs().into_owned().collect();
        assert_eq!(flow.client_id(), "advertised-desktop-client");
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("advertised-desktop-client")
        );
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid profile groups")
        );
        server.join().unwrap();
    }

    #[test]
    fn webfinger_accepts_space_delimited_scope_array_value() {
        let body = json!({
            "links": [{"rel": WEBFINGER_ISSUER_REL, "href": "{server}"}],
            "properties": {
                WEBFINGER_CLIENT_ID: "advertised-desktop-client",
                WEBFINGER_SCOPES: ["openid profile email"]
            }
        })
        .to_string();
        let (base, server) = start_discovery_only_server(200, &body, "{server}");
        let flow = AuthFlow::begin(&base, "").unwrap();
        let authorization = Url::parse(flow.public_info()["url"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> =
            authorization.query_pairs().into_owned().collect();
        assert_eq!(flow.client_id(), "advertised-desktop-client");
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid profile email")
        );
        server.join().unwrap();
    }

    #[test]
    fn webfinger_may_discover_oidc_issuer_on_a_separate_origin() {
        let (server, issuer, webfinger_task, issuer_task) = start_split_discovery_servers();
        let flow = AuthFlow::begin(&server, "").unwrap();
        assert_eq!(flow.client_id(), "split-origin-client");
        assert_eq!(flow.expected_issuer.as_deref(), Some(issuer.as_str()));
        let authorization = Url::parse(flow.public_info()["url"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> =
            authorization.query_pairs().into_owned().collect();
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid profile")
        );
        webfinger_task.join().unwrap();
        issuer_task.join().unwrap();
    }

    #[test]
    fn explicit_client_id_overrides_webfinger_but_uses_advertised_scopes() {
        let body = json!({
            "links": [{"rel": LEGACY_WEBFINGER_ISSUER_REL, "href": "{server}"}],
            "properties": {
                WEBFINGER_CLIENT_ID: "advertised-desktop-client",
                WEBFINGER_SCOPES: ["openid profile email groups"]
            }
        })
        .to_string();
        let (base, server) = start_discovery_only_server(200, &body, "{server}");
        let flow = AuthFlow::begin(&base, "manual-client").unwrap();
        let authorization = Url::parse(flow.public_info()["url"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> =
            authorization.query_pairs().into_owned().collect();
        assert_eq!(flow.client_id(), "manual-client");
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("manual-client")
        );
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid profile email groups offline_access")
        );
        server.join().unwrap();
    }

    #[test]
    fn missing_webfinger_issuer_falls_back_to_manual_client_and_legacy_scopes() {
        let body = json!({
            "links": [],
            "properties": {
                WEBFINGER_CLIENT_ID: "ignored-without-issuer",
                WEBFINGER_SCOPES: ["openid", "groups"]
            }
        })
        .to_string();
        let (base, server) = start_discovery_only_server(200, &body, "https://issuer.example");
        let flow = AuthFlow::begin(&base, "").unwrap();
        let authorization = Url::parse(flow.public_info()["url"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> =
            authorization.query_pairs().into_owned().collect();
        assert_eq!(flow.client_id(), DEFAULT_CLIENT_ID);
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid offline_access profile email")
        );
        server.join().unwrap();
    }

    #[test]
    fn webfinger_404_uses_legacy_issuer_client_and_scopes() {
        let (base, server) = start_discovery_only_server(404, "", "https://issuer.example");
        let flow = AuthFlow::begin(&base, "").unwrap();
        let authorization = Url::parse(flow.public_info()["url"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> =
            authorization.query_pairs().into_owned().collect();
        assert_eq!(flow.client_id(), DEFAULT_CLIENT_ID);
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid offline_access profile email")
        );
        server.join().unwrap();
    }

    #[test]
    fn webfinger_issuer_must_match_oidc_metadata_exactly() {
        let body = json!({
            "links": [{"rel": WEBFINGER_ISSUER_REL, "href": "{server}"}],
            "properties": {}
        })
        .to_string();
        let (base, server) =
            start_discovery_only_server(200, &body, "https://other-issuer.example");
        let error = match AuthFlow::begin(&base, "") {
            Ok(_) => panic!("issuer mismatch accepted"),
            Err(error) => error,
        };
        assert!(error.contains("does not match the WebFinger issuer"));
        server.join().unwrap();
    }

    #[test]
    fn malformed_or_oversized_webfinger_fails_closed() {
        let (base, server) = start_webfinger_only_server(
            200,
            json!({"properties": {WEBFINGER_SCOPES: ["openid", "invalid\\scope"]}}).to_string(),
        );
        let url = Url::parse(&base).unwrap();
        let error = get_webfinger(&safe_client().unwrap(), &base, &url).unwrap_err();
        assert!(error.contains("scope value is invalid"));
        server.join().unwrap();

        let (base, server) = start_webfinger_only_server(200, " ".repeat(65_537));
        let url = Url::parse(&base).unwrap();
        let error = get_webfinger(&safe_client().unwrap(), &base, &url).unwrap_err();
        assert!(error.contains("exceeds the size limit"));
        server.join().unwrap();
    }

    #[test]
    fn webfinger_network_error_does_not_downgrade_to_direct_discovery() {
        let (base, server) = start_webfinger_disconnect_server();
        let error = match AuthFlow::begin(&base, "") {
            Ok(_) => panic!("network error unexpectedly fell back to direct discovery"),
            Err(error) => error,
        };
        assert!(error.contains("Could not contact OpenCloud WebFinger"));
        assert!(
            !server.join().unwrap(),
            "direct OIDC fallback request was sent"
        );
    }

    #[test]
    fn rejects_bad_state_without_exchanging_code() {
        let (base, server) = start_server();
        let flow = AuthFlow::begin(&base, "OpenCloudDesktop").unwrap();
        let info = flow.public_info();
        let authorization = Url::parse(info["url"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> =
            authorization.query_pairs().into_owned().collect();
        let redirect = Url::parse(params.get("redirect_uri").unwrap()).unwrap();
        let waiter = thread::spawn(move || flow.wait());
        let mut callback = TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).unwrap();
        write!(
            callback,
            "GET /?code=auth-code&state=wrong HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        let error = match waiter.join().unwrap() {
            Ok(_) => panic!("bad state accepted"),
            Err(error) => error,
        };
        assert!(error.contains("state"));
        // Only discovery should have reached the synthetic issuer.
        let _ = server.join();
    }

    #[test]
    fn rejects_insecure_discovered_endpoints_and_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            let (mut webfinger, _) = listener.accept().unwrap();
            let _ = read_http_request(&webfinger);
            response(&mut webfinger, 404, "");
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_http_request(&stream);
            let body = json!({"issuer":"https://issuer.example","authorization_endpoint":"http://example.com/authorize","token_endpoint":"https://issuer.example/token"}).to_string();
            response(&mut stream, 200, &body);
        });
        let error = match AuthFlow::begin(&base, "OpenCloudDesktop") {
            Ok(_) => panic!("insecure endpoint accepted"),
            Err(error) => error,
        };
        assert!(error.contains("HTTPS"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            let (mut webfinger, _) = listener.accept().unwrap();
            let _ = read_http_request(&webfinger);
            response(&mut webfinger, 404, "");
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_http_request(&stream);
            write!(stream, "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let error = match AuthFlow::begin(&base, "OpenCloudDesktop") {
            Ok(_) => panic!("redirect accepted"),
            Err(error) => error,
        };
        assert!(error.contains("302"));
    }

    #[test]
    fn bounds_callbacks_and_validates_http_only_for_loopback() {
        assert!(validate_url("http://127.0.0.1:8000/token", false, "token endpoint").is_err());
        assert!(validate_url("http://127.0.0.1:8000/token", true, "token endpoint").is_ok());
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"abd"));
        assert!(!constant_time_equal(b"abc", b"abcd"));
        assert_eq!(base64_url(b"foo"), "Zm9v");
        assert_eq!(base64_url(b"f"), "Zg");
    }

    #[test]
    fn graph_error_hints_only_on_a_bounded_unverified_issuer_mismatch() {
        fn jwt(issuer: &str) -> String {
            let payload = URL_SAFE_NO_PAD.encode(
                json!({"iss":issuer,"sub":"private-subject","custom":"private-claim"}).to_string(),
            );
            format!("e30.{payload}.synthetic-signature")
        }
        let session = |access_token: String| Session {
            server: "https://cloud.example".into(),
            client_id: "OpenCloudDesktop".into(),
            access_token,
            refresh_token: None,
            expires_at: 1,
            token_endpoint: "https://issuer.example/token".into(),
            expected_issuer: Some("https://issuer.example".into()),
            last_refresh_at: None,
            proxy: ProxyConfig::System,
        };

        let mismatch_token = jwt("https://legacy.example");
        let diagnostic =
            graph_error_with_issuer_hint("Graph request failed", &session(mismatch_token.clone()));
        assert!(diagnostic.contains(ISSUER_MISMATCH_HINT));
        assert!(!diagnostic.contains(&mismatch_token));
        assert!(!diagnostic.contains("legacy.example"));
        assert!(!diagnostic.contains("private-subject"));
        assert!(!diagnostic.contains("private-claim"));

        let matching = session(jwt("https://issuer.example"));
        assert_eq!(
            graph_error_with_issuer_hint("Graph request failed", &matching),
            "Graph request failed"
        );
        let opaque = session("opaque-access-secret".into());
        assert_eq!(
            graph_error_with_issuer_hint("Graph request failed", &opaque),
            "Graph request failed"
        );
        let malformed = session(format!("e30.{}.sig", "a".repeat(MAX_JWT_PAYLOAD * 2 + 1)));
        assert_eq!(
            graph_error_with_issuer_hint("Graph request failed", &malformed),
            "Graph request failed"
        );
    }
}
