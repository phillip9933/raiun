//! Bounded, in-memory registry for verified vault sessions.
//!
//! Scope identity includes the local account, canonical server origin, Graph
//! Space, and DAV resource. The registry owns each verified session and exposes
//! only scoped codec operations; it never returns key or session handles.
//! Network I/O must be staged outside the registry lock. Explicit lock/logout
//! waits for any active local crypto or transactional file operation.

use std::{
    collections::HashMap,
    io::Read,
    path::Path,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use url::Url;
use zeroize::Zeroizing;

use crate::{
    NewVaultDraft, PortableVaultPath, VaultCipher, VaultError, VerifiedVaultSession, invalid,
};

const MAX_SESSIONS: usize = 16;
const MAX_PENDING_UNLOCKS: usize = 16;
const MAX_ACCOUNT_ID_BYTES: usize = 256;
const MAX_SERVER_ORIGIN_BYTES: usize = 2_048;
const MAX_SPACE_ID_BYTES: usize = 512;
const MAX_RESOURCE_ID_BYTES: usize = 512;

/// Identity of the precise encrypted collection unlocked by a session.
///
/// The server origin is parsed and canonicalized as an HTTP(S) origin. IDs are
/// opaque validated identifiers and are not asserted to be globally unique.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VaultSessionScope {
    account_id: String,
    server_origin: String,
    space_id: String,
    resource_id: String,
}

impl VaultSessionScope {
    /// Construct a scope from an account ID, an origin URL, a Graph Space ID,
    /// and a DAV resource ID. The URL must be an origin with no path beyond `/`,
    /// credentials, query, or fragment.
    pub fn new(
        account_id: &str,
        server_origin: &str,
        space_id: &str,
        resource_id: &str,
    ) -> Result<Self, VaultError> {
        validate_id(account_id, MAX_ACCOUNT_ID_BYTES, "account identifier")?;
        validate_id(space_id, MAX_SPACE_ID_BYTES, "Space identifier")?;
        validate_id(resource_id, MAX_RESOURCE_ID_BYTES, "resource identifier")?;

        if server_origin.len() > MAX_SERVER_ORIGIN_BYTES {
            return Err(invalid("vault server origin is too long"));
        }
        if server_origin.trim() != server_origin
            || server_origin.contains('\\')
            || !has_only_optional_slash_path(server_origin)
        {
            return Err(invalid("vault server URL must be a bare HTTP(S) origin"));
        }
        let origin =
            Url::parse(server_origin).map_err(|_| invalid("vault server origin is invalid"))?;
        if !matches!(origin.scheme(), "http" | "https")
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || !matches!(origin.path(), "" | "/")
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(invalid("vault server URL must be a bare HTTP(S) origin"));
        }

        Ok(Self {
            account_id: account_id.to_owned(),
            server_origin: origin.origin().ascii_serialization(),
            space_id: space_id.to_owned(),
            resource_id: resource_id.to_owned(),
        })
    }

    /// Account-local identifier used to isolate sessions and logout cleanup.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Canonical HTTP(S) origin, without a trailing slash.
    pub fn server_origin(&self) -> &str {
        &self.server_origin
    }

    /// Graph Space ID within the server/account scope.
    pub fn space_id(&self) -> &str {
        &self.space_id
    }

    /// DAV resource ID within the server/account/Space scope.
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
}

/// A single-use unlock ticket captured before password KDF work.
///
/// Tickets are not cloneable and are bound to one registry instance. Lock or
/// account logout removes the pending generation, so a KDF started before
/// either operation cannot publish a session afterward.
pub struct UnlockTicket {
    scope: VaultSessionScope,
    generation: u64,
    registry_identity: Weak<()>,
}

/// A new vault's local key/token draft with a pre-KDF publication ticket.
/// The generated token may be sent to the remote root, but the key session is
/// inserted only after exact-token readback via `finish_create`.
pub struct PendingVaultCreation<'a> {
    coordinator: &'a VaultSessionCoordinator,
    ticket: Option<UnlockTicket>,
    draft: Option<NewVaultDraft>,
}

impl PendingVaultCreation<'_> {
    /// Encrypted UUID metadata to write to the already-created remote root.
    pub fn integrity_token(&self) -> &str {
        self.draft
            .as_ref()
            .expect("pending vault creation draft is present")
            .integrity_token()
    }
}

impl Drop for PendingVaultCreation<'_> {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            let _ = self.coordinator.registry.cancel_unlock(ticket);
        }
        // Dropping the draft wipes its owned codec key bundle.
        self.draft.take();
    }
}

/// Registry of at most 16 verified vault sessions. It owns all session keys;
/// callers can request scoped metadata decoding but cannot clone or extract a
/// session. No automatic expiry or persistence is provided.
pub struct VaultSessionRegistry {
    identity: Arc<()>,
    state: Mutex<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    next_generation: u64,
    sessions: HashMap<VaultSessionScope, VerifiedVaultSession>,
    pending: HashMap<VaultSessionScope, u64>,
}

impl Default for VaultSessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultSessionRegistry {
    pub fn new() -> Self {
        Self {
            identity: Arc::new(()),
            state: Mutex::new(RegistryState::default()),
        }
    }

    /// Capture a generation before running password derivation and token
    /// verification. A newer attempt for the same scope replaces this pending
    /// generation. At most 16 pending scopes are tracked; superseded KDFs may
    /// still be running in caller threads and need separate concurrency limits.
    pub fn begin_unlock(&self, scope: &VaultSessionScope) -> Result<UnlockTicket, VaultError> {
        let mut state = self.lock_state()?;
        if !state.pending.contains_key(scope) && state.pending.len() >= MAX_PENDING_UNLOCKS {
            return Err(invalid("too many vault unlock attempts are pending"));
        }
        let generation = state
            .next_generation
            .checked_add(1)
            .ok_or_else(|| invalid("vault session generation is exhausted"))?;
        state.next_generation = generation;
        state.pending.insert(scope.clone(), generation);
        Ok(UnlockTicket {
            scope: scope.clone(),
            generation,
            registry_identity: Arc::downgrade(&self.identity),
        })
    }

    /// Insert a previously verified session if its pre-KDF ticket is still
    /// current. The ticket is consumed even on failure; a rejected session is
    /// dropped and its retained key material is zeroized by the codec.
    pub fn insert_unlocked(
        &self,
        ticket: UnlockTicket,
        session: VerifiedVaultSession,
    ) -> Result<(), VaultError> {
        let this_registry = Arc::downgrade(&self.identity);
        if !Weak::ptr_eq(&ticket.registry_identity, &this_registry) {
            return Err(invalid("vault unlock ticket belongs to another registry"));
        }

        let mut state = self.lock_state()?;
        if state.pending.get(&ticket.scope) != Some(&ticket.generation) {
            return Err(invalid("vault unlock ticket is stale"));
        }
        state.pending.remove(&ticket.scope);
        if !state.sessions.contains_key(&ticket.scope) && state.sessions.len() >= MAX_SESSIONS {
            return Err(invalid("vault session limit reached"));
        }
        // Replacing a session drops the old verified codec and zeroizes its
        // retained key bundle when the returned old value leaves this scope.
        state.sessions.insert(ticket.scope, session);
        Ok(())
    }

    /// Cancel a failed or abandoned unlock attempt. Returns `false` when the
    /// ticket became stale after a newer attempt, lock, or logout. This never
    /// removes a newer ticket for the same scope.
    pub fn cancel_unlock(&self, ticket: UnlockTicket) -> Result<bool, VaultError> {
        self.cancel_generation(&ticket.scope, ticket.generation, &ticket.registry_identity)
    }

    fn cancel_generation(
        &self,
        scope: &VaultSessionScope,
        generation: u64,
        registry_identity: &Weak<()>,
    ) -> Result<bool, VaultError> {
        let this_registry = Arc::downgrade(&self.identity);
        if !Weak::ptr_eq(registry_identity, &this_registry) {
            return Err(invalid("vault unlock ticket belongs to another registry"));
        }
        let mut state = self.lock_state()?;
        if state.pending.get(scope) != Some(&generation) {
            return Ok(false);
        }
        state.pending.remove(scope);
        Ok(true)
    }

    /// Forget one scope and invalidate its pending KDF ticket, even if no
    /// session has been inserted yet. This waits for any scoped local crypto
    /// or file operation currently using the registry lock, then drops the
    /// owned codec before returning. Network I/O must stay outside the lock.
    pub fn lock(&self, scope: &VaultSessionScope) -> Result<(), VaultError> {
        let removed = {
            let mut state = self.lock_state()?;
            state.pending.remove(scope);
            state.sessions.remove(scope)
        };
        drop(removed);
        Ok(())
    }

    /// Forget every active session and invalidate every pending unlock ticket.
    /// This waits for scoped local crypto/file operations using the registry
    /// lock and does not reset the monotonic ticket generation counter.
    pub fn lock_all(&self) -> Result<(), VaultError> {
        let removed = {
            let mut state = self.lock_state()?;
            state.pending.clear();
            std::mem::take(&mut state.sessions)
        };
        drop(removed);
        Ok(())
    }

    /// Forget all sessions and invalidate pending unlocks for one account.
    /// This is intended for explicit account logout and is safe when no session
    /// has yet been inserted. It waits for scoped local crypto/file operations
    /// using the registry lock; network I/O must remain outside this lock.
    pub fn logout_account(&self, account_id: &str) -> Result<(), VaultError> {
        validate_id(account_id, MAX_ACCOUNT_ID_BYTES, "account identifier")?;
        let mut state = self.lock_state()?;
        state
            .sessions
            .retain(|scope, _| scope.account_id != account_id);
        state
            .pending
            .retain(|scope, _| scope.account_id != account_id);
        Ok(())
    }

    /// Decode one name using only the session for the complete supplied scope.
    pub fn decrypt_name(
        &self,
        scope: &VaultSessionScope,
        encrypted_name: &str,
    ) -> Result<String, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        session.decrypt_name(encrypted_name)
    }

    /// Decode and validate a complete encrypted directory listing with the
    /// session for the supplied complete scope. The registry lock is held for
    /// the bounded batch, so lock/logout cannot interleave with its decode.
    /// No plaintext is returned unless every name passes validation and
    /// collision checks.
    pub fn decode_directory_names(
        &self,
        scope: &VaultSessionScope,
        encrypted_names: &[&str],
    ) -> Result<Vec<String>, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        crate::directory::decode_directory_names(session, encrypted_names)
    }

    /// Encode a complete bounded set of new directory names after checking
    /// collisions against the complete current remote sibling listing.
    pub fn encode_directory_names(
        &self,
        scope: &VaultSessionScope,
        plain_names: &[&str],
        existing_encrypted_names: &[&str],
    ) -> Result<Vec<String>, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        crate::directory::encode_directory_names(session, plain_names, existing_encrypted_names)
    }

    /// Decode a relative path to portable components using only the session for
    /// the complete supplied scope. No absolute path join is performed.
    pub fn decrypt_path(
        &self,
        scope: &VaultSessionScope,
        encrypted_path: &str,
    ) -> Result<PortableVaultPath, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        session.decrypt_path(encrypted_path)
    }

    /// Return whether this exact scope currently has an unlocked session.
    pub fn is_unlocked(&self, scope: &VaultSessionScope) -> Result<bool, VaultError> {
        Ok(self.lock_state()?.sessions.contains_key(scope))
    }

    /// Check a freshly-read root token against the session for this exact scope.
    /// This is a local codec check only; fetch metadata before calling it.
    pub fn verify_integrity_token(
        &self,
        scope: &VaultSessionScope,
        integrity_token: &str,
    ) -> Result<bool, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        Ok(session.verify_integrity_token(integrity_token))
    }

    /// Encrypt one portable name using only the session for the complete scope.
    pub fn encrypt_name(
        &self,
        scope: &VaultSessionScope,
        plain_name: &str,
    ) -> Result<String, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        session.encrypt_name(plain_name)
    }

    /// Encrypt a portable relative path through only the exact scoped session.
    pub fn encrypt_path(
        &self,
        scope: &VaultSessionScope,
        plain_path: &str,
    ) -> Result<String, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        session.encrypt_path(plain_path)
    }

    /// Encrypt a local file through the exact scoped session and publish a new
    /// no-clobber ciphertext file. Keep network work outside this call.
    pub fn encrypt_file_transactional<R: Read>(
        &self,
        scope: &VaultSessionScope,
        input: &mut R,
        destination: &Path,
        expected_len: u64,
        maximum_plaintext_bytes: u64,
    ) -> Result<u64, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        session.encrypt_file_transactional(
            input,
            destination,
            expected_len,
            maximum_plaintext_bytes,
        )
    }

    /// Decrypt an already-local ciphertext spool through the exact scoped
    /// session. Do not pass a live network stream; download and validate it
    /// before acquiring the registry lock. Lock/logout waits for this bounded
    /// local operation to finish.
    pub fn decrypt_file_transactional<R: Read>(
        &self,
        scope: &VaultSessionScope,
        input: &mut R,
        destination: &Path,
        maximum_plaintext_bytes: u64,
        expected_len: Option<u64>,
    ) -> Result<u64, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        session.decrypt_file_transactional(
            input,
            destination,
            maximum_plaintext_bytes,
            expected_len,
        )
    }

    /// Decrypt one complete, metadata-bounded file to a zeroizing memory
    /// buffer. The exact unlocked scope is held only for local crypto.
    pub fn decrypt_file_to_bytes<R: Read>(
        &self,
        scope: &VaultSessionScope,
        input: &mut R,
        maximum_plaintext_bytes: u64,
        expected_len: u64,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        session.decrypt_file_to_bytes(input, maximum_plaintext_bytes, expected_len)
    }

    /// Authenticate and decrypt at most one bounded prefix block through the
    /// exact scoped session. The session lock is held only for this local
    /// cryptographic operation; the returned plaintext buffer zeroizes on
    /// drop. This does not verify the remainder or total length of the file.
    pub fn decrypt_authenticated_prefix<R: Read>(
        &self,
        scope: &VaultSessionScope,
        input: &mut R,
        maximum_prefix_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        session.decrypt_authenticated_prefix(input, maximum_prefix_bytes)
    }

    /// Number of active sessions, exposed for status and bounded-capacity UI.
    pub fn active_session_count(&self) -> Result<usize, VaultError> {
        Ok(self.lock_state()?.sessions.len())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, RegistryState>, VaultError> {
        self.state
            .lock()
            .map_err(|_| invalid("vault session registry is unavailable"))
    }
}

/// Synchronous unlock controller with one nonblocking KDF permit. It owns the
/// registry and does not expose it or any verified session handles.
pub struct VaultSessionCoordinator {
    registry: VaultSessionRegistry,
    kdf_active: AtomicBool,
}

impl Default for VaultSessionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultSessionCoordinator {
    /// Create an empty coordinator. One instance must own the full set of an
    /// application's account sessions to enforce the session cap globally.
    pub fn new() -> Self {
        Self {
            registry: VaultSessionRegistry::new(),
            kdf_active: AtomicBool::new(false),
        }
    }

    /// Run a short local completion step while both exact vault scopes remain
    /// unlocked. A concurrent lock or account logout waits for the closure to
    /// finish; if revocation wins before admission, the closure is not run.
    /// Registries are locked in stable address order to avoid cross-account
    /// deadlocks. The closure must not perform network I/O or reenter either
    /// coordinator.
    pub fn with_unlocked_scopes<T>(
        first: &Self,
        first_scope: &VaultSessionScope,
        second: &Self,
        second_scope: &VaultSessionScope,
        complete: impl FnOnce() -> T,
    ) -> Result<T, VaultError> {
        Self::with_unlocked_scopes_and_sessions(first, first_scope, second, second_scope, |_, _| {
            complete()
        })
    }

    /// Run a bounded local operation while both exact scopes remain unlocked,
    /// exposing borrowed verified sessions so callers can validate sealed
    /// local metadata without re-entering this coordinator. Revocation waits
    /// until the closure returns; network I/O and coordinator re-entry are
    /// forbidden inside the closure.
    pub fn with_unlocked_scopes_and_sessions<T>(
        first: &Self,
        first_scope: &VaultSessionScope,
        second: &Self,
        second_scope: &VaultSessionScope,
        complete: impl FnOnce(&VerifiedVaultSession, &VerifiedVaultSession) -> T,
    ) -> Result<T, VaultError> {
        fn require<'a>(
            state: &'a RegistryState,
            scope: &VaultSessionScope,
        ) -> Result<&'a VerifiedVaultSession, VaultError> {
            state
                .sessions
                .get(scope)
                .ok_or_else(|| invalid("vault session is locked"))
        }
        if std::ptr::eq(first, second) {
            let state = first.registry.lock_state()?;
            let first_session = require(&state, first_scope)?;
            let second_session = require(&state, second_scope)?;
            return Ok(complete(first_session, second_session));
        }

        if (first as *const Self as usize) < (second as *const Self as usize) {
            let first_state = first.registry.lock_state()?;
            let second_state = second.registry.lock_state()?;
            let first_session = require(&first_state, first_scope)?;
            let second_session = require(&second_state, second_scope)?;
            Ok(complete(first_session, second_session))
        } else {
            let second_state = second.registry.lock_state()?;
            let first_state = first.registry.lock_state()?;
            let first_session = require(&first_state, first_scope)?;
            let second_session = require(&second_state, second_scope)?;
            Ok(complete(first_session, second_session))
        }
    }

    /// Derive local material for a newly-created remote root. The returned
    /// pending value exposes only its encrypted integrity token; it cannot be
    /// used for encryption or inserted into the registry until exact token
    /// readback is supplied to [`Self::finish_create`]. The caller must create
    /// the empty remote collection first so `scope` has its stable DAV ID.
    pub fn begin_create<'a>(
        &'a self,
        scope: &VaultSessionScope,
        password: &mut [u8],
    ) -> Result<PendingVaultCreation<'a>, VaultError> {
        let password = PasswordWiper(password);
        let _permit = KdfPermit::try_acquire(&self.kdf_active)?;
        let ticket = self.registry.begin_unlock(scope)?;
        let mut ticket_cleanup = PendingTicketCleanup::new(&self.registry, &ticket);
        let cipher = VaultCipher::from_password(password.0)?;
        let draft = cipher.initialize_new_vault()?;
        let pending = PendingVaultCreation {
            coordinator: self,
            ticket: Some(ticket),
            draft: Some(draft),
        };
        ticket_cleanup.disarm();
        Ok(pending)
    }

    /// Publish a pending creation only when it belongs to this coordinator,
    /// its pre-KDF ticket remains current, and the remote root reads back the
    /// exact token created by the draft. The caller performs all network I/O
    /// before invoking this local registry operation.
    pub fn finish_create(
        &self,
        mut pending: PendingVaultCreation<'_>,
        observed_integrity_token: &str,
    ) -> Result<(), VaultError> {
        if !std::ptr::eq(self, pending.coordinator) {
            return Err(invalid(
                "pending vault creation belongs to another coordinator",
            ));
        }
        let draft = pending
            .draft
            .take()
            .ok_or_else(|| invalid("pending vault creation is unavailable"))?;
        let session = draft.verify_created_root(observed_integrity_token)?;
        let ticket = pending
            .ticket
            .take()
            .ok_or_else(|| invalid("pending vault creation ticket is unavailable"))?;
        self.registry.insert_unlocked(ticket, session)
    }

    /// Derive and verify a vault session synchronously. A concurrent attempt
    /// returns an error immediately; its mutable password buffer is still
    /// wiped. Lock and logout remain available while scrypt runs.
    pub fn unlock(
        &self,
        scope: &VaultSessionScope,
        password: &mut [u8],
        integrity_token: &str,
    ) -> Result<(), VaultError> {
        self.unlock_with_deriver(scope, password, |password| {
            crate::VaultCipher::from_password(password)?.verify_and_unlock(integrity_token)
        })
    }

    /// Internal seam used by deterministic lifecycle tests. The callback is
    /// never public and cannot obtain a registry or session reference.
    pub(crate) fn unlock_with_deriver<F>(
        &self,
        scope: &VaultSessionScope,
        password: &mut [u8],
        derive: F,
    ) -> Result<(), VaultError>
    where
        F: FnOnce(&mut [u8]) -> Result<VerifiedVaultSession, VaultError>,
    {
        let password = PasswordWiper(password);
        let _permit = KdfPermit::try_acquire(&self.kdf_active)?;
        let ticket = self.registry.begin_unlock(scope)?;
        let _ticket_cleanup = PendingTicketCleanup::new(&self.registry, &ticket);
        let session = derive(password.0)?;
        self.registry.insert_unlocked(ticket, session)
    }

    /// Drop one verified session and invalidate an in-flight unlock for it.
    /// Waits for a scoped local crypto/file operation holding the registry lock.
    pub fn lock(&self, scope: &VaultSessionScope) -> Result<(), VaultError> {
        self.registry.lock(scope)
    }

    /// Drop every verified session and invalidate all pending unlocks. This
    /// waits for active local crypto/file operations, but not scrypt; an
    /// in-flight derivation retains the busy permit until it returns, then its
    /// stale ticket prevents publication.
    pub fn lock_all(&self) -> Result<(), VaultError> {
        self.registry.lock_all()
    }

    /// Drop all sessions and invalidate pending unlocks for one local account.
    /// Waits for a scoped local crypto/file operation holding the registry lock.
    pub fn logout_account(&self, account_id: &str) -> Result<(), VaultError> {
        self.registry.logout_account(account_id)
    }

    /// Decode one portable name only through the exact scoped session.
    pub fn decrypt_name(
        &self,
        scope: &VaultSessionScope,
        encrypted_name: &str,
    ) -> Result<String, VaultError> {
        self.registry.decrypt_name(scope, encrypted_name)
    }

    /// Decode and validate an entire bounded directory listing through only
    /// the exact scoped session. The coordinator retains the registry lock
    /// until the complete result has passed all checks.
    pub fn decode_directory_names(
        &self,
        scope: &VaultSessionScope,
        encrypted_names: &[&str],
    ) -> Result<Vec<String>, VaultError> {
        self.registry.decode_directory_names(scope, encrypted_names)
    }

    /// Encode a complete bounded set of new names only through the exact
    /// scoped session and against the supplied complete existing sibling list.
    pub fn encode_directory_names(
        &self,
        scope: &VaultSessionScope,
        plain_names: &[&str],
        existing_encrypted_names: &[&str],
    ) -> Result<Vec<String>, VaultError> {
        self.registry
            .encode_directory_names(scope, plain_names, existing_encrypted_names)
    }

    /// Decode a relative path only through the exact scoped session.
    pub fn decrypt_path(
        &self,
        scope: &VaultSessionScope,
        encrypted_path: &str,
    ) -> Result<PortableVaultPath, VaultError> {
        self.registry.decrypt_path(scope, encrypted_path)
    }

    /// Return whether this exact scope currently has an unlocked session.
    pub fn is_unlocked(&self, scope: &VaultSessionScope) -> Result<bool, VaultError> {
        self.registry.is_unlocked(scope)
    }

    /// Run a bounded local operation with a borrowed verified session while
    /// its exact scope remains unlocked. The closure must not perform network
    /// I/O or re-enter this coordinator.
    pub fn with_unlocked_session<T>(
        &self,
        scope: &VaultSessionScope,
        use_session: impl FnOnce(&VerifiedVaultSession) -> T,
    ) -> Result<T, VaultError> {
        let state = self.registry.lock_state()?;
        let session = state
            .sessions
            .get(scope)
            .ok_or_else(|| invalid("vault session is locked"))?;
        Ok(use_session(session))
    }

    /// Check a freshly-read root token against the session for this exact scope.
    pub fn verify_integrity_token(
        &self,
        scope: &VaultSessionScope,
        integrity_token: &str,
    ) -> Result<bool, VaultError> {
        self.registry.verify_integrity_token(scope, integrity_token)
    }

    /// Encrypt one portable name only through the exact scoped session.
    pub fn encrypt_name(
        &self,
        scope: &VaultSessionScope,
        plain_name: &str,
    ) -> Result<String, VaultError> {
        self.registry.encrypt_name(scope, plain_name)
    }

    /// Encrypt a portable relative path only through the exact scoped session.
    pub fn encrypt_path(
        &self,
        scope: &VaultSessionScope,
        plain_path: &str,
    ) -> Result<String, VaultError> {
        self.registry.encrypt_path(scope, plain_path)
    }

    /// Encrypt a local file through the exact scoped session and publish a new
    /// no-clobber ciphertext file. Keep network work outside this call.
    pub fn encrypt_file_transactional<R: Read>(
        &self,
        scope: &VaultSessionScope,
        input: &mut R,
        destination: &Path,
        expected_len: u64,
        maximum_plaintext_bytes: u64,
    ) -> Result<u64, VaultError> {
        self.registry.encrypt_file_transactional(
            scope,
            input,
            destination,
            expected_len,
            maximum_plaintext_bytes,
        )
    }

    /// Decrypt an already-local ciphertext spool through the exact scoped
    /// session. Keep network work outside this call; lock/logout waits for this
    /// local operation to finish.
    pub fn decrypt_file_transactional<R: Read>(
        &self,
        scope: &VaultSessionScope,
        input: &mut R,
        destination: &Path,
        maximum_plaintext_bytes: u64,
        expected_len: Option<u64>,
    ) -> Result<u64, VaultError> {
        self.registry.decrypt_file_transactional(
            scope,
            input,
            destination,
            maximum_plaintext_bytes,
            expected_len,
        )
    }

    /// Decrypt one complete, metadata-bounded file to a zeroizing memory
    /// buffer through the exact scope.
    pub fn decrypt_file_to_bytes<R: Read>(
        &self,
        scope: &VaultSessionScope,
        input: &mut R,
        maximum_plaintext_bytes: u64,
        expected_len: u64,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.registry
            .decrypt_file_to_bytes(scope, input, maximum_plaintext_bytes, expected_len)
    }

    /// Authenticate and decrypt at most one bounded prefix block through the
    /// exact scoped session. The rest of the file is not inspected.
    pub fn decrypt_authenticated_prefix<R: Read>(
        &self,
        scope: &VaultSessionScope,
        input: &mut R,
        maximum_prefix_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.registry
            .decrypt_authenticated_prefix(scope, input, maximum_prefix_bytes)
    }

    /// Return the number of retained verified sessions.
    pub fn active_session_count(&self) -> Result<usize, VaultError> {
        self.registry.active_session_count()
    }
}

struct PasswordWiper<'a>(&'a mut [u8]);

impl Drop for PasswordWiper<'_> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self.0);
    }
}

struct KdfPermit<'a>(&'a AtomicBool);

impl<'a> KdfPermit<'a> {
    fn try_acquire(active: &'a AtomicBool) -> Result<Self, VaultError> {
        active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .map(|_| Self(active))
            .map_err(|_| invalid("vault unlock is busy"))
    }
}

impl Drop for KdfPermit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct PendingTicketCleanup<'a> {
    registry: &'a VaultSessionRegistry,
    scope: VaultSessionScope,
    generation: u64,
    registry_identity: Weak<()>,
    active: bool,
}

impl<'a> PendingTicketCleanup<'a> {
    fn new(registry: &'a VaultSessionRegistry, ticket: &UnlockTicket) -> Self {
        Self {
            registry,
            scope: ticket.scope.clone(),
            generation: ticket.generation,
            registry_identity: ticket.registry_identity.clone(),
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for PendingTicketCleanup<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.registry.cancel_generation(
                &self.scope,
                self.generation,
                &self.registry_identity,
            );
        }
    }
}

fn validate_id(value: &str, maximum: usize, label: &'static str) -> Result<(), VaultError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(invalid(label));
    }
    Ok(())
}

fn has_only_optional_slash_path(value: &str) -> bool {
    let Some((_, authority_and_suffix)) = value.split_once("://") else {
        return false;
    };
    let suffix_start = authority_and_suffix
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_suffix.len());
    matches!(&authority_and_suffix[suffix_start..], "" | "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VaultCipher;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::mpsc,
        thread,
        time::Duration,
    };

    fn scope(account_id: &str, resource_id: &str) -> VaultSessionScope {
        VaultSessionScope::new(
            account_id,
            "HTTPS://Cloud.Example:443/",
            "space-id",
            resource_id,
        )
        .unwrap()
    }

    fn verified_session() -> VerifiedVaultSession {
        let material = hex(concat!(
            "7455c71ab17c865b8471f47b79acb07eb31d5678b80c7e2eaf4fc8066a9ee468",
            "765da27ab15d77f95796711f7b93ad63bbb484072e7180a8d17a9bbec14270d0",
            "c18d5932f55b2828c5e1e87215520310",
        ));
        let token = include_str!("../tests/fixtures/web-integrity-token.b64").trim();
        VaultCipher::from_key_material(&material)
            .unwrap()
            .verify_and_unlock(token)
            .unwrap()
    }

    fn hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid synthetic key fixture"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    fn unlock(
        registry: &VaultSessionRegistry,
        scope: &VaultSessionScope,
    ) -> Result<(), VaultError> {
        registry.insert_unlocked(registry.begin_unlock(scope)?, verified_session())
    }

    #[test]
    fn account_and_complete_resource_scope_isolation() {
        let registry = VaultSessionRegistry::new();
        let first = scope("account-one", "same-resource-id");
        let second = scope("account-two", "same-resource-id");
        let other_server = VaultSessionScope::new(
            "account-one",
            "https://other.example/",
            "space-id",
            "same-resource-id",
        )
        .unwrap();
        let other_space = VaultSessionScope::new(
            "account-one",
            "https://cloud.example/",
            "other-space",
            "same-resource-id",
        )
        .unwrap();
        assert_eq!(first.server_origin(), "https://cloud.example");
        unlock(&registry, &first).unwrap();
        unlock(&registry, &second).unwrap();
        unlock(&registry, &other_server).unwrap();
        unlock(&registry, &other_space).unwrap();

        assert!(
            registry
                .decrypt_path(&first, "um9jr7t436jbmsgpub5sfni4qk")
                .is_ok()
        );
        assert!(
            registry
                .decrypt_path(&second, "um9jr7t436jbmsgpub5sfni4qk")
                .is_ok()
        );
        registry.lock(&first).unwrap();
        assert!(
            registry
                .decrypt_path(&first, "um9jr7t436jbmsgpub5sfni4qk")
                .is_err()
        );
        assert!(
            registry
                .decrypt_path(&second, "um9jr7t436jbmsgpub5sfni4qk")
                .is_ok()
        );
        assert_eq!(registry.active_session_count().unwrap(), 3);
        registry.logout_account("account-one").unwrap();
        assert_eq!(registry.active_session_count().unwrap(), 1);
        assert!(
            registry
                .decrypt_path(&other_server, "um9jr7t436jbmsgpub5sfni4qk")
                .is_err()
        );
        assert!(
            registry
                .decrypt_path(&other_space, "um9jr7t436jbmsgpub5sfni4qk")
                .is_err()
        );
        assert!(
            registry
                .decrypt_path(&second, "um9jr7t436jbmsgpub5sfni4qk")
                .is_ok()
        );
    }

    #[test]
    fn lock_and_logout_invalidate_pending_unlock_tickets() {
        let registry = VaultSessionRegistry::new();
        let first = scope("account-one", "vault-one");
        let ticket = registry.begin_unlock(&first).unwrap();
        registry.lock(&first).unwrap();
        assert!(
            registry
                .insert_unlocked(ticket, verified_session())
                .is_err()
        );

        let second = scope("account-two", "vault-two");
        let ticket = registry.begin_unlock(&second).unwrap();
        registry.logout_account("account-two").unwrap();
        assert!(
            registry
                .insert_unlocked(ticket, verified_session())
                .is_err()
        );
        assert_eq!(registry.active_session_count().unwrap(), 0);
    }

    #[test]
    fn newest_ticket_replaces_old_ticket_and_session_replacement_is_bounded() {
        let registry = VaultSessionRegistry::new();
        let scope = scope("account-one", "vault-one");
        let older = registry.begin_unlock(&scope).unwrap();
        let newer = registry.begin_unlock(&scope).unwrap();
        assert!(registry.insert_unlocked(older, verified_session()).is_err());
        registry.insert_unlocked(newer, verified_session()).unwrap();
        assert_eq!(registry.active_session_count().unwrap(), 1);

        let older = registry.begin_unlock(&scope).unwrap();
        let newer = registry.begin_unlock(&scope).unwrap();
        registry.insert_unlocked(newer, verified_session()).unwrap();
        assert!(registry.insert_unlocked(older, verified_session()).is_err());
        unlock(&registry, &scope).unwrap();
        assert_eq!(registry.active_session_count().unwrap(), 1);
        assert!(
            registry
                .decrypt_path(&scope, "um9jr7t436jbmsgpub5sfni4qk")
                .is_ok()
        );
    }

    #[test]
    fn stale_cancel_cannot_remove_newer_pending_ticket() {
        let registry = VaultSessionRegistry::new();
        let scope = scope("account-one", "vault-one");
        let older = registry.begin_unlock(&scope).unwrap();
        let newer = registry.begin_unlock(&scope).unwrap();
        assert!(!registry.cancel_unlock(older).unwrap());
        registry.insert_unlocked(newer, verified_session()).unwrap();
        assert_eq!(registry.active_session_count().unwrap(), 1);
    }

    #[test]
    fn cancelling_failed_unlocks_releases_bounded_pending_capacity() {
        let registry = VaultSessionRegistry::new();
        let mut tickets = Vec::new();
        for index in 0..MAX_PENDING_UNLOCKS {
            let scope = scope("account-one", &format!("pending-{index}"));
            tickets.push(registry.begin_unlock(&scope).unwrap());
        }
        let extra = scope("account-one", "pending-over-cap");
        assert!(registry.begin_unlock(&extra).is_err());
        for ticket in tickets {
            assert!(registry.cancel_unlock(ticket).unwrap());
        }
        let ticket = registry.begin_unlock(&extra).unwrap();
        assert!(registry.cancel_unlock(ticket).unwrap());
    }

    #[test]
    fn replacing_an_active_session_does_not_evict_it_before_verified_insert() {
        let registry = VaultSessionRegistry::new();
        let scope = scope("account-one", "vault-one");
        unlock(&registry, &scope).unwrap();
        let ticket = registry.begin_unlock(&scope).unwrap();
        assert!(
            registry
                .decrypt_path(&scope, "um9jr7t436jbmsgpub5sfni4qk")
                .is_ok()
        );
        registry
            .insert_unlocked(ticket, verified_session())
            .unwrap();
        assert_eq!(registry.active_session_count().unwrap(), 1);
        assert!(
            registry
                .decrypt_path(&scope, "um9jr7t436jbmsgpub5sfni4qk")
                .is_ok()
        );
    }

    #[test]
    fn session_limit_rejects_additional_scope_without_evicting_existing_sessions() {
        let registry = VaultSessionRegistry::new();
        let mut scopes = Vec::new();
        for index in 0..MAX_SESSIONS {
            let scope = scope("account-one", &format!("vault-{index}"));
            unlock(&registry, &scope).unwrap();
            scopes.push(scope);
        }
        let extra = scope("account-one", "vault-over-cap");
        let ticket = registry.begin_unlock(&extra).unwrap();
        assert!(
            registry
                .insert_unlocked(ticket, verified_session())
                .is_err()
        );
        assert_eq!(registry.active_session_count().unwrap(), MAX_SESSIONS);
        for scope in scopes {
            assert!(registry.decrypt_path(&scope, "").unwrap().is_root());
        }
    }

    #[test]
    fn tickets_are_bound_to_the_registry_instance() {
        let first = VaultSessionRegistry::new();
        let second = VaultSessionRegistry::new();
        let scope = scope("account-one", "vault-one");
        let ticket = first.begin_unlock(&scope).unwrap();
        assert!(second.insert_unlocked(ticket, verified_session()).is_err());
        assert_eq!(first.active_session_count().unwrap(), 0);
        assert_eq!(second.active_session_count().unwrap(), 0);
    }

    #[test]
    fn scope_requires_bounded_ids_and_a_bare_http_origin() {
        assert!(VaultSessionScope::new("", "https://cloud.example", "space", "resource").is_err());
        assert!(
            VaultSessionScope::new("a", "https://u:p@cloud.example", "space", "resource").is_err()
        );
        assert!(
            VaultSessionScope::new("a", "https://cloud.example/path", "space", "resource").is_err()
        );
        assert!(
            VaultSessionScope::new("a", "https://cloud.example/../", "space", "resource").is_err()
        );
        assert!(
            VaultSessionScope::new("a", "https://cloud.example/?q=1", "space", "resource").is_err()
        );
        assert!(VaultSessionScope::new("a", "ftp://cloud.example", "space", "resource").is_err());
        assert!(VaultSessionScope::new("a", "https://cloud.example", " ", "resource").is_err());
        assert!(
            VaultSessionScope::new(
                "a",
                "https://cloud.example",
                "space",
                &"x".repeat(MAX_RESOURCE_ID_BYTES + 1)
            )
            .is_err()
        );
        assert!(
            VaultSessionScope::new(
                "a",
                &format!("https://{}", "x".repeat(MAX_SERVER_ORIGIN_BYTES)),
                "space",
                "resource"
            )
            .is_err()
        );
    }

    #[test]
    fn coordinator_returns_busy_without_running_second_deriver_and_wipes_both_passwords() {
        let coordinator = Arc::new(VaultSessionCoordinator::new());
        let scope = scope("account-one", "vault-one");
        let worker_coordinator = Arc::clone(&coordinator);
        let worker_scope = scope.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut password = b"first synthetic password".to_vec();
            let result =
                worker_coordinator.unlock_with_deriver(&worker_scope, &mut password, |_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(verified_session())
                });
            (result, password)
        });

        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut busy_password = b"second password".to_vec();
        let result = coordinator.unlock_with_deriver(&scope, &mut busy_password, |_| {
            panic!("busy coordinator invoked the second derivation")
        });
        assert!(result.is_err());
        assert!(busy_password.iter().all(|byte| *byte == 0));
        release_tx.send(()).unwrap();
        let (result, password) = worker.join().unwrap();
        assert!(result.is_ok());
        assert!(password.iter().all(|byte| *byte == 0));
        assert_eq!(coordinator.active_session_count().unwrap(), 1);
    }

    #[test]
    fn lock_and_logout_do_not_wait_for_kdf_and_prevent_late_publication() {
        let coordinator = Arc::new(VaultSessionCoordinator::new());
        for logout in [false, true] {
            let scope = scope(
                if logout {
                    "logout-account"
                } else {
                    "lock-account"
                },
                "vault-one",
            );
            let worker_coordinator = Arc::clone(&coordinator);
            let worker_scope = scope.clone();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let worker = thread::spawn(move || {
                let mut password = b"synthetic password".to_vec();
                let result =
                    worker_coordinator.unlock_with_deriver(&worker_scope, &mut password, |_| {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(verified_session())
                    });
                (result, password)
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

            let control_coordinator = Arc::clone(&coordinator);
            let control_scope = scope.clone();
            let account_id = scope.account_id().to_owned();
            let (control_tx, control_rx) = mpsc::channel();
            let control = thread::spawn(move || {
                let result = if logout {
                    control_coordinator.logout_account(&account_id)
                } else {
                    control_coordinator.lock(&control_scope)
                };
                control_tx.send(result.is_ok()).unwrap();
            });
            let control_completed = control_rx.recv_timeout(Duration::from_secs(2));
            assert!(coordinator.kdf_active.load(Ordering::Acquire));
            release_tx.send(()).unwrap();
            let (unlock_result, password) = worker.join().unwrap();
            control.join().unwrap();
            assert!(control_completed.unwrap_or(false));
            assert!(unlock_result.is_err());
            assert!(password.iter().all(|byte| *byte == 0));
            assert_eq!(coordinator.active_session_count().unwrap(), 0);
        }
    }

    #[test]
    fn completion_scope_lease_linearizes_lock_after_admission() {
        let coordinator = Arc::new(VaultSessionCoordinator::new());
        let scope = scope("completion-account", "completion-vault");
        unlock(&coordinator.registry, &scope).unwrap();

        let worker_coordinator = Arc::clone(&coordinator);
        let worker_scope = scope.clone();
        let (admitted_tx, admitted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let completion = thread::spawn(move || {
            VaultSessionCoordinator::with_unlocked_scopes_and_sessions(
                &worker_coordinator,
                &worker_scope,
                &worker_coordinator,
                &worker_scope,
                |first, second| {
                    assert!(std::ptr::eq(first, second));
                    admitted_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    "completed"
                },
            )
            .unwrap()
        });
        admitted_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let locker_coordinator = Arc::clone(&coordinator);
        let locker_scope = scope.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (locked_tx, locked_rx) = mpsc::channel();
        let locker = thread::spawn(move || {
            started_tx.send(()).unwrap();
            locker_coordinator.lock(&locker_scope).unwrap();
            locked_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            locked_rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "lock must wait until an admitted local completion leaves the session guard"
        );
        release_tx.send(()).unwrap();
        assert_eq!(completion.join().unwrap(), "completed");
        locked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        locker.join().unwrap();
        assert!(!coordinator.is_unlocked(&scope).unwrap());
    }

    #[test]
    fn lock_all_clears_every_account_invalidates_pending_work_and_keeps_kdf_permit() {
        let coordinator = Arc::new(VaultSessionCoordinator::new());
        let account_one = scope("account-one", "vault-one");
        let account_two = scope("account-two", "vault-two");
        let pending_scope = scope("account-three", "not-yet-unlocked");
        for active_scope in [&account_one, &account_two] {
            let ticket = coordinator.registry.begin_unlock(active_scope).unwrap();
            coordinator
                .registry
                .insert_unlocked(ticket, verified_session())
                .unwrap();
        }

        let worker_coordinator = Arc::clone(&coordinator);
        let worker_scope = pending_scope.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut password = b"blocked synthetic derivation".to_vec();
            let result =
                worker_coordinator.unlock_with_deriver(&worker_scope, &mut password, |_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(verified_session())
                });
            (result, password)
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(coordinator.kdf_active.load(Ordering::Acquire));
        let generation_before_lock = coordinator.registry.lock_state().unwrap().next_generation;

        let control_coordinator = Arc::clone(&coordinator);
        let (locked_tx, locked_rx) = mpsc::channel();
        let control = thread::spawn(move || {
            locked_tx.send(control_coordinator.lock_all()).unwrap();
        });
        let responsive_result = locked_rx.recv_timeout(Duration::from_secs(2));
        if responsive_result.is_err() {
            release_tx.send(()).unwrap();
            let _ = worker.join();
            control.join().unwrap();
            panic!("lock_all waited for the in-flight KDF");
        }
        responsive_result.unwrap().unwrap();
        control.join().unwrap();
        assert_eq!(
            coordinator.registry.lock_state().unwrap().next_generation,
            generation_before_lock
        );

        assert_eq!(coordinator.active_session_count().unwrap(), 0);
        assert!(
            coordinator
                .decrypt_name(&account_one, "um9jr7t436jbmsgpub5sfni4qk")
                .is_err()
        );
        assert!(
            coordinator
                .decrypt_name(&account_two, "um9jr7t436jbmsgpub5sfni4qk")
                .is_err()
        );
        assert!(
            coordinator
                .registry
                .lock_state()
                .unwrap()
                .pending
                .is_empty()
        );

        let mut busy_password = b"must wait for original KDF".to_vec();
        assert!(
            coordinator
                .unlock_with_deriver(&pending_scope, &mut busy_password, |_| {
                    panic!("lock_all released the KDF permit before derivation returned")
                })
                .is_err()
        );
        assert!(busy_password.iter().all(|byte| *byte == 0));
        assert!(coordinator.kdf_active.load(Ordering::Acquire));

        release_tx.send(()).unwrap();
        let (stale_result, worker_password) = worker.join().unwrap();
        assert!(stale_result.is_err());
        assert!(worker_password.iter().all(|byte| *byte == 0));
        assert!(!coordinator.kdf_active.load(Ordering::Acquire));
        assert_eq!(coordinator.active_session_count().unwrap(), 0);

        let mut retry_password = b"explicit unlock after lock all".to_vec();
        coordinator
            .unlock_with_deriver(&pending_scope, &mut retry_password, |_| {
                Ok(verified_session())
            })
            .unwrap();
        assert!(retry_password.iter().all(|byte| *byte == 0));
        assert_eq!(coordinator.active_session_count().unwrap(), 1);
        assert_eq!(
            coordinator.registry.lock_state().unwrap().next_generation,
            generation_before_lock + 1
        );
    }

    #[test]
    fn password_ticket_and_permit_cleanup_cover_errors_and_unwind() {
        let coordinator = VaultSessionCoordinator::new();
        let scope = scope("account-one", "vault-one");

        let mut generation_password = b"wipe on ticket failure".to_vec();
        coordinator.registry.lock_state().unwrap().next_generation = u64::MAX;
        assert!(
            coordinator
                .unlock_with_deriver(&scope, &mut generation_password, |_| {
                    panic!("deriver ran after ticket generation failure")
                })
                .is_err()
        );
        assert!(generation_password.iter().all(|byte| *byte == 0));
        assert!(!coordinator.kdf_active.load(Ordering::Acquire));
        coordinator.registry.lock_state().unwrap().next_generation = 0;

        let mut failed_password = b"wipe after derivation failure".to_vec();
        assert!(
            coordinator
                .unlock_with_deriver(&scope, &mut failed_password, |_| {
                    Err(invalid("synthetic derivation failure"))
                })
                .is_err()
        );
        assert!(failed_password.iter().all(|byte| *byte == 0));
        assert!(
            coordinator
                .registry
                .lock_state()
                .unwrap()
                .pending
                .is_empty()
        );

        let mut panic_password = b"wipe during unwind".to_vec();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = coordinator.unlock_with_deriver(&scope, &mut panic_password, |_| {
                panic!("synthetic derivation panic")
            });
        }));
        assert!(panic.is_err());
        assert!(panic_password.iter().all(|byte| *byte == 0));
        assert!(
            coordinator
                .registry
                .lock_state()
                .unwrap()
                .pending
                .is_empty()
        );
        assert!(!coordinator.kdf_active.load(Ordering::Acquire));

        let mut retry_password = b"retry after cleanup".to_vec();
        coordinator
            .unlock_with_deriver(&scope, &mut retry_password, |_| Ok(verified_session()))
            .unwrap();
        assert!(retry_password.iter().all(|byte| *byte == 0));
        assert_eq!(coordinator.active_session_count().unwrap(), 1);
    }

    #[test]
    fn create_ticket_publishes_only_after_exact_readback_and_invalidates_on_lock_or_logout() {
        let coordinator = VaultSessionCoordinator::new();
        let scope = scope("account-one", "new-vault-resource");
        let mut password = b"new vault password".to_vec();
        let pending = coordinator.begin_create(&scope, &mut password).unwrap();
        assert!(password.iter().all(|byte| *byte == 0));
        assert!(!coordinator.is_unlocked(&scope).unwrap());
        assert_eq!(coordinator.active_session_count().unwrap(), 0);
        assert!(
            coordinator
                .finish_create(pending, "incorrect readback")
                .is_err()
        );
        assert!(!coordinator.is_unlocked(&scope).unwrap());

        let mut password = b"new vault password".to_vec();
        let pending = coordinator.begin_create(&scope, &mut password).unwrap();
        let token = pending.integrity_token().to_owned();
        coordinator.finish_create(pending, &token).unwrap();
        assert!(coordinator.is_unlocked(&scope).unwrap());
        assert!(coordinator.verify_integrity_token(&scope, &token).unwrap());

        let mut password = b"replacement creation".to_vec();
        let pending = coordinator.begin_create(&scope, &mut password).unwrap();
        let token = pending.integrity_token().to_owned();
        coordinator.lock(&scope).unwrap();
        assert!(coordinator.finish_create(pending, &token).is_err());
        assert!(!coordinator.is_unlocked(&scope).unwrap());

        let mut password = b"logout creation".to_vec();
        let pending = coordinator.begin_create(&scope, &mut password).unwrap();
        let token = pending.integrity_token().to_owned();
        coordinator.logout_account(scope.account_id()).unwrap();
        assert!(coordinator.finish_create(pending, &token).is_err());
        assert!(!coordinator.is_unlocked(&scope).unwrap());
    }

    #[test]
    fn real_password_and_token_unlock_paths_clear_password_on_failure_and_success() {
        let coordinator = VaultSessionCoordinator::new();
        let scope = scope("account-one", "vault-one");
        let token = include_str!("../tests/fixtures/web-integrity-token.b64").trim();

        let mut wrong_password = b"wrong password".to_vec();
        assert!(
            coordinator
                .unlock(&scope, &mut wrong_password, token)
                .is_err()
        );
        assert!(wrong_password.iter().all(|byte| *byte == 0));

        let mut wrong_token_password = b"potato".to_vec();
        assert!(
            coordinator
                .unlock(&scope, &mut wrong_token_password, "not-a-valid-token")
                .is_err()
        );
        assert!(wrong_token_password.iter().all(|byte| *byte == 0));

        let mut valid_password = b"potato".to_vec();
        coordinator
            .unlock(&scope, &mut valid_password, token)
            .unwrap();
        assert!(valid_password.iter().all(|byte| *byte == 0));
        assert!(
            coordinator
                .decrypt_path(&scope, "um9jr7t436jbmsgpub5sfni4qk")
                .is_ok()
        );
    }

    #[test]
    fn coordinator_scoped_write_and_read_crypto_never_escape_locked_sessions() {
        let coordinator = VaultSessionCoordinator::new();
        let vault_scope = scope("account-one", "vault-one");
        let other_scope = scope("account-two", "vault-one");
        let token = include_str!("../tests/fixtures/web-integrity-token.b64").trim();
        assert!(!coordinator.is_unlocked(&vault_scope).unwrap());
        let mut password = b"potato".to_vec();
        coordinator
            .unlock(&vault_scope, &mut password, token)
            .unwrap();
        assert!(coordinator.is_unlocked(&vault_scope).unwrap());
        assert!(!coordinator.is_unlocked(&other_scope).unwrap());
        assert!(
            coordinator
                .verify_integrity_token(&vault_scope, token)
                .unwrap()
        );
        assert!(
            !coordinator
                .verify_integrity_token(&vault_scope, "not-a-valid-token")
                .unwrap()
        );
        let mut other_password = b"different synthetic password".to_vec();
        let other_draft = VaultCipher::from_password(&mut other_password)
            .unwrap()
            .initialize_new_vault()
            .unwrap();
        assert!(
            !coordinator
                .verify_integrity_token(&vault_scope, other_draft.integrity_token())
                .unwrap()
        );
        assert!(
            coordinator
                .verify_integrity_token(&other_scope, token)
                .is_err()
        );

        assert_eq!(
            coordinator
                .encrypt_path(&vault_scope, "folder/école.txt")
                .unwrap(),
            "um9jr7t436jbmsgpub5sfni4qk/ap8un5letkkhetgjpn9528qi4c"
        );
        assert!(coordinator.encrypt_path(&other_scope, "name").is_err());

        let existing = [coordinator.encrypt_name(&vault_scope, "Readme").unwrap()];
        assert!(
            coordinator
                .encode_directory_names(&vault_scope, &["README"], &[&existing[0]])
                .is_err()
        );
        let encoded = coordinator
            .encode_directory_names(&vault_scope, &["new-file.txt"], &[&existing[0]])
            .unwrap();
        assert_eq!(
            coordinator.decrypt_name(&vault_scope, &encoded[0]).unwrap(),
            "new-file.txt"
        );

        let directory = tempfile::tempdir().unwrap();
        let encrypted_path = directory.path().join("ciphertext");
        let plaintext = b"scoped encrypted payload";
        coordinator
            .encrypt_file_transactional(
                &vault_scope,
                &mut std::io::Cursor::new(plaintext),
                &encrypted_path,
                plaintext.len() as u64,
                1024,
            )
            .unwrap();
        let ciphertext = std::fs::read(encrypted_path).unwrap();
        let plaintext_path = directory.path().join("plaintext");
        coordinator
            .decrypt_file_transactional(
                &vault_scope,
                &mut std::io::Cursor::new(ciphertext),
                &plaintext_path,
                1024,
                Some(plaintext.len() as u64),
            )
            .unwrap();
        assert_eq!(std::fs::read(&plaintext_path).unwrap(), plaintext);
        assert!(
            coordinator
                .decrypt_file_transactional(
                    &other_scope,
                    &mut std::io::Cursor::new(b""),
                    &directory.path().join("wrong-scope"),
                    0,
                    Some(0),
                )
                .is_err()
        );

        coordinator.lock(&vault_scope).unwrap();
        assert!(!coordinator.is_unlocked(&vault_scope).unwrap());
        assert!(
            coordinator
                .encrypt_name(&vault_scope, "after-lock")
                .is_err()
        );
    }

    #[test]
    fn directory_decode_is_scoped_atomic_and_preserves_original_names() {
        let coordinator = VaultSessionCoordinator::new();
        let vault_scope = scope("account-one", "vault-one");
        let other_scope = scope("account-one", "vault-two");
        let token = include_str!("../tests/fixtures/web-integrity-token.b64").trim();
        let mut password = b"potato".to_vec();
        coordinator
            .unlock(&vault_scope, &mut password, token)
            .unwrap();

        let names = ["um9jr7t436jbmsgpub5sfni4qk", "ap8un5letkkhetgjpn9528qi4c"];
        assert_eq!(
            coordinator
                .decode_directory_names(&vault_scope, &names)
                .unwrap(),
            ["folder", "école.txt"]
        );
        assert!(
            coordinator
                .decode_directory_names(&other_scope, &names)
                .is_err()
        );

        // The first item is valid, but an invalid later ciphertext rejects the
        // whole batch; the API exposes no partial vector or callback.
        assert!(
            coordinator
                .decode_directory_names(&vault_scope, &[names[0], "not-a-ciphertext"])
                .is_err()
        );
        assert!(
            coordinator
                .decode_directory_names(&vault_scope, &[names[0], names[0]])
                .is_err()
        );

        coordinator.lock(&vault_scope).unwrap();
        assert!(
            coordinator
                .decode_directory_names(&vault_scope, &names)
                .is_err()
        );
    }
}
