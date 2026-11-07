//! An opt-in credential owner for an already verified native provider.
//! Global token generations and generic generation locks remain strict.
use super::*;

pub(super) struct ProviderCredentialBinding {
    token: Arc<Mutex<String>>,
    generation: u64,
    security_generation: u64,
    account_id: String,
    personal_space_id: String,
    personal_root_id: String,
}

/// Captures the original owner in body watchdogs, independently of token HTTP.
#[derive(Clone)]
pub(super) struct ContextGenerationFence {
    generation: Arc<AtomicU64>,
    security: Arc<AtomicU64>,
    revoked: Arc<AtomicBool>,
    provider: Option<Arc<ProviderCredentialBinding>>,
}

impl ContextGenerationFence {
    pub(super) fn strict(generation: Arc<AtomicU64>) -> Self {
        Self {
            generation,
            security: Arc::new(AtomicU64::new(0)),
            revoked: Arc::new(AtomicBool::new(false)),
            provider: None,
        }
    }

    pub(super) fn matches(&self, expected: u64) -> bool {
        if self.revoked.load(Ordering::Acquire) {
            return false;
        }
        let current = self.generation.load(Ordering::Acquire);
        match &self.provider {
            Some(owner) => {
                self.security.load(Ordering::Acquire) == owner.security_generation
                    && (expected == owner.generation || expected == current)
            }
            None => expected == current,
        }
    }
}

impl OpenCloudClient {
    /// Permanently revoke this in-memory credential store before waiting for
    /// provider workers to drain. No server credential or persisted session is
    /// changed. Fresh authentication must create a new client/store.
    pub fn invalidate_credentials(&self) -> Result<(), CloudError> {
        // Fence active bodies before waiting even for short publication locks;
        // a poisoned token mutex must never leave the old owner admitted.
        self.credentials_revoked.store(true, Ordering::Release);
        let mut token = self
            .token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        token.zeroize();
        let next = self.token_generation.load(Ordering::Acquire).checked_add(1);
        let next_security = self
            .security_generation
            .load(Ordering::Acquire)
            .checked_add(1);
        if let Some(next) = next {
            self.token_generation.store(next, Ordering::Release);
        }
        if let Some(next) = next_security {
            self.security_generation.store(next, Ordering::Release);
        }
        if next.is_none() || next_security.is_none() {
            return Err(invalid(
                "authentication generation exhausted; credentials revoked",
            ));
        }
        Ok(())
    }

    /// An SDK-created context on an admitted view retains its exact native
    /// owner across every later benign rotation. The public token generation
    /// getter continues to expose the actual global credential generation.
    pub fn provider_context_generation(&self) -> u64 {
        self.provider_credentials
            .as_ref()
            .map_or_else(|| self.token_generation(), |owner| owner.generation)
    }

    /// Verify and retain one exact Personal namespace before a native provider
    /// is admitted. This view shares the original credential store; it never
    /// changes or hides the globally observable token generation. Only this
    /// view's original generation can survive benign admitted token rotation.
    pub fn with_verified_provider_credentials(
        &self,
        expected_generation: u64,
        personal_space_id: &str,
        personal_root_id: &str,
    ) -> Result<Self, CloudError> {
        if self.provider_credentials.is_some() {
            return Err(invalid(
                "provider credential ownership was already admitted",
            ));
        }
        let context = RangeReadContext {
            deadline: Instant::now() + Duration::from_secs(30),
            token_generation: expected_generation,
        };
        self.ensure_context_current(context)?;
        let security_generation = self.security_generation.load(Ordering::Acquire);
        let spaces = self.spaces_with_context(context)?;
        let mut personal = spaces.iter().filter(|space| space.personal);
        let selected = personal
            .next()
            .ok_or_else(|| invalid("Personal drive is unavailable"))?;
        if personal.next().is_some() || selected.id != personal_space_id || selected.encrypted {
            return Err(invalid("Personal drive credential binding changed"));
        }
        let root = self.stat_discovered_space_root_with_context(selected, context)?;
        if root.id != personal_root_id || root.id.is_empty() || !root.directory || root.encrypted {
            return Err(invalid("Personal root credential binding changed"));
        }
        let bytes = format!("{}\0{personal_space_id}", self.configured_server_url());
        let mut account_id = String::with_capacity(bytes.len() * 2);
        for byte in bytes.bytes() {
            use std::fmt::Write as _;
            let _ = write!(account_id, "{byte:02x}");
        }
        self.with_token_generation(expected_generation, || {
            let mut client = self.clone();
            client.provider_credentials = Some(Arc::new(ProviderCredentialBinding {
                token: Arc::clone(&self.token),
                generation: expected_generation,
                security_generation,
                account_id,
                personal_space_id: personal_space_id.to_owned(),
                personal_root_id: personal_root_id.to_owned(),
            }));
            client
        })
    }

    /// Check an optional native credential owner against the trusted scope.
    /// Generic clients remain usable through their strict current generation.
    pub fn provider_credentials_match(
        &self,
        account_id: &str,
        personal_space_id: Option<&str>,
        personal_root_id: Option<&str>,
    ) -> bool {
        !self.credentials_revoked.load(Ordering::Acquire)
            && self.provider_credentials.as_ref().is_none_or(|owner| {
                Arc::ptr_eq(&owner.token, &self.token)
                    && owner.account_id == account_id
                    && personal_space_id.is_none_or(|id| id == owner.personal_space_id)
                    && personal_root_id.is_none_or(|id| id == owner.personal_root_id)
                    && self.security_generation.load(Ordering::Acquire) == owner.security_generation
            })
    }

    /// Require a new native provider scope to retain this proof's original
    /// generation, rather than accidentally minting a later-lived scope.
    pub fn provider_scope_generation_is_admitted(&self, expected: u64) -> bool {
        self.provider_credentials
            .as_ref()
            .is_none_or(|owner| owner.generation == expected)
            && self.provider_generation_is_current(expected)
    }

    pub(super) fn context_generation_fence(&self) -> ContextGenerationFence {
        ContextGenerationFence {
            generation: Arc::clone(&self.token_generation),
            security: Arc::clone(&self.security_generation),
            revoked: Arc::clone(&self.credentials_revoked),
            provider: self.provider_credentials.clone(),
        }
    }

    /// Explicit native-owner validation. Arbitrary retired generations never
    /// gain authority: only the admitted original and actual current match.
    pub fn provider_generation_is_current(&self, expected: u64) -> bool {
        self.context_generation_fence().matches(expected)
    }

    /// Short local publication under the original native credential owner.
    pub fn with_provider_generation<T>(
        &self,
        expected: u64,
        publish: impl FnOnce() -> T,
    ) -> Result<T, CloudError> {
        let _token = self
            .token
            .lock()
            .map_err(|_| invalid("authentication state unavailable"))?;
        if !self.provider_generation_is_current(expected) {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "native credential owner changed",
            ));
        }
        Ok(publish())
    }

    /// Deadline-aware publication lock for an explicit native owner.
    pub fn try_lock_provider_generation(
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
        if !self.provider_generation_is_current(expected) {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "native credential owner changed",
            ));
        }
        Ok(Some(TokenGenerationLease { _token: token }))
    }
}
