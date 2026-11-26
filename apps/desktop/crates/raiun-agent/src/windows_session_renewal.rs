// One account-owned authentication object is shared by native mounts, folder
// work and explicit recovery. Routine OAuth renewal changes only its bearer;
// the original native/journal owner generations are never rewritten.
struct RenewableAccountClient {
    generation: u64,
    session: auth::Session,
    scope: windows_bandwidth::Scope,
    personal_space_id: String,
    personal_root_id: String,
    client: Arc<OpenCloudClient>,
}

struct PendingSessionRenewal {
    generation: u64,
    original: auth::Session,
    candidate: auth::Session,
}

impl ProviderManager {
    fn share_account_client(
        &self,
        client: Arc<OpenCloudClient>,
        session: &auth::Session,
        generation: u64,
        scope: &windows_bandwidth::Scope,
        personal_space_id: &str,
        personal_root_id: &str,
    ) -> Result<Arc<OpenCloudClient>, String> {
        let mut retained = self
            .account_client
            .lock()
            .map_err(|_| "Account credentials are unavailable")?;
        if self.authorized_generation.load(Ordering::Acquire) != generation {
            return Err("The account changed before client publication".into());
        }
        if let Some(current) = retained.as_ref().filter(|row| row.generation == generation) {
            if current.scope != *scope
                || current.personal_space_id != personal_space_id
                || current.personal_root_id != personal_root_id
                || !WindowsAgent::same_session(Some(&current.session), Some(session))
            {
                return Err("The sign-in changed during client preparation; try again".into());
            }
            return Ok(Arc::clone(&current.client));
        }
        *retained = Some(RenewableAccountClient {
            generation,
            session: session.clone(),
            scope: scope.clone(),
            personal_space_id: personal_space_id.to_owned(),
            personal_root_id: personal_root_id.to_owned(),
            client: Arc::clone(&client),
        });
        Ok(client)
    }
}

fn registered_account_client(
    registry: &Mutex<Option<RenewableAccountClient>>,
    generation: u64,
    client: &OpenCloudClient,
) -> bool {
    // Existing typed, non-renewing provider constructors have no shared owner.
    // They retain their strict token-generation lifetime. Once the Agent has
    // registered a renewable owner, every publication must share that object.
    client.provider_generation_is_current(client.provider_context_generation())
        && registry.lock().is_ok_and(|registry| {
            registry.as_ref().is_none_or(|row| {
                row.generation == generation && row.client.shares_authentication_with(client)
            })
        })
}

impl WindowsAgent {
    // Returns true while routine renewal owns the worker, including backoff.
    // Startup, explicit security recovery and app tokens keep the old strict
    // disconnect path. No provider-manager command/HTTP runs under state locks.
    fn try_start_routine_refresh(&self) -> Result<bool, String> {
        let snapshot = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.routine_refresh_generation == Some(state.active_generation) {
                return Ok(true);
            }
            if state.retiring
                || state.offline_cached
                || state.logout_pending
                || state.authenticating
                || state.refreshing
                || state.needs_refresh
                || !state.online_authenticated
            {
                return Ok(false);
            }
            let Some(session) = state
                .session
                .clone()
                .filter(|session| session.app_token_username.is_none())
            else {
                return Ok(false);
            };
            if state
                .root_configuration
                .as_ref()
                .is_some_and(|configuration| {
                    !configuration.valid
                        || configuration
                            .registration_ownership
                            .as_ref()
                            .is_none_or(|owner| owner.state != "registered")
                })
            {
                return Ok(false);
            }
            let now = unix_time_now();
            if state.pending_renewal.is_none() && session.expires_at > now.saturating_add(120) {
                return Ok(false);
            }
            let registry = self
                .provider
                .account_client
                .lock()
                .map_err(|_| "Account credentials are unavailable")?;
            let Some(owner) = registry.as_ref().filter(|row| {
                row.generation == state.active_generation
                    && self.generation.load(Ordering::Acquire) == row.generation
                    && self.provider.authorized_generation.load(Ordering::Acquire) == row.generation
                    && Self::same_session(Some(&row.session), Some(&session))
            }) else {
                return Ok(false);
            };
            if state.refresh_retry_at > now {
                return Ok(true);
            }
            let candidate = state
                .pending_renewal
                .as_ref()
                .filter(|pending| {
                    pending.generation == owner.generation
                        && Self::same_session(Some(&pending.original), Some(&session))
                })
                .map(|pending| pending.candidate.clone());
            let value = (
                session,
                owner.generation,
                state.root_configuration.clone(),
                Arc::clone(&owner.client),
                owner.personal_space_id.clone(),
                owner.personal_root_id.clone(),
                owner.scope.clone(),
                candidate,
            );
            state.routine_refresh_generation = Some(owner.generation);
            value
        };
        let (
            session,
            generation,
            configuration,
            client,
            personal_space,
            personal_root,
            scope,
            candidate,
        ) = snapshot;
        let state = Arc::clone(&self.state);
        let current_generation = Arc::clone(&self.generation);
        let store = Arc::clone(&self.session_store);
        let provider = Arc::clone(&self.provider);
        let profile = self.profile_scope.clone();
        let vault_sessions = Arc::clone(&self.vault_sessions);
        let copy_jobs = Arc::clone(&self.vault_copy_jobs);
        let copy_serialization = Arc::clone(&self.vault_copy_serialization);
        let worker = thread::spawn(move || {
            let current = |state: &AccountState| {
                state.routine_refresh_generation == Some(generation)
                    && state.active_generation == generation
                    && current_generation.load(Ordering::Acquire) == generation
                    && provider.authorized_generation.load(Ordering::Acquire) == generation
                    && state.online_authenticated
                    && !state.refreshing
                    && !state.authenticating
                    && !state.retiring
                    && !state.logout_pending
                    && !state.offline_cached
                    && !state.needs_refresh
                    && state.root_configuration == configuration
                    && WindowsAgent::same_session(state.session.as_ref(), Some(&session))
            };
            let mut refreshed = candidate.unwrap_or_else(|| session.clone());
            let token_result = if refreshed.expires_at <= unix_time_now().saturating_add(120)
                || WindowsAgent::same_session(Some(&refreshed), Some(&session))
            {
                refreshed.refresh_classified()
            } else {
                Ok(())
            };
            // A rejected grant is a security event. Transient transport/storage
            // failures retain the original owner and any rotated refresh token.
            let mut rejected = matches!(token_result, Err(auth::RefreshError::Rejected(_)));
            let outcome = (|| -> Result<(), String> {
                token_result.map_err(|_| "Could not renew sign-in; Raiun will retry".to_owned())?;
                {
                    let mut state = state.lock().map_err(|_| "Account state is unavailable")?;
                    if !current(&state) {
                        return Err("The account changed during sign-in renewal".into());
                    }
                    state.pending_renewal = Some(PendingSessionRenewal {
                        generation,
                        original: session.clone(),
                        candidate: refreshed.clone(),
                    });
                    // Retain a rotated refresh token even if the following
                    // root read is temporarily offline. Startup still verifies
                    // the saved root before reconnecting any provider.
                    store.save_pending(&profile, &refreshed)?;
                }
                let (verified_space, verified_account, verified_root) =
                    verified_personal_root_identity(&refreshed)?;
                let expected_scope = windows_bandwidth::Scope::new(
                    &profile,
                    &refreshed.server,
                    &refreshed.client_id,
                    refreshed.expected_issuer.as_deref(),
                    &verified_account,
                )?;
                if verified_space != personal_space
                    || verified_root != personal_root
                    || expected_scope != scope
                {
                    rejected = true;
                    return Err(
                        "The renewed sign-in belongs to a different account or drive".into(),
                    );
                }
                // Drains only short operations; native ordinary body leases
                // retain their original cancellation, owner and security epoch.
                let mut admission = client
                    .begin_bearer_refresh()
                    .map_err(|_| "Sign-in renewal is waiting for account metadata".to_owned())?;
                let mut state = state.lock().map_err(|_| "Account state is unavailable")?;
                let mut registry = provider
                    .account_client
                    .lock()
                    .map_err(|_| "Account credentials are unavailable")?;
                if !current(&state)
                    || registry.as_ref().is_none_or(|owner| {
                        owner.generation != generation
                            || !owner.client.shares_authentication_with(&client)
                            || !WindowsAgent::same_session(Some(&owner.session), Some(&session))
                            || owner.scope != scope
                            || owner.personal_space_id != personal_space
                            || owner.personal_root_id != personal_root
                    })
                {
                    return Err("The account changed during sign-in renewal".into());
                }
                // Short state -> registry -> token ordering; never wait for a
                // manager command or admission while any of these locks is held.
                store.save_pending(&profile, &refreshed)?;
                client
                    .set_refreshed_bearer_token(refreshed.access_token.clone(), &mut admission)
                    .map_err(|_| "The account credentials changed during renewal".to_owned())?;
                if let Some(owner) = registry.as_mut() {
                    owner.session = refreshed.clone();
                }
                state.session = Some(refreshed.clone());
                state.pending_renewal = None;
                state.routine_refresh_generation = None;
                state.refresh_retry_at = 0;
                state.error = None;
                Ok(())
            })();
            if let Err(error) = outcome {
                let mut revoke = None;
                if let Ok(mut state) = state.lock() {
                    let owns_result = current(&state);
                    if state.routine_refresh_generation == Some(generation) {
                        state.routine_refresh_generation = None;
                    }
                    if owns_result {
                        state.refresh_retry_at =
                            unix_time_now().saturating_add(windows_headless::retry_seconds());
                        state.error = Some(error);
                        if rejected {
                            let next = generation.checked_add(1).unwrap_or(0);
                            if (next == 0
                                && current_generation.load(Ordering::Acquire) == generation)
                                || current_generation
                                    .compare_exchange(
                                        generation,
                                        next,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok()
                            {
                                state.active_generation = next;
                                state.online_authenticated = false;
                                state.session = None;
                                state.pending_renewal = None;
                                state.root_configuration = None;
                                // Reserve this exact security transition until
                                // its old native/vault owners finish draining.
                                state.refreshing = true;
                                state.logout_pending = true;
                                provider.authorize_generation(next);
                                revoke = Some(next);
                            }
                        }
                    }
                }
                if let Some(next) = revoke {
                    // Invalidation was published under state before releasing
                    // the security-transition reservation. Never reload a newer
                    // generation and mistake it for this cleanup's owner.
                    let copy_failed = copy_jobs.cancel_all_and_wait().is_err();
                    let pin_failed = copy_serialization.cancel_all_and_wait().is_err();
                    let native_failed = provider.disconnect().is_err();
                    let vault_failed = vault_sessions.logout_account(&profile).is_err();
                    if let Ok(mut state) = state.lock()
                        && state.active_generation == next
                        && state.session.is_none()
                        && state.logout_pending
                        && state.refreshing
                        && !state.authenticating
                    {
                        state.session_cleanup_uncertain =
                            revoke_and_remove(&store, &profile, &refreshed);
                        state.refreshing = false;
                        let incomplete = copy_failed || pin_failed || native_failed || vault_failed;
                        state.logout_pending = incomplete;
                        if incomplete {
                            state.error = Some("Sign-in was rejected; the previous Windows drive is still stopping".into());
                        }
                    }
                }
            }
        });
        *self
            .refresh_thread
            .lock()
            .map_err(|_| "Session refresh worker state is unavailable")? = Some(worker);
        Ok(true)
    }
}
