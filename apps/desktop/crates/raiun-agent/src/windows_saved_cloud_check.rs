// Explicit informational comparison. Never dispatch, acknowledge or retire a saved edit.
impl WindowsAgent {
    fn check_saved_edit_cloud(&self, request: &Value) -> Result<Value, String> {
        use raiun_cloudfiles_windows::{EditRecoveryProvider, SavedEditCloudCheck};

        self.check_headless_recovery_request(request)?;
        let mut request = request.clone();
        if mount_only() {
            // RuntimeMode already checked this transport-only field before dispatch.
            request.as_object_mut().ok_or("Invalid saved-copy request")?.remove("required_mode");
        }
        let record_id = request.get("record_id").and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or("Choose a saved copy from the current list")?;
        let record_generation = request.get("generation").and_then(Value::as_u64)
            .filter(|generation| *generation != 0)
            .ok_or("Choose a saved copy from the current list")?;
        // Reject stale account requests before any authenticated discovery.
        {
            let state = self.state.lock().map_err(|_| "Account state is unavailable")?;
            if request["expected_generation"].as_u64() != Some(state.active_generation)
                || self.generation.load(Ordering::Acquire) != state.active_generation
                || !state.online_authenticated || state.authenticating || state.refreshing
                || state.retiring || state.logout_pending
            {
                return Err("Refresh saved copies for the current account".into());
            }
        }
        let verified = self.prepare_recovery_context()?;
        let scope_token = self.provider.recovery_cursor_context(
            &verified.provider_scope, verified.local_root_identity, verified.agent_generation,
        )?;
        crate::windows_recovery_request::validate_check(
            &request, &self.profile_scope, verified.agent_generation, &scope_token,
        )?;
        let mut selected = verified.recovery_provider.unresolved_edits()
            .map_err(|_| "Saved-copy metadata could not be authenticated")?
            .into_iter()
            .filter(|item| item.record_id == record_id && item.generation == record_generation);
        let metadata = selected.next().ok_or("The selected saved copy is unavailable")?;
        if selected.next().is_some()
            || metadata.scope.profile_id != verified.provider_scope.profile_id()
            || metadata.scope.server_origin != verified.provider_scope.server_origin()
            || metadata.scope.account_subject != verified.provider_scope.account_id()
            || metadata.scope.root_volume_serial != verified.local_root_identity.volume_serial
            || metadata.scope.root_file_index != verified.local_root_identity.file_index
        {
            return Err("The saved copy belongs to a different account or drive folder".into());
        }
        let mut spaces = verified.spaces.iter().filter(|space| space.id == metadata.scope.space_id);
        let space = spaces.next().filter(|space| !space.encrypted && space.writable)
            .ok_or("The saved copy's Space is unavailable or protected")?;
        if spaces.next().is_some() {
            return Err("The saved copy's Space is ambiguous".into());
        }
        let current = || -> Result<(), String> {
            let state = self.state.lock().map_err(|_| "Account state is unavailable")?;
            if self.generation.load(Ordering::Acquire) != verified.agent_generation
                || self.provider.authorized_generation.load(Ordering::Acquire) != verified.agent_generation
                || state.active_generation != verified.agent_generation
                || !state.online_authenticated || state.authenticating || state.refreshing
                || state.needs_refresh || state.retiring || state.logout_pending
                || state.session_cleanup_uncertain
                || state.root_configuration.as_ref() != Some(&verified.configuration)
                || !Self::same_session(state.session.as_ref(), Some(&verified.session))
            {
                return Err("The account changed while checking the saved copy".into());
            }
            Ok(())
        };
        let root = || -> Result<raiun_core::backend::RemoteEntry, String> {
            current()?;
            let root = verified.client.stat_discovered_space_root_with_context(
                space, RangeReadContext {
                    deadline: Instant::now() + Duration::from_secs(30),
                    token_generation: verified.client.token_generation(),
                },
            ).map_err(|_| "Could not verify the saved copy's current Space root")?;
            current()?;
            if !root.directory || root.encrypted || !root.writable
                || root.id != metadata.scope.root_resource_id
            {
                return Err("The saved copy's Space root has changed".into());
            }
            Ok(root)
        };
        let remote_root = root()?;
        let prepared = verified.recovery_provider.prepare(
            &verified.provider_scope, verified.local_root_identity,
        ).map_err(|_| "Protected saved copies are unavailable")?;
        if prepared.provider_scope() != &verified.provider_scope
            || prepared.root_identity() != verified.local_root_identity
        {
            return Err("The saved-copy storage no longer matches this drive".into());
        }
        let remote = Arc::new(raiun_cloudfiles_windows::OpenCloudRecoveryRemote::new(
            Arc::clone(&verified.client), metadata.scope.clone(), remote_root.path,
            verified.client.token_generation(),
        ).map_err(|_| "Could not prepare the read-only cloud check")?);
        let remote = AgentGenerationRecoveryRemote {
            inner: RecoveryRemoteHandle::Owned(remote),
            authorized_generation: Arc::clone(&self.provider.authorized_generation),
            expected_generation: verified.agent_generation,
        };
        current()?;
        let result = prepared.check_recovered_edit_readback(record_id, record_generation, &remote)
            .map_err(|_| "The retained saved copy could not be authenticated")?;
        // A NotFound in a descendant request must never masquerade as absence
        // after the selected root has been replaced or become unavailable.
        root()?;
        current()?;
        let pinned = pin_registered_configured_root(
            Path::new(&verified.configuration.path), verified.local_root_identity,
        ).map_err(root_error_text)?;
        if pinned.identity() != verified.local_root_identity {
            return Err("The Windows drive folder changed during the check".into());
        }
        let (result, bytes) = match result {
            SavedEditCloudCheck::Matched { bytes } => ("matched", Some(bytes)),
            SavedEditCloudCheck::Missing => ("missing", None),
            SavedEditCloudCheck::Different => ("different", None),
            SavedEditCloudCheck::Unavailable => ("unavailable", None),
        };
        current()?;
        Ok(json!({
            "profile_id": self.profile_scope, "auth_generation": verified.agent_generation,
            "recovery_scope_token": scope_token, "record_id": record_id,
            "generation": record_generation, "result": result, "bytes": bytes,
            "read_only": true, "cloud_mutated": false, "local_completion": "unchanged",
            "original_snapshot_retained": true,
        }))
    }
}
