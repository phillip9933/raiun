use super::super::ProviderCommand;
use super::*;

type Commands = mpsc::SyncSender<ProviderCommand>;

struct InterceptedAgent {
    agent: Arc<WindowsAgent>,
    store: Arc<MemoryStore>,
    original: Option<Commands>,
    receiver: Option<mpsc::Receiver<ProviderCommand>>,
    callers: Vec<thread::JoinHandle<()>>,
    held_auth_release: Option<mpsc::Sender<()>>,
}

impl InterceptedAgent {
    fn new() -> Self {
        let store = Arc::new(MemoryStore::default());
        let mut agent = WindowsAgent::new(store.clone());
        let (commands, receiver) = mpsc::sync_channel(8);
        let original = std::mem::replace(
            &mut Arc::get_mut(&mut agent.provider)
                .expect("unshared test manager")
                .commands,
            commands,
        );
        Self {
            agent: Arc::new(agent),
            store,
            original: Some(original),
            receiver: Some(receiver),
            callers: Vec::new(),
            held_auth_release: None,
        }
    }

    fn agent(&self) -> Arc<WindowsAgent> {
        Arc::clone(&self.agent)
    }

    fn spawn(
        &mut self,
        action: impl FnOnce(&Arc<WindowsAgent>) -> Result<Value, String> + Send + 'static,
    ) -> mpsc::Receiver<Result<Value, String>> {
        let agent = self.agent();
        let (done, result) = mpsc::channel();
        self.callers.push(thread::spawn(move || {
            // A failed assertion may already have dropped the result receiver.
            let _ = done.send(action(&agent));
        }));
        result
    }

    fn disconnect_response(&self) -> mpsc::SyncSender<Result<(), String>> {
        match self
            .receiver
            .as_ref()
            .expect("fake receiver is open")
            .recv_timeout(Duration::from_secs(5))
            .expect("actual disconnect request")
        {
            ProviderCommand::Disconnect(response) => response,
            _ => panic!("expected actual disconnect request"),
        }
    }

    fn hold_auth(&mut self) {
        let (release, blocked) = mpsc::channel();
        self.held_auth_release = Some(release);
        *self.agent.auth_thread.lock().unwrap() = Some(thread::spawn(move || {
            let _ = blocked.recv();
        }));
    }

    fn release_auth(&mut self) {
        self.held_auth_release.take().unwrap().send(()).unwrap();
        let handle = self.agent.auth_thread.lock().unwrap().take().unwrap();
        handle.join().unwrap();
    }

    fn join_callers(&mut self) -> bool {
        let mut joined = true;
        for caller in self.callers.drain(..) {
            joined &= caller.join().is_ok();
        }
        joined
    }

    fn cleanup(&mut self) -> bool {
        // The receiver must close before the final agent can send an unanswered Stop.
        // This also disposes any queued disconnect responses before joining callers.
        drop(self.receiver.take());
        drop(self.held_auth_release.take());
        let mut joined = self.join_callers();
        {
            let agent = &self.agent;
            // No mutex needed by an owned worker is held across its join.
            let auth = agent
                .auth_thread
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(auth) = auth {
                joined &= auth.join().is_ok();
            }
            let refresh = agent
                .refresh_thread
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(refresh) = refresh {
                joined &= refresh.join().is_ok();
            }
        }
        if self.original.is_some() {
            let provider =
                Arc::get_mut(&mut self.agent).and_then(|agent| Arc::get_mut(&mut agent.provider));
            let Some(provider) = provider else {
                return false;
            };
            if let Some(original) = self.original.take() {
                provider.commands = original;
            }
        }
        joined
    }

    fn finish(mut self, agent: Arc<WindowsAgent>) {
        drop(agent);
        assert!(
            self.cleanup(),
            "owned fixture workers joined and manager commands restored"
        );
    }
}

impl Drop for InterceptedAgent {
    fn drop(&mut self) {
        // Cleanup preserves the original assertion/timeout panic without a second panic.
        let _ = self.cleanup();
    }
}

fn seed_retained_session(agent: &WindowsAgent, store: &MemoryStore, session: auth::Session) {
    seed_active_session(store, "default", session.clone());
    let mut state = agent.state.lock().unwrap();
    state.session = Some(session);
    state.online_authenticated = true;
    state.needs_refresh = false;
}

#[test]
fn logout_refusal_retains_session_and_restore_authority_without_holding_worker_locks() {
    let mut fixture = InterceptedAgent::new();
    let agent = fixture.agent();
    let store = Arc::clone(&fixture.store);
    seed_retained_session(
        &agent,
        &store,
        synthetic_session(
            "https://cloud.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    let result = fixture.spawn(|caller| caller.logout());
    let response = fixture.disconnect_response();
    assert!(agent.state.try_lock().is_ok());
    assert!(agent.folder_lifecycle.try_lock().is_ok());
    assert!(agent.vault_credential_operation.try_lock().is_ok());
    assert!(store.active_identity.lock().unwrap().is_some());
    assert_eq!(store.sessions.lock().unwrap().len(), 1);
    response
        .send(Err("synthetic drain refusal".into()))
        .unwrap();
    assert!(
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    assert!(fixture.join_callers(), "test caller joined without panic");
    let state = agent.state.lock().unwrap();
    assert!(state.session.is_some());
    assert!(state.logout_pending);
    assert!(state.error.is_some());
    drop(state);
    assert!(store.active_identity.lock().unwrap().is_some());
    fixture.finish(agent);
}

#[test]
fn cancellation_refusal_does_not_join_auth_worker_or_remove_saved_session() {
    let mut fixture = InterceptedAgent::new();
    let agent = fixture.agent();
    let store = Arc::clone(&fixture.store);
    seed_retained_session(
        &agent,
        &store,
        synthetic_session(
            "https://cloud.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    agent.state.lock().unwrap().authenticating = true;
    fixture.hold_auth();
    let result = fixture.spawn(|caller| caller.cancel_auth());
    fixture
        .disconnect_response()
        .send(Err("synthetic drain refusal".into()))
        .unwrap();
    assert!(
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    assert!(fixture.join_callers(), "test caller joined without panic");
    assert!(agent.auth_thread.lock().unwrap().is_some());
    assert!(store.active_identity.lock().unwrap().is_some());
    fixture.release_auth();
    fixture.finish(agent);
}

#[test]
fn refresh_refusal_runs_off_control_thread_and_before_auth_network() {
    let fixture = InterceptedAgent::new();
    let agent = fixture.agent();
    let store = Arc::clone(&fixture.store);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    seed_retained_session(
        &agent,
        &store,
        session_for_refresh(&endpoint, unix_time_now() + 10),
    );
    // This returns while the actual disconnect response remains withheld.
    agent.maybe_start_refresh().unwrap();
    let response = fixture.disconnect_response();
    assert!(agent.state.try_lock().is_ok());
    assert!(agent.vault_credential_operation.try_lock().is_ok());
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    response
        .send(Err("synthetic drain refusal".into()))
        .unwrap();
    let refresh = agent.refresh_thread.lock().unwrap().take().unwrap();
    refresh.join().unwrap();
    let state = agent.state.lock().unwrap();
    assert!(state.session.is_some());
    assert!(!state.refreshing);
    assert!(state.refresh_retry_at > unix_time_now());
    assert!(state.error.is_some());
    drop(state);
    assert!(store.active_identity.lock().unwrap().is_some());
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    fixture.finish(agent);
}

#[test]
fn stale_refresh_drain_acknowledgement_cannot_start_auth_network() {
    let fixture = InterceptedAgent::new();
    let agent = fixture.agent();
    let store = Arc::clone(&fixture.store);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    seed_retained_session(
        &agent,
        &store,
        session_for_refresh(&endpoint, unix_time_now() + 10),
    );
    agent.maybe_start_refresh().unwrap();
    let response = fixture.disconnect_response();
    {
        let mut state = agent.state.lock().unwrap();
        state.active_generation = agent.next_generation().unwrap();
        state.refreshing = false;
        state.logout_pending = true;
    }
    response.send(Ok(())).unwrap();
    let refresh = agent.refresh_thread.lock().unwrap().take().unwrap();
    refresh.join().unwrap();
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert!(store.active_identity.lock().unwrap().is_some());
    fixture.finish(agent);
}

#[test]
fn new_auth_refusal_preserves_prior_restore_pointer_before_discovery() {
    let mut fixture = InterceptedAgent::new();
    let agent = fixture.agent();
    let store = Arc::clone(&fixture.store);
    seed_active_session(
        &store,
        "default",
        synthetic_session(
            "https://prior.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    let result = fixture.spawn(|caller| {
        caller.begin_auth(&json!({"server":"https://cloud.example","client_id":"synthetic-client"}))
    });
    let response = fixture.disconnect_response();
    assert!(agent.state.try_lock().is_ok());
    assert!(agent.vault_credential_operation.try_lock().is_ok());
    response
        .send(Err("synthetic drain refusal".into()))
        .unwrap();
    assert!(
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    assert!(fixture.join_callers(), "test caller joined without panic");
    assert!(store.active_identity.lock().unwrap().is_some());
    assert!(!agent.state.lock().unwrap().authenticating);
    fixture.finish(agent);
}

#[test]
fn configure_root_refusal_precedes_root_inspection_and_storage() {
    let mut fixture = InterceptedAgent::new();
    let agent = fixture.agent();
    let store = Arc::clone(&fixture.store);
    seed_retained_session(
        &agent,
        &store,
        synthetic_session(
            "https://cloud.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    let result = fixture.spawn(|caller| {
        caller.configure_root(&json!({"cloud_root":r"C:\Synthetic-Drain-Refused"}))
    });
    let response = fixture.disconnect_response();
    assert!(agent.state.try_lock().is_ok());
    assert!(agent.folder_lifecycle.try_lock().is_ok());
    response
        .send(Err("synthetic root drain refusal".into()))
        .unwrap();
    assert!(
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    assert!(fixture.join_callers(), "test caller joined without panic");
    assert!(store.root_configs.lock().unwrap().is_empty());
    {
        let state = agent.state.lock().unwrap();
        assert!(state.session.is_some());
        assert!(
            !state.authenticating,
            "refused configure releases its own reservation"
        );
    }
    fixture.finish(agent);
}

#[test]
fn idle_stop_refusal_keeps_original_auth_worker_handle() {
    let mut fixture = InterceptedAgent::new();
    let agent = fixture.agent();
    fixture.hold_auth();
    let result = fixture.spawn(|caller| caller.stop_and_join().map(|()| Value::Null));
    fixture
        .disconnect_response()
        .send(Err("synthetic stop drain refusal".into()))
        .unwrap();
    assert!(
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    assert!(fixture.join_callers(), "test caller joined without panic");
    assert!(agent.auth_thread.lock().unwrap().is_some());
    fixture.release_auth();
    fixture.finish(agent);
}

#[test]
fn broken_owner_queue_is_not_successful_logout() {
    let mut fixture = InterceptedAgent::new();
    let agent = fixture.agent();
    let store = Arc::clone(&fixture.store);
    seed_retained_session(
        &agent,
        &store,
        synthetic_session(
            "https://cloud.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    drop(fixture.receiver.take());
    assert!(agent.logout().is_err());
    assert!(agent.state.lock().unwrap().session.is_some());
    assert!(store.active_identity.lock().unwrap().is_some());
    assert_eq!(store.sessions.lock().unwrap().len(), 1);
    fixture.finish(agent);
}

#[test]
fn stale_root_refusal_does_not_clear_new_generation_reservation() {
    let mut fixture = InterceptedAgent::new();
    let agent = fixture.agent();
    let store = Arc::clone(&fixture.store);
    seed_retained_session(
        &agent,
        &store,
        synthetic_session(
            "https://cloud.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    let result = fixture
        .spawn(|caller| caller.configure_root(&json!({"cloud_root":r"C:\Synthetic-Stale-Root"})));
    let response = fixture.disconnect_response();
    {
        let mut state = agent.state.lock().unwrap();
        assert!(state.authenticating);
        state.active_generation = agent.next_generation().unwrap();
    }
    response
        .send(Err("synthetic stale drain refusal".into()))
        .unwrap();
    assert!(
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    assert!(fixture.join_callers(), "test caller joined without panic");
    assert!(agent.state.lock().unwrap().authenticating);
    assert!(store.root_configs.lock().unwrap().is_empty());
    fixture.finish(agent);
}
