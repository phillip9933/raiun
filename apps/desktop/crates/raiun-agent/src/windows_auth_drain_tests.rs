use super::super::ProviderCommand;
use super::*;

type Commands = mpsc::SyncSender<ProviderCommand>;

fn intercepted_agent() -> (
    WindowsAgent,
    Arc<MemoryStore>,
    Commands,
    mpsc::Receiver<ProviderCommand>,
) {
    let store = Arc::new(MemoryStore::default());
    let mut agent = WindowsAgent::new(store.clone());
    let (commands, receiver) = mpsc::sync_channel(8);
    let original = std::mem::replace(
        &mut Arc::get_mut(&mut agent.provider)
            .expect("unshared test manager")
            .commands,
        commands,
    );
    (agent, store, original, receiver)
}

fn seed_retained_session(agent: &WindowsAgent, store: &MemoryStore, session: auth::Session) {
    seed_active_session(store, "default", session.clone());
    let mut state = agent.state.lock().unwrap();
    state.session = Some(session);
    state.online_authenticated = true;
    state.needs_refresh = false;
}

fn disconnect_response(
    receiver: &mpsc::Receiver<ProviderCommand>,
) -> mpsc::SyncSender<Result<(), String>> {
    match receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("actual disconnect request")
    {
        ProviderCommand::Disconnect(response) => response,
        _ => panic!("expected actual disconnect request"),
    }
}

fn restore_commands(mut agent: Arc<WindowsAgent>, original: Commands) {
    let agent = Arc::get_mut(&mut agent).expect("test callers joined");
    Arc::get_mut(&mut agent.provider)
        .expect("test workers joined")
        .commands = original;
}

#[test]
fn logout_refusal_retains_session_and_restore_authority_without_holding_worker_locks() {
    let (agent, store, original, receiver) = intercepted_agent();
    seed_retained_session(
        &agent,
        &store,
        synthetic_session(
            "https://cloud.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    let agent = Arc::new(agent);
    let caller = Arc::clone(&agent);
    let worker = thread::spawn(move || caller.logout());
    let response = disconnect_response(&receiver);
    assert!(agent.state.try_lock().is_ok());
    assert!(agent.folder_lifecycle.try_lock().is_ok());
    assert!(agent.vault_credential_operation.try_lock().is_ok());
    assert!(store.active_identity.lock().unwrap().is_some());
    assert_eq!(store.sessions.lock().unwrap().len(), 1);
    response
        .send(Err("synthetic drain refusal".into()))
        .unwrap();
    assert!(worker.join().unwrap().is_err());
    let state = agent.state.lock().unwrap();
    assert!(state.session.is_some());
    assert!(state.logout_pending);
    assert!(state.error.is_some());
    drop(state);
    assert!(store.active_identity.lock().unwrap().is_some());
    restore_commands(agent, original);
}

#[test]
fn cancellation_refusal_does_not_join_auth_worker_or_remove_saved_session() {
    let (agent, store, original, receiver) = intercepted_agent();
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
    let (release, blocked) = mpsc::channel();
    *agent.auth_thread.lock().unwrap() = Some(thread::spawn(move || {
        let _ = blocked.recv();
    }));
    let agent = Arc::new(agent);
    let caller = Arc::clone(&agent);
    let (done, result) = mpsc::channel();
    let worker = thread::spawn(move || {
        done.send(caller.cancel_auth()).unwrap();
    });
    disconnect_response(&receiver)
        .send(Err("synthetic drain refusal".into()))
        .unwrap();
    assert!(
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    worker.join().unwrap();
    assert!(agent.auth_thread.lock().unwrap().is_some());
    assert!(store.active_identity.lock().unwrap().is_some());
    release.send(()).unwrap();
    agent
        .auth_thread
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap();
    restore_commands(agent, original);
}

#[test]
fn refresh_refusal_runs_off_control_thread_and_before_auth_network() {
    let (agent, store, original, receiver) = intercepted_agent();
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
    let response = disconnect_response(&receiver);
    assert!(agent.state.try_lock().is_ok());
    assert!(agent.vault_credential_operation.try_lock().is_ok());
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    response
        .send(Err("synthetic drain refusal".into()))
        .unwrap();
    agent
        .refresh_thread
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap();
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
    restore_commands(Arc::new(agent), original);
}

#[test]
fn stale_refresh_drain_acknowledgement_cannot_start_auth_network() {
    let (agent, store, original, receiver) = intercepted_agent();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    seed_retained_session(
        &agent,
        &store,
        session_for_refresh(&endpoint, unix_time_now() + 10),
    );
    agent.maybe_start_refresh().unwrap();
    let response = disconnect_response(&receiver);
    {
        let mut state = agent.state.lock().unwrap();
        state.active_generation = agent.next_generation().unwrap();
        state.refreshing = false;
        state.logout_pending = true;
    }
    response.send(Ok(())).unwrap();
    agent
        .refresh_thread
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap();
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert!(store.active_identity.lock().unwrap().is_some());
    restore_commands(Arc::new(agent), original);
}

#[test]
fn new_auth_refusal_preserves_prior_restore_pointer_before_discovery() {
    let (agent, store, original, receiver) = intercepted_agent();
    seed_active_session(
        &store,
        "default",
        synthetic_session(
            "https://prior.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    let agent = Arc::new(agent);
    let caller = Arc::clone(&agent);
    let worker = thread::spawn(move || {
        caller.begin_auth(&json!({"server":"https://cloud.example","client_id":"synthetic-client"}))
    });
    let response = disconnect_response(&receiver);
    assert!(agent.state.try_lock().is_ok());
    assert!(agent.vault_credential_operation.try_lock().is_ok());
    response
        .send(Err("synthetic drain refusal".into()))
        .unwrap();
    assert!(worker.join().unwrap().is_err());
    assert!(store.active_identity.lock().unwrap().is_some());
    assert!(!agent.state.lock().unwrap().authenticating);
    restore_commands(agent, original);
}

#[test]
fn configure_root_refusal_precedes_root_inspection_and_storage() {
    let (agent, store, original, receiver) = intercepted_agent();
    seed_retained_session(
        &agent,
        &store,
        synthetic_session(
            "https://cloud.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    let agent = Arc::new(agent);
    let caller = Arc::clone(&agent);
    let worker = thread::spawn(move || {
        caller.configure_root(&json!({"cloud_root":r"C:\Synthetic-Drain-Refused"}))
    });
    let response = disconnect_response(&receiver);
    assert!(agent.state.try_lock().is_ok());
    assert!(agent.folder_lifecycle.try_lock().is_ok());
    response
        .send(Err("synthetic root drain refusal".into()))
        .unwrap();
    assert!(worker.join().unwrap().is_err());
    assert!(store.root_configs.lock().unwrap().is_empty());
    {
        let state = agent.state.lock().unwrap();
        assert!(state.session.is_some());
        assert!(
            !state.authenticating,
            "refused configure releases its own reservation"
        );
    }
    restore_commands(agent, original);
}

#[test]
fn idle_stop_refusal_keeps_original_auth_worker_handle() {
    let (agent, _, original, receiver) = intercepted_agent();
    let (release, blocked) = mpsc::channel();
    *agent.auth_thread.lock().unwrap() = Some(thread::spawn(move || {
        let _ = blocked.recv();
    }));
    let agent = Arc::new(agent);
    let caller = Arc::clone(&agent);
    let (done, result) = mpsc::channel();
    let worker = thread::spawn(move || {
        done.send(caller.stop_and_join()).unwrap();
    });
    disconnect_response(&receiver)
        .send(Err("synthetic stop drain refusal".into()))
        .unwrap();
    assert!(
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    worker.join().unwrap();
    assert!(agent.auth_thread.lock().unwrap().is_some());
    release.send(()).unwrap();
    agent
        .auth_thread
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap();
    restore_commands(agent, original);
}

#[test]
fn broken_owner_queue_is_not_successful_logout() {
    let (agent, store, original, receiver) = intercepted_agent();
    seed_retained_session(
        &agent,
        &store,
        synthetic_session(
            "https://cloud.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    drop(receiver);
    assert!(agent.logout().is_err());
    assert!(agent.state.lock().unwrap().session.is_some());
    assert!(store.active_identity.lock().unwrap().is_some());
    assert_eq!(store.sessions.lock().unwrap().len(), 1);
    restore_commands(Arc::new(agent), original);
}

#[test]
fn stale_root_refusal_does_not_clear_new_generation_reservation() {
    let (agent, store, original, receiver) = intercepted_agent();
    seed_retained_session(
        &agent,
        &store,
        synthetic_session(
            "https://cloud.example",
            "synthetic-client",
            unix_time_now() + 3600,
        ),
    );
    let agent = Arc::new(agent);
    let caller = Arc::clone(&agent);
    let worker = thread::spawn(move || {
        caller.configure_root(&json!({"cloud_root":r"C:\Synthetic-Stale-Root"}))
    });
    let response = disconnect_response(&receiver);
    {
        let mut state = agent.state.lock().unwrap();
        assert!(state.authenticating);
        state.active_generation = agent.next_generation().unwrap();
    }
    response
        .send(Err("synthetic stale drain refusal".into()))
        .unwrap();
    assert!(worker.join().unwrap().is_err());
    assert!(agent.state.lock().unwrap().authenticating);
    assert!(store.root_configs.lock().unwrap().is_empty());
    restore_commands(agent, original);
}
