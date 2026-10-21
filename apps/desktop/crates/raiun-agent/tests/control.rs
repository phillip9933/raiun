#![cfg(unix)]
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn request(socket: &std::path::Path, value: Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(stream, "{value}").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}
fn shutdown(agent: &mut Agent, socket: &std::path::Path) {
    let response = request(socket, json!({"action":"shutdown"}));
    assert_eq!(response["ok"], true);
    assert_eq!(response["data"]["stopping"], true);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if agent.0.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "agent did not stop after shutdown"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!socket.exists(), "agent left its owned socket behind");
}
#[test]
fn socket_settings_survive_restart_and_invalid_changes_are_atomic() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let launch = || {
        Agent(
            Command::new(env!("CARGO_BIN_EXE_raiun-agent"))
                .arg("serve")
                .env("RAIUN_STATE_DIR", &state)
                .env("HOME", tmp.path())
                .env("XDG_CONFIG_HOME", tmp.path().join("config"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        )
    };
    let mut agent = launch();
    let socket = state.join("control.sock");
    let start = Instant::now();
    while UnixStream::connect(&socket).is_err() {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(25));
    }
    let status = request(&socket, json!({"action":"status"}));
    assert_eq!(status["data"]["connected"], false);
    assert_eq!(status["data"]["pair_reports"], json!({}));
    assert_eq!(status["data"]["autostart"], false);
    assert!(status["data"]["recovery_folder"].is_null());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&state).unwrap().permissions().mode() & 0o077,
        0
    );
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o077,
        0
    );
    assert_eq!(
        request(&socket, json!({"action":"pause","paused":true}))["ok"],
        true
    );
    let first_local = tmp.path().join("pair-one");
    let second_local = tmp.path().join("pair-two");
    std::fs::create_dir_all(&first_local).unwrap();
    std::fs::create_dir_all(&second_local).unwrap();
    let pair = |id: &str, local_path: &std::path::Path, remote_path: &str| {
        json!({
            "action":"pair_add", "id":id, "local_path":local_path, "space_id":"personal",
            "remote_path":remote_path, "mode":"two_way"
        })
    };
    assert_eq!(
        request(&socket, pair("retired", &first_local, "/one"))["ok"],
        true
    );
    assert_eq!(
        request(&socket, json!({"action":"pair_remove","id":"retired"}))["ok"],
        true
    );
    let reused = request(&socket, pair("retired", &first_local, "/one"));
    assert_eq!(reused["ok"], false);
    assert!(reused["error"].as_str().unwrap().contains("retired"));
    assert_eq!(
        request(&socket, pair("fresh", &second_local, "/two"))["ok"],
        true
    );
    assert_eq!(
        request(
            &socket,
            json!({"action":"configure","cloud_root":"relative"})
        )["ok"],
        false
    );
    assert_eq!(
        request(&socket, json!({"action":"status"}))["data"]["cloud_root"],
        tmp.path().join("OpenCloud").to_str().unwrap()
    );
    let mut oversized = UnixStream::connect(&socket).unwrap();
    oversized.write_all(&vec![b' '; 1_048_577]).unwrap();
    oversized.write_all(b"\n").unwrap();
    let mut response = String::new();
    BufReader::new(oversized).read_line(&mut response).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&response).unwrap()["ok"],
        false
    );
    shutdown(&mut agent, &socket);
    let mut second_agent = launch();
    let start = Instant::now();
    while UnixStream::connect(&socket).is_err() {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        request(&socket, json!({"action":"status"}))["data"]["paused"],
        true
    );
    let pairs = request(&socket, json!({"action":"pairs"}));
    assert_eq!(pairs["ok"], true);
    assert_eq!(pairs["data"].as_array().unwrap().len(), 1);
    assert_eq!(pairs["data"][0]["id"], "fresh");
    assert_eq!(
        request(&socket, pair("retired", &first_local, "/one"))["ok"],
        false
    );
    shutdown(&mut second_agent, &socket);

    let mut signal_agent = launch();
    let start = Instant::now();
    while UnixStream::connect(&socket).is_err() {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(25));
    }
    let status = std::process::Command::new("kill")
        .args(["-TERM", &signal_agent.0.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if signal_agent.0.try_wait().unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "agent did not stop on SIGTERM");
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!socket.exists(), "SIGTERM left the control socket behind");
}
