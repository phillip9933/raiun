use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

fn run(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_raiun"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("run raiun CLI")
}

fn run_media_preview(input: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_raiun"))
        .arg("media-preview")
        .arg("--input")
        .arg(input)
        .output()
        .expect("run media preview CLI")
}

fn config_path(temp: &TempDir) -> PathBuf {
    temp.path().join("cfg").join("config.json")
}

fn init(temp: &TempDir) -> PathBuf {
    let config = config_path(temp);
    let cloud_root = temp.path().join("cloud");
    fs::create_dir_all(&cloud_root).unwrap();
    let output = run(
        &config,
        &[
            "config",
            "init",
            "--cloud-root",
            cloud_root.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    config
}

#[test]
fn config_init_add_show_remove_round_trip() {
    let temp = TempDir::new().unwrap();
    let config = init(&temp);
    let local = temp.path().join("local");
    fs::create_dir(&local).unwrap();
    let add = run(
        &config,
        &[
            "pair",
            "add",
            "--id",
            "photos",
            "--local",
            local.to_str().unwrap(),
            "--space-id",
            "space-manual",
            "--remote",
            "/Photos",
            "--mode",
            "two-way",
        ],
    );
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );

    let shown = run(&config, &["config", "show"]);
    assert!(shown.status.success());
    let text = String::from_utf8(shown.stdout).unwrap();
    assert!(text.contains("photos"));
    assert!(text.contains("space-manual"));

    let removed = run(&config, &["pair", "remove", "--id", "photos"]);
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    assert!(local.is_dir(), "removal must preserve local data");
    let shown = run(&config, &["config", "show"]);
    assert!(shown.status.success());
    assert!(!String::from_utf8(shown.stdout).unwrap().contains("photos"));
}

#[test]
fn init_does_not_overwrite_existing_file() {
    let temp = TempDir::new().unwrap();
    let config = init(&temp);
    let original = fs::read(&config).unwrap();
    let output = run(
        &config,
        &[
            "config",
            "init",
            "--cloud-root",
            temp.path().to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn rejects_unsupported_schema_and_oversized_config() {
    let temp = TempDir::new().unwrap();
    let config = config_path(&temp);
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &config,
        br#"{"schema_version":999,"cloud_root":"/tmp","pairs":[]}"#,
    )
    .unwrap();
    let output = run(&config, &["config", "show"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("schema version"));

    fs::write(&config, vec![b'x'; 1024 * 1024 + 10]).unwrap();
    let output = run(&config, &["config", "show"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("1 MiB"));
}

#[test]
fn invalid_pair_and_invalid_mode_do_not_change_config() {
    let temp = TempDir::new().unwrap();
    let config = init(&temp);
    let before = fs::read(&config).unwrap();
    let local = temp.path().join("local");
    fs::create_dir(&local).unwrap();

    let invalid = run(
        &config,
        &[
            "pair",
            "add",
            "--id",
            "bad",
            "--local",
            local.to_str().unwrap(),
            "--space-id",
            "",
            "--remote",
            "../escape",
            "--mode",
            "two-way",
        ],
    );
    assert!(!invalid.status.success());
    assert_eq!(fs::read(&config).unwrap(), before);

    let bad_mode = run(
        &config,
        &[
            "pair",
            "add",
            "--id",
            "good",
            "--local",
            local.to_str().unwrap(),
            "--space-id",
            "space",
            "--remote",
            "Folder",
            "--mode",
            "bogus",
        ],
    );
    assert!(!bad_mode.status.success());
    assert!(String::from_utf8_lossy(&bad_mode.stderr).contains("possible values"));
    assert_eq!(fs::read(&config).unwrap(), before);
}

#[test]
fn status_does_not_claim_sync_is_running() {
    let temp = TempDir::new().unwrap();
    let config = init(&temp);
    let output = run(&config, &["status"]);
    assert!(output.status.success());
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("Configured folder pairs: 0"));
    assert!(report.contains("Sync engine: unavailable"));
    assert!(report.contains("transfers: not available"));
}

#[test]
fn stale_local_directories_can_be_inspected_and_removed_pair_by_pair() {
    let temp = TempDir::new().unwrap();
    let config = init(&temp);
    let first_local = temp.path().join("first-local");
    let second_local = temp.path().join("second-local");
    fs::create_dir(&first_local).unwrap();
    fs::create_dir(&second_local).unwrap();

    for (id, local, remote) in [
        ("first", &first_local, "/first"),
        ("second", &second_local, "/second"),
    ] {
        let added = run(
            &config,
            &[
                "pair",
                "add",
                "--id",
                id,
                "--local",
                local.to_str().unwrap(),
                "--space-id",
                "space-manual",
                "--remote",
                remote,
                "--mode",
                "two-way",
            ],
        );
        assert!(
            added.status.success(),
            "{}",
            String::from_utf8_lossy(&added.stderr)
        );
    }

    fs::remove_dir(&first_local).unwrap();
    fs::remove_dir(&second_local).unwrap();

    let show = run(&config, &["config", "show"]);
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    assert!(String::from_utf8_lossy(&show.stdout).contains("first"));
    assert!(String::from_utf8_lossy(&show.stdout).contains("second"));

    let remove_first = run(&config, &["pair", "remove", "--id", "first"]);
    assert!(
        remove_first.status.success(),
        "{}",
        String::from_utf8_lossy(&remove_first.stderr)
    );
    let status = run(&config, &["status"]);
    assert!(!status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains("Configured folder pairs: 1"));
    assert!(String::from_utf8_lossy(&status.stderr).contains("second-local"));

    let remove_second = run(&config, &["pair", "remove", "--id", "second"]);
    assert!(
        remove_second.status.success(),
        "{}",
        String::from_utf8_lossy(&remove_second.stderr)
    );
    let show = run(&config, &["config", "show"]);
    assert!(show.status.success());
    assert!(!String::from_utf8_lossy(&show.stdout).contains("second"));
}

#[test]
fn oversized_add_preserves_existing_config() {
    const MAX_CONFIG_BYTES: usize = 1024 * 1024;

    let temp = TempDir::new().unwrap();
    let config = config_path(&temp);
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    let cloud = temp.path().join("cloud");
    let existing_local = temp.path().join("existing-local");
    let new_local = temp.path().join("new-local");
    fs::create_dir(&cloud).unwrap();
    fs::create_dir(&existing_local).unwrap();
    fs::create_dir(&new_local).unwrap();

    let mut document = serde_json::json!({
        "schema_version": 1,
        "cloud_root": cloud,
        "pairs": [{
            "id": "",
            "local_path": existing_local,
            "space_id": "space-manual",
            "remote_path": "/existing",
            "mode": "two_way"
        }]
    });
    let base_size = serde_json::to_vec_pretty(&document).unwrap().len();
    let id_len = MAX_CONFIG_BYTES - base_size - 20;
    document["pairs"][0]["id"] = serde_json::Value::String("x".repeat(id_len));
    let mut original = serde_json::to_vec_pretty(&document).unwrap();
    original.push(b'\n');
    assert!(original.len() < MAX_CONFIG_BYTES);
    fs::write(&config, &original).unwrap();

    let add = run(
        &config,
        &[
            "pair",
            "add",
            "--id",
            "new",
            "--local",
            new_local.to_str().unwrap(),
            "--space-id",
            "space-manual",
            "--remote",
            "/new",
            "--mode",
            "two-way",
        ],
    );
    assert!(!add.status.success());
    assert!(String::from_utf8_lossy(&add.stderr).contains("1 MiB limit"));
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn media_preview_reports_unsafe_paths_and_existing_or_source_collisions() {
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("media-preview.json");
    let request = serde_json::json!({
        "options": {
            "destination_root": "/Personal/Photos",
            "filter": "all",
            "organization": "utc_year_month"
        },
        "sources": [
            {"relative_path": "../escape.jpg", "kind": "photo", "utc_date": {"year": 2026, "month": 7}},
            {"relative_path": "camera-a/IMG.jpg", "kind": "photo", "utc_date": {"year": 2026, "month": 7}},
            {"relative_path": "camera-b/img.JPG", "kind": "photo", "utc_date": {"year": 2026, "month": 7}},
            {"relative_path": "already-there.png", "kind": "photo", "utc_date": {"year": 2026, "month": 7}}
        ],
        "existing_destinations": ["/Personal/Photos/2026/07/already-there.png"]
    });
    let original = serde_json::to_vec_pretty(&request).unwrap();
    fs::write(&input, &original).unwrap();

    let output = run_media_preview(&input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(preview.as_array().unwrap().len(), 4);
    let unsafe_item = preview
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["source_relative_path"] == "../escape.jpg")
        .unwrap();
    assert_eq!(
        unsafe_item["outcome"]["rejected"]["reason"],
        "unsafe_relative_path"
    );
    let same_dest = preview
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["source_relative_path"] == "camera-a/IMG.jpg")
        .unwrap();
    assert_eq!(
        same_dest["outcome"]["collision"]["source_path_conflict"],
        true
    );
    assert_eq!(same_dest["outcome"]["collision"]["matching_sources"], 2);
    let existing = preview
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["source_relative_path"] == "already-there.png")
        .unwrap();
    assert_eq!(
        existing["outcome"]["collision"]["existing_path_conflict"],
        true
    );
    assert_eq!(
        fs::read(input).unwrap(),
        original,
        "preview must not alter input"
    );
}

#[test]
fn media_preview_rejects_oversized_and_untyped_requests_without_output() {
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("media-preview.json");
    fs::write(&input, vec![b' '; 1024 * 1024 + 1]).unwrap();
    let oversized = run_media_preview(&input);
    assert!(!oversized.status.success());
    assert!(String::from_utf8_lossy(&oversized.stderr).contains("1 MiB limit"));
    assert!(oversized.stdout.is_empty());

    fs::write(
        &input,
        br#"{"options":{"destination_root":"/Personal/Photos","filter":"all","organization":"preserve_relative_path"},"sources":[],"existing_destinations":[],"extra":true}"#,
    )
    .unwrap();
    let untyped = run_media_preview(&input);
    assert!(!untyped.status.success());
    assert!(String::from_utf8_lossy(&untyped.stderr).contains("unknown field"));
    assert!(untyped.stdout.is_empty());
}
