//! Synthetic inventory benchmark for the engine's directory scan and staged
//! reconciliation path. It uses empty files and a generated remote tree, so
//! it does not hold a million-entry cloud listing in memory or contact a
//! production server.
//!
//! Usage: `cargo run --release -p raiun-engine --example inventory_scale -- [file-count]`
//! The default is 10,000 files. Pass a count explicitly for a larger run.
//! All local, engine-state, and generated data lives in a temporary directory.

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use raiun_core::backend::{
    CloudBackend, CloudError, CloudSpace, ErrorKind, RemoteEntry, WriteCondition,
};
use raiun_core::{FolderPair, SyncMode};
use raiun_engine::Engine;
use rusqlite::{Connection, params};
use tempfile::TempDir;

const SPACE: &str = "synthetic";
const REMOTE_ROOT: &str = "/inventory";
const FILES_PER_DIRECTORY: usize = 128;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct GeneratedRemote {
    file_count: usize,
    directory_count: usize,
}

impl GeneratedRemote {
    fn file_name(index: usize) -> String {
        format!("file-{index:06}.dat")
    }

    fn directory_name(index: usize) -> String {
        format!("dir-{index:06}")
    }

    fn entry(path: &str, directory: bool) -> RemoteEntry {
        RemoteEntry {
            id: path.to_owned(),
            path: path.to_owned(),
            directory,
            size: 0,
            etag: if directory { "dir-v1" } else { "empty-v1" }.to_owned(),
            modified_unix: 1,
            writable: true,
            encrypted: false,
        }
    }
}

impl CloudBackend for GeneratedRemote {
    fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
        Ok(vec![CloudSpace {
            id: SPACE.into(),
            name: "Synthetic inventory".into(),
            dav_url: "https://synthetic.invalid/dav".into(),
            personal: false,
            writable: true,
            encrypted: false,
        }])
    }

    fn list(
        &self,
        space: &str,
        path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        if space != SPACE {
            return Err(not_found("synthetic Space not found"));
        }
        if path == REMOTE_ROOT {
            for index in 0..self.directory_count {
                visit(GeneratedRemote::entry(
                    &format!("{REMOTE_ROOT}/{}", Self::directory_name(index)),
                    true,
                ))?;
            }
            return Ok(());
        }
        let Some(dir_name) = path.strip_prefix(&format!("{REMOTE_ROOT}/")) else {
            return Err(not_found("synthetic directory not found"));
        };
        if dir_name.contains('/') || !dir_name.starts_with("dir-") {
            return Err(not_found("synthetic directory not found"));
        }
        let Ok(directory) = dir_name[4..].parse::<usize>() else {
            return Err(not_found("synthetic directory not found"));
        };
        if directory >= self.directory_count {
            return Err(not_found("synthetic directory not found"));
        }
        let first = directory * FILES_PER_DIRECTORY;
        let end = (first + FILES_PER_DIRECTORY).min(self.file_count);
        for index in first..end {
            visit(GeneratedRemote::entry(
                &format!("{path}/{}", Self::file_name(index)),
                false,
            ))?;
        }
        Ok(())
    }

    fn stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        if space != SPACE {
            return Err(not_found("synthetic Space not found"));
        }
        if path == REMOTE_ROOT {
            return Ok(Self::entry(path, true));
        }
        let Some(tail) = path.strip_prefix(&format!("{REMOTE_ROOT}/")) else {
            return Err(not_found("synthetic item not found"));
        };
        let Some((directory_name, file_name)) = tail.split_once('/') else {
            let Ok(index) = directory_name_index(tail) else {
                return Err(not_found("synthetic item not found"));
            };
            return (index < self.directory_count)
                .then(|| Self::entry(path, true))
                .ok_or_else(|| not_found("synthetic item not found"));
        };
        if file_name.contains('/') {
            return Err(not_found("synthetic item not found"));
        }
        let Ok(directory) = directory_name_index(directory_name) else {
            return Err(not_found("synthetic item not found"));
        };
        let Some(index) = file_name_index(file_name) else {
            return Err(not_found("synthetic item not found"));
        };
        if directory < self.directory_count
            && index < self.file_count
            && index / FILES_PER_DIRECTORY == directory
        {
            Ok(Self::entry(path, false))
        } else {
            Err(not_found("synthetic item not found"))
        }
    }

    fn download(
        &self,
        space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<RemoteEntry, CloudError> {
        let entry = self.stat(space, path)?;
        if entry.directory || expected_etag.is_some_and(|etag| etag != entry.etag) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "synthetic revision mismatch",
            ));
        }
        fs::write(destination, []).map_err(|error| {
            CloudError::new(
                ErrorKind::Io,
                format!("could not write synthetic file: {error}"),
            )
        })?;
        Ok(entry)
    }

    fn upload(
        &self,
        _space: &str,
        _path: &str,
        _source: &Path,
        _condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        Err(unsupported())
    }

    fn mkdir(&self, _space: &str, _path: &str) -> Result<RemoteEntry, CloudError> {
        Err(unsupported())
    }

    fn delete(&self, _space: &str, _path: &str, _expected_etag: &str) -> Result<(), CloudError> {
        Err(unsupported())
    }

    fn rename(
        &self,
        _space: &str,
        _from: &str,
        _to: &str,
        _expected_etag: &str,
    ) -> Result<RemoteEntry, CloudError> {
        Err(unsupported())
    }
}

fn directory_name_index(name: &str) -> Result<usize, ()> {
    name.strip_prefix("dir-").ok_or(())?.parse().map_err(|_| ())
}

fn file_name_index(name: &str) -> Option<usize> {
    name.strip_prefix("file-")?
        .strip_suffix(".dat")?
        .parse()
        .ok()
}

fn not_found(message: &str) -> CloudError {
    CloudError::new(ErrorKind::NotFound, message)
}

fn unsupported() -> CloudError {
    CloudError::new(
        ErrorKind::Unsupported,
        "benchmark backend does not mutate files",
    )
}

fn create_local_inventory(
    root: &Path,
    count: usize,
    dirs: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    for directory in 0..dirs {
        let dir = root.join(GeneratedRemote::directory_name(directory));
        fs::create_dir(&dir)?;
        let first = directory * FILES_PER_DIRECTORY;
        let end = (first + FILES_PER_DIRECTORY).min(count);
        for index in first..end {
            FilePlaceholder::create(dir.join(GeneratedRemote::file_name(index)))?;
        }
        if end % 100_000 == 0 || end == count {
            eprintln!("fixture_local_files={end}/{count}");
        }
    }
    Ok(())
}

// Keep the generated payload genuinely empty while still creating a disk-backed
// directory tree that exercises the engine's normal local scanner.
struct FilePlaceholder;

impl FilePlaceholder {
    fn create(path: PathBuf) -> std::io::Result<()> {
        fs::File::create(path).map(drop)
    }
}

fn seed_baselines(
    state_dir: &Path,
    local_root: &Path,
    count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut db = Connection::open(state_dir.join("engine.sqlite3"))?;
    let tx = db.transaction()?;
    {
        let mut insert = tx.prepare("INSERT INTO baselines(pair_id,rel_path,local_hash,local_size,local_mtime,remote_etag,remote_hash,remote_size) VALUES(?1,?2,?3,0,?4,'empty-v1',?3,0)")?;
        for index in 0..count {
            let rel = format!(
                "{}/{}",
                GeneratedRemote::directory_name(index / FILES_PER_DIRECTORY),
                GeneratedRemote::file_name(index)
            );
            let metadata = fs::metadata(local_root.join(&rel))?;
            let modified = metadata
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as i64;
            insert.execute(params!["inventory-scale", rel, EMPTY_SHA256, modified])?;
            if (index + 1) % 100_000 == 0 || index + 1 == count {
                eprintln!("fixture_baselines={}/{count}", index + 1);
            }
        }
    }
    tx.commit()?;
    Ok(())
}

fn parse_count() -> Result<usize, String> {
    let mut args = env::args().skip(1);
    let value = args.next().unwrap_or_else(|| "10000".to_owned());
    if args.next().is_some() {
        return Err("usage: inventory_scale [file-count]".into());
    }
    let count: usize = value
        .parse()
        .map_err(|_| "file-count must be a positive integer")?;
    if count == 0 || count > 1_000_000 {
        return Err("file-count must be between 1 and 1,000,000".into());
    }
    Ok(count)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let count = parse_count().map_err(std::io::Error::other)?;
    let started = Instant::now();
    let directory_count = count.div_ceil(FILES_PER_DIRECTORY);
    eprintln!("fixture_start files={count} directories={directory_count}");
    let temp = TempDir::new()?;
    let local_root = temp.path().join("local");
    let state_dir = temp.path().join("engine-state");
    fs::create_dir(&local_root)?;
    fs::create_dir(&state_dir)?;
    create_local_inventory(&local_root, count, directory_count)?;
    eprintln!("fixture_generated_ms={}", started.elapsed().as_millis());
    let backend = Arc::new(GeneratedRemote {
        file_count: count,
        directory_count,
    });
    let engine = Engine::open(&state_dir, backend)?;
    seed_baselines(&state_dir, &local_root, count)?;
    eprintln!("baseline_seeded_ms={}", started.elapsed().as_millis());
    let pair = FolderPair {
        id: "inventory-scale".into(),
        local_path: local_root,
        space_id: SPACE.into(),
        vault: None,
        remote_path: REMOTE_ROOT.into(),
        mode: SyncMode::TwoWay,
        excluded_paths: Vec::new(),
    };
    let start = Instant::now();
    let report = engine.sync_pair(&pair)?;
    let elapsed = start.elapsed();
    eprintln!("sync_finished_ms={}", started.elapsed().as_millis());
    println!(
        "files={count} directories={directory_count} inventory_entries={} elapsed_ms={} unchanged={} uploaded={} downloaded={} conflicts={} needs_attention={}",
        count + directory_count,
        elapsed.as_millis(),
        report.unchanged,
        report.uploaded,
        report.downloaded,
        report.conflicts,
        report.needs_attention,
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("inventory_scale: {error}");
        std::process::exit(1);
    }
}
