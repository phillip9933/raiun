use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use raiun_core::media_plan::{
    MediaFilter, MediaOrganization, MediaPlanItem, MediaPlanOptions, MediaSource, plan_media_import,
};
use raiun_core::media_scan::{MediaScanOptions, MediaScanReport, scan_media_folder};
use raiun_core::{
    CONFIG_SCHEMA_VERSION, Config, FolderPair, SyncMode, validate_config, validate_pair,
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_MEDIA_PREVIEW_INPUT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "raiun",
    version,
    about = "Configure Raiun desktop synchronization"
)]
struct Cli {
    /// Configuration file path. Defaults to the platform configuration directory.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Pair {
        #[command(subcommand)]
        command: PairCommand,
    },
    /// Report configuration and engine availability.
    Status,
    /// Print a redacted, local-only diagnostic summary.
    Diagnostics {
        /// Write the redacted JSON report to a new file instead of stdout.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Preview deterministic media destinations from an already-classified JSON manifest.
    MediaPreview {
        /// JSON request file. This command does not scan files or contact a server.
        #[arg(long, value_name = "JSON")]
        input: PathBuf,
    },
    /// Read-only scan of one selected folder; prints a planner manifest and preview.
    /// Extract the `manifest` object to use it with `media-preview --input`.
    MediaScan {
        /// Absolute source folder to inspect. The scanner never writes to it.
        #[arg(long, value_name = "PATH")]
        source: PathBuf,
        /// Remote destination root, such as /Personal/Photos.
        #[arg(long, value_name = "REMOTE_PATH")]
        destination_root: String,
        /// Which classified source types to include in the preview.
        #[arg(long, value_enum)]
        filter: ScanFilterArg,
        /// Destination layout. Defaults to preserving relative source folders.
        #[arg(long, value_enum, default_value_t = ScanOrganizationArg::PreserveRelativePath)]
        organization: ScanOrganizationArg,
        /// Include filesystem modification time interpreted as a UTC month.
        #[arg(long)]
        filesystem_mtime_utc: bool,
    },
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct MediaPreviewRequest {
    options: MediaPlanOptions,
    sources: Vec<MediaSource>,
    existing_destinations: Vec<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ScanFilterArg {
    Photos,
    Videos,
    All,
}

impl From<ScanFilterArg> for MediaFilter {
    fn from(value: ScanFilterArg) -> Self {
        match value {
            ScanFilterArg::Photos => Self::Photos,
            ScanFilterArg::Videos => Self::Videos,
            ScanFilterArg::All => Self::All,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ScanOrganizationArg {
    PreserveRelativePath,
    UtcYearMonth,
}

impl From<ScanOrganizationArg> for MediaOrganization {
    fn from(value: ScanOrganizationArg) -> Self {
        match value {
            ScanOrganizationArg::PreserveRelativePath => Self::PreserveRelativePath,
            ScanOrganizationArg::UtcYearMonth => Self::UtcYearMonth,
        }
    }
}

#[derive(Debug, Serialize)]
struct DiagnosticsReport {
    schema_version: u32,
    app_version: &'static str,
    target_os: &'static str,
    target_arch: &'static str,
    config: ConfigDiagnostics,
}

#[derive(Debug, Serialize)]
struct ConfigDiagnostics {
    parse_valid: bool,
    folder_pair_count: Option<usize>,
    mode_counts: Option<SyncModeCounts>,
    vault_pair_count: Option<usize>,
}

#[derive(Debug, Default, Serialize)]
struct SyncModeCounts {
    two_way: usize,
    upload_only: usize,
    download_only: usize,
}

#[derive(Debug, serde::Serialize)]
struct MediaScanOutput {
    manifest: MediaPreviewRequest,
    scan: MediaScanReport,
    preview: Vec<MediaPlanItem>,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Create an initial configuration file.
    Init(InitArgs),
    /// Display the current configuration.
    Show,
    /// Check the configuration and configured folder pairs.
    Validate,
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long, value_name = "PATH")]
    cloud_root: PathBuf,
}

#[derive(Debug, Subcommand)]
enum PairCommand {
    /// Add a configured folder pair.
    Add(AddPairArgs),
    /// Remove a folder pair from configuration; local and cloud data are untouched.
    Remove(RemovePairArgs),
}

#[derive(Debug, Args)]
struct AddPairArgs {
    #[arg(long)]
    id: String,
    #[arg(long, value_name = "PATH")]
    local: PathBuf,
    #[arg(long)]
    space_id: String,
    #[arg(long)]
    remote: String,
    #[arg(long, value_enum)]
    mode: ModeArg,
}

#[derive(Debug, Args)]
struct RemovePairArgs {
    #[arg(long)]
    id: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeArg {
    TwoWay,
    UploadOnly,
    DownloadOnly,
}

impl From<ModeArg> for SyncMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::TwoWay => Self::TwoWay,
            ModeArg::UploadOnly => Self::UploadOnly,
            ModeArg::DownloadOnly => Self::DownloadOnly,
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let Cli { config, command } = cli;
    let command = match command {
        Command::MediaPreview { input } => return media_preview(&input),
        Command::MediaScan {
            source,
            destination_root,
            filter,
            organization,
            filesystem_mtime_utc,
        } => {
            return media_scan(
                &source,
                destination_root,
                filter,
                organization,
                filesystem_mtime_utc,
            );
        }
        command => command,
    };

    let config_path = match config {
        Some(path) => {
            if !path.is_absolute() {
                return Err("--config must be an absolute path".into());
            }
            path
        }
        None => default_config_path()?,
    };

    match command {
        Command::Config { command } => match command {
            ConfigCommand::Init(args) => init(&config_path, args.cloud_root),
            ConfigCommand::Show => {
                let config = read_config(&config_path)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&config).map_err(display)?
                );
                Ok(())
            }
            ConfigCommand::Validate => {
                let config = read_config(&config_path)?;
                ensure_valid(&config)?;
                println!("Configuration is valid.");
                println!("Space IDs are supplied manually; no remote spaces were discovered.");
                Ok(())
            }
        },
        Command::Pair { command } => match command {
            PairCommand::Add(args) => add_pair(
                &config_path,
                FolderPair {
                    id: args.id,
                    local_path: args.local,
                    space_id: args.space_id,
                    vault: None,
                    remote_path: args.remote,
                    mode: args.mode.into(),
                    excluded_paths: Vec::new(),
                },
            ),
            PairCommand::Remove(args) => remove_pair(&config_path, args.id),
        },
        Command::Diagnostics { output } => diagnostics(&config_path, output.as_deref()),
        Command::Status => {
            let config = read_config(&config_path)?;
            let issues = validate_config(&config);
            println!(
                "Configuration: {} ({})",
                config_path.display(),
                if issues.is_empty() {
                    "valid"
                } else {
                    "invalid"
                }
            );
            println!("Configured folder pairs: {}", config.pairs.len());
            println!("Sync engine: unavailable (configuration foundation only)");
            println!("Mounting and transfers: not available");
            if !issues.is_empty() {
                return Err(format!(
                    "configuration is invalid:\n- {}",
                    issues.join("\n- ")
                ));
            }
            Ok(())
        }
        Command::MediaPreview { .. } | Command::MediaScan { .. } => {
            unreachable!("handled before configuration lookup")
        }
    }
}

fn media_preview(path: &Path) -> Result<(), String> {
    let mut file = File::open(path).map_err(|error| {
        format!(
            "cannot open media preview input {}: {error}",
            path.display()
        )
    })?;
    let mut bytes = Vec::new();
    Read::take(&mut file, MAX_MEDIA_PREVIEW_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!(
                "cannot read media preview input {}: {error}",
                path.display()
            )
        })?;
    if bytes.len() as u64 > MAX_MEDIA_PREVIEW_INPUT_BYTES {
        return Err("media preview input exceeds the 1 MiB limit".into());
    }
    let request: MediaPreviewRequest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid media preview JSON: {error}"))?;
    let preview = plan_media_import(
        &request.sources,
        &request.options,
        &request.existing_destinations,
    )
    .map_err(display)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&preview).map_err(display)?
    );
    Ok(())
}

fn diagnostics(config_path: &Path, destination: Option<&Path>) -> Result<(), String> {
    let config = match read_config(config_path) {
        Ok(config) => {
            let mut mode_counts = SyncModeCounts::default();
            for pair in &config.pairs {
                match pair.mode {
                    SyncMode::TwoWay => mode_counts.two_way += 1,
                    SyncMode::UploadOnly => mode_counts.upload_only += 1,
                    SyncMode::DownloadOnly => mode_counts.download_only += 1,
                }
            }
            ConfigDiagnostics {
                parse_valid: true,
                folder_pair_count: Some(config.pairs.len()),
                mode_counts: Some(mode_counts),
                vault_pair_count: Some(
                    config
                        .pairs
                        .iter()
                        .filter(|pair| pair.vault.is_some())
                        .count(),
                ),
            }
        }
        Err(_) => ConfigDiagnostics {
            parse_valid: false,
            folder_pair_count: None,
            mode_counts: None,
            vault_pair_count: None,
        },
    };
    let report = DiagnosticsReport {
        schema_version: 1,
        app_version: env!("CARGO_PKG_VERSION"),
        target_os: env::consts::OS,
        target_arch: env::consts::ARCH,
        config,
    };
    let output = serde_json::to_string_pretty(&report)
        .map_err(|_| "could not encode redacted diagnostics".to_string())?;
    if let Some(destination) = destination {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(destination).map_err(|_| {
            "could not create diagnostics file (choose a new local file path)".to_string()
        })?;
        file.write_all(output.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|_| "could not write diagnostics file".to_string())?;
        println!("Diagnostics saved to the selected file.");
    } else {
        println!("{output}");
    }
    Ok(())
}

fn media_scan(
    source_root: &Path,
    destination_root: String,
    filter: ScanFilterArg,
    organization: ScanOrganizationArg,
    filesystem_mtime_utc: bool,
) -> Result<(), String> {
    let scan = scan_media_folder(
        source_root,
        MediaScanOptions {
            filesystem_mtime_utc,
        },
    )
    .map_err(display)?;
    let manifest = MediaPreviewRequest {
        options: MediaPlanOptions {
            destination_root,
            filter: filter.into(),
            organization: organization.into(),
        },
        sources: scan.sources.clone(),
        existing_destinations: Vec::new(),
    };
    let preview = plan_media_import(
        &manifest.sources,
        &manifest.options,
        &manifest.existing_destinations,
    )
    .map_err(display)?;
    let incomplete = !scan.complete || scan.truncated;
    let output = MediaScanOutput {
        manifest,
        scan,
        preview,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(display)?
    );
    if incomplete {
        return Err(
            "media scan is incomplete; review the scan warnings before using its manifest".into(),
        );
    }
    Ok(())
}

fn default_config_path() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    {
        let root = env::var_os("APPDATA")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| "APPDATA must be set to an absolute path".to_string())?;
        Ok(root.join("RaiunDesktop").join("config.json"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| "HOME must be set to an absolute path".to_string())?;
        Ok(home.join("Library/Application Support/RaiunDesktop/config.json"))
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
            let path = PathBuf::from(xdg);
            if !path.is_absolute() {
                return Err("XDG_CONFIG_HOME must be an absolute path".into());
            }
            return Ok(path.join("raiun-desktop/config.json"));
        }
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| "HOME must be set to an absolute path".to_string())?;
        Ok(home.join(".config/raiun-desktop/config.json"))
    }
}

fn init(path: &Path, cloud_root: PathBuf) -> Result<(), String> {
    prepare_parent(path)?;
    let _lock = ConfigLock::acquire(path)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(format!(
            "configuration already exists at {}; it was not changed",
            path.display()
        ));
    }
    let config = Config {
        schema_version: CONFIG_SCHEMA_VERSION,
        cloud_root,
        pairs: Vec::new(),
    };
    ensure_valid(&config)?;
    write_config(path, &config, true)
}

fn add_pair(path: &Path, pair: FolderPair) -> Result<(), String> {
    let _lock = ConfigLock::acquire(path)?;
    let mut config = read_config(path)?;
    ensure_valid(&config)?;
    let issues = validate_pair(&pair, &config.pairs, &config.cloud_root);
    if !issues.is_empty() {
        return Err(format!(
            "folder pair is invalid:\n- {}",
            issues.join("\n- ")
        ));
    }
    config.pairs.push(pair);
    ensure_valid(&config)?;
    write_config(path, &config, false)
}

fn remove_pair(path: &Path, id: String) -> Result<(), String> {
    let _lock = ConfigLock::acquire(path)?;
    let mut config = read_config(path)?;
    let original_len = config.pairs.len();
    config.pairs.retain(|pair| pair.id != id);
    if config.pairs.len() == original_len {
        return Err(format!("no configured folder pair has id '{id}'"));
    }
    write_config(path, &config, false)?;
    println!("Removed configuration for pair '{id}'. Local and cloud data were not touched.");
    Ok(())
}

fn read_config(path: &Path) -> Result<Config, String> {
    reject_symlink_file(path)?;
    let mut file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(format!(
            "configuration exceeds the 1 MiB limit: {}",
            path.display()
        ));
    }
    let config: Config = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid configuration {}: {error}", path.display()))?;
    if config.schema_version != CONFIG_SCHEMA_VERSION {
        return Err(format!(
            "unsupported configuration schema version {} (this build supports {})",
            config.schema_version, CONFIG_SCHEMA_VERSION
        ));
    }
    Ok(config)
}

fn ensure_valid(config: &Config) -> Result<(), String> {
    let issues = validate_config(config);
    if issues.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "configuration is invalid:\n- {}",
            issues.join("\n- ")
        ))
    }
}

fn write_config(path: &Path, config: &Config, create_only: bool) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(config).map_err(display)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("configuration exceeds the 1 MiB limit; existing file was not changed".into());
    }
    prepare_parent(path)?;
    reject_symlink_file(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| "configuration path has no parent".to_string())?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| format!("cannot create temporary configuration: {error}"))?;
    set_private_file_permissions(temporary.as_file()).map_err(display)?;
    temporary.write_all(&bytes).map_err(display)?;
    temporary.as_file().sync_all().map_err(display)?;
    reject_symlink_file(path)?;
    if create_only {
        temporary.persist_noclobber(path).map_err(|error| {
            format!(
                "cannot create {} without replacing an existing file: {}",
                path.display(),
                error.error
            )
        })?;
    } else {
        temporary.persist(path).map_err(|error| {
            format!(
                "cannot atomically replace {}: {}",
                path.display(),
                error.error
            )
        })?;
    }
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn prepare_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "configuration path has no parent".to_string())?;
    let mut missing = Vec::new();
    let mut cursor = parent;
    while !cursor.exists() {
        missing.push(cursor.to_path_buf());
        cursor = cursor
            .parent()
            .ok_or_else(|| "cannot find an existing parent directory".to_string())?;
    }
    for directory in missing.into_iter().rev() {
        match fs::create_dir(&directory) {
            Ok(()) => set_private_dir_permissions(&directory).map_err(display)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create configuration directory {}: {error}",
                    directory.display()
                ));
            }
        }
    }
    Ok(())
}

fn reject_symlink_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "refusing to read or write symlink configuration file {}",
            path.display()
        )),
        Ok(metadata) if !metadata.is_file() => Err(format!(
            "configuration path is not a regular file: {}",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect {}: {error}", path.display())),
    }
}

struct ConfigLock {
    path: PathBuf,
    _file: File,
}

impl ConfigLock {
    fn acquire(config_path: &Path) -> Result<Self, String> {
        let lock_path = config_path.with_extension("json.lock");
        if let Some(parent) = lock_path.parent() {
            if !parent.exists() {
                // Init creates the directory while it holds the lock; the lock lives beside it.
                if config_path.exists() {
                    return Err(format!(
                        "configuration directory is missing: {}",
                        parent.display()
                    ));
                }
            }
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&lock_path).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                format!("configuration is locked at {}; if no Raiun command is running, inspect and remove this stale lock manually", lock_path.display())
            } else {
                format!("cannot create configuration lock {}: {error}", lock_path.display())
            }
        })?;
        let _ = writeln!(file, "pid={}", std::process::id());
        Ok(Self {
            path: lock_path,
            _file: file,
        })
    }
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn set_private_file_permissions(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_file: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
