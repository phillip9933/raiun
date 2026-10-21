use std::{fs, io::Write, path::PathBuf};

fn entry_path() -> Result<PathBuf, String> {
    let base = if let Some(value) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(value)
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or("HOME is unset")?).join(".config")
    };
    if !base.is_absolute() {
        return Err("Config directory must be absolute".into());
    }
    Ok(base.join("autostart").join("raiun-desktop.desktop"))
}

fn desktop_entry(shell: &std::path::Path) -> Result<String, String> {
    let path = shell.to_str().ok_or("Executable path is not UTF-8")?;
    if path.chars().any(char::is_control) {
        return Err("Executable path contains control characters".into());
    }
    // Desktop Entry Exec quoting, including literal percent expansion escaping.
    let quoted = path
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
        .replace('%', "%%");
    Ok(format!(
        "[Desktop Entry]\nType=Application\nName=Raiun Desktop\nExec=\"{quoted}\" --background\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
    ))
}

fn startup_executable(
    agent: &std::path::Path,
    appdir: Option<&std::ffi::OsStr>,
    appimage: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, String> {
    if let (Some(directory), Some(image)) = (appdir, appimage) {
        let directory = std::path::Path::new(directory);
        // Only use AppImage metadata when this agent actually runs inside its AppDir.
        if directory.is_absolute() && directory.parent().is_some() && agent.starts_with(directory) {
            let image = PathBuf::from(image);
            if !image.is_absolute() {
                return Err("AppImage path must be absolute before enabling autostart".into());
            }
            return Ok(image);
        }
    }
    Ok(agent
        .parent()
        .ok_or("Invalid executable path")?
        .join("raiun-desktop"))
}

pub fn is_enabled() -> bool {
    entry_path()
        .and_then(|path| {
            fs::symlink_metadata(path)
                .map(|metadata| metadata.file_type().is_file())
                .map_err(|error| error.to_string())
        })
        .unwrap_or(false)
}

pub fn configure(enabled: bool) -> Result<(), String> {
    let base = if let Some(value) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(value)
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or("HOME is unset")?).join(".config")
    };
    if !base.is_absolute() {
        return Err("Config directory must be absolute".into());
    }
    let directory = base.join("autostart");
    let entry = directory.join("raiun-desktop.desktop");
    if !enabled {
        match fs::remove_file(entry) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.to_string()),
        }
    }
    let shell = startup_executable(
        &std::env::current_exe().map_err(|e| e.to_string())?,
        std::env::var_os("APPDIR").as_deref(),
        std::env::var_os("APPIMAGE").as_deref(),
    )?;
    if !shell.is_file() {
        return Err(
            "Raiun startup executable is unavailable; keep Raiun at a permanent path before enabling start at login".into(),
        );
    }
    let contents = desktop_entry(&shell)?;
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(&directory).map_err(|e| e.to_string())?;
    file.write_all(contents.as_bytes())
        .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(entry).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{desktop_entry, startup_executable};
    use std::path::Path;

    #[test]
    fn generated_desktop_entry_starts_shell_in_background_mode() {
        let entry = desktop_entry(Path::new("/opt/Raiun Desktop/raiun-desktop"))
            .expect("valid desktop entry");

        assert!(entry.contains("Exec=\"/opt/Raiun Desktop/raiun-desktop\" --background\n"));
    }

    #[test]
    fn generated_desktop_entry_escapes_exec_path_characters() {
        let entry = desktop_entry(Path::new("/opt/raiun$home%bin/raiun-desktop"))
            .expect("valid desktop entry");

        assert!(entry.contains("Exec=\"/opt/raiun\\$home%%bin/raiun-desktop\" --background\n"));
    }

    #[test]
    fn generated_desktop_entry_rejects_control_characters() {
        let error = desktop_entry(Path::new("/opt/raiun\ndesktop"))
            .expect_err("control characters must not enter the desktop entry");

        assert!(error.contains("control characters"));
    }

    #[test]
    fn appimage_startup_uses_persistent_image_not_temporary_mount() {
        let shell = startup_executable(
            Path::new("/tmp/.mount_Raiun/usr/bin/raiun-agent"),
            Some(std::ffi::OsStr::new("/tmp/.mount_Raiun")),
            Some(std::ffi::OsStr::new("/home/demo/Applications/Raiun.AppImage")),
        )
        .expect("absolute AppImage path");
        assert_eq!(shell, Path::new("/home/demo/Applications/Raiun.AppImage"));
    }

    #[test]
    fn ordinary_install_ignores_unrelated_appimage_environment() {
        let shell = startup_executable(
            Path::new("/opt/raiun/raiun-agent"),
            Some(std::ffi::OsStr::new("/tmp/.mount_Other")),
            Some(std::ffi::OsStr::new("/home/demo/Other.AppImage")),
        )
        .expect("ordinary sibling shell");
        assert_eq!(shell, Path::new("/opt/raiun/raiun-desktop"));
    }

    #[test]
    fn appimage_startup_rejects_relative_image_path() {
        assert!(startup_executable(
            Path::new("/tmp/.mount_Raiun/usr/bin/raiun-agent"),
            Some(std::ffi::OsStr::new("/tmp/.mount_Raiun")),
            Some(std::ffi::OsStr::new("Raiun.AppImage")),
        )
        .is_err());
    }

}
