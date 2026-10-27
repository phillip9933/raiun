//! Explicit current-user startup opt-in. Reading status never writes registry.
use std::io;
#[cfg(windows)]
const VALUE: &str = "Raiun Desktop";
#[cfg(windows)]
const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const MAX_UNITS: usize = 32_768;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Raiun startup entry is unavailable or belongs to another command",
    )
}
fn expected_command(module: &str) -> io::Result<String> {
    let b = module.as_bytes();
    if b.len() < 4
        || !b[0].is_ascii_alphabetic()
        || b[1] != b':'
        || b[2] != b'\\'
        || module.contains('/')
        || module.contains('"')
        || module.chars().any(char::is_control)
        || module[3..]
            .split('\\')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.contains(':'))
    {
        return Err(invalid());
    }
    let (_, basename) = module.rsplit_once('\\').ok_or_else(invalid)?;
    if !basename.eq_ignore_ascii_case("raiun-desktop-shell.exe") {
        return Err(invalid());
    }
    let result = format!("\"{module}\"");
    if result.encode_utf16().count() >= MAX_UNITS {
        return Err(invalid());
    }
    Ok(result)
}
// HKCU Run command line limit includes quotes and is counted as UTF-16 units.
fn run_command_supported(command: &str) -> bool {
    command.encode_utf16().count() <= 260
}
#[derive(PartialEq, Eq)]
enum Change {
    None,
    Enable,
    Disable,
}
fn policy(current: Option<&str>, expected: &str, enabled: bool) -> io::Result<Change> {
    match current {
        Some(value) if value != expected => Err(invalid()),
        Some(_) => Ok(if enabled {
            Change::None
        } else {
            Change::Disable
        }),
        None => Ok(if enabled {
            Change::Enable
        } else {
            Change::None
        }),
    }
}
fn decode_reg_sz(kind: u32, data: &[u16], bytes: u32) -> io::Result<String> {
    let count = bytes as usize / 2;
    if kind != 1
        || bytes < 2
        || bytes % 2 != 0
        || count > data.len()
        || count > MAX_UNITS
        || data[count - 1] != 0
        || data[..count - 1].contains(&0)
    {
        return Err(invalid());
    }
    String::from_utf16(&data[..count - 1]).map_err(|_| invalid())
}
/// None means an unknown/foreign value; reading never mutates it.
#[cfg(windows)]
pub fn autostart_status(exe: &std::path::Path) -> io::Result<Option<bool>> {
    native::status_for(exe)
}
/// The caller supplies the trusted sibling desktop executable, never UI input.
#[cfg(windows)]
pub fn configure_autostart(exe: &std::path::Path, enabled: bool) -> io::Result<()> {
    native::configure(exe, enabled)
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod native {
    use super::*;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
        System::Registry::*,
    };
    struct OwnedKey(HKEY);
    impl Drop for OwnedKey {
        fn drop(&mut self) {
            // SAFETY: this wrapper owns one successfully opened/created key.
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    fn status(code: u32) -> io::Result<()> {
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }
    fn command(exe: &std::path::Path) -> io::Result<String> {
        expected_command(exe.to_str().ok_or_else(invalid)?)
    }
    fn open(write: bool, create: bool) -> io::Result<Option<OwnedKey>> {
        let path = wide(KEY);
        let mut key = null_mut();
        let access = KEY_QUERY_VALUE | if write { KEY_SET_VALUE } else { 0 };
        // SAFETY: fixed NUL-terminated subkey, valid output storage and HKCU;
        // no security descriptor, machine key or arbitrary path is accepted.
        let code = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, access, &mut key) };
        if code == ERROR_FILE_NOT_FOUND {
            if !create {
                return Ok(None);
            }
            let mut disposition = 0;
            // SAFETY: explicit enable only, fixed current-user Run key.
            status(unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    null(),
                    REG_OPTION_NON_VOLATILE,
                    access,
                    null(),
                    &mut key,
                    &mut disposition,
                )
            })?;
        } else {
            status(code)?;
        }
        if key.is_null() {
            return Err(invalid());
        }
        Ok(Some(OwnedKey(key)))
    }
    fn read(key: &OwnedKey) -> io::Result<Option<String>> {
        let name = wide(VALUE);
        let mut kind = 0;
        let mut data = vec![0u16; MAX_UNITS];
        let mut bytes = (data.len() * 2) as u32;
        // SAFETY: owned key, fixed name, bounded aligned output buffer whose
        // byte capacity is passed in/out exactly; pointers live for this call.
        let code = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        status(code)?;
        decode_reg_sz(kind, &data, bytes).map(Some)
    }
    pub(super) fn status_for(exe: &std::path::Path) -> io::Result<Option<bool>> {
        let expected = command(exe)?;
        if !run_command_supported(&expected) {
            return Ok(None);
        }
        let current = match open(false, false)? {
            Some(key) => match read(&key) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::InvalidData => return Ok(None),
                Err(error) => return Err(error),
            },
            None => None,
        };
        Ok(match current {
            None => Some(false),
            Some(value) if value == expected => Some(true),
            Some(_) => None,
        })
    }
    pub(super) fn configure(exe: &std::path::Path, enabled: bool) -> io::Result<()> {
        let expected = command(exe)?;
        if enabled && !run_command_supported(&expected) {
            return Err(invalid());
        }
        if enabled {
            use std::os::windows::fs::MetadataExt;
            let metadata = std::fs::symlink_metadata(exe)?;
            if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid());
            }
        }
        let Some(key) = open(true, enabled)? else {
            return Ok(());
        };
        let current = read(&key)?;
        let change = policy(current.as_deref(), &expected, enabled)?;
        // Re-read immediately before mutation; serialize explicit application
        // calls at the agent layer. Windows registry offers no value CAS against
        // unrelated same-user writers; this is not a cross-process transaction.
        if read(&key)? != current {
            return Err(invalid());
        }
        let name = wide(VALUE);
        match change {
            Change::None => {}
            Change::Enable => {
                let value = wide(&expected);
                // SAFETY: fixed owned key/name, REG_SZ, live terminated UTF16.
                status(unsafe {
                    RegSetValueExW(
                        key.0,
                        name.as_ptr(),
                        0,
                        REG_SZ,
                        value.as_ptr().cast(),
                        (value.len() * 2) as u32,
                    )
                })?;
            }
            Change::Disable => {
                // SAFETY: fixed name revalidated as our exact command above.
                status(unsafe { RegDeleteValueW(key.0, name.as_ptr()) })?;
            }
        }
        let after = read(&key)?;
        if after.as_deref()
            != if enabled {
                Some(expected.as_str())
            } else {
                None
            }
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_sibling_command_is_quoted_and_rejects_nonabsolute_or_ambiguous_modules() {
        assert_eq!(
            expected_command(r"C:\Program Files\Raiun\raiun-desktop-shell.exe").unwrap(),
            r#""C:\Program Files\Raiun\raiun-desktop-shell.exe""#
        );
        for bad in [
            r"raiun-desktop-shell.exe",
            r"C:\Raiun\other.exe",
            r"C:\Raiun\..\raiun-agent.exe",
            r"C:\Raiun\.\raiun-agent.exe",
            r"C:/Raiun/raiun-agent.exe",
            "C:\\bad\"\\agent.exe",
            "C:\\bad\n\\agent.exe",
        ] {
            assert!(expected_command(bad).is_err());
        }
    }
    #[test]
    fn explicit_memory_policy_is_idempotent_and_preserves_foreign_values() {
        let expected = expected_command(r"C:\Raiun\raiun-desktop-shell.exe").unwrap();
        let mut stored = None::<String>;
        for enabled in [true, true, false, false] {
            match policy(stored.as_deref(), &expected, enabled).unwrap() {
                Change::None => {}
                Change::Enable => stored = Some(expected.clone()),
                Change::Disable => stored = None,
            }
            assert_eq!(stored.is_some(), enabled);
        }
        stored = Some(r#""C:\Other\other.exe""#.into());
        let before = stored.clone();
        for enabled in [true, false] {
            assert!(policy(stored.as_deref(), &expected, enabled).is_err());
            assert_eq!(stored, before);
        }
    }
    #[test]
    fn registry_string_requires_exact_type_termination_and_utf16() {
        assert_eq!(decode_reg_sz(1, &[65, 0], 4).unwrap(), "A");
        for (kind, data, bytes) in [
            (2, vec![65, 0], 4),
            (1, vec![65, 0], 3),
            (1, vec![65], 2),
            (1, vec![65, 0, 66, 0], 8),
            (1, vec![0xd800, 0], 4),
            (1, vec![0], 4),
        ] {
            assert!(decode_reg_sz(kind, &data, bytes).is_err());
        }
    }
    #[test]
    fn run_limit_counts_quotes_and_utf16_but_owned_long_entry_can_be_disabled() {
        let fixed = expected_command(r"C:\x\raiun-desktop-shell.exe")
            .unwrap()
            .encode_utf16()
            .count()
            - 1;
        let path = |units: usize| {
            format!(
                "C:\\{}😀\\raiun-desktop-shell.exe",
                "a".repeat(units - fixed - 2)
            )
        };
        let exact = expected_command(&path(260)).unwrap();
        let long = expected_command(&path(261)).unwrap();
        assert_eq!(exact.encode_utf16().count(), 260);
        assert_eq!(long.encode_utf16().count(), 261);
        assert!(run_command_supported(&exact));
        assert!(!run_command_supported(&long));
        assert!(matches!(
            policy(Some(&long), &long, false).unwrap(),
            Change::Disable
        ));
        assert!(policy(Some("foreign"), &long, false).is_err());
    }
}
