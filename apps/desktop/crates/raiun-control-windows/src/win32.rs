use std::{
    ffi::c_void,
    io::{self, Read, Write},
    mem::zeroed,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
        ERROR_SEM_TIMEOUT, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_KERNEL_OBJECT,
        },
        GetTokenInformation, IsValidSid, OWNER_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, WaitNamedPipeW,
        },
        Threading::{
            CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        },
    },
};

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const PIPE_INSTANCE_COUNT: u32 = 1;
const MAX_WAIT: Duration = Duration::from_secs(300);
const MAX_IO_WAIT: Duration = Duration::from_secs(24 * 60 * 60 + 30);
const SDDL_REVISION_1: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_BROKEN_PIPE: u32 = 109;
const INFINITE: u32 = u32::MAX;

/// One private pipe instance. The server handle is consumed by `accept`.
pub struct NamedPipeListener {
    pipe: Option<OwnedHandle>,
    io_timeout: Duration,
}

/// A current-user named pipe implementing byte-stream `Read` and `Write`.
pub struct PipeStream {
    handle: OwnedHandle,
    // Client streams retain the authenticated process object, never just a PID.
    _server_process: Option<OwnedHandle>,
    io_timeout: Duration,
}

impl PipeStream {
    /// Set the bound for subsequent read/write operations on this connection.
    /// Values are clamped to one millisecond through 24 hours plus 30 seconds.
    /// Connection establishment retains its separate five-minute maximum.
    /// Callers can leave request writes at their ordinary bound and extend only
    /// the later response read for a separately bounded long-running operation.
    pub fn set_io_timeout(&mut self, timeout: Duration) {
        self.io_timeout = bounded_io_timeout(timeout);
    }
}

impl NamedPipeListener {
    /// Create a pipe instance with an explicit current-user-only DACL.
    pub fn bind(io_timeout: Duration) -> io::Result<Self> {
        let io_timeout = bounded_timeout(io_timeout);
        let pipe_name = current_user_pipe_path()?;
        let wide_name = wide(&pipe_name);
        let sid = current_user_sid()?;
        // Pin the owner to TokenUser too: an elevated token's default owner can
        // otherwise be Administrators, which cannot authenticate this endpoint.
        let sddl = wide(&format!("O:{sid}D:P(A;;GA;;;{sid})"));
        let mut descriptor = null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 || descriptor.is_null() {
            return Err(last_error());
        }
        let security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        // Always claim the first instance. If another same-user process has
        // squatted the stable endpoint, startup must fail closed every time.
        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
        let pipe = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_INSTANCE_COUNT,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                &security,
            )
        };
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(descriptor);
        }
        if pipe == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        Ok(Self {
            pipe: Some(unsafe { OwnedHandle::from_raw_handle(pipe as RawHandle) }),
            io_timeout,
        })
    }

    /// Wait at most `io_timeout` for a local client to connect.
    pub fn accept(mut self) -> io::Result<PipeStream> {
        let pipe = self
            .pipe
            .take()
            .ok_or_else(|| io::Error::other("Windows pipe instance was already accepted"))?;
        let event = create_event()?;
        let mut overlapped: OVERLAPPED = unsafe { zeroed() };
        overlapped.hEvent = event.as_raw_handle() as HANDLE;
        let connected =
            unsafe { ConnectNamedPipe(pipe.as_raw_handle() as HANDLE, &mut overlapped) };
        if connected == 0 {
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if error != ERROR_PIPE_CONNECTED {
                if error != ERROR_IO_PENDING {
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
                wait_operation(
                    pipe.as_raw_handle() as HANDLE,
                    &mut overlapped,
                    event.as_raw_handle() as HANDLE,
                    self.io_timeout,
                )?;
            }
        }
        Ok(PipeStream {
            handle: pipe,
            _server_process: None,
            io_timeout: self.io_timeout,
        })
    }
}

/// Connect to the named pipe for the current Windows user.
pub fn connect_current_user(timeout: Duration) -> io::Result<PipeStream> {
    let timeout = bounded_timeout(timeout);
    let path = current_user_pipe_path()?;
    let wide_path = wide(&path);
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Timed out waiting for Raiun's control pipe",
            ));
        }
        let waited = unsafe { WaitNamedPipeW(wide_path.as_ptr(), timeout_millis(remaining)) };
        if waited == 0 {
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if error == ERROR_FILE_NOT_FOUND
                || error == ERROR_PIPE_BUSY
                || error == ERROR_SEM_TIMEOUT
            {
                std::thread::sleep(remaining.min(Duration::from_millis(25)));
                continue;
            }
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let raw = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                0x8000_0000 | 0x4000_0000,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            let handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
            // No protocol bytes may leave this client until the connected
            // object's owner and its live server's TokenUser are authenticated.
            let server_process = authenticate_server(&handle).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Cannot authenticate Raiun's control pipe; restart Raiun's agent and retry",
                )
            })?;
            return Ok(PipeStream {
                handle,
                _server_process: Some(server_process),
                io_timeout: timeout,
            });
        }
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if error == ERROR_PIPE_BUSY || error == ERROR_FILE_NOT_FOUND {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        return Err(io::Error::from_raw_os_error(error as i32));
    }
}

fn authenticate_server(pipe: &OwnedHandle) -> io::Result<OwnedHandle> {
    let expected_sid = current_user_sid()?;
    // This check binds authentication to this exact connected pipe object. It
    // also closes the PID-reuse gap if the original server died before OpenProcess:
    // an unrelated user's pipe cannot acquire this user's owner SID without
    // privileges that already defeat the current-user security boundary.
    if pipe_owner_sid(pipe)? != expected_sid {
        return Err(io::Error::other("Unexpected control pipe owner"));
    }
    let pipe_handle = pipe.as_raw_handle() as HANDLE;
    let mut process_id = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe_handle, &mut process_id) } == 0 || process_id == 0
    {
        return Err(io::Error::other("Missing local control pipe server"));
    }
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            process_id,
        )
    };
    if process.is_null() {
        return Err(last_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process as RawHandle) };
    let process_handle = process.as_raw_handle() as HANDLE;
    if process_user_sid(process_handle)? != expected_sid {
        return Err(io::Error::other("Unexpected control pipe server identity"));
    }
    let mut confirmed_id = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe_handle, &mut confirmed_id) } == 0
        || confirmed_id != process_id
        || unsafe { WaitForSingleObject(process_handle, 0) } != WAIT_TIMEOUT
    {
        return Err(io::Error::other("Control pipe server is unavailable"));
    }
    // The fixed local pipe path never permits a caller-selected remote host.
    // Missing/inaccessible server-process metadata is rejected, not downgraded
    // to trusting a name, owner alone, or a PID from protocol input.
    Ok(process)
}

fn pipe_owner_sid(pipe: &OwnedHandle) -> io::Result<String> {
    let mut owner = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            pipe.as_raw_handle() as HANDLE,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    let sid = if result == 0 && !descriptor.is_null() {
        sid_string(owner)
    } else {
        Err(io::Error::other("Cannot query control pipe owner"))
    };
    if !descriptor.is_null() {
        unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor) };
    }
    sid
}

impl Read for PipeStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let event = create_event()?;
        let mut overlapped: OVERLAPPED = unsafe { zeroed() };
        overlapped.hEvent = event.as_raw_handle() as HANDLE;
        let amount = buffer.len().min(u32::MAX as usize) as u32;
        let mut transferred = 0_u32;
        let success = unsafe {
            ReadFile(
                self.handle.as_raw_handle() as HANDLE,
                buffer.as_mut_ptr(),
                amount,
                null_mut(),
                &mut overlapped,
            )
        };
        finish_io(
            self.handle.as_raw_handle() as HANDLE,
            &mut overlapped,
            event.as_raw_handle() as HANDLE,
            success,
            &mut transferred,
            self.io_timeout,
        )?;
        Ok(transferred as usize)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let event = create_event()?;
        let mut overlapped: OVERLAPPED = unsafe { zeroed() };
        overlapped.hEvent = event.as_raw_handle() as HANDLE;
        let amount = buffer.len().min(u32::MAX as usize) as u32;
        let mut transferred = 0_u32;
        let success = unsafe {
            WriteFile(
                self.handle.as_raw_handle() as HANDLE,
                buffer.as_ptr(),
                amount,
                null_mut(),
                &mut overlapped,
            )
        };
        finish_io(
            self.handle.as_raw_handle() as HANDLE,
            &mut overlapped,
            event.as_raw_handle() as HANDLE,
            success,
            &mut transferred,
            self.io_timeout,
        )?;
        Ok(transferred as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn finish_io(
    pipe: HANDLE,
    overlapped: &mut OVERLAPPED,
    event: HANDLE,
    started: i32,
    transferred: &mut u32,
    timeout: Duration,
) -> io::Result<()> {
    if started != 0 {
        let success = unsafe { GetOverlappedResult(pipe, overlapped, transferred, 0) };
        return if success != 0 {
            Ok(())
        } else {
            Err(last_error())
        };
    }
    let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    if error != ERROR_IO_PENDING {
        if error == ERROR_BROKEN_PIPE {
            *transferred = 0;
            return Ok(());
        }
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    wait_operation(pipe, overlapped, event, timeout)?;
    let success = unsafe { GetOverlappedResult(pipe, overlapped, transferred, 0) };
    if success == 0 {
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if error == ERROR_BROKEN_PIPE {
            *transferred = 0;
            return Ok(());
        }
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    Ok(())
}

fn wait_operation(
    pipe: HANDLE,
    overlapped: &mut OVERLAPPED,
    event: HANDLE,
    timeout: Duration,
) -> io::Result<()> {
    match unsafe { WaitForSingleObject(event, bounded_io_timeout(timeout).as_millis() as u32) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => {
            unsafe {
                CancelIoEx(pipe, overlapped);
                // Drain cancellation before the OVERLAPPED/event storage drops.
                WaitForSingleObject(event, INFINITE);
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Named pipe I/O timed out",
            ))
        }
        _ => {
            let error = last_error();
            unsafe {
                CancelIoEx(pipe, overlapped);
                // A failed wait must not let the kernel retain a pointer to
                // stack-owned OVERLAPPED storage.
                WaitForSingleObject(event, INFINITE);
            }
            Err(error)
        }
    }
}

fn create_event() -> io::Result<OwnedHandle> {
    let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
    if handle.is_null() {
        return Err(last_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

fn current_user_pipe_path() -> io::Result<String> {
    let sid = current_user_sid()?;
    let path = match super::headless_context()? {
        Some(context) => super::headless_pipe_path_for_sid(&sid, context.scope_id()),
        None => super::pipe_path_for_sid(&sid),
    };
    path.ok_or_else(|| io::Error::other("Windows returned an invalid user SID or scope"))
}

fn current_user_sid() -> io::Result<String> {
    process_user_sid(unsafe { GetCurrentProcess() })
}

fn process_user_sid(process: HANDLE) -> io::Result<String> {
    let mut token = null_mut();
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if opened == 0 || token.is_null() {
        return Err(last_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    let mut needed = 0_u32;
    let first = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            null_mut(),
            0,
            &mut needed,
        )
    };
    if first != 0
        || unsafe { windows_sys::Win32::Foundation::GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || needed == 0
    {
        return Err(last_error());
    }
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let queried = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            storage.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    };
    if queried == 0 {
        return Err(last_error());
    }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

fn sid_string(sid: PSID) -> io::Result<String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::other("Windows returned an invalid user SID"));
    }
    let mut sid_string = null_mut();
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut sid_string) };
    if converted == 0 || sid_string.is_null() {
        return Err(last_error());
    }
    let mut length = 0;
    unsafe {
        while *sid_string.add(length) != 0 {
            length += 1;
        }
    }
    let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_string, length) });
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(sid_string.cast());
    }
    Ok(sid)
}

pub(super) fn current_user_sid_for_storage() -> io::Result<String> {
    current_user_sid()
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn bounded_timeout(timeout: Duration) -> Duration {
    timeout.clamp(Duration::from_millis(1), MAX_WAIT)
}

fn bounded_io_timeout(timeout: Duration) -> Duration {
    timeout.clamp(Duration::from_millis(1), MAX_IO_WAIT)
}

fn timeout_millis(timeout: Duration) -> u32 {
    bounded_timeout(timeout).as_millis() as u32
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_control::{read_json_value, write_json_line};
    use serde_json::{Value, json};
    use std::{sync::Mutex, thread};

    static WINDOWS_PIPE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn current_user_pipe_roundtrips_shared_json_protocol() {
        let _guard = WINDOWS_PIPE_TEST_LOCK.lock().expect("test pipe lock");
        let server = NamedPipeListener::bind(Duration::from_secs(3)).expect("bind pipe");
        let worker = thread::spawn(move || {
            let mut connection = server.accept().expect("accept local client");
            let request: Value = read_json_value(&mut connection).expect("read request");
            assert_eq!(request["action"], "status");
            write_json_line(
                &mut connection,
                &json!({"ok": true, "data": {"ready": true}}),
            )
            .expect("send response");
        });

        let mut client = connect_current_user(Duration::from_secs(3)).expect("connect pipe");
        write_json_line(&mut client, &json!({"action": "status"})).expect("write request");
        let response: Value = read_json_value(&mut client).expect("read response");
        assert_eq!(response.pointer("/data/ready"), Some(&Value::Bool(true)));
        worker.join().expect("server worker");
    }

    #[test]
    fn current_user_pipe_preserves_a_maximum_supported_session_field() {
        let _guard = WINDOWS_PIPE_TEST_LOCK.lock().expect("test pipe lock");
        let server = NamedPipeListener::bind(Duration::from_secs(3)).expect("bind pipe");
        let worker = thread::spawn(move || {
            let mut connection = server.accept().expect("accept local client");
            let request: Value = read_json_value(&mut connection).expect("read request");
            assert_eq!(request["session"].as_str().unwrap().len(), 65_536);
            write_json_line(&mut connection, &json!({"ok": true})).expect("send response");
        });

        let mut client = connect_current_user(Duration::from_secs(3)).expect("connect pipe");
        write_json_line(
            &mut client,
            &json!({"action":"auth_restore","session":"s".repeat(65_536)}),
        )
        .expect("write maximum supported session frame");
        let response: Value = read_json_value(&mut client).expect("read response");
        assert_eq!(response["ok"], Value::Bool(true));
        worker.join().expect("server worker");
    }
}
