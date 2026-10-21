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
        },
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_WAIT, WaitNamedPipeW,
        },
        Threading::{CreateEventW, GetCurrentProcess, OpenProcessToken, WaitForSingleObject},
    },
};

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const PIPE_INSTANCE_COUNT: u32 = 1;
const MAX_WAIT: Duration = Duration::from_secs(300);
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
    io_timeout: Duration,
}

impl NamedPipeListener {
    /// Create a pipe instance with an explicit current-user-only DACL.
    pub fn bind(io_timeout: Duration) -> io::Result<Self> {
        let io_timeout = bounded_timeout(io_timeout);
        let pipe_name = current_user_pipe_path()?;
        let wide_name = wide(&pipe_name);
        let sid = current_user_sid()?;
        let sddl = wide(&format!("D:P(A;;GA;;;{sid})"));
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
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            return Ok(PipeStream {
                handle: unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) },
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
    match unsafe { WaitForSingleObject(event, timeout_millis(timeout)) } {
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
    super::pipe_path_for_sid(&sid)
        .ok_or_else(|| io::Error::other("Windows returned an invalid user SID"))
}

fn current_user_sid() -> io::Result<String> {
    let mut token = null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
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
    let mut sid_string = null_mut();
    let converted = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_string) };
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
