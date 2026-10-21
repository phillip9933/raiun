# Win32 adapter safety boundary

The workspace denies unsafe code by default. This adapter is a separately
reviewed native boundary. Its crate-level `unsafe_code = deny` policy is
lowered only for the native `src/win32.rs` and `src/session_store.rs` modules;
the portable `raiun-control` crate remains unsafe-free.

The adapter obtains the current process token SID from Win32 and uses that
trusted value to form both the pipe name and protected DACLs. The pipe is
created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, a current-user-only SDDL DACL,
and `PIPE_REJECT_REMOTE_CLIENTS`. It never starts a service, requests
elevation, accepts caller-provided pipe paths, or inherits handles.

All overlapped I/O keeps its `OVERLAPPED` and event alive until completion or
cancellation is drained. Read and write buffers remain borrowed for that
interval. OS handles are immediately wrapped in `OwnedHandle`. Security
descriptor memory returned by Win32 is freed after pipe creation. The shared
safe crate owns JSON serialization, one-megabyte framing limits, and buffer
zeroization.

The session-store adapter obtains `%LOCALAPPDATA%` from the current process,
creates `Raiun/sessions` with a protected DACL granting access only to that
user SID, and re-applies the protected DACL to existing directories before
use. Session filenames contain only a SHA-256 identity digest. DPAPI protects
each opaque session with current-user scope and identity-derived optional
entropy; machine-wide protection is never enabled. Files are created with the
same protected DACL, reparse points are rejected, and replacement is atomic.
Decrypted Win32 output is zeroized before `LocalFree`, and loaded payloads use
zeroizing buffers. The serialized session remains capped at 65,536 bytes.

The Windows-only tests must exercise local same-user request/response, the
65,536-byte session bound, and DPAPI save/load/replace/remove in a synthetic
user account. Remote
client rejection is set at pipe creation; VM tests do not claim that a remote
host was connected. The adapter does not make the Windows agent or filesystem
provider supported by itself.
