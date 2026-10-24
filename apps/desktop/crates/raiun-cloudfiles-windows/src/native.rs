//! Raw Cloud Files API and Win32 FFI. Keep every unsafe operation here.
//!
//! ABI declarations in this file follow the Microsoft `cfapi.h` structures
//! documented in `SAFETY.md`. Compile-time layout checks intentionally limit
//! this first callback bridge to 64-bit Windows, which is the only supported
//! Windows target for the application today.

use crate::{
    BackendError, BoundedPermit, BoundedPermitPool, CancellationToken, Error, FetchRange,
    LocalFileIdentity, MAX_CONCURRENT_DIRECTORY_ENUMERATIONS, MAX_CONCURRENT_FETCHES,
    MAX_FILE_BYTES, MAX_RANGE_BYTES, MAX_REQUEST_BYTES, MAX_STAGED_CALLBACKS, PlaceholderBackend,
    PlaceholderMetadata, PlatformVersion, PreparedConfiguredRootRuntime, PreparedEditRecovery,
    RequestPublicationGate, RequestPublicationPermit, SyntheticEntry, checked_fetch_range,
    next_chunk_len, placeholder_population_completed,
};
#[cfg(test)]
use crate::{PreparedFetch, PreparedFetchSession};
use std::time::Instant;
use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::c_void,
    fs,
    io::Read,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        ffi::OsStringExt,
        io::{AsRawHandle, FromRawHandle},
    },
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT: u32 = 0x2;
const CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH: u32 = 0x4;
const CALLBACK_INITIALIZING: u8 = 0;
const CALLBACK_READY: u8 = 1;
const CALLBACK_CLOSING: u8 = 2;
const CALLBACK_FAILED: u8 = 3;
const CF_SYNC_ROOT_INFO_STANDARD: u32 = 1;
const CF_SYNC_ROOT_IDENTITY_MAX: usize = 64 * 1024;
const CF_HYDRATION_POLICY_FULL: u16 = 2;
const CF_POPULATION_POLICY_FULL: u16 = 2;
const CF_CALLBACK_TYPE_FETCH_DATA: i32 = 0;
const CF_CALLBACK_TYPE_CANCEL_FETCH_DATA: i32 = 2;
const CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS: i32 = 3;
const CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS: i32 = 4;
const CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION: i32 = 6;
const CF_CALLBACK_TYPE_NONE: i32 = -1;
const CF_OPERATION_TYPE_TRANSFER_DATA: i32 = 0;
const CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS: i32 = 4;
const CF_OPERATION_TRANSFER_DATA_FLAG_NONE: u32 = 0;
const CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE: u32 = 0;
const CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION: u32 = 2;
// The Cloud Files contract defines FETCH_DATA ParamSize as the arm size plus
// the leading ULONG (60 on x64). A Windows 11 runtime trace also reported the
// fully aligned structure size (64). Accept only those two ABI-derived values.
const CF_FETCH_DATA_PARAM_SIZE_DOCUMENTED: usize =
    size_of::<CfCallbackFetchData>() + size_of::<u32>();
const CF_FETCH_DATA_PARAM_SIZE_ALIGNED: usize =
    std::mem::offset_of!(CfCallbackParameters, data) + size_of::<CfCallbackFetchData>();
// CANCEL_FETCH_DATA includes the nested offset/length pair and two ULONGs
// (ParamSize and the outer cancellation flags), as specified by cfapi.h.
const CF_CANCEL_FETCH_DATA_PARAM_SIZE: usize =
    size_of::<CfCallbackCancelRange>() + 2 * size_of::<u32>();
const CF_FETCH_PLACEHOLDERS_PARAM_SIZE_DOCUMENTED: usize =
    size_of::<CfCallbackFetchPlaceholders>() + size_of::<u32>();
const CF_FETCH_PLACEHOLDERS_PARAM_SIZE_ALIGNED: usize =
    std::mem::offset_of!(CfCallbackParameters, data) + size_of::<CfCallbackFetchPlaceholders>();
const CF_CANCEL_FETCH_PLACEHOLDERS_PARAM_SIZE_DOCUMENTED: usize =
    size_of::<CfCallbackCancelFetchPlaceholders>() + size_of::<u32>();
const CF_CANCEL_FETCH_PLACEHOLDERS_PARAM_SIZE_ALIGNED: usize =
    std::mem::offset_of!(CfCallbackParameters, data)
        + size_of::<CfCallbackCancelFetchPlaceholders>();
const CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC: u32 = 2;
const CF_CREATE_FLAG_STOP_ON_ERROR: u32 = 1;
const CF_UPDATE_FLAG_ENABLE_ON_DEMAND_POPULATION: u32 = 0x8;
const CF_PLACEHOLDER_INFO_BASIC: u32 = 0;
const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_ATTRIBUTE_TAG_INFO_CLASS: u32 = 9;
const FILE_DISPOSITION_INFO_CLASS: u32 = 4;
const CF_PLACEHOLDER_STATE_PLACEHOLDER: u32 = 0x1;
const CF_PLACEHOLDER_STATE_SYNC_ROOT: u32 = 0x2;
const CF_PLACEHOLDER_STATE_IN_SYNC: u32 = 0x8;
const CF_PLACEHOLDER_STATE_PARTIAL: u32 = 0x10;
const CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK: u32 = 0x20;
const CF_PLACEHOLDER_RANGE_INFO_MODIFIED: u32 = 3;
const CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED: u32 = 0x1;
const IO_REPARSE_TAG_CLOUD: u32 = 0x9000_001a;
const IO_REPARSE_TAG_CLOUD_MASK: u32 = 0xffff_00ff;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_WRITE_DATA: u32 = 0x2;
const GENERIC_READ: u32 = 0x8000_0000;
const DELETE_ACCESS: u32 = 0x0001_0000;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_SHARE_DELETE: u32 = 4;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER_CLASS: u32 = 1;
const SDDL_REVISION_1: u32 = 1;
const INVALID_HANDLE_VALUE: Handle = -1_isize as Handle;
const PAYLOAD_LEN: usize = 4096;
const FILE_NAME: &str = "synthetic.bin";
const FILE_IDENTITY: [u8; 16] = *b"RaiunSynFileV1!!";
const SECOND_FILE_NAME: &str = "second.bin";
const SECOND_FILE_IDENTITY: [u8; 16] = *b"RaiunSynFileV2!!";
const FIRST_FOLDER_NAME: &str = "first-folder";
const SECOND_FOLDER_NAME: &str = "second-folder";
const FIRST_FOLDER_IDENTITY: [u8; 16] = *b"RaiunSynDirV1!!!";
const SECOND_FOLDER_IDENTITY: [u8; 16] = *b"RaiunSynDirV2!!!";
const SECOND_PAYLOAD_LEN: usize = 8192;
const NESTED_FILE_NAME: &str = "nested.bin";
const NESTED_FILE_IDENTITY: [u8; 16] = *b"RaiunNestedV1!!!";
const NESTED_PAYLOAD_LEN: usize = 4096;
#[cfg(test)]
const SECOND_FOLDER_CHILD_NAME: &str = "retained-child.bin";
#[cfg(test)]
const SECOND_FOLDER_CHILD_IDENTITY: [u8; 16] = *b"RaiunKeepChildV1";
#[cfg(test)]
const SECOND_FOLDER_CHILD_LEN: usize = 1024;
const STATUS_CANCELLED: i32 = 0xC000_0120_u32 as i32;
const FIXTURE_ITEMS: [FixtureItem; 4] = [
    FixtureItem {
        name: FIRST_FOLDER_NAME,
        identity: &FIRST_FOLDER_IDENTITY,
        is_directory: true,
        len: 0,
    },
    FixtureItem {
        name: SECOND_FOLDER_NAME,
        identity: &SECOND_FOLDER_IDENTITY,
        is_directory: true,
        len: 0,
    },
    FixtureItem {
        name: FILE_NAME,
        identity: &FILE_IDENTITY,
        is_directory: false,
        len: PAYLOAD_LEN,
    },
    FixtureItem {
        name: SECOND_FILE_NAME,
        identity: &SECOND_FILE_IDENTITY,
        is_directory: false,
        len: SECOND_PAYLOAD_LEN,
    },
];

const NESTED_FIXTURE_ITEM: FixtureItem = FixtureItem {
    name: NESTED_FILE_NAME,
    identity: &NESTED_FILE_IDENTITY,
    is_directory: false,
    len: NESTED_PAYLOAD_LEN,
};

#[cfg(test)]
const SECOND_FOLDER_CHILD_FIXTURE_ITEM: FixtureItem = FixtureItem {
    name: SECOND_FOLDER_CHILD_NAME,
    identity: &SECOND_FOLDER_CHILD_IDENTITY,
    is_directory: false,
    len: SECOND_FOLDER_CHILD_LEN,
};

#[derive(Clone, Copy)]
struct FixtureItem {
    name: &'static str,
    identity: &'static [u8; 16],
    is_directory: bool,
    len: usize,
}
const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001_u32 as i32;
static TEST_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

type Handle = *mut c_void;
type HResult = i32;
type Callback =
    Option<unsafe extern "system" fn(*const CfCallbackInfo, *const CfCallbackParameters)>;

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfPlatformInfo {
    build_number: u32,
    revision_number: u32,
    integration_number: u32,
}

#[repr(C)]
#[allow(dead_code)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
#[allow(dead_code)]
struct CfSyncRegistration {
    struct_size: u32,
    provider_name: *const u16,
    provider_version: *const u16,
    sync_root_identity: *const c_void,
    sync_root_identity_length: u32,
    file_identity: *const c_void,
    file_identity_length: u32,
    provider_id: Guid,
}

#[repr(C)]
#[allow(dead_code)]
struct CfSyncRootStandardInfoHeader {
    sync_root_file_id: i64,
    hydration_policy: CfHydrationPolicy,
    population_policy: CfPopulationPolicy,
    in_sync_policy: u32,
    hard_link_policy: u32,
    provider_status: u32,
    provider_name: [u16; 256],
    provider_version: [u16; 256],
    sync_root_identity_length: u32,
}

#[repr(C)]
#[allow(dead_code)]
struct CfHydrationPolicy {
    primary: u16,
    modifier: u16,
}

#[repr(C)]
#[allow(dead_code)]
struct CfPopulationPolicy {
    primary: u16,
    modifier: u16,
}

#[repr(C)]
#[allow(dead_code)]
struct CfSyncPolicies {
    struct_size: u32,
    hydration: CfHydrationPolicy,
    population: CfPopulationPolicy,
    in_sync: u32,
    hard_link: u32,
    placeholder_management: u32,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfConnectionKey {
    // cfapi.h: DECLARE_OPAQUE_KEY(CF_CONNECTION_KEY) wraps one LONGLONG.
    internal: i64,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfTransferKey {
    // cfapi.h typedefs CF_TRANSFER_KEY as LARGE_INTEGER.
    internal: i64,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfRequestKey {
    // cfapi.h typedefs CF_REQUEST_KEY as LARGE_INTEGER.
    internal: i64,
}

#[repr(C)]
#[allow(dead_code)]
struct CfCallbackRegistration {
    callback_type: i32,
    callback: Callback,
}

#[repr(C)]
#[allow(dead_code)]
struct CfCallbackInfo {
    struct_size: u32,
    connection_key: CfConnectionKey,
    callback_context: *mut c_void,
    volume_guid_name: *const u16,
    volume_dos_name: *const u16,
    volume_serial_number: u32,
    sync_root_file_id: i64,
    sync_root_identity: *const c_void,
    sync_root_identity_length: u32,
    file_id: i64,
    file_size: i64,
    file_identity: *const c_void,
    file_identity_length: u32,
    normalized_path: *const u16,
    transfer_key: CfTransferKey,
    priority_hint: u8,
    correlation_vector: *const c_void,
    process_info: *const c_void,
    request_key: CfRequestKey,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfCallbackFetchData {
    flags: u32,
    required_file_offset: i64,
    required_length: i64,
    optional_file_offset: i64,
    optional_length: i64,
    last_dehydration_time: i64,
    last_dehydration_reason: i32,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfCallbackCancelFetchData {
    flags: u32,
    fetch_data: CfCallbackCancelRange,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfCallbackFetchPlaceholders {
    flags: u32,
    pattern: *const u16,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfCallbackCancelFetchPlaceholders {
    flags: u32,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfCallbackCloseCompletion {
    flags: u32,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfFileRange {
    starting_offset: i64,
    length: i64,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct CfCallbackCancelRange {
    file_offset: i64,
    length: i64,
}

#[repr(C)]
#[allow(dead_code)]
union CfCallbackParameterData {
    fetch_data: CfCallbackFetchData,
    cancel_fetch_data: CfCallbackCancelFetchData,
    fetch_placeholders: CfCallbackFetchPlaceholders,
    cancel_fetch_placeholders: CfCallbackCancelFetchPlaceholders,
    close_completion: CfCallbackCloseCompletion,
    align: u64,
}

#[repr(C)]
#[allow(dead_code)]
struct CfCallbackParameters {
    param_size: u32,
    data: CfCallbackParameterData,
}

#[repr(C)]
#[allow(dead_code)]
struct CfOperationInfo {
    struct_size: u32,
    operation_type: i32,
    connection_key: CfConnectionKey,
    transfer_key: CfTransferKey,
    correlation_vector: *const c_void,
    sync_status: *const c_void,
    request_key: CfRequestKey,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct CfTransferDataParameters {
    flags: u32,
    completion_status: i32,
    buffer: *const c_void,
    offset: i64,
    length: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct CfTransferPlaceholdersParameters {
    flags: u32,
    completion_status: i32,
    placeholder_total_count: i64,
    placeholder_array: *mut CfPlaceholderCreateInfo,
    placeholder_count: u32,
    entries_processed: u32,
}

#[repr(C)]
#[allow(dead_code)]
union CfOperationParameterData {
    transfer_data: CfTransferDataParameters,
    transfer_placeholders: CfTransferPlaceholdersParameters,
    // The Windows SDK union is 40 bytes on x64 (RetrieveData is its largest
    // member). Keep the complete ABI storage even though this adapter currently
    // sends only TransferData, whose ParamSize is 40 bytes including the prefix.
    align: [u64; 5],
}

#[repr(C)]
#[allow(dead_code)]
struct CfOperationParameters {
    param_size: u32,
    data: CfOperationParameterData,
}

#[repr(C)]
#[allow(dead_code)]
struct FileBasicInfo {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: u32,
}

#[repr(C)]
#[allow(dead_code)]
struct CfFsMetadata {
    basic_info: FileBasicInfo,
    file_size: i64,
}

#[repr(C)]
#[allow(dead_code)]
struct CfPlaceholderCreateInfo {
    relative_file_name: *const u16,
    fs_metadata: CfFsMetadata,
    file_identity: *const c_void,
    file_identity_length: u32,
    flags: u32,
    result: HResult,
    create_usn: i64,
}

#[repr(C)]
#[allow(dead_code)]
struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut c_void,
    inherit_handle: i32,
}

#[repr(C)]
#[allow(dead_code)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[repr(C)]
#[allow(dead_code)]
struct TokenUser {
    user: SidAndAttributes,
}

#[repr(C)]
#[allow(dead_code)]
struct FileTime {
    low: u32,
    high: u32,
}

#[repr(C)]
#[allow(dead_code)]
struct ByHandleFileInformation {
    attributes: u32,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct FileAttributeTagInfo {
    file_attributes: u32,
    reparse_tag: u32,
}

#[repr(C)]
struct FileDispositionInfo {
    delete_file: i8,
}

#[derive(Clone, Copy, Debug)]
struct RootSnapshot {
    identity: RootIdentity,
    file_attributes: u32,
    reparse_tag: u32,
    placeholder_state: u32,
    file_size: u64,
    last_write_time: i64,
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<CfSyncRegistration>() == 72);
    assert!(size_of::<CfSyncPolicies>() == 24);
    assert!(size_of::<CfConnectionKey>() == 8);
    assert!(size_of::<CfTransferKey>() == 8);
    assert!(size_of::<CfRequestKey>() == 8);
    assert!(size_of::<CfCallbackRegistration>() == 16);
    assert!(size_of::<CfCallbackInfo>() == 152);
    assert!(size_of::<CfCallbackFetchData>() == 56);
    assert!(size_of::<CfCallbackCancelFetchData>() == 24);
    assert!(std::mem::offset_of!(CfCallbackCancelFetchData, fetch_data) == 8);
    assert!(CF_CANCEL_FETCH_DATA_PARAM_SIZE == 24);
    assert!(size_of::<CfCallbackParameters>() == 64);
    assert!(CF_FETCH_DATA_PARAM_SIZE_DOCUMENTED == 60);
    assert!(CF_FETCH_DATA_PARAM_SIZE_ALIGNED == 64);
    assert!(size_of::<CfCallbackFetchPlaceholders>() == 16);
    assert!(size_of::<CfCallbackCancelFetchPlaceholders>() == 4);
    assert!(size_of::<CfCallbackCloseCompletion>() == 4);
    assert!(size_of::<CfFileRange>() == 16);
    assert!(CF_FETCH_PLACEHOLDERS_PARAM_SIZE_DOCUMENTED == 20);
    assert!(CF_FETCH_PLACEHOLDERS_PARAM_SIZE_ALIGNED == 24);
    assert!(CF_CANCEL_FETCH_PLACEHOLDERS_PARAM_SIZE_DOCUMENTED == 8);
    assert!(CF_CANCEL_FETCH_PLACEHOLDERS_PARAM_SIZE_ALIGNED == 12);
    assert!(size_of::<CfCallbackFetchData>() == 56);
    assert!(size_of::<CfOperationInfo>() == 48);
    assert!(size_of::<CfTransferDataParameters>() == 32);
    assert!(size_of::<CfTransferPlaceholdersParameters>() == 32);
    assert!(std::mem::offset_of!(CfTransferPlaceholdersParameters, placeholder_total_count) == 8);
    assert!(std::mem::offset_of!(CfTransferPlaceholdersParameters, placeholder_array) == 16);
    assert!(std::mem::offset_of!(CfTransferPlaceholdersParameters, placeholder_count) == 24);
    assert!(std::mem::offset_of!(CfTransferPlaceholdersParameters, entries_processed) == 28);
    assert!(size_of::<CfOperationParameters>() == 48);
    assert!(size_of::<CfFsMetadata>() == 48);
    assert!(size_of::<CfPlaceholderCreateInfo>() == 88);
    assert!(size_of::<SecurityAttributes>() == 24);
    assert!(size_of::<TokenUser>() == 16);
    assert!(size_of::<ByHandleFileInformation>() == 52);
    assert!(std::mem::offset_of!(CfCallbackInfo, connection_key) == 8);
    assert!(std::mem::offset_of!(CfCallbackInfo, callback_context) == 16);
    assert!(std::mem::offset_of!(CfCallbackInfo, file_identity) == 88);
    assert!(std::mem::offset_of!(CfCallbackInfo, transfer_key) == 112);
    assert!(std::mem::offset_of!(CfCallbackInfo, request_key) == 144);
    assert!(std::mem::offset_of!(CfOperationInfo, connection_key) == 8);
    assert!(std::mem::offset_of!(CfOperationInfo, transfer_key) == 16);
    assert!(std::mem::offset_of!(CfOperationInfo, request_key) == 40);
    assert!(std::mem::offset_of!(CfOperationParameters, data) == 8);
    assert!(std::mem::offset_of!(CfCallbackParameters, data) == 8);
    assert!(std::mem::offset_of!(CfPlaceholderCreateInfo, create_usn) == 80);
    assert!(std::mem::offset_of!(CfSyncRootStandardInfoHeader, provider_name) == 28);
    assert!(std::mem::offset_of!(CfSyncRootStandardInfoHeader, provider_version) == 540);
    assert!(std::mem::offset_of!(CfSyncRootStandardInfoHeader, sync_root_identity_length) == 1052);
    assert!(size_of::<CfSyncRootStandardInfoHeader>() == 1056);
};

#[link(name = "CldApi")]
unsafe extern "system" {
    fn CfGetPlatformInfo(platform_version: *mut CfPlatformInfo) -> HResult;
    fn CfRegisterSyncRoot(
        sync_root_path: *const u16,
        registration: *const CfSyncRegistration,
        policies: *const CfSyncPolicies,
        register_flags: u32,
    ) -> HResult;
    fn CfUnregisterSyncRoot(sync_root_path: *const u16) -> HResult;
    fn CfGetSyncRootInfoByPath(
        file_path: *const u16,
        info_class: u32,
        info_buffer: *mut c_void,
        info_buffer_length: u32,
        returned_length: *mut u32,
    ) -> HResult;
    fn CfConnectSyncRoot(
        sync_root_path: *const u16,
        callback_table: *const CfCallbackRegistration,
        callback_context: *const c_void,
        connect_flags: u32,
        connection_key: *mut CfConnectionKey,
    ) -> HResult;
    fn CfDisconnectSyncRoot(connection_key: CfConnectionKey) -> HResult;
    fn CfGetPlaceholderInfo(
        file_handle: Handle,
        info_class: u32,
        info_buffer: *mut c_void,
        info_buffer_length: u32,
        returned_length: *mut u32,
    ) -> HResult;
    fn CfHydratePlaceholder(
        file_handle: Handle,
        starting_offset: i64,
        length: i64,
        hydrate_flags: u32,
        overlapped: *mut c_void,
    ) -> HResult;
    fn CfOpenFileWithOplock(path: *const u16, flags: u32, protected: *mut Handle) -> HResult;
    fn CfReferenceProtectedHandle(protected: Handle) -> u8;
    fn CfGetWin32HandleFromProtectedHandle(protected: Handle) -> Handle;
    fn CfReleaseProtectedHandle(protected: Handle);
    fn CfCloseHandle(protected: Handle);
    fn CfSetInSyncState(
        file_handle: Handle,
        in_sync_state: u32,
        in_sync_flags: u32,
        in_sync_usn: *mut i64,
    ) -> HResult;
    fn CfUpdatePlaceholder(
        file_handle: Handle,
        fs_metadata: *const CfFsMetadata,
        file_identity: *const c_void,
        file_identity_length: u32,
        dehydrate_range_array: *const c_void,
        dehydrate_range_count: u32,
        update_flags: u32,
        update_usn: *mut i64,
        overlapped: *mut c_void,
    ) -> HResult;
    fn CfCreatePlaceholders(
        base_directory_path: *const u16,
        placeholder_array: *mut CfPlaceholderCreateInfo,
        placeholder_count: u32,
        create_flags: u32,
        entries_processed: *mut u32,
    ) -> HResult;
    fn CfExecute(
        operation_info: *const CfOperationInfo,
        operation_parameters: *mut CfOperationParameters,
    ) -> HResult;
    fn CfGetPlaceholderStateFromAttributeTag(file_attributes: u32, reparse_tag: u32) -> u32;
    fn CfGetPlaceholderRangeInfo(
        file_handle: Handle,
        info_class: u32,
        starting_offset: i64,
        length: i64,
        info_buffer: *mut c_void,
        info_buffer_length: u32,
        returned_length: *mut u32,
    ) -> HResult;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn OpenProcessToken(
        process_handle: Handle,
        desired_access: u32,
        token_handle: *mut Handle,
    ) -> i32;
    fn GetTokenInformation(
        token_handle: Handle,
        token_information_class: u32,
        token_information: *mut c_void,
        token_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn DeviceIoControl(
        device: Handle,
        control_code: u32,
        input: *const c_void,
        input_len: u32,
        output: *mut c_void,
        output_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn CreateEventW(
        attributes: *const c_void,
        manual_reset: i32,
        initial: i32,
        name: *const u16,
    ) -> Handle;
    fn ReadFile(
        file: Handle,
        buffer: *mut c_void,
        length: u32,
        returned: *mut u32,
        overlapped: *mut CompletionOverlapped,
    ) -> i32;
    fn GetOverlappedResult(
        file: Handle,
        overlapped: *mut CompletionOverlapped,
        returned: *mut u32,
        wait: i32,
    ) -> i32;
    fn GetLastError() -> u32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetFileInformationByHandle(file: Handle, information: *mut ByHandleFileInformation) -> i32;
    fn SetFileInformationByHandle(
        file: Handle,
        file_information_class: u32,
        file_information: *const c_void,
        buffer_size: u32,
    ) -> i32;
    fn GetFileInformationByHandleEx(
        file: Handle,
        information_class: u32,
        information: *mut c_void,
        buffer_size: u32,
    ) -> i32;
    fn GetFinalPathNameByHandleW(
        file: Handle,
        file_path: *mut u16,
        buffer_length: u32,
        flags: u32,
    ) -> u32;
    fn CreateDirectoryW(
        path_name: *const u16,
        security_attributes: *const SecurityAttributes,
    ) -> i32;
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const SecurityAttributes,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: Handle,
    ) -> Handle;
    fn QueryDosDeviceW(device_name: *const u16, target_path: *mut u16, max_chars: u32) -> u32;
    #[cfg(test)]
    fn GetShortPathNameW(long_path: *const u16, short_path: *mut u16, buffer_len: u32) -> u32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        string_sd_revision: u32,
        security_descriptor: *mut *mut c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: Handle) -> Handle;
}

pub(super) fn platform_version() -> Result<PlatformVersion, Error> {
    let mut info = CfPlatformInfo {
        build_number: 0,
        revision_number: 0,
        integration_number: 0,
    };
    // SAFETY: the API writes one fixed-size platform-info structure to a valid
    // stack address. No pointers are retained by the system.
    let result = unsafe { CfGetPlatformInfo(&mut info) };
    if result < 0 {
        return Err(native_error("CfGetPlatformInfo", result));
    }
    Ok(PlatformVersion {
        build: info.build_number,
        revision: info.revision_number,
        integration: info.integration_number,
    })
}

pub(super) struct OwnedSyntheticRoot {
    path: PathBuf,
    handle: RawOwnedHandle,
    identity: RootIdentity,
    registered: bool,
    connected: bool,
    preserve_registration_on_drop: bool,
    fixture_created: bool,
    fixture_identities: [Option<RootIdentity>; 4],
    nested_identity: Option<RootIdentity>,
    #[cfg(test)]
    second_folder_child_identity: Option<RootIdentity>,
    // The localhost OpenCloud callback fixture can exercise a larger
    // placeholder while ordinary synthetic provider tests stay small.
    synthetic_payload_len: usize,
    // OpenCloud callback tests hydrate `synthetic.bin` with the exact bytes
    // from their localhost DAV fixture. Teardown checks those bytes after
    // unregister converts the hydrated placeholder into a normal file.
    expected_hydrated_payload: Option<Vec<u8>>,
}

pub(super) struct SyntheticConnection {
    root: Option<Box<OwnedSyntheticRoot>>,
    state: Arc<CallbackState>,
    context_key: usize,
    connection_key: CfConnectionKey,
    connected: bool,
    placeholder_created: bool,
}

/// Connection and registration ownership for one explicitly validated root.
/// This remains an internal foundation; no application path enables it yet.
#[allow(dead_code)]
pub(super) struct ConfiguredRootConnection {
    root: Option<Box<OwnedConfiguredRoot>>,
    state: Arc<CallbackState>,
    context_key: usize,
    connection_key: CfConnectionKey,
    connected: bool,
}

#[allow(dead_code)]
struct OwnedConfiguredRoot {
    path: PathBuf,
    lease: RootInspectionLease,
    identity: RootIdentity,
    registered: bool,
    connected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CallbackObservation {
    pub directory_callback_entries: usize,
    pub directory_callback_guard_rejections: usize,
    pub fetch_callbacks: usize,
    pub last_fetch_param_size: usize,
    pub transferred_bytes: usize,
    pub last_requested_offset: u64,
    pub last_requested_length: u64,
    pub last_staged_fetch_millis: u64,
    pub first_failed_hresult: i32,
    pub directory_callbacks: usize,
    pub last_directory_param_size: usize,
    pub placeholder_entries_submitted: usize,
    pub modified_placeholder_closes: usize,
    pub journaled_placeholder_closes: usize,
    pub unverifiable_placeholder_closes: usize,
    pub close_completion_callbacks: usize,
    pub last_close_param_size: usize,
    pub last_close_validation_stage: usize,
    pub last_close_validation_hresult: i32,
    pub last_close_path_common_prefix_bytes: usize,
}

static DIRECTORY_CALLBACK_ENTRIES: AtomicUsize = AtomicUsize::new(0);
static DIRECTORY_CALLBACK_GUARD_REJECTIONS: AtomicUsize = AtomicUsize::new(0);

impl OwnedSyntheticRoot {
    fn fixture_len(&self, item: &FixtureItem) -> usize {
        if item.name == FILE_NAME {
            self.synthetic_payload_len
        } else {
            item.len
        }
    }

    pub(super) fn create_and_register() -> Result<Self, Error> {
        let path = create_private_test_root()?;
        let handle = open_owned_root(&path)?;
        let identity = root_identity(handle.0)?;
        let mut root = Self {
            path,
            handle,
            identity,
            registered: false,
            connected: false,
            preserve_registration_on_drop: false,
            fixture_created: false,
            fixture_identities: [None; 4],
            nested_identity: None,
            #[cfg(test)]
            second_folder_child_identity: None,
            synthetic_payload_len: PAYLOAD_LEN,
            expected_hydrated_payload: None,
        };
        if let Err(error) = register_root(&root.path) {
            // A failed registration leaves the directory as an ordinary
            // directory. Remove it only while the owned handle still matches
            // the original root and the directory is still empty; otherwise
            // preserve it for inspection rather than cleaning by pathname.
            if root.verify_contents(false).is_ok() {
                root.remove_owned_root(false)?;
            }
            return Err(error);
        }
        root.registered = true;
        Ok(root)
    }

    #[cfg(test)]
    pub(super) fn reopen_registered_for_test(path: PathBuf) -> Result<Self, Error> {
        // This entrypoint accepts only the unique private test roots created
        // by this module. Production code never reopens an arbitrary path.
        if path.parent() != Some(env::temp_dir().as_path())
            || !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("Raiun-CfApi-Synthetic-"))
        {
            return Err(Error::InvalidSyntheticPath);
        }
        let handle = open_owned_root(&path)?;
        let identity = root_identity(handle.0)?;
        verify_synthetic_sync_root_registration(&path, identity)?;
        Ok(Self {
            path,
            handle,
            identity,
            registered: true,
            connected: false,
            preserve_registration_on_drop: true,
            // This process did not create the fixture and is therefore never
            // permitted to remove it during Drop, even after a failed check.
            fixture_created: false,
            fixture_identities: [None; 4],
            nested_identity: None,
            #[cfg(test)]
            second_folder_child_identity: None,
            synthetic_payload_len: PAYLOAD_LEN,
            expected_hydrated_payload: None,
        })
    }

    #[cfg(test)]
    pub(super) fn identity_for_test(&self) -> Result<crate::ConfiguredRootIdentity, Error> {
        self.verify_identity()?;
        Ok(crate::ConfiguredRootIdentity {
            volume_serial: self.identity.volume_serial,
            file_index: self.identity.file_index,
        })
    }

    pub(super) fn unregister(mut self) -> Result<(), Error> {
        self.verify_contents(false)?;
        self.unregister_inner()?;
        self.remove_owned_root(false)
    }

    fn unregister_inner(&mut self) -> Result<(), Error> {
        if !self.registered {
            return Ok(());
        }
        if self.connected {
            return Err(Error::ConnectionStateInvalid);
        }
        self.verify_identity()?;
        let path = wide_path(&self.path)?;
        // SAFETY: the root handle prevents rename/replacement while the path
        // is passed to this path-based API. Its file ID is checked immediately
        // before the call, and only this module created the root.
        let result = unsafe { CfUnregisterSyncRoot(path.as_ptr()) };
        if result < 0 {
            return Err(native_error("CfUnregisterSyncRoot", result));
        }
        self.registered = false;
        self.verify_identity()
    }

    fn verify_identity(&self) -> Result<(), Error> {
        let state = root_snapshot_state(self.registered, self.connected)
            .ok_or(Error::SyntheticRootChanged)?;
        if self.registered {
            verify_synthetic_sync_root_registration(&self.path, self.identity)?;
        }
        let actual = root_snapshot(self.handle.0)?;
        if !valid_root_snapshot(actual, self.identity, state) {
            eprintln!(
                "synthetic root state mismatch: connected={} attrs={:#x} tag={:#x} placeholder={:#x}",
                self.connected,
                actual.file_attributes,
                actual.reparse_tag,
                actual.placeholder_state
            );
            return Err(Error::SyntheticRootChanged);
        }
        let path_handle = open_root_for_identity_check(&self.path)?;
        let path_snapshot = root_snapshot(path_handle.0)?;
        if !valid_root_snapshot(path_snapshot, self.identity, state) {
            eprintln!(
                "synthetic root path state mismatch: connected={} attrs={:#x} tag={:#x} placeholder={:#x}",
                self.connected,
                path_snapshot.file_attributes,
                path_snapshot.reparse_tag,
                path_snapshot.placeholder_state
            );
            return Err(Error::SyntheticRootChanged);
        }
        Ok(())
    }

    fn verify_contents(&self, expect_placeholder: bool) -> Result<(), Error> {
        self.verify_contents_with_materialized_directories(expect_placeholder, false)
    }

    fn verify_contents_with_materialized_directories(
        &self,
        expect_placeholder: bool,
        allow_materialized_directories: bool,
    ) -> Result<(), Error> {
        self.verify_contents_with_teardown_state(
            expect_placeholder,
            allow_materialized_directories,
            false,
        )
    }

    fn verify_contents_with_teardown_state(
        &self,
        expect_placeholder: bool,
        allow_materialized_directories: bool,
        allow_unregistered_files_missing: bool,
    ) -> Result<(), Error> {
        self.verify_identity().inspect_err(|error| {
            eprintln!(
                "synthetic teardown predicate failed phase=verify_contents_identity error={error:?}"
            );
        })?;
        let entries = fs::read_dir(&self.path).map_err(|error| {
            eprintln!("synthetic teardown predicate failed phase=read_dir error={error:?}");
            io_error("enumerate test root", error)
        })?;
        let mut names = HashSet::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                eprintln!(
                    "synthetic teardown predicate failed phase=read_dir_entry error={error:?}"
                );
                io_error("enumerate test root", error)
            })?;
            let file_type = entry.file_type().map_err(|error| {
                eprintln!(
                    "synthetic teardown predicate failed phase=file_type name={:?} error={error:?}",
                    entry.file_name()
                );
                io_error("inspect test root entry", error)
            })?;
            if file_type.is_symlink() {
                eprintln!(
                    "synthetic teardown predicate failed phase=unexpected_symlink name={:?}",
                    entry.file_name()
                );
                return Err(Error::SyntheticRootChanged);
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(item) = FIXTURE_ITEMS.iter().find(|item| item.name == name) else {
                eprintln!(
                    "synthetic teardown predicate failed phase=unexpected_child name={name:?}"
                );
                return Err(Error::SyntheticRootChanged);
            };
            if item.is_directory != file_type.is_dir()
                || (!item.is_directory && !file_type.is_file())
            {
                eprintln!(
                    "synthetic teardown predicate failed phase=child_type name={name:?} expected_directory={} actual_directory={} actual_file={}",
                    item.is_directory,
                    file_type.is_dir(),
                    file_type.is_file()
                );
                return Err(Error::SyntheticRootChanged);
            }
            // Open the exact expected entry without following reparse data.
            // An ordinary file is required before placeholder creation.
            // Afterwards, accept only the expected Cloud Files placeholder or
            // its exact hydrated archive-file form, never an arbitrary
            // reparse point or sync root.
            let entry_snapshot = entry_snapshot(&entry.path(), item.is_directory).inspect_err(|error| {
                eprintln!("synthetic teardown predicate failed phase=entry_snapshot name={name:?} error={error:?}");
            })?;
            let materialized_directory = allow_materialized_directories
                && item.is_directory
                && FIXTURE_ITEMS
                    .iter()
                    .position(|fixture| fixture.name == name)
                    .and_then(|index| self.fixture_identities[index])
                    .is_some_and(|identity| identity == entry_snapshot.identity)
                && valid_materialized_directory(entry_snapshot);
            if !valid_fixture_entry(
                entry_snapshot,
                item.is_directory,
                self.fixture_len(item) as u64,
                expect_placeholder,
            ) && !materialized_directory
            {
                eprintln!(
                    "synthetic child state mismatch: directory={} placeholder_expected={} attrs={:#x} tag={:#x} placeholder={:#x} size={}",
                    item.is_directory,
                    expect_placeholder,
                    entry_snapshot.file_attributes,
                    entry_snapshot.reparse_tag,
                    entry_snapshot.placeholder_state,
                    entry_snapshot.file_size
                );
                return Err(Error::SyntheticRootChanged);
            }
            if let Some(index) = FIXTURE_ITEMS
                .iter()
                .position(|fixture| fixture.name == name)
                && !fixture_identity_matches(
                    self.fixture_identities[index],
                    entry_snapshot.identity,
                )
            {
                eprintln!(
                    "synthetic teardown predicate failed phase=child_identity name={name:?} expected={:?} actual={:?}",
                    self.fixture_identities[index], entry_snapshot.identity
                );
                return Err(Error::SyntheticRootChanged);
            }
            if !names.insert(name.clone()) {
                eprintln!(
                    "synthetic teardown predicate failed phase=duplicate_child name={name:?}"
                );
                return Err(Error::SyntheticRootChanged);
            }
        }
        if !fixture_names_match_expected(
            &names,
            expect_placeholder,
            allow_unregistered_files_missing,
        ) {
            let missing = FIXTURE_ITEMS
                .iter()
                .filter(|item| !names.contains(item.name))
                .map(|item| item.name)
                .collect::<Vec<_>>();
            eprintln!(
                "synthetic teardown predicate failed phase=fixture_set placeholder_expected={} allow_unregistered_missing_files={} missing={missing:?} actual={names:?}",
                expect_placeholder, allow_unregistered_files_missing
            );
            return Err(Error::SyntheticRootChanged);
        }
        if !expect_placeholder && !names.is_empty() {
            eprintln!("synthetic teardown predicate failed phase=nonempty_root children={names:?}");
            return Err(Error::SyntheticRootChanged);
        }
        #[cfg(test)]
        self.verify_second_folder_child().inspect_err(|error| {
            eprintln!(
                "synthetic teardown predicate failed phase=second_folder_child error={error:?}"
            );
        })?;
        Ok(())
    }

    fn capture_fixture_identities(&mut self) -> Result<(), Error> {
        let mut identities = [None; 4];
        for (index, item) in FIXTURE_ITEMS.iter().enumerate() {
            let snapshot = entry_snapshot(&self.path.join(item.name), item.is_directory)?;
            if snapshot.identity.volume_serial != self.identity.volume_serial
                || !valid_fixture_entry(
                    snapshot,
                    item.is_directory,
                    self.fixture_len(item) as u64,
                    true,
                )
            {
                return Err(Error::SyntheticRootChanged);
            }
            identities[index] = Some(snapshot.identity);
        }
        self.fixture_identities = identities;
        Ok(())
    }

    fn remove_owned_root(&mut self, expect_payload: bool) -> Result<(), Error> {
        self.verify_identity()?;
        if expect_payload {
            // Disconnect may materialize empty directory placeholders as
            // ordinary directories. Successful unregister may also evict
            // unhydrated regular-file placeholders. Missing names are allowed
            // only after unregister; every surviving entry still needs its
            // recorded identity/type and exact Cloud Files state.
            let allow_unregistered_files_missing = !self.registered;
            self.verify_contents_with_teardown_state(true, true, allow_unregistered_files_missing)?;
            for item in FIXTURE_ITEMS.iter().filter(|item| !item.is_directory) {
                let file_path = self.path.join(item.name);
                let expected = self.fixture_identity(item.name)?;
                let guard = match open_fixture_entry(
                    &file_path,
                    expected,
                    FILE_READ_ATTRIBUTES,
                    false,
                    self.fixture_len(item) as u64,
                    false,
                ) {
                    Ok(guard) => guard,
                    Err(Error::Io {
                        kind: std::io::ErrorKind::NotFound,
                        ..
                    }) if allow_unregistered_files_missing => {
                        eprintln!(
                            "known unhydrated synthetic file evicted after unregister: {:?}",
                            item.name
                        );
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let fixture_len = self.fixture_len(item);
                let file_handle = open_fixture_content(&file_path, expected, fixture_len).inspect_err(|error| {
                    eprintln!("synthetic teardown failed phase=open_file_contents name={} error={error:?}", item.name);
                })?;
                let snapshot = root_snapshot(guard.0).inspect_err(|error| {
                    eprintln!("synthetic teardown failed phase=snapshot_file_guard name={} error={error:?}", item.name);
                })?;
                if snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
                    let (bytes, after_read) = read_open_file(file_handle, fixture_len).inspect_err(|error| {
                        eprintln!("synthetic teardown failed phase=read_hydrated_file name={} error={error:?}", item.name);
                    })?;
                    if !valid_fixture_entry(after_read, false, fixture_len as u64, false) {
                        return Err(Error::SyntheticRootChanged);
                    }
                    let expected_bytes = if item.name == "synthetic.bin" {
                        self.expected_hydrated_payload
                            .clone()
                            .unwrap_or_else(|| synthetic_payload_for(item.identity, fixture_len))
                    } else {
                        synthetic_payload_for(item.identity, fixture_len)
                    };
                    if bytes != expected_bytes {
                        eprintln!(
                            "synthetic hydrated child content mismatch: name={} bytes={} expected_bytes={}",
                            item.name,
                            bytes.len(),
                            expected_bytes.len()
                        );
                        return Err(Error::SyntheticRootChanged);
                    }
                }
            }
            for item in FIXTURE_ITEMS.iter().filter(|item| !item.is_directory) {
                match self.delete_fixture_entry(item) {
                    Ok(()) => {}
                    Err(Error::Io {
                        kind: std::io::ErrorKind::NotFound,
                        ..
                    }) if allow_unregistered_files_missing => {
                        eprintln!(
                            "known synthetic file already absent during cleanup: {:?}",
                            item.name
                        );
                    }
                    Err(error) => {
                        eprintln!(
                            "synthetic teardown failed phase=delete_root_file name={} error={error:?}",
                            item.name
                        );
                        return Err(error);
                    }
                }
            }
            if let Some(expected_identity) = self.nested_identity {
                let path = self.path.join(FIRST_FOLDER_NAME).join(NESTED_FILE_NAME);
                match open_fixture_entry(
                    &path,
                    expected_identity,
                    DELETE_ACCESS | FILE_READ_ATTRIBUTES,
                    false,
                    NESTED_PAYLOAD_LEN as u64,
                    false,
                ) {
                    Ok(guard) => {
                        let snapshot = root_snapshot(guard.0)?;
                        if self.registered
                            && snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                        {
                            // Content was verified before unregister. After a successful
                            // unregister Cloud Files can retain an exclusive handle, so
                            // revalidate identity/type/state but do not reopen the data.
                            let handle =
                                open_fixture_content(&path, expected_identity, NESTED_PAYLOAD_LEN)?;
                            let (bytes, after_read) = read_open_file(handle, NESTED_PAYLOAD_LEN)?;
                            if !valid_fixture_entry(
                                after_read,
                                false,
                                NESTED_PAYLOAD_LEN as u64,
                                false,
                            ) || bytes
                                != synthetic_payload_for(&NESTED_FILE_IDENTITY, NESTED_PAYLOAD_LEN)
                            {
                                return Err(Error::SyntheticRootChanged);
                            }
                        }
                        delete_by_handle(guard.0).inspect_err(|error| {
                            eprintln!("synthetic teardown failed phase=delete_nested_child error={error:?}");
                        })?;
                    }
                    Err(Error::Io {
                        kind: std::io::ErrorKind::NotFound,
                        ..
                    }) if allow_unregistered_files_missing => {}
                    Err(error) => return Err(error),
                }
            }
            #[cfg(test)]
            self.delete_second_folder_child().inspect_err(|error| {
                eprintln!("synthetic teardown failed phase=delete_populated_second_folder_child error={error:?}");
            })?;
            for item in FIXTURE_ITEMS.iter().filter(|item| item.is_directory) {
                self.delete_fixture_entry_with_policy(item, true).inspect_err(|error| {
                    eprintln!("synthetic teardown failed phase=delete_directory name={} error={error:?}", item.name);
                })?;
            }
            self.verify_contents(false).inspect_err(|error| {
                eprintln!("synthetic teardown failed phase=verify_empty_root error={error:?}");
            })?;
        } else {
            self.verify_contents(false)?;
        }
        delete_by_handle(self.handle.0).inspect_err(|error| {
            eprintln!("synthetic teardown failed phase=delete_root_handle error={error:?}");
        })?;
        drop(std::mem::replace(
            &mut self.handle,
            RawOwnedHandle::invalid(),
        ));
        Ok(())
    }

    fn fixture_identity(&self, name: &str) -> Result<RootIdentity, Error> {
        let index = FIXTURE_ITEMS
            .iter()
            .position(|item| item.name == name)
            .ok_or(Error::SyntheticRootChanged)?;
        self.fixture_identities[index].ok_or(Error::SyntheticRootChanged)
    }

    #[cfg(test)]
    fn fixture_presence_for_test(&self) -> [bool; 5] {
        std::array::from_fn(|index| {
            let path = if index < FIXTURE_ITEMS.len() {
                self.path.join(FIXTURE_ITEMS[index].name)
            } else {
                self.path
                    .join(SECOND_FOLDER_NAME)
                    .join(SECOND_FOLDER_CHILD_NAME)
            };
            fs::symlink_metadata(path).is_ok()
        })
    }

    #[cfg(test)]
    fn verify_second_folder_child(&self) -> Result<(), Error> {
        let Some(expected_identity) = self.second_folder_child_identity else {
            return Ok(());
        };
        let folder_path = self.path.join(SECOND_FOLDER_NAME);
        let _folder_guard = open_fixture_entry(
            &folder_path,
            self.fixture_identity(SECOND_FOLDER_NAME)?,
            FILE_READ_ATTRIBUTES,
            true,
            0,
            true,
        )?;
        let mut entries = fs::read_dir(&folder_path)
            .map_err(|error| io_error("enumerate populated synthetic directory", error))?;
        let entry = entries
            .next()
            .transpose()
            .map_err(|error| io_error("read populated synthetic directory", error))?
            .ok_or(Error::SyntheticRootChanged)?;
        if entry.file_name() != SECOND_FOLDER_CHILD_NAME || entries.next().is_some() {
            return Err(Error::SyntheticRootChanged);
        }
        let file_type = entry
            .file_type()
            .map_err(|error| io_error("inspect populated synthetic child", error))?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(Error::SyntheticRootChanged);
        }
        let child_path = folder_path.join(SECOND_FOLDER_CHILD_NAME);
        let initial = entry_snapshot(&child_path, false)?;
        let is_placeholder = initial.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER != 0;
        let _child_guard = open_fixture_entry(
            &child_path,
            expected_identity,
            FILE_READ_ATTRIBUTES,
            false,
            SECOND_FOLDER_CHILD_LEN as u64,
            is_placeholder,
        )?;
        if initial.identity != expected_identity
            || (is_placeholder
                && !valid_fixture_entry(initial, false, SECOND_FOLDER_CHILD_LEN as u64, true))
        {
            return Err(Error::SyntheticRootChanged);
        }
        if !is_placeholder {
            let content =
                open_fixture_content(&child_path, expected_identity, SECOND_FOLDER_CHILD_LEN)?;
            let (bytes, snapshot) = read_open_file(content, SECOND_FOLDER_CHILD_LEN)?;
            if !valid_fixture_entry(snapshot, false, SECOND_FOLDER_CHILD_LEN as u64, false)
                || bytes
                    != synthetic_payload_for(&SECOND_FOLDER_CHILD_IDENTITY, SECOND_FOLDER_CHILD_LEN)
            {
                return Err(Error::SyntheticRootChanged);
            }
        }
        Ok(())
    }

    fn verify_nested_child_content(&self) -> Result<(), Error> {
        let Some(expected_identity) = self.nested_identity else {
            return Ok(());
        };
        let path = self.path.join(FIRST_FOLDER_NAME).join(NESTED_FILE_NAME);
        let guard = open_fixture_entry(
            &path,
            expected_identity,
            FILE_READ_ATTRIBUTES,
            false,
            NESTED_PAYLOAD_LEN as u64,
            false,
        )?;
        let content = open_fixture_content(&path, expected_identity, NESTED_PAYLOAD_LEN)?;
        let (bytes, snapshot) = read_open_file(content, NESTED_PAYLOAD_LEN)?;
        if !valid_fixture_entry(snapshot, false, NESTED_PAYLOAD_LEN as u64, false)
            || bytes != synthetic_payload_for(&NESTED_FILE_IDENTITY, NESTED_PAYLOAD_LEN)
        {
            return Err(Error::SyntheticRootChanged);
        }
        drop(guard);
        Ok(())
    }

    #[cfg(test)]
    fn delete_second_folder_child(&mut self) -> Result<(), Error> {
        let Some(expected_identity) = self.second_folder_child_identity else {
            return Ok(());
        };
        self.verify_second_folder_child()?;
        let folder_path = self.path.join(SECOND_FOLDER_NAME);
        let _folder_guard = open_fixture_entry(
            &folder_path,
            self.fixture_identity(SECOND_FOLDER_NAME)?,
            FILE_READ_ATTRIBUTES,
            true,
            0,
            true,
        )?;
        let child_path = folder_path.join(SECOND_FOLDER_CHILD_NAME);
        let child = open_fixture_entry(
            &child_path,
            expected_identity,
            DELETE_ACCESS | FILE_READ_ATTRIBUTES,
            false,
            SECOND_FOLDER_CHILD_LEN as u64,
            false,
        )?;
        let child_snapshot = root_snapshot(child.0)?;
        eprintln!(
            "synthetic populated child cleanup: attrs={:#x} tag={:#x} placeholder={:#x} size={} identity={:?}",
            child_snapshot.file_attributes,
            child_snapshot.reparse_tag,
            child_snapshot.placeholder_state,
            child_snapshot.file_size,
            child_snapshot.identity
        );
        delete_by_handle(child.0).inspect_err(|error| {
            eprintln!("synthetic populated child disposition failed: {error:?}");
        })?;
        self.second_folder_child_identity = None;
        Ok(())
    }

    fn delete_fixture_entry(&self, item: &FixtureItem) -> Result<(), Error> {
        self.delete_fixture_entry_with_policy(item, false)
    }

    fn delete_fixture_entry_with_policy(
        &self,
        item: &FixtureItem,
        allow_materialized_directory: bool,
    ) -> Result<(), Error> {
        let handle = open_fixture_entry(
            &self.path.join(item.name),
            self.fixture_identity(item.name)?,
            DELETE_ACCESS | FILE_READ_ATTRIBUTES,
            item.is_directory,
            self.fixture_len(item) as u64,
            allow_materialized_directory,
        )?;
        delete_by_handle(handle.0)
    }

    fn remove_created_fixture_entries(&mut self) -> Result<(), Error> {
        for (index, item) in FIXTURE_ITEMS.iter().enumerate().rev() {
            if self.fixture_identities[index].is_some() {
                self.delete_fixture_entry(item)?;
                self.fixture_identities[index] = None;
            }
        }
        self.verify_contents(false)
    }
}

#[allow(dead_code)]
impl OwnedConfiguredRoot {
    fn new(path: PathBuf, lease: RootInspectionLease, registered: bool) -> Result<Self, Error> {
        let identity = RootIdentity {
            volume_serial: lease.identity.volume_serial,
            file_index: lease.identity.file_index,
        };
        let root = Self {
            path,
            lease,
            identity,
            registered,
            connected: false,
        };
        root.verify_identity(false)?;
        if registered {
            root.verify_registered()?;
        } else {
            let mut entries = fs::read_dir(&root.path)
                .map_err(|error| io_error("verify configured root before registration", error))?;
            if entries
                .next()
                .transpose()
                .map_err(|error| io_error("read configured root before registration", error))?
                .is_some()
            {
                return Err(Error::ConfiguredRootNotEmpty);
            }
        }
        Ok(root)
    }

    fn root_handle(&self) -> Result<Handle, Error> {
        self.lease
            ._pinned
            .last()
            .map(|handle| handle.0)
            .ok_or(Error::InvalidConfiguredRoot)
    }

    fn verify_identity(&self, connected: bool) -> Result<(), Error> {
        if self.connected != connected {
            return Err(Error::ConfiguredRootChanged);
        }
        let state =
            root_snapshot_state(self.registered, connected).ok_or(Error::ConfiguredRootChanged)?;
        if self.registered {
            self.verify_registered()?;
        }
        let expected = RootIdentity {
            volume_serial: self.identity.volume_serial,
            file_index: self.identity.file_index,
        };
        let pinned = root_snapshot(self.root_handle()?)?;
        if !valid_root_snapshot(pinned, expected, state) {
            return Err(Error::ConfiguredRootChanged);
        }
        let path_handle = open_root_for_identity_check(&self.path)?;
        let current = root_snapshot(path_handle.0)?;
        if !valid_root_snapshot(current, expected, state) {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }

    fn register(&mut self, file_identity: &[u8]) -> Result<(), Error> {
        self.verify_identity(false)?;
        let identity = configured_sync_root_identity(self.identity);
        register_root_with_identity(
            &self.path,
            &identity,
            Some(file_identity),
            "Raiun Internal Cloud Files Root",
            "0.0.0-internal",
        )?;
        self.registered = true;
        Ok(())
    }

    fn verify_registered(&self) -> Result<(), Error> {
        if !self.registered {
            return Err(Error::ConfiguredRootChanged);
        }
        verify_sync_root_registration(&self.path, self.identity)
    }

    fn unregister(&mut self) -> Result<(), Error> {
        if !self.registered {
            return Ok(());
        }
        if self.connected {
            return Err(Error::ConnectionStateInvalid);
        }
        self.verify_identity(false)?;
        self.verify_registered()?;
        let path = wide_path(&self.path)?;
        // SAFETY: this object owns the still-open no-follow component handles,
        // the root's stable file identity was checked immediately above, and
        // unregister is issued only after its Cloud Files connection drained.
        let result = unsafe { CfUnregisterSyncRoot(path.as_ptr()) };
        if result < 0 {
            return Err(native_error("CfUnregisterSyncRoot configured root", result));
        }
        self.registered = false;
        self.verify_identity(false)
    }
}

#[allow(dead_code)]
impl ConfiguredRootConnection {
    // Admission only: this is not a proof that all filesystem names/content
    // are absent. Reconnected roots deliberately have unknown prior custody.
    pub(super) fn can_admit_vault_session(&self) -> bool {
        self.connected
            && self.root.is_some()
            && self
                .state
                .hydrated_files
                .lock()
                .is_ok_and(|inventory| inventory.is_complete())
    }

    // Only changes population policy on an already owned directory. The caller
    // supplies a current backend identity; the path is merely a locator.
    pub(super) fn refresh_namespace_parent_population(
        &self,
        expected_root: crate::ConfiguredRootIdentity,
        components: &[&str],
        parent: &crate::PlaceholderChild,
    ) -> Result<(), Error> {
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        if !self.connected
            || root.identity.volume_serial != expected_root.volume_serial
            || root.identity.file_index != expected_root.file_index
        {
            return Err(Error::ConfiguredRootChanged);
        }
        enable_configured_directory_population_at(root, parent, components)
    }

    // Future route owner must revoke/drain the exact route and prove complete
    // restart coverage before calling. No public lock wrapper exists yet.
    pub(super) fn cleanup_recorded_vault_files(
        &self,
        expected_root: crate::ConfiguredRootIdentity,
        route_owned: &std::collections::BTreeSet<[u8; 16]>,
    ) -> Result<(), Error> {
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        if root.identity.volume_serial != expected_root.volume_serial
            || root.identity.file_index != expected_root.file_index
        {
            return Err(Error::ConfiguredRootChanged);
        }
        if self.state.has_unresolved_placeholder_data() {
            return Err(Error::UnresolvedPlaceholderEdits);
        }
        let rows = {
            let inventory = self
                .state
                .hydrated_files
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            if !inventory.is_complete() {
                return Err(Error::EditRecoveryUnavailable);
            }
            inventory.snapshot(route_owned)
        };
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        for row in rows {
            let components = row
                .components()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let mut path = root.path.clone();
            for part in &components {
                path.push(part);
            }
            let (_root_final, _parents, _entry, _snapshot) =
                pin_callback_path_chain(&path, root.identity, row.file_index(), row.length())
                    .map_err(|_| Error::ConfiguredRootChanged)?;
            let usn = {
                let file = ProtectedCompletionFile::open(&wide_path(&path)?)?;
                clean_dehydrate_identity(
                    file.protected,
                    root.identity.file_index,
                    row.file_index(),
                    row.identity(),
                )?;
                completion_usn(file.raw, row.file_index())?
            };
            if self.state.has_unresolved_placeholder_data() {
                return Err(Error::UnresolvedPlaceholderEdits);
            }
            self.dehydrate_clean_vault_placeholder(
                &components,
                row.file_index(),
                row.length(),
                row.identity(),
                usn,
            )?;
        }
        // Rows intentionally remain after success, and especially on failure.
        Ok(())
    }

    // Internal per-file primitive only. Before calling, the route owner must
    // revoke/drain hydration and exclude dirty/uncertain recovery using its exact
    // hydration inventory. No public wrapper/caller or vault capability exists.
    pub(super) fn dehydrate_clean_vault_placeholder(
        &self,
        local_components: &[&str],
        expected_file_index: u64,
        expected_length: u64,
        expected_identity: &[u8; 16],
        expected_usn: i64,
    ) -> Result<(), Error> {
        if !self.connected
            || expected_file_index == 0
            || expected_usn <= 0
            || local_components.is_empty()
            || local_components.iter().any(|part| !valid_component(part))
        {
            return Err(Error::ConnectionStateInvalid);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let mut path = root.path.clone();
        for part in local_components {
            path.push(part);
        }
        let (root_final, _ancestors, entry, before) =
            pin_callback_path_chain(&path, root.identity, expected_file_index, expected_length)
                .map_err(|_| Error::ConfiguredRootChanged)?;
        let file = ProtectedCompletionFile::open(&wide_path(&path)?)?;
        let opened = root_snapshot(file.raw)?;
        let entry_final =
            final_path_for_handle(entry.0).map_err(|_| Error::ConfiguredRootChanged)?;
        let opened_final =
            final_path_for_handle(file.raw).map_err(|_| Error::ConfiguredRootChanged)?;
        if !same_edit_snapshot(before, opened)
            || !windows_paths_equal(&entry_final, &opened_final)
            || !windows_path_is_within(&opened_final, &root_final)
            || opened.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || opened.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0
        {
            return Err(Error::ConfiguredRootChanged);
        }
        clean_dehydrate_identity(
            file.protected,
            root.identity.file_index,
            expected_file_index,
            expected_identity,
        )?;
        if modified_ranges_for_handle(file.raw).map_err(|_| Error::EditRecoveryUnavailable)?
            || completion_usn(file.raw, expected_file_index)? != expected_usn
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        let range = CfFileRange {
            starting_offset: 0,
            length: -1,
        };
        let mut usn = expected_usn;
        // SAFETY: exact referenced protected EXCLUSIVE|WRITE_ACCESS handle and all
        // ancestor pins remain live. NULL Overlapped forces synchronous completion.
        // Only VERIFY_IN_SYNC (1): never mark clean, unpin, replace metadata/identity,
        // clear always-full policy, or force dirty dehydration. Nonzero USN guards
        // the complete preflight snapshot against intervening local changes.
        let hr = unsafe {
            CfUpdatePlaceholder(
                file.protected,
                null(),
                null(),
                0,
                (&range as *const CfFileRange).cast(),
                1,
                1,
                &mut usn,
                null_mut(),
            )
        };
        if hr < 0 {
            return Err(native_error("dehydrate clean vault file", hr));
        }
        root.verify_identity(true)?;
        root.verify_registered()?;
        let after = root_snapshot(file.raw)?;
        if after.identity != opened.identity
            || after.file_size != opened.file_size
            || after.last_write_time != opened.last_write_time
        {
            return Err(Error::ConfiguredRootChanged);
        }
        clean_dehydrate_identity(
            file.protected,
            root.identity.file_index,
            expected_file_index,
            expected_identity,
        )?;
        if modified_ranges_for_handle(file.raw).map_err(|_| Error::EditRecoveryUnavailable)? {
            return Err(Error::EditRecoveryUnavailable);
        }
        // A bounded empty ONDISK response is the postcondition. More-data, malformed
        // lengths, or any resident range are cleanup-incomplete, never locked.
        let mut ranges = [CfFileRange {
            starting_offset: 0,
            length: 0,
        }; 64];
        let mut returned = 0;
        let hr = unsafe {
            CfGetPlaceholderRangeInfo(
                file.raw,
                1,
                0,
                -1,
                ranges.as_mut_ptr().cast(),
                size_of_val(&ranges) as u32,
                &mut returned,
            )
        };
        if hr < 0 || returned != 0 {
            return Err(Error::EditRecoveryUnavailable);
        }
        Ok(())
    }

    pub(super) fn acknowledge_verified_edit(
        &self,
        local_components: &[&str],
        publication: &crate::VerifiedEditPublication<'_, '_>,
    ) -> Result<(), Error> {
        macro_rules! observe_completion {
            ($stage:literal) => {
                #[cfg(feature = "synthetic-agent-integration")]
                eprintln!("synthetic_save_completion_stage={}", $stage);
            };
        }
        observe_completion!("connection_and_scope");
        if !self.connected
            || local_components.is_empty()
            || local_components
                .iter()
                .any(|component| !valid_component(component))
        {
            return Err(Error::ConnectionStateInvalid);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let recovery = self
            .state
            .recovery
            .as_ref()
            .ok_or(Error::EditRecoveryUnavailable)?;
        let metadata = publication.proof().metadata();
        if recovery.provider_scope() != publication.provider_scope()
            || metadata.generation != publication.provider_scope().token_generation()
            || metadata.scope.root_volume_serial != root.identity.volume_serial
            || metadata.scope.root_file_index != root.identity.file_index
            || metadata.local_file.volume_serial != root.identity.volume_serial
            || metadata.content_len > MAX_REQUEST_BYTES
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        // The existing backend publication fence also guards every payload
        // CfExecute. Acquire it BEFORE the protected open/reference, avoiding
        // gate/oplock inversion and excluding provider writes for the proof.
        observe_completion!("acquire_publication_and_token_permit");
        publication.publish_and_complete(|| {
            observe_completion!("root_identity_and_registration");
            root.verify_identity(true)?;
            root.verify_registered()?;
            let mut path = root.path.clone();
            for component in local_components {
                path.push(component);
            }
            observe_completion!("pin_local_components");
            let (root_final, _ancestors, entry_guard, before) = pin_callback_path_chain(
                &path,
                root.identity,
                metadata.local_file.file_index,
                metadata.content_len,
            )
            .map_err(|stage| {
                #[cfg(feature = "synthetic-agent-integration")]
                eprintln!("synthetic_save_completion_pin_refused stage={stage}");
                #[cfg(not(feature = "synthetic-agent-integration"))]
                let _ = stage;
                Error::ConfiguredRootChanged
            })?;
            observe_completion!("require_full_local_content");
            if before.placeholder_state & CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK != 0 {
                return Err(Error::EditRecoveryUnavailable);
            }
            let path_wide = wide_path(&path)?;
            // The no-follow chain pins every name. An exclusive Cloud Files
            // handle plus a retained reference protects the exact completion span.
            observe_completion!("open_immutable_completion_stream");
            let file = ProtectedCompletionFile::open(&path_wide)?;
            observe_completion!("validate_opened_stream_identity");
            let opened = root_snapshot(file.raw)?;
            let entry_final =
                final_path_for_handle(entry_guard.0).map_err(|_| Error::ConfiguredRootChanged)?;
            let opened_final =
                final_path_for_handle(file.raw).map_err(|_| Error::ConfiguredRootChanged)?;
            if !same_edit_snapshot(before, opened)
                || !windows_paths_equal(&entry_final, &opened_final)
                || !windows_path_is_within(&opened_final, &root_final)
            {
                return Err(Error::ConfiguredRootChanged);
            }
            observe_completion!("validate_publication_identity");
            verify_completion_identity(file.protected, publication.identity())?;
            // This is a fresh local revalidation snapshot, not a blind new USN
            // sampled after upload. Its full bytes must match the immutable record.
            observe_completion!("capture_nonzero_usn_and_hash");
            let saved_usn = completion_usn(file.raw, metadata.local_file.file_index)?;
            #[cfg(feature = "synthetic-agent-integration")]
            eprintln!("synthetic_save_completion_usn_first={saved_usn}");
            let len = usize::try_from(metadata.content_len)
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            let mut bytes = Zeroizing::new(vec![0_u8; len]);
            file.read_complete(&mut bytes)?;
            if crate::recovery_reconcile::digest_hex(&bytes) != metadata.content_sha256
                || !same_edit_snapshot(opened, root_snapshot(file.raw)?)
                || {
                    let observed_usn = completion_usn(file.raw, metadata.local_file.file_index)?;
                    #[cfg(feature = "synthetic-agent-integration")]
                    eprintln!("synthetic_save_completion_usn_second={observed_usn}");
                    observed_usn != saved_usn
                }
            {
                return Err(Error::EditRecoveryUnavailable);
            }
            root.verify_identity(true)?;
            root.verify_registered()?;
            // The exclusive referenced handle excludes ordinary writers and the
            // same retained publication fence excludes provider payload writes.
            // Both cover the fresh fully-resident hash through durable ACK. OS USN
            // comparison is omitted BY DESIGN under this combined content fence,
            // never as a fallback/retry after a failed comparison. The two positive
            // USN reads above remain an additional pre-call consistency check.
            observe_completion!("native_in_sync_exclusive");
            // SAFETY: same opaque exclusive owner, referenced throughout this
            // closure. No USN comparison/output is requested: the retained
            // combined content fence is the authority, not an optional output.
            // Windows may leave a zero-input USN untouched even on S_OK.
            let result = unsafe { CfSetInSyncState(file.protected, 1, 0, null_mut()) };
            #[cfg(feature = "synthetic-agent-integration")]
            eprintln!("synthetic_save_completion_no_usn_comparison hresult={result}");
            if result < 0 {
                return Err(native_error("complete verified edit in-sync", result));
            }
            observe_completion!("validate_completed_file_identity");
            if root_snapshot(file.raw)?.identity != opened.identity {
                return Err(Error::ConfiguredRootChanged);
            }
            observe_completion!("validate_completed_root_identity");
            root.verify_identity(true)?;
            observe_completion!("validate_completed_registration");
            root.verify_registered()?;
            observe_completion!("validate_completed_publication_identity");
            verify_completion_identity(file.protected, publication.identity())?;
            // Still under the same publication/token permit and held local
            // handle: record only this exact native-completed snapshot. If
            // persistence fails, its encrypted body remains unresolved.
            observe_completion!("persist_local_completion");
            recovery
                .record_local_completion(crate::CompletedLocalEdit::from_native_completion(
                    metadata,
                ))
                .map_err(|error| {
                    #[cfg(feature = "synthetic-agent-integration")]
                    eprintln!("synthetic_save_completion_journal_refused error={error:?}");
                    #[cfg(not(feature = "synthetic-agent-integration"))]
                    let _ = error;
                    Error::EditRecoveryUnavailable
                })
        })
    }
    pub(super) fn take_initial_edit(&self) -> Result<Option<crate::PendingInitialEdit>, Error> {
        if !self.connected {
            return Err(Error::ConnectionStateInvalid);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        self.state
            .initial_edits
            .take()
            .map_err(|_| Error::EditRecoveryUnavailable)
    }

    #[cfg(feature = "synthetic-agent-integration")]
    pub(super) fn directory_observation(&self) -> (usize, usize, usize, usize, usize) {
        (
            DIRECTORY_CALLBACK_ENTRIES.load(Ordering::Relaxed),
            DIRECTORY_CALLBACK_GUARD_REJECTIONS.load(Ordering::Relaxed),
            self.state.directory_callbacks.load(Ordering::Relaxed),
            self.state.last_directory_param_size.load(Ordering::Relaxed),
            self.state
                .placeholder_entries_submitted
                .load(Ordering::Relaxed),
        )
    }

    #[cfg(feature = "synthetic-agent-integration")]
    pub(super) fn fetch_validation_stage(&self) -> usize {
        self.state.fetch_validation_stage.load(Ordering::Relaxed)
    }

    #[cfg(feature = "synthetic-agent-integration")]
    pub(super) fn fetch_observation(&self) -> (usize, usize, usize, i32) {
        (
            self.state.fetch_callbacks.load(Ordering::Relaxed),
            self.state.last_fetch_param_size.load(Ordering::Relaxed),
            self.state.transferred_bytes.load(Ordering::Relaxed),
            self.state.first_failed_hresult.load(Ordering::Relaxed),
        )
    }

    #[cfg(feature = "synthetic-agent-integration")]
    pub(super) fn close_observation_for_integration(
        &self,
    ) -> (usize, usize, usize, usize, usize, i32, usize, usize) {
        (
            self.state
                .modified_placeholder_closes
                .load(Ordering::Acquire),
            self.state
                .unverifiable_placeholder_closes
                .load(Ordering::Acquire),
            self.state
                .close_completion_callbacks
                .load(Ordering::Relaxed),
            self.state.last_close_param_size.load(Ordering::Relaxed),
            self.state
                .last_close_validation_stage
                .load(Ordering::Relaxed),
            self.state
                .last_close_validation_hresult
                .load(Ordering::Relaxed),
            self.state
                .last_close_path_common_prefix_bytes
                .load(Ordering::Relaxed),
            self.state
                .journaled_placeholder_closes
                .load(Ordering::Acquire),
        )
    }

    #[cfg(feature = "synthetic-agent-integration")]
    pub(super) fn placeholder_observation(
        &self,
        relative_components: &[&str],
    ) -> Result<(u32, u32, u32, u64), Error> {
        if relative_components.is_empty()
            || relative_components.len() > 16
            || relative_components
                .iter()
                .any(|part| !valid_component(part))
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let mut path = root.path.clone();
        for component in relative_components {
            path.push(component);
        }
        let wide = wide_path(&path)?;
        // SAFETY: the requested relative components are validated and bounded;
        // OPEN_REPARSE_POINT observes the exact Cloud Files entry without
        // following it, and the root registration is checked around the query.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("inspect synthetic placeholder state"));
        }
        let handle = RawOwnedHandle(raw);
        let snapshot = root_snapshot(handle.0)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        Ok((
            snapshot.file_attributes,
            snapshot.reparse_tag,
            snapshot.placeholder_state,
            snapshot.file_size,
        ))
    }

    #[cfg(feature = "synthetic-agent-integration")]
    pub(super) fn hydrate_test_placeholder(
        &self,
        relative_components: &[&str],
    ) -> Result<i32, Error> {
        if relative_components.is_empty()
            || relative_components.len() > 16
            || relative_components
                .iter()
                .any(|part| !valid_component(part))
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let mut path = root.path.clone();
        for component in relative_components {
            path.push(component);
        }
        let wide = wide_path(&path)?;
        // SAFETY: this is a test-only request for one validated fixture file.
        // The no-follow handle pins the exact placeholder name while Cloud
        // Files performs its documented hydration operation.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("open synthetic placeholder for hydration"));
        }
        let handle = RawOwnedHandle(raw);
        let snapshot = root_snapshot(handle.0)?;
        if snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
            || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || snapshot.file_size > MAX_FILE_BYTES
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let result = unsafe { CfHydratePlaceholder(handle.0, 0, -1, 0, null_mut()) };
        root.verify_identity(true)?;
        root.verify_registered()?;
        Ok(result)
    }

    pub(super) fn connect(runtime: PreparedConfiguredRootRuntime) -> Result<Self, Error> {
        let PreparedConfiguredRootRuntime {
            root: configured_root,
            backend,
            composite_root_identity,
            recovery,
        } = runtime;
        let path = configured_root.path;
        let identity = configured_root.identity;
        let registered = configured_root.registered;
        let lease = configured_root._native;
        let backend: Arc<dyn PlaceholderBackend> = backend;
        if identity != lease.identity {
            return Err(Error::InvalidConfiguredRoot);
        }
        let mut root = Box::new(OwnedConfiguredRoot::new(path, lease, registered)?);
        // Do every fallible path conversion before creating a system
        // registration so a malformed path cannot strand an unowned root.
        let wide_root = wide_path(&root.path)?;
        let already_registered = root.registered;
        if already_registered {
            root.verify_registered()?;
        } else {
            root.register(composite_root_identity.as_bytes())?;
        }

        let mut state = CallbackState::new_for_root(
            Arc::clone(&backend),
            root.path.clone(),
            root.identity,
            Some(recovery),
        );
        // A new process has no complete history of plaintext published through
        // this retained registration. Empty current rows cannot prove cleanup.
        if already_registered {
            state
                .hydrated_files
                .get_mut()
                .map_err(|_| Error::EditRecoveryUnavailable)?
                .mark_incomplete();
        }
        let state = Arc::new(state);
        state.record_reconnect_scan(scan_registered_root(&root.path, root.identity));
        let context_key = Arc::as_ptr(&state) as usize;
        callback_registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(context_key, Arc::clone(&state));
        let callback_table = callback_table();
        let mut connection_key = CfConnectionKey { internal: 0 };
        // SAFETY: root path and callback table stay alive for the call. The
        // context is an opaque key resolved only through the protected map.
        let result = unsafe {
            CfConnectSyncRoot(
                wide_root.as_ptr(),
                callback_table.as_ptr(),
                context_key as *const c_void,
                // Admission validates the callback path against pinned native
                // identities; request the path without relaxing those checks.
                CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH,
                &mut connection_key,
            )
        };
        if result < 0 {
            state.fail_initial_readiness();
            callback_registry()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&context_key);
            state.wait_for_callbacks();
            if already_registered {
                // A reconnect failure must not unregister a previously owned
                // root or remove its placeholder namespace. Keep its on-disk
                // registration intact for the next explicit reconnect.
                root.verify_registered()?;
                return Err(native_error("CfConnectSyncRoot configured root", result));
            }
            if let Err(cleanup_error) = root.unregister() {
                // Keep both the root handle lease and the successful native
                // registration alive for process lifetime when rollback is
                // rejected. Never release ownership and later clean by path.
                let _ = Box::leak(root);
                return Err(cleanup_error);
            }
            return Err(native_error("CfConnectSyncRoot configured root", result));
        }

        root.connected = true;
        if let Err(error) = root.verify_identity(true) {
            state.fail_initial_readiness();
            let mut connection = Self {
                root: Some(root),
                state,
                context_key,
                connection_key,
                connected: true,
            };
            if connection.finish(false).is_err() {
                let _ = Box::leak(Box::new(connection));
            }
            return Err(error);
        }
        let mut connection = Self {
            root: Some(root),
            state,
            context_key,
            connection_key,
            connected: true,
        };
        let initialized = (|| {
            let root = connection
                .root
                .as_mut()
                .ok_or(Error::ConnectionStateInvalid)?;
            if !already_registered {
                populate_initial_sync_root(
                    root,
                    backend.as_ref(),
                    composite_root_identity.as_bytes(),
                )?;
            }
            // Retain every immediate-child pin through the Ready publication,
            // including on first connection after the individual create/update calls.
            let _namespace_pins = verify_existing_initial_sync_root(
                root,
                backend.as_ref(),
                composite_root_identity.as_bytes(),
                !already_registered,
            )?;
            root.verify_identity(true)?;
            root.verify_registered()?;
            connection.state.publish_initial_readiness()
        })();
        if let Err(error) = initialized {
            connection.state.fail_initial_readiness();
            if let Err(cleanup_error) = connection.finish(false) {
                connection.preserve_after_cleanup_failure();
                return Err(cleanup_error);
            }
            return Err(error);
        }
        Ok(connection)
    }

    pub(super) fn disconnect(&mut self) -> Result<(), Error> {
        self.finish(false)
    }

    pub(super) fn unregister(mut self) -> Result<(), Error> {
        self.finish(true)
    }

    fn finish(&mut self, unregister: bool) -> Result<(), Error> {
        if self.root.is_none() && !self.connected {
            return Ok(());
        }
        if self.connected {
            self.state.close_readiness();
            // Keep callback state registered through CfDisconnectSyncRoot;
            // Windows may deliver callbacks while the disconnect is running.
            let result = unsafe { CfDisconnectSyncRoot(self.connection_key) };
            if result < 0 {
                return Err(native_error("CfDisconnectSyncRoot configured root", result));
            }
            self.connected = false;
            if let Some(root) = self.root.as_mut() {
                root.connected = false;
            }
        }
        let removed = callback_registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.context_key);
        if removed.is_none() {
            return Err(Error::ConnectionStateInvalid);
        }
        self.state.cancel_all_requests();
        self.state.wait_for_callbacks();
        let root = self.root.as_mut().ok_or(Error::ConnectionStateInvalid)?;
        root.verify_identity(false)?;
        root.verify_registered()?;
        if unregister {
            // Callback counters are process-local. Rescan the exact pinned
            // registered tree immediately before destructive unregister so
            // edits/materialized files left by an earlier process remain a
            // hard stop. An incomplete/over-limit scan is unresolved too.
            self.state
                .record_reconnect_scan(scan_registered_root(&root.path, root.identity));
        }
        if unregister && self.state.has_unresolved_placeholder_data() {
            return Err(Error::UnresolvedPlaceholderEdits);
        }
        if unregister {
            root.unregister()?;
        }
        // Ordinary disconnect drops only this process's handles and callback
        // state. The OS registration and placeholder namespace remain intact.
        self.root.take();
        self.connected = false;
        Ok(())
    }

    fn preserve_after_cleanup_failure(&mut self) {
        if let Some(root) = self.root.take() {
            let _ = Box::leak(root);
        }
    }
}

impl Drop for ConfiguredRootConnection {
    fn drop(&mut self) {
        if self.finish(false).is_err() {
            self.preserve_after_cleanup_failure();
        }
    }
}

#[allow(dead_code)]
fn callback_table() -> [CfCallbackRegistration; 6] {
    [
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_FETCH_DATA,
            callback: Some(fetch_data_callback),
        },
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
            callback: Some(cancel_fetch_data_callback),
        },
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
            callback: Some(fetch_placeholders_callback),
        },
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS,
            callback: Some(cancel_fetch_placeholders_callback),
        },
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
            callback: Some(notify_file_close_completion_callback),
        },
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_NONE,
            callback: None,
        },
    ]
}

unsafe extern "system" fn notify_file_close_completion_callback(
    info: *const CfCallbackInfo,
    parameters: *const CfCallbackParameters,
) {
    let Some(guard) = callback_guard(info) else {
        return;
    };
    if info.is_null() || parameters.is_null() {
        guard
            .0
            .unverifiable_placeholder_closes
            .fetch_add(1, Ordering::AcqRel);
        return;
    }
    // SAFETY: Cloud Files owns both structures throughout this notification;
    // ParamSize is checked before the callback-specific union arm is read.
    let info = unsafe { &*info };
    let parameters = unsafe { &*parameters };
    if !valid_close_completion_param_size(parameters.param_size as usize) {
        guard
            .0
            .unverifiable_placeholder_closes
            .fetch_add(1, Ordering::AcqRel);
        return;
    }
    guard
        .0
        .close_completion_callbacks
        .fetch_add(1, Ordering::Relaxed);
    guard
        .0
        .last_close_param_size
        .store(parameters.param_size as usize, Ordering::Relaxed);
    // SAFETY: this notification selects the one-ULONG CloseCompletion arm,
    // covered by the validated documented or aligned ParamSize.
    let flags = unsafe { parameters.data.close_completion.flags };
    if flags & !CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED != 0 {
        guard
            .0
            .unverifiable_placeholder_closes
            .fetch_add(1, Ordering::AcqRel);
        return;
    }
    guard.0.record_placeholder_close(info, flags);
}

fn valid_close_completion_param_size(value: usize) -> bool {
    value == size_of::<CfCallbackCloseCompletion>() + size_of::<u32>()
        || value
            == std::mem::offset_of!(CfCallbackParameters, data)
                + size_of::<CfCallbackCloseCompletion>()
}

struct CallbackPathGuard {
    path: PathBuf,
    root_final_path: PathBuf,
    _directory_chain: Vec<RawOwnedHandle>,
    entry: RawOwnedHandle,
    snapshot: RootSnapshot,
}

fn callback_path(
    root_path: &Path,
    volume_dos_name: *const u16,
    normalized_path: *const u16,
    expected_root: RootIdentity,
    expected_file_id: u64,
    expected_size: u64,
    mismatch_prefix_bytes: &AtomicUsize,
) -> Result<CallbackPathGuard, u8> {
    let dos_name = unsafe { read_bounded_wide_string(volume_dos_name).map_err(|_| 1)? };
    let normalized = unsafe { read_bounded_wide_string(normalized_path).map_err(|_| 2)? };
    if dos_name.len() != 2 || !dos_name.ends_with(':') {
        return Err(3);
    }
    let dos_name_wide = wide_literal(&dos_name);
    let mut device_target = vec![0_u16; 32_768];
    let device_len = unsafe {
        QueryDosDeviceW(
            dos_name_wide.as_ptr(),
            device_target.as_mut_ptr(),
            device_target.len() as u32,
        )
    } as usize;
    if device_len == 0 {
        return Err(4);
    }
    if device_len >= device_target.len() {
        return Err(5);
    }
    let device_end = device_target[..device_len]
        .iter()
        .position(|word| *word == 0)
        .ok_or(6)?;
    let device = String::from_utf16(&device_target[..device_end]).map_err(|_| 7)?;
    let normalized = normalized.replace('/', "\\");
    if normalized
        .split('\\')
        .any(|component| component == "." || component == "..")
    {
        return Err(8);
    }
    let device = device.trim_end_matches('\\');
    let absolute = match callback_path_suffix(&normalized, &dos_name, device) {
        Ok(suffix) => format!("{dos_name}{suffix}"),
        Err(form) => {
            let common_prefix = normalized
                .bytes()
                .zip(device.bytes())
                .take_while(|(left, right)| left.eq_ignore_ascii_case(right))
                .count();
            mismatch_prefix_bytes.store(common_prefix, Ordering::Release);
            // Keep diagnostics structural only. Never record either callback
            // path or a user-visible filename.
            return Err(match form {
                NormalizedPathForm::NtDos => 21,
                NormalizedPathForm::Win32Dos => 22,
                NormalizedPathForm::DriveAbsolute => 23,
                NormalizedPathForm::VolumeRooted => 24,
                NormalizedPathForm::Other => 25,
                NormalizedPathForm::Device => 26,
            });
        }
    };
    let path = PathBuf::from(std::ffi::OsString::from_wide(
        &absolute.encode_utf16().collect::<Vec<_>>(),
    ));
    let lexical_match = windows_path_is_within(&path, root_path);
    if !lexical_match {
        let common_prefix_bytes = containment_common_prefix_bytes(&path, root_path);
        mismatch_prefix_bytes.store(common_prefix_bytes, Ordering::Release);
    }
    if !lexical_match && !is_supported_local_drive_path(&path) {
        return Err(13);
    }
    // Walk every path component from the drive root using no-follow handles.
    // Before the configured root, only ordinary directories are accepted; the
    // root must match its registered volume/file ID. Below it, only ordinary
    // directories or Cloud Files directory placeholders are accepted.
    let (root_final_path, directory_chain, entry, snapshot) =
        pin_callback_path_chain(&path, expected_root, expected_file_id, expected_size)
            .map_err(|stage| 13 + stage)?;
    Ok(CallbackPathGuard {
        path,
        root_final_path,
        _directory_chain: directory_chain,
        entry,
        snapshot,
    })
}

fn pin_callback_path_chain(
    path: &Path,
    expected_root: RootIdentity,
    expected_file_id: u64,
    expected_size: u64,
) -> Result<(PathBuf, Vec<RawOwnedHandle>, RawOwnedHandle, RootSnapshot), u8> {
    if !is_supported_local_drive_path(path) {
        return Err(1);
    }
    let text = path.to_str().ok_or(2)?;
    let components: Vec<&str> = text[3..].split('\\').collect();
    if components.is_empty()
        || components.iter().any(|component| {
            component.is_empty()
                || *component == "."
                || *component == ".."
                || component.contains(':')
        })
    {
        return Err(3);
    }
    let drive_root = PathBuf::from(&text[..3]);
    let mut current = drive_root;
    let mut directories = Vec::with_capacity(components.len());
    let drive_root_wide = wide_path(&current).map_err(|_| 4)?;
    let drive_root_raw = unsafe {
        CreateFileW(
            drive_root_wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if drive_root_raw.is_null() || drive_root_raw == INVALID_HANDLE_VALUE {
        return Err(5);
    }
    let drive_root_handle = RawOwnedHandle(drive_root_raw);
    let drive_root_snapshot = root_snapshot(drive_root_handle.0).map_err(|_| 6)?;
    if drive_root_snapshot.identity.volume_serial != expected_root.volume_serial
        || drive_root_snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || !valid_callback_directory_snapshot(drive_root_snapshot)
    {
        return Err(7);
    }
    directories.push(drive_root_handle);
    let mut expected_root_snapshot = None;
    let mut root_final_path: Option<PathBuf> = None;
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        let is_file = index + 1 == components.len();
        let wide = wide_path(&current).map_err(|_| 4)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if is_file {
                        0
                    } else {
                        FILE_FLAG_BACKUP_SEMANTICS
                    },
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(5);
        }
        let handle = RawOwnedHandle(raw);
        let snapshot = root_snapshot(handle.0).map_err(|_| 6)?;
        if is_file {
            let Some(root_snapshot) = expected_root_snapshot else {
                return Err(8);
            };
            if !valid_callback_entry_snapshot(
                root_snapshot,
                snapshot,
                expected_root,
                expected_file_id,
                expected_size,
            ) {
                return Err(9);
            }
            let root_final = root_final_path.ok_or(10)?;
            let file_final = final_path_for_handle(handle.0).map_err(|_| 11)?;
            if !windows_path_is_within(&file_final, &root_final) {
                return Err(12);
            }
            return Ok((root_final, directories, handle, snapshot));
        }

        if snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || snapshot.identity.volume_serial != expected_root.volume_serial
        {
            return Err(13);
        }
        if expected_root_snapshot.is_none() {
            if snapshot.identity == expected_root {
                if !valid_root_snapshot(snapshot, expected_root, RootSnapshotState::Connected) {
                    return Err(14);
                }
                root_final_path = Some(final_path_for_handle(handle.0).map_err(|_| 15)?);
                expected_root_snapshot = Some(snapshot);
            } else if snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || snapshot.reparse_tag != 0
                || snapshot.placeholder_state != 0
            {
                // Do not traverse junctions/symlinks or unknown Cloud Files
                // roots while resolving a callback path to the configured root.
                return Err(16);
            }
        } else if !valid_callback_directory_snapshot(snapshot) {
            return Err(17);
        }
        directories.push(handle);
    }
    Err(18)
}

fn valid_callback_directory_snapshot(snapshot: RootSnapshot) -> bool {
    if snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return snapshot.reparse_tag == 0 && snapshot.placeholder_state == 0;
    }
    snapshot.reparse_tag & IO_REPARSE_TAG_CLOUD_MASK
        == (IO_REPARSE_TAG_CLOUD & IO_REPARSE_TAG_CLOUD_MASK)
        && snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER != 0
        && snapshot.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT == 0
        && snapshot.placeholder_state & !0x3f == 0
}

fn valid_callback_entry_snapshot(
    root: RootSnapshot,
    child: RootSnapshot,
    expected_root: RootIdentity,
    expected_file_id: u64,
    expected_size: u64,
) -> bool {
    valid_root_snapshot(root, expected_root, RootSnapshotState::Connected)
        && child.identity.volume_serial == expected_root.volume_serial
        && child.identity.file_index == expected_file_id
        && child.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        && child.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && child.reparse_tag & IO_REPARSE_TAG_CLOUD_MASK
            == (IO_REPARSE_TAG_CLOUD & IO_REPARSE_TAG_CLOUD_MASK)
        && child.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER != 0
        && child.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT == 0
        && child.placeholder_state & !0x3f == 0
        && child.file_size == expected_size
        && child.file_size <= MAX_FILE_BYTES
}

fn is_supported_local_drive_path(path: &Path) -> bool {
    let Some(path) = path.to_str() else {
        return false;
    };
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
        && !path.starts_with("\\\\")
        && !path.starts_with("\\\\?\\")
        && !path.starts_with("\\\\.\\")
}

fn windows_paths_equal(left: &Path, right: &Path) -> bool {
    normalize_windows_containment_path(left)
        .eq_ignore_ascii_case(&normalize_windows_containment_path(right))
}

fn final_path_for_handle(handle: Handle) -> Result<PathBuf, ()> {
    let required = unsafe { GetFinalPathNameByHandleW(handle, null_mut(), 0, 0) } as usize;
    if required == 0 || required > 32_768 {
        return Err(());
    }
    let mut buffer = vec![0_u16; required.saturating_add(1)];
    let written =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) }
            as usize;
    if written == 0 || written >= buffer.len() {
        return Err(());
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..written],
    )))
}

fn containment_common_prefix_bytes(path: &Path, root: &Path) -> usize {
    let path = normalize_windows_containment_path(path);
    let root = normalize_windows_containment_path(root);
    path.bytes()
        .zip(root.bytes())
        .take_while(|(left, right)| left.eq_ignore_ascii_case(right))
        .count()
}

fn callback_path_suffix<'a>(
    normalized: &'a str,
    volume_dos_name: &str,
    volume_device_name: &str,
) -> Result<&'a str, NormalizedPathForm> {
    if let Some(suffix) = normalized
        .get(..volume_device_name.len())
        .and_then(|prefix| {
            prefix
                .eq_ignore_ascii_case(volume_device_name)
                .then(|| normalized.get(volume_device_name.len()..))
                .flatten()
        })
    {
        return suffix
            .starts_with('\\')
            .then_some(suffix)
            .ok_or(NormalizedPathForm::Other);
    }
    match normalized_path_form(normalized, volume_dos_name) {
        NormalizedPathForm::NtDos => Ok(normalized.get(6..).ok_or(NormalizedPathForm::Other)?),
        NormalizedPathForm::Win32Dos => Ok(normalized.get(6..).ok_or(NormalizedPathForm::Other)?),
        NormalizedPathForm::DriveAbsolute => {
            Ok(normalized.get(2..).ok_or(NormalizedPathForm::Other)?)
        }
        NormalizedPathForm::VolumeRooted if !normalized.starts_with("\\\\") => Ok(normalized),
        form => Err(form),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizedPathForm {
    Device,
    NtDos,
    Win32Dos,
    DriveAbsolute,
    VolumeRooted,
    Other,
}

fn normalized_path_form(path: &str, volume_dos_name: &str) -> NormalizedPathForm {
    if path.starts_with("\\Device\\") {
        NormalizedPathForm::Device
    } else if path
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("\\??\\"))
        && path
            .get(4..6)
            .is_some_and(|drive| drive.eq_ignore_ascii_case(volume_dos_name))
        && path.as_bytes().get(6) == Some(&b'\\')
    {
        NormalizedPathForm::NtDos
    } else if path
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("\\\\?\\"))
        && path
            .get(4..6)
            .is_some_and(|drive| drive.eq_ignore_ascii_case(volume_dos_name))
        && path.as_bytes().get(6) == Some(&b'\\')
    {
        NormalizedPathForm::Win32Dos
    } else if path
        .get(..2)
        .is_some_and(|drive| drive.eq_ignore_ascii_case(volume_dos_name))
        && path.as_bytes().get(2) == Some(&b'\\')
    {
        NormalizedPathForm::DriveAbsolute
    } else if path.starts_with('\\') {
        NormalizedPathForm::VolumeRooted
    } else {
        NormalizedPathForm::Other
    }
}

unsafe fn read_bounded_wide_string(pointer: *const u16) -> Result<String, ()> {
    if pointer.is_null() {
        return Err(());
    }
    let mut words = Vec::new();
    for index in 0..32_768 {
        // SAFETY: the callback owns a valid NUL-terminated string for the
        // callback duration; scanning is bounded to the Windows path limit.
        let word = unsafe { pointer.add(index).read() };
        if word == 0 {
            return String::from_utf16(&words).map_err(|_| ());
        }
        words.push(word);
    }
    Err(())
}

fn windows_path_is_within(path: &Path, root: &Path) -> bool {
    let path = normalize_windows_containment_path(path);
    let root = normalize_windows_containment_path(root);
    let Some(prefix) = path.get(..root.len()) else {
        return false;
    };
    path.len() > root.len()
        && prefix.eq_ignore_ascii_case(&root)
        && path.as_bytes().get(root.len()) == Some(&b'\\')
}

fn normalize_windows_containment_path(value: &Path) -> String {
    let value = value.to_string_lossy().replace('/', "\\");
    let value = strip_drive_namespace_prefix(&value);
    value.trim_end_matches('\\').to_owned()
}

/// Windows exposes the same local path through ordinary DOS spelling and
/// the documented extended drive prefixes. Treat only these drive prefixes
/// as equivalent; volume/device/UNC aliases remain distinct and fail closed.
fn strip_drive_namespace_prefix(value: &str) -> &str {
    for prefix in ["\\\\?\\", "\\??\\"] {
        if value
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        {
            let remainder = &value[prefix.len()..];
            if remainder.as_bytes().get(1) == Some(&b':')
                && remainder.as_bytes().get(2) == Some(&b'\\')
                && remainder.as_bytes()[0].is_ascii_alphabetic()
            {
                return remainder;
            }
        }
    }
    value
}

#[cfg(test)]
fn short_windows_path(path: &Path) -> Option<PathBuf> {
    let input = wide_path(path).ok()?;
    let needed = unsafe { GetShortPathNameW(input.as_ptr(), null_mut(), 0) } as usize;
    if needed == 0 || needed > 32_768 {
        return None;
    }
    let mut output = vec![0_u16; needed + 1];
    let written =
        unsafe { GetShortPathNameW(input.as_ptr(), output.as_mut_ptr(), output.len() as u32) }
            as usize;
    if written == 0 || written >= output.len() {
        return None;
    }
    output.truncate(written);
    Some(PathBuf::from(std::ffi::OsString::from_wide(&output)))
}

impl Drop for OwnedSyntheticRoot {
    fn drop(&mut self) {
        // Failure is intentionally not followed by path cleanup. The root is
        // left in place rather than risking deletion after an unverifiable
        // unregister result. Explicit test cleanup reports the failure.
        if !self.preserve_registration_on_drop
            && self.registered
            && self.verify_contents(self.fixture_created).is_ok()
            && self.unregister_inner().is_ok()
        {
            let _ = self.remove_owned_root(self.fixture_created);
        }
    }
}

impl SyntheticConnection {
    pub(super) fn connect(root: OwnedSyntheticRoot) -> Result<Self, Error> {
        Self::connect_with_backend(root, Arc::new(SyntheticBackend), true, None)
    }

    #[cfg(test)]
    pub(super) fn connect_with_opencloud_backend(
        mut root: OwnedSyntheticRoot,
        backend: Arc<crate::OpenCloudPlaceholderBackend>,
        remote_identity: Vec<u8>,
        expected_hydrated_payload: Vec<u8>,
        recovery: Option<Arc<dyn PreparedEditRecovery>>,
    ) -> Result<Self, Error> {
        if let Some(prepared) = &recovery {
            if prepared.root_identity() != root.identity_for_test()?
                || prepared.provider_scope() != backend.scope()
                || backend.is_revoked()
            {
                return Err(Error::EditRecoveryUnavailable);
            }
        }
        let metadata = backend
            .lookup(&remote_identity)
            .map_err(|_| Error::SyntheticCallbackFailed)?
            .ok_or(Error::SyntheticCallbackFailed)?;
        let payload_len = expected_hydrated_payload.len();
        if metadata.is_directory || metadata.length != payload_len as u64 {
            return Err(Error::SyntheticCallbackFailed);
        }
        if payload_len == 0 || payload_len as u64 > MAX_FILE_BYTES {
            return Err(Error::SyntheticCallbackFailed);
        }
        root.synthetic_payload_len = payload_len;
        root.expected_hydrated_payload = Some(expected_hydrated_payload);
        let bridge = OpenCloudFixtureBackend {
            remote: backend,
            remote_identity,
        };
        Self::connect_with_backend(root, Arc::new(bridge), true, recovery)
    }

    #[cfg(test)]
    pub(super) fn reconnect_existing_for_test(root: OwnedSyntheticRoot) -> Result<Self, Error> {
        Self::connect_with_backend(root, Arc::new(SyntheticBackend), false, None)
    }

    fn connect_with_backend(
        root: OwnedSyntheticRoot,
        backend: Arc<dyn PlaceholderBackend>,
        create_fixture: bool,
        recovery: Option<Arc<dyn PreparedEditRecovery>>,
    ) -> Result<Self, Error> {
        let root = Box::new(root);
        if create_fixture {
            root.verify_contents(false)?;
        } else {
            root.verify_identity()?;
            verify_synthetic_sync_root_registration(&root.path, root.identity)?;
        }
        let state = Arc::new(CallbackState::new_for_root(
            backend,
            root.path.clone(),
            root.identity,
            recovery,
        ));
        state.record_reconnect_scan(scan_registered_root(&root.path, root.identity));
        let context_key = Arc::as_ptr(&state) as usize;
        callback_registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(context_key, Arc::clone(&state));
        let callback_table = [
            CfCallbackRegistration {
                callback_type: CF_CALLBACK_TYPE_FETCH_DATA,
                callback: Some(fetch_data_callback),
            },
            CfCallbackRegistration {
                callback_type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
                callback: Some(cancel_fetch_data_callback),
            },
            CfCallbackRegistration {
                callback_type: CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
                callback: Some(fetch_placeholders_callback),
            },
            CfCallbackRegistration {
                callback_type: CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS,
                callback: Some(cancel_fetch_placeholders_callback),
            },
            CfCallbackRegistration {
                callback_type: CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
                callback: Some(notify_file_close_completion_callback),
            },
            CfCallbackRegistration {
                callback_type: CF_CALLBACK_TYPE_NONE,
                callback: None,
            },
        ];
        let path = wide_path(&root.path)?;
        let mut connection_key = CfConnectionKey { internal: 0 };
        // SAFETY: path/table remain valid for this call; table has the required
        // sentinel. CallbackContext is an opaque registry key, never dereferenced.
        let result = unsafe {
            CfConnectSyncRoot(
                path.as_ptr(),
                callback_table.as_ptr(),
                context_key as *const c_void,
                0,
                &mut connection_key,
            )
        };
        if result < 0 {
            callback_registry()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&context_key);
            return Err(native_error("CfConnectSyncRoot", result));
        }
        let mut root = root;
        root.connected = true;
        let mut connected = Self {
            root: Some(root),
            state,
            context_key,
            connection_key,
            connected: true,
            placeholder_created: false,
        };
        if create_fixture {
            connected.create_synthetic_placeholder()?;
            connected.placeholder_created = true;
        }
        connected
            .root
            .as_ref()
            .ok_or(Error::SyntheticRootChanged)?
            .verify_identity()?;
        connected.state.publish_initial_readiness()?;
        Ok(connected)
    }

    fn create_synthetic_placeholder(&mut self) -> Result<(), Error> {
        let root = self.root.as_mut().ok_or(Error::SyntheticRootChanged)?;
        root.verify_contents(false)?;
        let names = FIXTURE_ITEMS
            .iter()
            .map(|item| wide_literal(item.name))
            .collect::<Vec<_>>();
        let mut identities = FIXTURE_ITEMS
            .iter()
            .map(|item| *item.identity)
            .collect::<Vec<_>>();
        let mut infos = FIXTURE_ITEMS
            .iter()
            .enumerate()
            .map(|(index, item)| CfPlaceholderCreateInfo {
                relative_file_name: names[index].as_ptr(),
                fs_metadata: CfFsMetadata {
                    basic_info: FileBasicInfo {
                        creation_time: 132_223_104_000_000_000,
                        last_access_time: 132_223_104_000_000_000,
                        last_write_time: 132_223_104_000_000_000,
                        change_time: 132_223_104_000_000_000,
                        file_attributes: if item.is_directory {
                            FILE_ATTRIBUTE_DIRECTORY
                        } else {
                            FILE_ATTRIBUTE_ARCHIVE
                        },
                    },
                    file_size: root.fixture_len(item) as i64,
                },
                file_identity: identities[index].as_mut_ptr().cast(),
                file_identity_length: identities[index].len() as u32,
                // A directory's namespace is not yet in sync merely because
                // its placeholder exists. Keep directory placeholders out of
                // sync until their bounded child listing is transferred so
                // Cloud Files requests FETCH_PLACEHOLDERS on access.
                flags: if item.is_directory {
                    0
                } else {
                    CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
                },
                result: 0,
                create_usn: 0,
            })
            .collect::<Vec<_>>();
        let path = wide_path(&root.path)?;
        for (index, info) in infos.iter_mut().enumerate() {
            let mut processed = 0_u32;
            // SAFETY: the bounded fixture arrays and their names/identities
            // remain valid for the synchronous one-entry call. Creating one
            // item at a time isolates native failures and permits exact
            // cleanup of the prefix already created.
            let result = unsafe {
                CfCreatePlaceholders(
                    path.as_ptr(),
                    info,
                    1,
                    CF_CREATE_FLAG_STOP_ON_ERROR,
                    &mut processed,
                )
            };
            if result < 0 || processed != 1 || info.result < 0 {
                let hresult = if result < 0 {
                    result
                } else if info.result < 0 {
                    info.result
                } else {
                    STATUS_UNSUCCESSFUL
                };
                eprintln!(
                    "synthetic CfCreatePlaceholders failed: item_index={index} hresult={hresult:#010x} processed={processed} item_result={:#010x}",
                    info.result
                );
                root.remove_created_fixture_entries()?;
                return Err(native_error("CfCreatePlaceholders", hresult));
            }
            let snapshot = match entry_snapshot(
                &root.path.join(FIXTURE_ITEMS[index].name),
                FIXTURE_ITEMS[index].is_directory,
            ) {
                Ok(snapshot)
                    if snapshot.identity.volume_serial == root.identity.volume_serial
                        && valid_fixture_entry(
                            snapshot,
                            FIXTURE_ITEMS[index].is_directory,
                            root.fixture_len(&FIXTURE_ITEMS[index]) as u64,
                            true,
                        ) =>
                {
                    snapshot
                }
                _ => {
                    root.remove_created_fixture_entries()?;
                    return Err(Error::SyntheticRootChanged);
                }
            };
            root.fixture_identities[index] = Some(snapshot.identity);
        }
        root.fixture_created = true;
        root.capture_fixture_identities()?;
        root.verify_contents(true)
    }

    pub(super) fn enumerate(&self) -> Result<Vec<SyntheticEntry>, Error> {
        let root = self.root.as_ref().ok_or(Error::SyntheticRootChanged)?;
        root.verify_contents_with_materialized_directories(true, true)?;
        Ok(FIXTURE_ITEMS
            .iter()
            .map(|item| SyntheticEntry {
                name: item.name.to_owned(),
                is_file: !item.is_directory,
                len: root.fixture_len(item) as u64,
            })
            .collect())
    }

    #[cfg(test)]
    pub(super) fn fixture_presence_for_test(&self) -> [bool; 5] {
        let Some(root) = self.root.as_ref() else {
            return [false; 5];
        };
        root.fixture_presence_for_test()
    }

    #[cfg(test)]
    pub(super) fn owned_fixture_directory_path_for_test(
        &self,
        directory_name: &str,
    ) -> Result<PathBuf, Error> {
        let Some(_) = directory_cloud_identity(directory_name) else {
            return Err(Error::SyntheticCallbackFailed);
        };
        let root = self.root.as_ref().ok_or(Error::SyntheticRootChanged)?;
        root.verify_contents_with_materialized_directories(true, true)?;
        let path = root.path.join(directory_name);
        let identity = root.fixture_identity(directory_name)?;
        let _guard = open_fixture_entry(&path, identity, FILE_READ_ATTRIBUTES, true, 0, true)?;
        Ok(path)
    }

    pub(super) fn enumerate_directory(
        &mut self,
        directory_name: &str,
    ) -> Result<Vec<SyntheticEntry>, Error> {
        let item = match directory_name {
            FIRST_FOLDER_NAME => &NESTED_FIXTURE_ITEM,
            #[cfg(test)]
            SECOND_FOLDER_NAME => &SECOND_FOLDER_CHILD_FIXTURE_ITEM,
            _ => return Err(Error::SyntheticCallbackFailed),
        };
        let root = self.root.as_mut().ok_or(Error::SyntheticRootChanged)?;
        root.verify_contents_with_materialized_directories(true, true)?;
        let folder_path = root.path.join(directory_name);
        let folder_identity = root.fixture_identity(directory_name)?;
        let _folder_guard = open_fixture_entry(
            &folder_path,
            folder_identity,
            FILE_READ_ATTRIBUTES,
            true,
            0,
            true,
        )?;
        let entries = fs::read_dir(&folder_path)
            .map_err(|error| io_error("enumerate synthetic nested folder", error))?;
        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| io_error("read synthetic nested entry", error))?;
            if entry.file_name() != item.name {
                return Err(Error::SyntheticRootChanged);
            }
            let file_type = entry
                .file_type()
                .map_err(|error| io_error("inspect synthetic nested entry", error))?;
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(Error::SyntheticRootChanged);
            }
            let snapshot = entry_snapshot(&entry.path(), false)?;
            if !valid_fixture_entry(snapshot, false, item.len as u64, true) {
                return Err(Error::SyntheticRootChanged);
            }
            if directory_name == FIRST_FOLDER_NAME {
                root.nested_identity = Some(snapshot.identity);
            } else {
                #[cfg(test)]
                {
                    root.second_folder_child_identity = Some(snapshot.identity);
                }
            }
            result.push(SyntheticEntry {
                name: item.name.to_owned(),
                is_file: true,
                len: snapshot.file_size,
            });
        }
        if result.len() != 1 {
            return Err(Error::SyntheticCallbackFailed);
        }
        Ok(result)
    }

    #[cfg(test)]
    pub(super) fn registered_population_policy(&self) -> Result<u32, Error> {
        let root = self.root.as_ref().ok_or(Error::SyntheticRootChanged)?;
        root.verify_contents_with_materialized_directories(true, true)?;
        let path = wide_path(&root.path.join(FIRST_FOLDER_NAME))?;
        // CF_SYNC_ROOT_STANDARD_INFO starts with SyncRootFileId (8 bytes),
        // HydrationPolicy (4 bytes), then PopulationPolicy (4 bytes). Keep a
        // generously sized aligned buffer; the API returns its actual length.
        let mut buffer = [0_u64; 512];
        let mut returned_length = 0_u32;
        // SAFETY: the buffer is aligned and large enough for the bounded
        // standard-info record, the path is a verified descendant of our
        // synthetic root, and no pointers are retained.
        let result = unsafe {
            CfGetSyncRootInfoByPath(
                path.as_ptr(),
                1,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                &mut returned_length,
            )
        };
        if result < 0 {
            return Err(native_error("CfGetSyncRootInfoByPath", result));
        }
        if returned_length < 16 || returned_length as usize > std::mem::size_of_val(&buffer) {
            return Err(Error::SyntheticCallbackFailed);
        }
        // SAFETY: the response length was checked and the standard-info
        // PopulationPolicy DWORD occupies bytes 12..16 per cfapi.h.
        let bytes = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned_length as usize)
        };
        let policy = u32::from_ne_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| Error::SyntheticCallbackFailed)?,
        );
        Ok(policy)
    }

    #[cfg(test)]
    pub(super) fn enable_directory_population(&self, directory_name: &str) -> Result<i32, Error> {
        let identity =
            directory_cloud_identity(directory_name).ok_or(Error::SyntheticCallbackFailed)?;
        let root = self.root.as_ref().ok_or(Error::SyntheticRootChanged)?;
        root.verify_contents_with_materialized_directories(true, true)?;
        let path = root.path.join(directory_name);
        let root_identity = root.fixture_identity(directory_name)?;
        let handle = open_fixture_entry(
            &path,
            root_identity,
            FILE_READ_ATTRIBUTES | FILE_WRITE_DATA,
            true,
            0,
            false,
        )?;
        // Explicitly mark only this exact owned synthetic directory as partial.
        // The directory handle and identity were pinned/checked above; metadata
        // and range arguments are null because this test changes only the
        // documented on-demand-population state.
        let result = unsafe {
            CfUpdatePlaceholder(
                handle.0,
                null(),
                identity.as_ptr().cast(),
                identity.len() as u32,
                null(),
                0,
                CF_UPDATE_FLAG_ENABLE_ON_DEMAND_POPULATION,
                null_mut(),
                null_mut(),
            )
        };
        if result < 0 {
            return Err(native_error("CfUpdatePlaceholder", result));
        }
        Ok(result)
    }

    pub(super) fn directory_placeholder_state(&self, directory_name: &str) -> Result<u32, Error> {
        if directory_cloud_identity(directory_name).is_none() {
            return Err(Error::SyntheticCallbackFailed);
        }
        let root = self.root.as_ref().ok_or(Error::SyntheticRootChanged)?;
        root.verify_contents_with_materialized_directories(true, true)?;
        let path = root.path.join(directory_name);
        let identity = root.fixture_identity(directory_name)?;
        let guard = open_fixture_entry(&path, identity, FILE_READ_ATTRIBUTES, true, 0, true)?;
        Ok(root_snapshot(guard.0)?.placeholder_state)
    }

    pub(super) fn read_payload(&self) -> Result<Vec<u8>, Error> {
        self.read_file(FILE_NAME)
    }

    pub(super) fn read_nested_payload(&self) -> Result<Vec<u8>, Error> {
        let root = self.root.as_ref().ok_or(Error::SyntheticRootChanged)?;
        root.verify_contents_with_materialized_directories(true, true)?;
        let identity = root.nested_identity.ok_or(Error::SyntheticCallbackFailed)?;
        let path = root.path.join(FIRST_FOLDER_NAME).join(NESTED_FILE_NAME);
        let _guard = open_fixture_entry(
            &path,
            identity,
            FILE_READ_ATTRIBUTES,
            false,
            NESTED_PAYLOAD_LEN as u64,
            false,
        )?;
        let content = open_fixture_content(&path, identity, NESTED_PAYLOAD_LEN)?;
        let (bytes, snapshot) = read_open_file(content, NESTED_PAYLOAD_LEN)?;
        if !valid_fixture_entry(snapshot, false, NESTED_PAYLOAD_LEN as u64, false)
            || bytes != synthetic_payload_for(&NESTED_FILE_IDENTITY, NESTED_PAYLOAD_LEN)
        {
            return Err(Error::SyntheticCallbackFailed);
        }
        Ok(bytes)
    }

    #[cfg(test)]
    pub(super) fn read_second_folder_child_payload(&self) -> Result<Vec<u8>, Error> {
        let root = self.root.as_ref().ok_or(Error::SyntheticRootChanged)?;
        root.verify_contents_with_materialized_directories(true, true)?;
        let identity = root
            .second_folder_child_identity
            .ok_or(Error::SyntheticCallbackFailed)?;
        let path = root
            .path
            .join(SECOND_FOLDER_NAME)
            .join(SECOND_FOLDER_CHILD_NAME);
        let _guard = open_fixture_entry(
            &path,
            identity,
            FILE_READ_ATTRIBUTES,
            false,
            SECOND_FOLDER_CHILD_LEN as u64,
            true,
        )?;
        let content = open_fixture_content(&path, identity, SECOND_FOLDER_CHILD_LEN)?;
        let (bytes, snapshot) = read_open_file(content, SECOND_FOLDER_CHILD_LEN)?;
        if !valid_fixture_entry(snapshot, false, SECOND_FOLDER_CHILD_LEN as u64, false)
            || bytes
                != synthetic_payload_for(&SECOND_FOLDER_CHILD_IDENTITY, SECOND_FOLDER_CHILD_LEN)
        {
            return Err(Error::SyntheticCallbackFailed);
        }
        Ok(bytes)
    }

    pub(super) fn read_file(&self, name: &str) -> Result<Vec<u8>, Error> {
        self.read_file_inner(name, true)
    }

    #[cfg(test)]
    pub(super) fn read_opencloud_fixture(&self) -> Result<Vec<u8>, Error> {
        self.read_file_inner(FILE_NAME, false)
    }

    #[cfg(test)]
    pub(super) fn root_identity_for_test(&self) -> Result<(u32, u64), Error> {
        let root = self.root.as_ref().ok_or(Error::SyntheticRootChanged)?;
        root.verify_identity()?;
        Ok((root.identity.volume_serial, root.identity.file_index))
    }

    #[cfg(test)]
    pub(super) fn fixture_file_identity_for_test(&self, name: &str) -> Result<(u32, u64), Error> {
        let root = self.root.as_ref().ok_or(Error::SyntheticRootChanged)?;
        let expected = root.fixture_identity(name)?;
        let snapshot = entry_snapshot(&root.path.join(name), false)?;
        if snapshot.identity != expected {
            return Err(Error::SyntheticRootChanged);
        }
        Ok((
            snapshot.identity.volume_serial,
            snapshot.identity.file_index,
        ))
    }

    #[cfg(test)]
    pub(super) fn journaled_close_count_for_test(&self) -> usize {
        self.state
            .journaled_placeholder_closes
            .load(Ordering::Acquire)
    }

    fn read_file_inner(
        &self,
        name: &str,
        verify_synthetic_payload: bool,
    ) -> Result<Vec<u8>, Error> {
        let item = FIXTURE_ITEMS
            .iter()
            .find(|item| item.name == name && !item.is_directory)
            .ok_or(Error::SyntheticCallbackFailed)?;
        let root = self.root.as_ref().ok_or(Error::SyntheticRootChanged)?;
        root.verify_contents(true)?;
        let path = root.path.join(item.name);
        let fixture_len = root.fixture_len(item);
        let _guard = open_fixture_entry(
            &path,
            root.fixture_identity(item.name)?,
            FILE_READ_ATTRIBUTES,
            false,
            fixture_len as u64,
            false,
        )?;
        let handle = open_fixture_content(&path, root.fixture_identity(item.name)?, fixture_len)?;
        let (bytes, snapshot) = match read_open_file(handle, fixture_len) {
            Ok(result) => result,
            Err(error) => {
                eprintln!(
                    "synthetic read failed: name={} length={} error={error:?} fetch_callbacks={} last_param_size={} transferred_bytes={}",
                    item.name,
                    fixture_len,
                    self.state.fetch_callbacks.load(Ordering::Relaxed),
                    self.state.last_fetch_param_size.load(Ordering::Relaxed),
                    self.state.transferred_bytes.load(Ordering::Relaxed),
                );
                eprintln!(
                    "synthetic callback detail: requested_offset={} requested_length={} staged_fetch_ms={} first_failed_hresult={:#x}",
                    self.state.last_requested_offset.load(Ordering::Relaxed),
                    self.state.last_requested_length.load(Ordering::Relaxed),
                    self.state.last_staged_fetch_millis.load(Ordering::Relaxed),
                    self.state.first_failed_hresult.load(Ordering::Relaxed),
                );
                return Err(error);
            }
        };
        if !valid_fixture_entry(snapshot, false, fixture_len as u64, false) {
            eprintln!(
                "synthetic hydrated file state mismatch: attrs={:#x} tag={:#x} placeholder={:#x} size={} callbacks={} transferred={}",
                snapshot.file_attributes,
                snapshot.reparse_tag,
                snapshot.placeholder_state,
                snapshot.file_size,
                self.state.fetch_callbacks.load(Ordering::Relaxed),
                self.state.transferred_bytes.load(Ordering::Relaxed)
            );
            return Err(Error::SyntheticRootChanged);
        }
        if verify_synthetic_payload && bytes != synthetic_payload_for(item.identity, fixture_len) {
            return Err(Error::SyntheticCallbackFailed);
        }
        Ok(bytes)
    }

    pub(super) fn callback_observation(&self) -> CallbackObservation {
        CallbackObservation {
            directory_callback_entries: DIRECTORY_CALLBACK_ENTRIES.load(Ordering::Relaxed),
            directory_callback_guard_rejections: DIRECTORY_CALLBACK_GUARD_REJECTIONS
                .load(Ordering::Relaxed),
            fetch_callbacks: self.state.fetch_callbacks.load(Ordering::Relaxed),
            last_fetch_param_size: self.state.last_fetch_param_size.load(Ordering::Relaxed),
            transferred_bytes: self.state.transferred_bytes.load(Ordering::Relaxed),
            last_requested_offset: self.state.last_requested_offset.load(Ordering::Relaxed),
            last_requested_length: self.state.last_requested_length.load(Ordering::Relaxed),
            last_staged_fetch_millis: self.state.last_staged_fetch_millis.load(Ordering::Relaxed),
            first_failed_hresult: self.state.first_failed_hresult.load(Ordering::Relaxed),
            directory_callbacks: self.state.directory_callbacks.load(Ordering::Relaxed),
            last_directory_param_size: self.state.last_directory_param_size.load(Ordering::Relaxed),
            placeholder_entries_submitted: self
                .state
                .placeholder_entries_submitted
                .load(Ordering::Relaxed),
            modified_placeholder_closes: self
                .state
                .modified_placeholder_closes
                .load(Ordering::Acquire),
            journaled_placeholder_closes: self
                .state
                .journaled_placeholder_closes
                .load(Ordering::Acquire),
            unverifiable_placeholder_closes: self
                .state
                .unverifiable_placeholder_closes
                .load(Ordering::Acquire),
            close_completion_callbacks: self
                .state
                .close_completion_callbacks
                .load(Ordering::Relaxed),
            last_close_param_size: self.state.last_close_param_size.load(Ordering::Relaxed),
            last_close_validation_stage: self
                .state
                .last_close_validation_stage
                .load(Ordering::Relaxed),
            last_close_validation_hresult: self
                .state
                .last_close_validation_hresult
                .load(Ordering::Relaxed),
            last_close_path_common_prefix_bytes: self
                .state
                .last_close_path_common_prefix_bytes
                .load(Ordering::Relaxed),
        }
    }

    #[cfg(test)]
    pub(super) fn close_observation_for_test(
        &self,
    ) -> (usize, usize, usize, usize, usize, i32, usize) {
        let observation = self.callback_observation();
        (
            observation.modified_placeholder_closes,
            observation.unverifiable_placeholder_closes,
            observation.close_completion_callbacks,
            observation.last_close_param_size,
            observation.last_close_validation_stage,
            observation.last_close_validation_hresult,
            observation.last_close_path_common_prefix_bytes,
        )
    }

    #[cfg(test)]
    pub(super) fn last_close_file_id_for_test(&self) -> u64 {
        self.state.last_close_file_id.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn owned_fixture_file_path_for_test(&self, name: &str) -> Result<PathBuf, Error> {
        if name != FILE_NAME && name != SECOND_FILE_NAME {
            return Err(Error::SyntheticRootChanged);
        }
        Ok(self
            .root
            .as_ref()
            .ok_or(Error::SyntheticRootChanged)?
            .path
            .join(name))
    }

    #[cfg(test)]
    pub(super) fn disconnect_for_test(&mut self) -> Result<(), Error> {
        self.disconnect_inner()
    }

    #[cfg(test)]
    pub(super) fn release_registration_for_restart_test(&mut self) -> Result<PathBuf, Error> {
        self.disconnect_inner()?;
        let mut root = self.root.take().ok_or(Error::SyntheticRootChanged)?;
        root.preserve_registration_on_drop = true;
        let path = root.path.clone();
        drop(root);
        Ok(path)
    }

    pub(super) fn shutdown(mut self) -> Result<(), Error> {
        match self.shutdown_inner() {
            Ok(()) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn shutdown_inner(&mut self) -> Result<(), Error> {
        if self.state.has_unresolved_placeholder_data() {
            return Err(Error::UnresolvedPlaceholderEdits);
        }
        #[cfg(test)]
        if let Some(root) = self.root.as_ref() {
            eprintln!(
                "synthetic fixture presence stage=before_disconnect {:?}",
                root.fixture_presence_for_test()
            );
        }
        self.disconnect_inner().inspect_err(|error| {
            eprintln!("synthetic shutdown failed phase=disconnect error={error:?}");
        })?;
        let mut root = self.root.take().ok_or(Error::SyntheticRootChanged)?;
        #[cfg(test)]
        eprintln!(
            "synthetic fixture presence stage=after_disconnect {:?}",
            root.fixture_presence_for_test()
        );
        root.verify_contents_with_materialized_directories(self.placeholder_created, true)
            .inspect_err(|error| {
                eprintln!("synthetic shutdown failed phase=post_disconnect_verify error={error:?}");
            })?;
        root.verify_nested_child_content().inspect_err(|error| {
            eprintln!("synthetic shutdown failed phase=verify_nested_payload_before_unregister error={error:?}");
        })?;
        #[cfg(test)]
        {
            let presence = root.fixture_presence_for_test();
            eprintln!("synthetic fixture presence stage=after_disconnect_verify {presence:?}");
            if root.second_folder_child_identity.is_some() {
                assert_eq!(
                    presence, [true; 5],
                    "all fixtures, including the populated second-folder child, must exist before unregister"
                );
            }
        }
        root.unregister_inner().inspect_err(|error| {
            eprintln!("synthetic shutdown failed phase=unregister error={error:?}");
        })?;
        #[cfg(test)]
        {
            let presence = root.fixture_presence_for_test();
            eprintln!("synthetic fixture presence stage=after_unregister {presence:?}");
            if root.second_folder_child_identity.is_some() {
                assert!(
                    presence[0] && presence[1] && presence[2] && presence[4],
                    "unregister must retain hydrated files, both populated directories, and the populated second-folder child; only the known unhydrated regular-file placeholder may be evicted"
                );
            }
        }
        root.remove_owned_root(self.placeholder_created)
            .inspect_err(|error| {
                eprintln!("synthetic shutdown failed phase=remove_root error={error:?}");
            })
    }

    fn disconnect_inner(&mut self) -> Result<(), Error> {
        if !self.connected {
            return Ok(());
        }
        self.state.close_readiness();
        // SAFETY: the connection key was returned by CfConnectSyncRoot. State
        // and its registry entry stay live throughout this call; Microsoft's
        // contract permits callbacks during disconnect and forbids them after.
        let result = unsafe { CfDisconnectSyncRoot(self.connection_key) };
        if result < 0 {
            return Err(native_error("CfDisconnectSyncRoot", result));
        }
        self.connected = false;
        if let Some(root) = self.root.as_mut() {
            root.connected = false;
        }
        let removed = callback_registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.context_key);
        if removed.is_none() {
            return Err(Error::SyntheticCallbackFailed);
        }
        self.state.wait_for_callbacks();
        Ok(())
    }
}

impl Drop for SyntheticConnection {
    fn drop(&mut self) {
        if self.shutdown_inner().is_err() {
            // Keep a failed/disconnected root registered and untouched. If
            // disconnect failed, its callback registry entry remains alive.
            // If unregister failed, no attempt is made to delete the tree.
            if let Some(root) = self.root.take() {
                Box::leak(root);
            }
        }
    }
}

mod hydration_inventory {
    use std::collections::{BTreeMap, BTreeSet};
    const MAX_ROWS: usize = 100_000;

    #[derive(Clone)]
    pub struct HydratedFileRow {
        identity: [u8; 16],
        file_index: u64,
        length: u64,
        components: Vec<String>,
    }
    impl HydratedFileRow {
        pub fn identity(&self) -> &[u8; 16] {
            &self.identity
        }
        pub fn file_index(&self) -> u64 {
            self.file_index
        }
        pub fn length(&self) -> u64 {
            self.length
        }
        pub fn components(&self) -> &[String] {
            &self.components
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum InventoryError {
        InvalidFileIndex,
        Conflict,
        Capacity,
    }
    #[derive(Default)]
    pub struct HydratedFileInventory {
        rows: BTreeMap<([u8; 16], u64), HydratedFileRow>,
        incomplete: bool,
    }
    impl HydratedFileInventory {
        pub fn new() -> Self {
            Self::default()
        }
        /// Components must already be validated and root-relative by the native
        /// caller. No filesystem lookup, normalization, or authority is added here.
        pub fn record(
            &mut self,
            identity: [u8; 16],
            file_index: u64,
            length: u64,
            components: Vec<String>,
        ) -> Result<(), InventoryError> {
            if file_index == 0 {
                self.incomplete = true;
                return Err(InventoryError::InvalidFileIndex);
            }
            let key = (identity, file_index);
            if let Some(old) = self.rows.get(&key) {
                if old.length != length || old.components != components {
                    self.incomplete = true;
                    return Err(InventoryError::Conflict);
                }
                return Ok(());
            }
            if self.rows.len() >= MAX_ROWS {
                self.incomplete = true;
                return Err(InventoryError::Capacity);
            }
            self.rows.insert(
                key,
                HydratedFileRow {
                    identity,
                    file_index,
                    length,
                    components,
                },
            );
            Ok(())
        }
        pub fn mark_incomplete(&mut self) {
            self.incomplete = true;
        }
        pub fn is_complete(&self) -> bool {
            !self.incomplete
        }
        /// The caller supplies an independently authenticated route-owned set.
        /// Filtering does not establish that set's authority. No rows are removed,
        /// including after failed cleanup; incompleteness remains permanently sticky.
        pub fn snapshot(&self, route_owned: &BTreeSet<[u8; 16]>) -> Vec<HydratedFileRow> {
            self.rows
                .values()
                .filter(|row| route_owned.contains(&row.identity))
                .cloned()
                .collect()
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn record_repeat_and_conflict_preserve_prior_bookkeeping() {
            let mut inventory = HydratedFileInventory::new();
            let id = [7; 16];
            let owned = BTreeSet::from([id]);
            let path = vec!["Vault".into(), "photo.jpg".into()];
            assert!(inventory.record(id, 19, 42, path.clone()).is_ok());
            assert!(inventory.record(id, 19, 42, path.clone()).is_ok());
            assert!(inventory.is_complete());
            assert_eq!(inventory.snapshot(&owned).len(), 1);
            assert!(inventory.snapshot(&BTreeSet::from([[8; 16]])).is_empty());
            assert!(matches!(
                inventory.record(id, 19, 43, path.clone()),
                Err(InventoryError::Conflict)
            ));
            assert!(matches!(
                inventory.record(id, 19, 42, vec!["replacement.jpg".into()]),
                Err(InventoryError::Conflict)
            ));
            assert!(!inventory.is_complete());
            let retained = inventory.snapshot(&owned);
            assert_eq!(retained[0].identity(), &id);
            assert_eq!(retained[0].file_index(), 19);
            assert_eq!(retained[0].length(), 42);
            assert_eq!(retained[0].components(), path);
            assert!(inventory.record(id, 19, 42, path).is_ok());
            assert!(!inventory.is_complete());
        }
    }
}

struct CallbackState {
    #[cfg(feature = "synthetic-agent-integration")]
    fetch_validation_stage: AtomicUsize,
    hydrated_files: Mutex<hydration_inventory::HydratedFileInventory>,
    readiness: std::sync::atomic::AtomicU8,
    readiness_fetch_rejections: AtomicUsize,
    activity: Mutex<CallbackActivity>,
    drained: Condvar,
    backend: Arc<dyn PlaceholderBackend>,
    recovery: Option<Arc<dyn PreparedEditRecovery>>,
    initial_edits: crate::initial_edit_queue::InitialEditQueue,
    root_path: Option<PathBuf>,
    root_identity: Option<RootIdentity>,
    modified_placeholder_closes: AtomicUsize,
    journaled_placeholder_closes: AtomicUsize,
    unverifiable_placeholder_closes: AtomicUsize,
    close_completion_callbacks: AtomicUsize,
    last_close_param_size: AtomicUsize,
    last_close_file_id: AtomicU64,
    last_close_validation_stage: AtomicUsize,
    last_close_validation_hresult: std::sync::atomic::AtomicI32,
    last_close_path_common_prefix_bytes: AtomicUsize,
    close_check_pool: Arc<BoundedPermitPool>,
    directory_enumeration_pool: Arc<BoundedPermitPool>,
    fetch_callbacks: AtomicUsize,
    last_fetch_param_size: AtomicUsize,
    transferred_bytes: AtomicUsize,
    last_requested_offset: AtomicU64,
    last_requested_length: AtomicU64,
    last_staged_fetch_millis: AtomicU64,
    first_failed_hresult: std::sync::atomic::AtomicI32,
    directory_callbacks: AtomicUsize,
    last_directory_param_size: AtomicUsize,
    placeholder_entries_submitted: AtomicUsize,
}

struct CallbackActivity {
    active_callbacks: usize,
    active_fetches: usize,
    staged_fetches: usize,
    requests: HashMap<i64, ActiveFetch>,
}

struct ActiveFetch {
    cancellation: CancellationToken,
    remaining: FetchRange,
    publication_gate: Arc<RequestPublicationGate>,
}

impl ActiveFetch {
    fn covers_remaining(&self, cancelled: FetchRange) -> bool {
        cancelled.offset <= self.remaining.offset && cancelled.end >= self.remaining.end
    }
}

impl CallbackState {
    #[cfg(test)]
    fn new(backend: Arc<dyn PlaceholderBackend>) -> Self {
        Self::new_inner(backend, None, None, None)
    }

    fn new_for_root(
        backend: Arc<dyn PlaceholderBackend>,
        root_path: PathBuf,
        root_identity: RootIdentity,
        recovery: Option<Arc<dyn PreparedEditRecovery>>,
    ) -> Self {
        Self::new_inner(backend, Some(root_path), Some(root_identity), recovery)
    }

    fn new_inner(
        backend: Arc<dyn PlaceholderBackend>,
        root_path: Option<PathBuf>,
        root_identity: Option<RootIdentity>,
        recovery: Option<Arc<dyn PreparedEditRecovery>>,
    ) -> Self {
        let readiness = if root_path.is_some() {
            CALLBACK_INITIALIZING
        } else {
            CALLBACK_READY
        };
        Self {
            #[cfg(feature = "synthetic-agent-integration")]
            fetch_validation_stage: AtomicUsize::new(0),
            hydrated_files: Mutex::new(hydration_inventory::HydratedFileInventory::new()),
            readiness: std::sync::atomic::AtomicU8::new(readiness),
            readiness_fetch_rejections: AtomicUsize::new(0),
            activity: Mutex::new(CallbackActivity {
                active_callbacks: 0,
                active_fetches: 0,
                staged_fetches: 0,
                requests: HashMap::new(),
            }),
            drained: Condvar::new(),
            backend,
            recovery,
            initial_edits: crate::initial_edit_queue::InitialEditQueue::default(),
            root_path,
            root_identity,
            modified_placeholder_closes: AtomicUsize::new(0),
            journaled_placeholder_closes: AtomicUsize::new(0),
            unverifiable_placeholder_closes: AtomicUsize::new(0),
            close_completion_callbacks: AtomicUsize::new(0),
            last_close_param_size: AtomicUsize::new(0),
            last_close_file_id: AtomicU64::new(0),
            last_close_validation_stage: AtomicUsize::new(0),
            last_close_validation_hresult: std::sync::atomic::AtomicI32::new(0),
            last_close_path_common_prefix_bytes: AtomicUsize::new(0),
            close_check_pool: BoundedPermitPool::new(2),
            directory_enumeration_pool: BoundedPermitPool::new(
                MAX_CONCURRENT_DIRECTORY_ENUMERATIONS,
            ),
            fetch_callbacks: AtomicUsize::new(0),
            last_fetch_param_size: AtomicUsize::new(0),
            transferred_bytes: AtomicUsize::new(0),
            last_requested_offset: AtomicU64::new(0),
            last_requested_length: AtomicU64::new(0),
            last_staged_fetch_millis: AtomicU64::new(0),
            first_failed_hresult: std::sync::atomic::AtomicI32::new(0),
            directory_callbacks: AtomicUsize::new(0),
            last_directory_param_size: AtomicUsize::new(0),
            placeholder_entries_submitted: AtomicUsize::new(0),
        }
    }

    fn publish_initial_readiness(&self) -> Result<(), Error> {
        self.readiness
            .compare_exchange(
                CALLBACK_INITIALIZING,
                CALLBACK_READY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| Error::ConnectionStateInvalid)
    }

    fn fail_initial_readiness(&self) {
        self.readiness.store(CALLBACK_FAILED, Ordering::Release);
    }

    fn close_readiness(&self) {
        // Serialize the phase boundary with request admission. A callback
        // that observed Ready before taking this mutex cannot enter afterward.
        let _activity = self
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A failed initialization is terminal and cannot be reopened by cleanup.
        self.readiness.fetch_max(CALLBACK_CLOSING, Ordering::AcqRel);
    }

    fn has_unresolved_placeholder_data(&self) -> bool {
        self.modified_placeholder_closes.load(Ordering::Acquire) != 0
            || self.unverifiable_placeholder_closes.load(Ordering::Acquire) != 0
            || self
                .recovery
                .as_ref()
                .is_some_and(|recovery| recovery.has_unresolved().unwrap_or(true))
    }

    fn record_reconnect_scan(&self, scan: ReconnectScan) {
        if scan.modified_files != 0 {
            self.modified_placeholder_closes
                .fetch_add(scan.modified_files, Ordering::AcqRel);
        }
        if scan.unresolved_objects != 0 {
            self.unverifiable_placeholder_closes
                .fetch_add(scan.unresolved_objects, Ordering::AcqRel);
        }
    }

    fn record_placeholder_close(&self, info: &CfCallbackInfo, flags: u32) {
        self.last_close_file_id
            .store(info.file_id as u64, Ordering::Release);
        let Some(_permit) = self.close_check_pool.try_acquire() else {
            self.unverifiable_placeholder_closes
                .fetch_add(1, Ordering::AcqRel);
            return;
        };
        if flags & CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED != 0 {
            self.unverifiable_placeholder_closes
                .fetch_add(1, Ordering::AcqRel);
            return;
        }
        let result = self.capture_and_journal_modified_file(info);
        match result {
            Ok(false) => {}
            Ok(true) => {
                self.modified_placeholder_closes
                    .fetch_add(1, Ordering::AcqRel);
                self.journaled_placeholder_closes
                    .fetch_add(1, Ordering::AcqRel);
            }
            Err((stage, hresult, modified)) => {
                self.last_close_validation_stage
                    .store(stage, Ordering::Release);
                self.last_close_validation_hresult
                    .store(hresult, Ordering::Release);
                if modified {
                    self.modified_placeholder_closes
                        .fetch_add(1, Ordering::AcqRel);
                }
                // A close we cannot verify must block destructive unregister
                // just like known modified content. This is intentionally
                // conservative; disconnect preserves the root for recovery.
                self.unverifiable_placeholder_closes
                    .fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    fn capture_and_journal_modified_file(
        &self,
        info: &CfCallbackInfo,
    ) -> Result<bool, (usize, i32, bool)> {
        let root_path = self.root_path.as_deref().ok_or((1, 0, false))?;
        let root_identity = self.root_identity.ok_or((1, 0, false))?;
        if info.volume_serial_number != root_identity.volume_serial
            || info.sync_root_file_id as u64 != root_identity.file_index
        {
            return Err((2, 0, false));
        }
        if info.file_identity.is_null() || info.file_identity_length != 16 || info.file_size < 0 {
            return Err((3, 0, false));
        }
        // SAFETY: the bounded opaque identity is owned by Cloud Files and is
        // valid throughout this callback. It is never interpreted as a path.
        let identity = unsafe { std::slice::from_raw_parts(info.file_identity.cast::<u8>(), 16) };
        // This guard binds the recovery copy to the exact authenticated
        // account/root and blocks logout or token replacement until the
        // encrypted record has been durably published.
        let prepared = self
            .backend
            .prepare_edit_binding(identity)
            .map_err(|_| (4, 0, false))?;
        let binding = prepared.binding();
        if binding.account_generation == 0
            || binding.root_resource_id.is_empty()
            || binding.remote_resource_id.is_empty()
        {
            return Err((5, 0, false));
        }
        let callback_guard = callback_path(
            root_path,
            info.volume_dos_name,
            info.normalized_path,
            root_identity,
            info.file_id as u64,
            info.file_size as u64,
            &self.last_close_path_common_prefix_bytes,
        )
        .map_err(|stage| (30 + usize::from(stage), 0, false))?;
        let path = &callback_guard.path;
        let path_wide = wide_path(path).map_err(|_| (6, 0, false))?;
        let snapshot = callback_guard.snapshot;
        if snapshot.identity.volume_serial != root_identity.volume_serial
            || snapshot.identity.file_index != info.file_id as u64
            || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            || snapshot.reparse_tag & IO_REPARSE_TAG_CLOUD_MASK
                != (IO_REPARSE_TAG_CLOUD & IO_REPARSE_TAG_CLOUD_MASK)
            || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
            || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK != 0
            || snapshot.file_size != info.file_size as u64
            || snapshot.file_size > MAX_REQUEST_BYTES
        {
            return Err((9, 0, false));
        }
        let len = usize::try_from(snapshot.file_size).map_err(|_| (15, 0, true))?;
        // Keep the no-follow entry guard open without FILE_SHARE_DELETE, then
        // open the Cloud Files data stream normally. The guard prevents name
        // substitution; the second handle is checked against the guard's file
        // ID before its bytes are accepted.
        let content_handle = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                GENERIC_READ | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if content_handle.is_null() || content_handle == INVALID_HANDLE_VALUE {
            let error = unsafe { GetLastError() } as i32;
            return Err((21, error, true));
        }
        let content_handle = RawOwnedHandle(content_handle);
        let content_snapshot = root_snapshot(content_handle.0).map_err(|_| (22, 0, true))?;
        let pinned_entry_final =
            final_path_for_handle(callback_guard.entry.0).map_err(|_| (24, 0, true))?;
        let content_final = final_path_for_handle(content_handle.0).map_err(|_| (25, 0, true))?;
        if content_snapshot.identity != snapshot.identity
            || content_snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || content_snapshot.file_attributes != snapshot.file_attributes
            || content_snapshot.reparse_tag != snapshot.reparse_tag
            || content_snapshot.placeholder_state != snapshot.placeholder_state
            || content_snapshot.file_size != snapshot.file_size
            || content_snapshot.last_write_time != snapshot.last_write_time
            || !windows_paths_equal(&content_final, &pinned_entry_final)
            || !windows_path_is_within(&pinned_entry_final, &callback_guard.root_final_path)
        {
            return Err((23, 0, true));
        }
        // Query modified ranges through the ordinary data-stream handle. The
        // separate no-follow entry handle remains open without FILE_SHARE_DELETE
        // and pins the exact reparse-point identity while this handle is used.
        let mut ranges = [CfFileRange {
            starting_offset: 0,
            length: 0,
        }; 64];
        let mut returned = 0_u32;
        let hr = unsafe {
            CfGetPlaceholderRangeInfo(
                content_handle.0,
                CF_PLACEHOLDER_RANGE_INFO_MODIFIED,
                0,
                -1,
                ranges.as_mut_ptr().cast(),
                size_of::<CfFileRange>()
                    .checked_mul(ranges.len())
                    .ok_or((10, 0, false))? as u32,
                &mut returned,
            )
        };
        if hr < 0 {
            return Err((11, hr, false));
        }
        if returned as usize > std::mem::size_of_val(&ranges) {
            return Err((12, 0, false));
        }
        let returned = returned as usize;
        if returned.checked_rem(size_of::<CfFileRange>()) != Some(0) {
            return Err((13, 0, false));
        }
        let count = returned / size_of::<CfFileRange>();
        for range in ranges.iter().take(count) {
            if range.starting_offset < 0
                || range.length <= 0
                || range.starting_offset.checked_add(range.length).is_none()
            {
                return Err((14, 0, false));
            }
        }
        if count == 0 {
            return Ok(false);
        }
        // The adversarial integration barrier runs only once a real modified
        // range is confirmed and this exact identity-validated stream handle
        // is open. A delayed read-only close from hydration cannot consume
        // the race probe.
        #[cfg(feature = "synthetic-agent-integration")]
        if wait_for_synthetic_path_guard_release(
            info.sync_root_file_id as u64 == root_identity.file_index,
            content_snapshot.identity.volume_serial == root_identity.volume_serial
                && content_snapshot.identity.file_index == info.file_id as u64
                && windows_paths_equal(&content_final, &pinned_entry_final),
        )
        .is_err()
        {
            return Err((29, 0, true));
        }
        let (content, after_read) = read_placeholder_for_recovery(content_handle, len)
            .map_err(|(stage, hresult)| (stage, hresult, true))?;
        if after_read.identity != snapshot.identity
            || after_read.file_attributes != snapshot.file_attributes
            || after_read.reparse_tag != snapshot.reparse_tag
            || after_read.placeholder_state != snapshot.placeholder_state
            || after_read.file_size != snapshot.file_size
            || after_read.last_write_time != snapshot.last_write_time
        {
            return Err((16, 0, true));
        }

        // A path may have changed after the stream handle was opened. The
        // bytes above came from that pinned, identity-checked handle; before
        // persisting them, resolve the callback path again under a fresh
        // no-follow root/ancestor/entry guard. Any rename/reparse/identity
        // change fails closed, so replacement bytes can never enter recovery.
        let post_read_guard = callback_path(
            root_path,
            info.volume_dos_name,
            info.normalized_path,
            root_identity,
            info.file_id as u64,
            info.file_size as u64,
            &self.last_close_path_common_prefix_bytes,
        )
        .map_err(|stage| (40 + usize::from(stage), 0, true))?;
        if post_read_guard.snapshot.identity != snapshot.identity
            || !windows_paths_equal(
                &post_read_guard.root_final_path,
                &callback_guard.root_final_path,
            )
        {
            return Err((39, 0, true));
        }

        let relative_path = binding
            .virtual_path
            .strip_prefix('/')
            .filter(|relative| !relative.is_empty())
            .ok_or((17, 0, true))?;
        let recovery = self.recovery.as_ref().ok_or((18, 0, true))?;
        let receipt = recovery
            .append_edit_for_initial_dispatch(
                binding,
                crate::ConfiguredRootIdentity {
                    volume_serial: root_identity.volume_serial,
                    file_index: root_identity.file_index,
                },
                LocalFileIdentity {
                    volume_serial: after_read.identity.volume_serial,
                    file_index: after_read.identity.file_index,
                },
                relative_path,
                &content,
            )
            .map_err(|_| (19, 0, true))?;
        if let Some(receipt) = receipt {
            // Saturation/contention loses only automatic scheduling. The
            // immutable body was already durably retained for explicit review.
            // Use the pinned local entry's actual position under the pinned
            // root. The journal's relative_path is a cloud path and may omit
            // the composite Personal/Spaces directories on disk.
            let location = pinned_entry_final
                .strip_prefix(&callback_guard.root_final_path)
                .ok()
                .and_then(|relative| {
                    relative
                        .components()
                        .map(|component| match component {
                            std::path::Component::Normal(value) => {
                                value.to_str().map(str::to_owned)
                            }
                            _ => None,
                        })
                        .collect::<Option<Vec<_>>>()
                })
                .and_then(|components| {
                    crate::InitialEditLocation::new(
                        components,
                        identity.try_into().ok()?,
                        crate::ConfiguredRootIdentity {
                            volume_serial: root_identity.volume_serial,
                            file_index: root_identity.file_index,
                        },
                        LocalFileIdentity {
                            volume_serial: after_read.identity.volume_serial,
                            file_index: after_read.identity.file_index,
                        },
                        &receipt,
                    )
                    .ok()
                });
            if let Some(location) = location {
                let _ =
                    self.initial_edits
                        .push_with_location(Arc::clone(recovery), receipt, location);
            }
        }
        Ok(true)
    }

    fn record_fetch_callback(&self, param_size: usize) {
        self.fetch_callbacks.fetch_add(1, Ordering::Relaxed);
        self.last_fetch_param_size
            .store(param_size, Ordering::Relaxed);
    }

    fn record_directory_callback(&self, param_size: usize) {
        self.directory_callbacks.fetch_add(1, Ordering::Relaxed);
        self.last_directory_param_size
            .store(param_size, Ordering::Relaxed);
    }

    fn record_transfer(&self, bytes: usize) {
        self.transferred_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_request(&self, range: FetchRange) {
        self.last_requested_offset
            .store(range.offset, Ordering::Relaxed);
        self.last_requested_length
            .store(range.len(), Ordering::Relaxed);
    }

    fn record_staged_duration(&self, duration: std::time::Duration) {
        self.last_staged_fetch_millis.store(
            duration.as_millis().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    fn record_failed_hresult(&self, result: HResult) {
        if result < 0 {
            let _ = self.first_failed_hresult.compare_exchange(
                0,
                result,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }

    fn wait_for_callbacks(&self) {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while activity.active_callbacks != 0 {
            activity = self
                .drained
                .wait(activity)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn begin_fetch(
        self: &Arc<Self>,
        request_key: i64,
        required_range: FetchRange,
    ) -> Option<FetchPermit> {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.readiness.load(Ordering::Acquire) != CALLBACK_READY {
            self.readiness_fetch_rejections
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if activity.active_fetches >= MAX_CONCURRENT_FETCHES
            || activity.requests.contains_key(&request_key)
        {
            return None;
        }
        let cancellation = CancellationToken::new();
        let publication_gate = Arc::new(RequestPublicationGate::new());
        activity.active_fetches += 1;
        activity.requests.insert(
            request_key,
            ActiveFetch {
                cancellation: cancellation.clone(),
                remaining: required_range,
                publication_gate: Arc::clone(&publication_gate),
            },
        );
        Some(FetchPermit {
            state: Arc::clone(self),
            request_key,
            cancellation,
            publication_gate,
        })
    }

    fn begin_directory_enumeration(&self) -> Option<BoundedPermit> {
        self.directory_enumeration_pool.try_acquire()
    }

    fn advance_fetch(&self, request_key: i64, next_offset: u64) {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(fetch) = activity.requests.get_mut(&request_key)
            && next_offset >= fetch.remaining.offset
            && next_offset <= fetch.remaining.end
        {
            fetch.remaining.offset = next_offset;
        }
    }

    fn commit_transfer_result(
        &self,
        request_key: i64,
        offset: u64,
        bytes: usize,
        execute_result: HResult,
    ) -> Option<u64> {
        if execute_result < 0 {
            return None;
        }
        let next_offset = offset.checked_add(bytes as u64)?;
        self.record_transfer(bytes);
        self.advance_fetch(request_key, next_offset);
        Some(next_offset)
    }

    fn cancel_request(&self, request_key: i64, cancelled_range: FetchRange) {
        let target = {
            let activity = self
                .activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            activity.requests.get(&request_key).and_then(|fetch| {
                fetch.covers_remaining(cancelled_range).then(|| {
                    (
                        fetch.cancellation.clone(),
                        Arc::clone(&fetch.publication_gate),
                    )
                })
            })
        };
        if let Some((cancellation, publication_gate)) = target {
            // Linearize cancellation against the synchronous CfExecute call:
            // if publication has already started, it finishes before cancel
            // becomes visible; otherwise publication observes the cancelled
            // token and submits no data for this request.
            publication_gate.cancel(&cancellation);
            self.drained.notify_all();
        }
    }

    #[allow(dead_code)]
    fn cancel_all_requests(&self) {
        let requests = {
            let activity = self
                .activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            activity
                .requests
                .values()
                .map(|fetch| {
                    (
                        fetch.cancellation.clone(),
                        Arc::clone(&fetch.publication_gate),
                    )
                })
                .collect::<Vec<_>>()
        };
        for (cancellation, gate) in requests {
            gate.cancel(&cancellation);
        }
        self.drained.notify_all();
    }

    fn reserve_staging(
        self: &Arc<Self>,
        cancellation: &CancellationToken,
    ) -> Option<StagingPermit> {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if cancellation.is_cancelled() || cancellation.is_expired() {
                return None;
            }
            if activity.staged_fetches < MAX_STAGED_CALLBACKS {
                activity.staged_fetches += 1;
                return Some(StagingPermit {
                    state: Arc::clone(self),
                });
            }
            let remaining = cancellation.remaining()?;
            let (next, timeout) = self
                .drained
                .wait_timeout(activity, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            activity = next;
            if timeout.timed_out() {
                return None;
            }
        }
    }
}

/// Pause a synthetic callback after it has pinned the configured root,
/// ancestors, and exact placeholder entry, but before it reopens the ordinary
/// content stream by path. This test-only hook lets the agent integration test
/// attempt hostile renames while the identity handles are live. It is absent
/// from production builds and emits no path or user data.
#[cfg(feature = "synthetic-agent-integration")]
fn wait_for_synthetic_path_guard_release(
    root_identity_verified: bool,
    entry_identity_verified: bool,
) -> Result<(), ()> {
    const BARRIER_ENV: &str = "RAIUN_SYNTHETIC_CFAPI_PATH_GUARD_DIR";
    let Some(directory) = env::var_os(BARRIER_ENV).map(PathBuf::from) else {
        return Ok(());
    };
    if !directory.join("armed").exists() {
        return Ok(());
    }
    if !root_identity_verified || !entry_identity_verified {
        return Err(());
    }
    static INVOCATION: AtomicUsize = AtomicUsize::new(0);
    let invocation = INVOCATION.fetch_add(1, Ordering::AcqRel) + 1;
    let marker = directory.join("guard-pinned");
    let release = directory.join("release");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(marker)
        .map_err(|_| ())?;
    use std::io::Write as _;
    // The marker contains only fixed safety facts and a local callback
    // ordinal; the exact identities and paths remain private. This is written
    // while CallbackPathGuard still owns every no-follow root/ancestor/entry
    // handle, whose CreateFile share mode deliberately omits DELETE.
    writeln!(
        file,
        "invocation={invocation};root_identity=verified;entry_identity=verified;entry_handle=live;delete_share=denied"
    )
    .map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    let deadline = Instant::now() + std::time::Duration::from_secs(15);
    while Instant::now() < deadline {
        if release.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err(())
}

struct StagingPermit {
    state: Arc<CallbackState>,
}

impl Drop for StagingPermit {
    fn drop(&mut self) {
        let mut activity = self
            .state
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        activity.staged_fetches = activity.staged_fetches.saturating_sub(1);
        self.state.drained.notify_all();
    }
}

struct FetchPermit {
    state: Arc<CallbackState>,
    request_key: i64,
    cancellation: CancellationToken,
    publication_gate: Arc<RequestPublicationGate>,
}

impl FetchPermit {
    fn begin_publish(&self) -> Result<RequestPublicationPermit<'_>, BackendError> {
        self.publication_gate.begin_publish(&self.cancellation)
    }
}

impl Drop for FetchPermit {
    fn drop(&mut self) {
        let mut activity = self
            .state
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        activity.requests.remove(&self.request_key);
        activity.active_fetches = activity.active_fetches.saturating_sub(1);
        if activity.active_fetches == 0 {
            self.state.drained.notify_all();
        }
    }
}

struct CallbackGuard(Arc<CallbackState>);

impl Drop for CallbackGuard {
    fn drop(&mut self) {
        let mut activity = self
            .0
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        activity.active_callbacks = activity.active_callbacks.saturating_sub(1);
        if activity.active_callbacks == 0 && activity.active_fetches == 0 {
            self.0.drained.notify_all();
        }
    }
}

fn callback_registry() -> &'static Mutex<HashMap<usize, Arc<CallbackState>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<usize, Arc<CallbackState>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn callback_guard(info: *const CfCallbackInfo) -> Option<CallbackGuard> {
    if info.is_null() {
        return None;
    }
    // SAFETY: `info` is supplied by Cloud Files for the duration of the
    // callback. Only its documented CallbackContext scalar is read.
    // Read only the leading size field until the full ABI structure size is
    // established; malformed callback data must not expose later fields.
    // SAFETY: Cloud Files supplies a readable callback-info prefix.
    let structure_size = unsafe { (*info).struct_size as usize };
    if structure_size < size_of::<CfCallbackInfo>() {
        return None;
    }
    // SAFETY: the verified structure size includes callback_context.
    let context = unsafe { (*info).callback_context as usize };
    let registry = callback_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let state = Arc::clone(registry.get(&context)?);
    let mut activity = state
        .activity
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    activity.active_callbacks += 1;
    drop(activity);
    drop(registry);
    Some(CallbackGuard(state))
}

unsafe extern "system" fn cancel_fetch_data_callback(
    info: *const CfCallbackInfo,
    parameters: *const CfCallbackParameters,
) {
    let Some(_guard) = callback_guard(info) else {
        return;
    };
    if info.is_null() || parameters.is_null() {
        return;
    }
    // SAFETY: Cloud Files owns both structures for the callback duration;
    // ParamSize is checked before reading the selected cancellation arm.
    let parameters = unsafe { &*parameters };
    if parameters.param_size as usize != CF_CANCEL_FETCH_DATA_PARAM_SIZE {
        return;
    }
    // SAFETY: this callback type selects Cancel.FetchData. Its offset and
    // length fields are covered by the checked callback-specific ParamSize.
    let cancelled_range = unsafe { parameters.data.cancel_fetch_data.fetch_data };
    let Some(cancelled_range) =
        checked_cancel_range(cancelled_range.file_offset, cancelled_range.length)
    else {
        return;
    };
    // SAFETY: the request key is a scalar documented in the callback info and
    // the structure is valid for the duration of this callback.
    let request_key = unsafe { (*info).request_key.internal };
    _guard.0.cancel_request(request_key, cancelled_range);
}

unsafe extern "system" fn cancel_fetch_placeholders_callback(
    info: *const CfCallbackInfo,
    parameters: *const CfCallbackParameters,
) {
    let Some(_guard) = callback_guard(info) else {
        return;
    };
    if info.is_null() || parameters.is_null() {
        return;
    }
    let parameters = unsafe { &*parameters };
    if !valid_cancel_placeholders_param_size(parameters.param_size as usize) {
        return;
    }
    let request_key = unsafe { (*info).request_key.internal };
    _guard
        .0
        .cancel_request(request_key, FetchRange { offset: 0, end: 0 });
}

unsafe extern "system" fn fetch_placeholders_callback(
    info: *const CfCallbackInfo,
    parameters: *const CfCallbackParameters,
) {
    DIRECTORY_CALLBACK_ENTRIES.fetch_add(1, Ordering::Relaxed);
    let Some(guard) = callback_guard(info) else {
        DIRECTORY_CALLBACK_GUARD_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if info.is_null() || parameters.is_null() {
        return;
    }
    let info = unsafe { &*info };
    let parameters = unsafe { &*parameters };
    let param_size = parameters.param_size as usize;
    guard.0.record_directory_callback(param_size);
    if !valid_fetch_placeholders_param_size(param_size) {
        #[cfg(test)]
        eprintln!("synthetic directory callback invalid parameter size={param_size}");
        execute_transfer_placeholders(info, &[], STATUS_UNSUCCESSFUL, false);
        return;
    }
    let identity_is_valid = !info.file_identity.is_null()
        && info.file_identity_length > 0
        && info.file_identity_length <= 256;
    if !identity_is_valid {
        #[cfg(test)]
        eprintln!(
            "synthetic directory callback invalid identity: pointer_present={} length={} sync_root_length={} is_root={}",
            !info.file_identity.is_null(),
            info.file_identity_length,
            info.sync_root_identity_length,
            info.file_id == info.sync_root_file_id
        );
        execute_transfer_placeholders(info, &[], STATUS_UNSUCCESSFUL, false);
        return;
    }
    let request_key = info.request_key.internal;
    let Some(fetch_permit) = guard
        .0
        .begin_fetch(request_key, FetchRange { offset: 0, end: 0 })
    else {
        #[cfg(test)]
        eprintln!("synthetic directory callback rejected during fetch admission");
        execute_transfer_placeholders(info, &[], STATUS_UNSUCCESSFUL, false);
        return;
    };
    let Some(_population_permit) = guard.0.begin_directory_enumeration() else {
        #[cfg(test)]
        eprintln!("synthetic directory callback rejected by enumeration bound");
        let outcome = execute_transfer_placeholders(info, &[], STATUS_UNSUCCESSFUL, false);
        guard.0.record_failed_hresult(outcome.hresult);
        return;
    };
    let identity = unsafe {
        std::slice::from_raw_parts(
            info.file_identity.cast::<u8>(),
            info.file_identity_length as usize,
        )
    };
    #[cfg(test)]
    eprintln!(
        "synthetic directory callback identity: len={} matches_expected={}",
        identity.len(),
        identity == FIRST_FOLDER_IDENTITY
    );
    if fetch_permit.cancellation.is_cancelled() || fetch_permit.cancellation.is_expired() {
        #[cfg(test)]
        eprintln!("synthetic directory callback cancelled before backend lookup");
        execute_transfer_placeholders(info, &[], STATUS_CANCELLED, false);
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        guard
            .0
            .backend
            .prepare_enumeration(identity, &fetch_permit.cancellation)
    }))
    .unwrap_or(Err(BackendError::Unavailable));
    match result {
        Ok(prepared) if prepared.children().len() <= crate::MAX_DIRECTORY_CHILDREN => {
            #[cfg(test)]
            eprintln!(
                "synthetic directory backend prepared {} children",
                prepared.children().len()
            );
            if fetch_permit.cancellation.is_cancelled() || fetch_permit.cancellation.is_expired() {
                #[cfg(test)]
                eprintln!("synthetic directory callback cancelled after backend lookup");
                execute_transfer_placeholders(info, &[], STATUS_CANCELLED, false);
                return;
            }
            if !valid_placeholder_children(prepared.children()) {
                execute_transfer_placeholders(info, &[], STATUS_UNSUCCESSFUL, false);
                return;
            }
            let read_only = prepared.read_only();
            let publish_permit = match prepared.begin_publish(&fetch_permit.cancellation) {
                Ok(permit) => permit,
                Err(BackendError::Cancelled) => {
                    execute_transfer_placeholders(info, &[], STATUS_CANCELLED, false);
                    return;
                }
                Err(_) => {
                    execute_transfer_placeholders(info, &[], STATUS_UNSUCCESSFUL, false);
                    return;
                }
            };
            let request_publish = match fetch_permit.begin_publish() {
                Ok(permit) => permit,
                Err(BackendError::Cancelled) => {
                    drop(publish_permit);
                    execute_transfer_placeholders(info, &[], STATUS_CANCELLED, false);
                    return;
                }
                Err(_) => {
                    drop(publish_permit);
                    execute_transfer_placeholders(info, &[], STATUS_UNSUCCESSFUL, false);
                    return;
                }
            };
            if fetch_permit.cancellation.is_cancelled() || fetch_permit.cancellation.is_expired() {
                drop(request_publish);
                drop(publish_permit);
                execute_transfer_placeholders(info, &[], STATUS_CANCELLED, false);
                return;
            }
            let children = prepared.children();
            let count = children.len();
            let outcome = execute_transfer_placeholders(info, children, STATUS_SUCCESS, read_only);
            #[cfg(test)]
            eprintln!(
                "synthetic directory CfExecute outcome: hresult={:#x} processed={} expected={} complete={} entry_failure={:?}",
                outcome.hresult,
                outcome.entries_processed,
                count,
                outcome.complete,
                outcome.entry_failure
            );
            if outcome.hresult >= 0 {
                guard
                    .0
                    .placeholder_entries_submitted
                    .fetch_add(outcome.entries_processed, Ordering::Relaxed);
            }
            drop(request_publish);
            drop(publish_permit);
            if outcome.hresult < 0 {
                guard.0.record_failed_hresult(outcome.hresult);
            } else if !outcome.complete {
                guard
                    .0
                    .record_failed_hresult(outcome.entry_failure.unwrap_or(STATUS_UNSUCCESSFUL));
            }
            debug_assert!(outcome.entries_processed <= count);
        }
        Err(BackendError::Cancelled) => {
            #[cfg(test)]
            eprintln!("synthetic directory backend cancelled");
            execute_transfer_placeholders(info, &[], STATUS_CANCELLED, false);
        }
        Err(_error) => {
            #[cfg(test)]
            eprintln!("synthetic directory backend failed: {_error:?}");
            execute_transfer_placeholders(info, &[], STATUS_UNSUCCESSFUL, false);
        }
        Ok(_) => {
            #[cfg(test)]
            eprintln!("synthetic directory backend exceeded the child bound");
            execute_transfer_placeholders(info, &[], STATUS_UNSUCCESSFUL, false);
        }
    }
}

fn valid_fetch_placeholders_param_size(value: usize) -> bool {
    value == CF_FETCH_PLACEHOLDERS_PARAM_SIZE_DOCUMENTED
        || value == CF_FETCH_PLACEHOLDERS_PARAM_SIZE_ALIGNED
}

fn valid_cancel_placeholders_param_size(value: usize) -> bool {
    value == CF_CANCEL_FETCH_PLACEHOLDERS_PARAM_SIZE_DOCUMENTED
        || value == CF_CANCEL_FETCH_PLACEHOLDERS_PARAM_SIZE_ALIGNED
}

// Fault injection belongs only to the native test executable. Thread-local
// admission prevents another synthetic root's initialization from consuming it.
#[cfg(test)]
thread_local! {
    static STOP_INITIAL_POPULATION_AFTER_FIRST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) fn stop_initial_population_after_first_for_test() {
    STOP_INITIAL_POPULATION_AFTER_FIRST.with(|flag| assert!(!flag.replace(true)));
}

fn populate_initial_sync_root(
    root: &mut OwnedConfiguredRoot,
    backend: &dyn PlaceholderBackend,
    root_identity: &[u8],
) -> Result<(), Error> {
    root.verify_identity(true)?;
    root.verify_registered()?;
    let mut existing = fs::read_dir(&root.path)
        .map_err(|error| io_error("inspect registered sync root", error))?;
    if existing
        .next()
        .transpose()
        .map_err(|error| io_error("inspect registered sync root", error))?
        .is_some()
    {
        return Err(Error::ConfiguredRootNotEmpty);
    }

    // The sync-root directory itself is not a placeholder, so Windows does
    // not issue FETCH_PLACEHOLDERS for its first listing. Populate its
    // immediate children explicitly while retaining the same authenticated
    // backend lease used by callback publication.
    let cancellation = CancellationToken::with_timeout(crate::DEFAULT_FETCH_TIMEOUT);
    let prepared = backend
        .prepare_enumeration(root_identity, &cancellation)
        .map_err(|_| Error::ProviderUnavailable)?;
    let read_only = prepared.read_only();
    let children = prepared.children();
    if children.is_empty() || !valid_placeholder_children(children) {
        return Err(Error::ProviderUnavailable);
    }
    let _publish = prepared
        .begin_publish(&cancellation)
        .map_err(|_| Error::ProviderUnavailable)?;
    if cancellation.is_cancelled() || cancellation.is_expired() {
        return Err(Error::ProviderUnavailable);
    }
    root.verify_identity(true)?;
    root.verify_registered()?;

    let names = children
        .iter()
        .map(|child| wide_literal(&child.name))
        .collect::<Vec<_>>();
    let identities = children
        .iter()
        .map(|child| child.identity.clone())
        .collect::<Vec<_>>();
    let mut entries = children
        .iter()
        .enumerate()
        .map(|(index, child)| CfPlaceholderCreateInfo {
            relative_file_name: names[index].as_ptr(),
            fs_metadata: CfFsMetadata {
                basic_info: FileBasicInfo {
                    creation_time: child.last_write_time,
                    last_access_time: child.last_write_time,
                    last_write_time: child.last_write_time,
                    change_time: child.last_write_time,
                    file_attributes: if child.metadata.is_directory {
                        FILE_ATTRIBUTE_DIRECTORY
                    } else {
                        FILE_ATTRIBUTE_ARCHIVE
                            | if read_only {
                                FILE_ATTRIBUTE_READONLY
                            } else {
                                0
                            }
                    },
                },
                file_size: if child.metadata.is_directory {
                    0
                } else {
                    child.metadata.length as i64
                },
            },
            file_identity: identities[index].as_ptr().cast(),
            file_identity_length: identities[index].len() as u32,
            flags: if child.metadata.is_directory {
                0
            } else {
                CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
            },
            result: STATUS_UNSUCCESSFUL,
            create_usn: 0,
        })
        .collect::<Vec<_>>();
    #[cfg(test)]
    let stop_after_first = STOP_INITIAL_POPULATION_AFTER_FIRST.with(|flag| flag.replace(false));
    #[cfg(test)]
    if stop_after_first {
        assert!(
            entries.len() > 1,
            "partial population fixture needs two children"
        );
        entries.truncate(1);
    }
    let path = wide_path(&root.path)?;
    let mut processed = 0_u32;
    // SAFETY: root remains registered and identity-pinned; the prepared
    // enumeration publication lease remains held; all names, identities,
    // metadata, and output storage remain alive for this synchronous call.
    let hresult = unsafe {
        CfCreatePlaceholders(
            path.as_ptr(),
            entries.as_mut_ptr(),
            entries.len() as u32,
            CF_CREATE_FLAG_STOP_ON_ERROR,
            &mut processed,
        )
    };
    if hresult < 0 {
        return Err(native_error(
            "CfCreatePlaceholders initial sync root",
            hresult,
        ));
    }
    let processed = (processed as usize).min(entries.len());
    let entry_results = entries
        .iter()
        .take(processed)
        .map(|entry| entry.result)
        .collect::<Vec<_>>();
    if !placeholder_population_completed(hresult, entries.len(), processed, &entry_results) {
        if let Some(error) = entry_results.iter().copied().find(|result| *result < 0) {
            return Err(native_error(
                "CfCreatePlaceholders initial sync root entry",
                error,
            ));
        }
        return Err(Error::ProviderUnavailable);
    }
    #[cfg(test)]
    if stop_after_first {
        return Err(Error::ProviderUnavailable);
    }
    for child in children.iter().filter(|child| child.metadata.is_directory) {
        enable_configured_directory_population(root, child)?;
    }
    root.verify_identity(true)?;
    root.verify_registered()?;
    Ok(())
}

fn verify_existing_initial_sync_root(
    root: &OwnedConfiguredRoot,
    backend: &dyn PlaceholderBackend,
    root_identity: &[u8],
    require_partial: bool,
) -> Result<Vec<(RawOwnedHandle, RootSnapshot)>, Error> {
    let cancellation = CancellationToken::with_timeout(crate::DEFAULT_FETCH_TIMEOUT);
    let prepared = backend
        .prepare_enumeration(root_identity, &cancellation)
        .map_err(|_| Error::ProviderUnavailable)?;
    let children = prepared.children();
    if children.is_empty()
        || !valid_placeholder_children(children)
        || children.iter().any(|child| !child.metadata.is_directory)
    {
        return Err(Error::ProviderUnavailable);
    }
    let _publish = prepared
        .begin_publish(&cancellation)
        .map_err(|_| Error::ProviderUnavailable)?;
    root.verify_identity(true)?;
    root.verify_registered()?;
    let expected = children
        .iter()
        .map(|child| child.name.as_str())
        .collect::<std::collections::HashSet<_>>();
    let mut actual = std::collections::HashSet::new();
    for entry in
        fs::read_dir(&root.path).map_err(|e| io_error("verify existing initial namespace", e))?
    {
        let entry = entry.map_err(|e| io_error("read existing initial namespace", e))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::ConfiguredRootChanged)?;
        if actual.len() >= crate::MAX_DIRECTORY_CHILDREN
            || !expected.contains(name.as_str())
            || !actual.insert(name)
        {
            return Err(Error::ConfiguredRootChanged);
        }
    }
    if actual.len() != expected.len() {
        return Err(Error::ConfiguredRootChanged);
    }
    let mut held = Vec::with_capacity(children.len());
    for child in children {
        let pinned = pin_configured_directory_identity(root, child, FILE_READ_ATTRIBUTES)?;
        // Fresh directories are created with on-demand population enabled and
        // explicitly confirmed by the policy update. Reconnected directories
        // may already be fully populated by a successful complete listing.
        if require_partial && pinned.1.placeholder_state & CF_PLACEHOLDER_STATE_PARTIAL == 0 {
            return Err(Error::ConfiguredRootChanged);
        }
        held.push(pinned);
    }
    if cancellation.is_cancelled() || cancellation.is_expired() {
        return Err(Error::ProviderUnavailable);
    }
    root.verify_identity(true)?;
    root.verify_registered()?;
    Ok(held)
}

fn pin_configured_directory_identity(
    root: &OwnedConfiguredRoot,
    child: &crate::PlaceholderChild,
    access: u32,
) -> Result<(RawOwnedHandle, RootSnapshot), Error> {
    let (entry, snapshot, _parents) =
        pin_configured_directory_path(root, child, &[child.name.as_str()], access)?;
    Ok((entry, snapshot))
}

type PinnedPopulationDirectory = (
    RawOwnedHandle,
    RootSnapshot,
    Vec<(RawOwnedHandle, RootSnapshot)>,
);

fn pin_configured_directory_path(
    root: &OwnedConfiguredRoot,
    child: &crate::PlaceholderChild,
    components: &[&str],
    access: u32,
) -> Result<PinnedPopulationDirectory, Error> {
    if !child.metadata.is_directory
        || components.is_empty()
        || components.len() > 256
        || components.last().copied() != Some(child.name.as_str())
        || components
            .iter()
            .any(|component| !valid_component(component))
    {
        return Err(Error::InvalidConfiguredRoot);
    }
    root.verify_identity(true)?;
    root.verify_registered()?;
    let mut path = root.path.clone();
    let mut parents = Vec::with_capacity(components.len() - 1);
    for component in &components[..components.len() - 1] {
        path.push(component);
        let wide = wide_path(&path)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(win32_io_error("pin population directory ancestor"));
        }
        let held = RawOwnedHandle(raw);
        let snapshot = root_snapshot(held.0)?;
        if snapshot.identity.volume_serial != root.identity.volume_serial
            || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || !valid_callback_directory_snapshot(snapshot)
        {
            return Err(Error::ConfiguredRootChanged);
        }
        parents.push((held, snapshot));
    }
    path.push(child.name.as_str());
    let path = wide_path(&path)?;
    // The exact generated child name is one validated component beneath the
    // held root. Open the reparse point itself and omit FILE_SHARE_DELETE so
    // it cannot be replaced while identity and population state are checked.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(win32_io_error("open configured Cloud Files directory"));
    }
    let child_handle = RawOwnedHandle(handle);
    let before = root_snapshot(child_handle.0)?;
    if before.identity.volume_serial != root.identity.volume_serial
        || before.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || before.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        || before.reparse_tag & IO_REPARSE_TAG_CLOUD_MASK != IO_REPARSE_TAG_CLOUD
        || before.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
        || before.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT != 0
        || before.placeholder_state
            & !(CF_PLACEHOLDER_STATE_PLACEHOLDER
                | 0x4
                | 0x8
                | CF_PLACEHOLDER_STATE_PARTIAL
                | CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK)
            != 0
        || (before.placeholder_state & CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK != 0
            && before.placeholder_state & CF_PLACEHOLDER_STATE_PARTIAL == 0)
    {
        return Err(Error::ConfiguredRootChanged);
    }

    // CfGetPlaceholderInfo returns the opaque provider identity attached to
    // this exact handle. Do not update a path-resolved or substituted child.
    const IDENTITY_OFFSET: usize = 28;
    const MAX_IDENTITY: usize = 256;
    let mut storage = [0_u64; (IDENTITY_OFFSET + MAX_IDENTITY).div_ceil(size_of::<u64>())];
    let mut returned = 0_u32;
    let info_result = unsafe {
        CfGetPlaceholderInfo(
            child_handle.0,
            CF_PLACEHOLDER_INFO_BASIC,
            storage.as_mut_ptr().cast(),
            size_of_val(&storage) as u32,
            &mut returned,
        )
    };
    if info_result < 0 {
        return Err(native_error(
            "CfGetPlaceholderInfo configured directory",
            info_result,
        ));
    }
    let returned = returned as usize;
    if !(IDENTITY_OFFSET..=size_of_val(&storage)).contains(&returned) {
        return Err(Error::ConfiguredRootChanged);
    }
    let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned) };
    let identity_length = u32::from_ne_bytes(
        bytes[24..28]
            .try_into()
            .map_err(|_| Error::ConfiguredRootChanged)?,
    ) as usize;
    if identity_length == 0
        || identity_length > MAX_IDENTITY
        || IDENTITY_OFFSET.saturating_add(identity_length) > bytes.len()
        || bytes[IDENTITY_OFFSET..IDENTITY_OFFSET + identity_length] != child.identity
    {
        return Err(Error::ConfiguredRootChanged);
    }

    verify_population_path(root, child_handle.0, &parents, components)?;
    root.verify_identity(true)?;
    root.verify_registered()?;
    Ok((child_handle, before, parents))
}

fn verify_population_path(
    root: &OwnedConfiguredRoot,
    child: Handle,
    parents: &[(RawOwnedHandle, RootSnapshot)],
    components: &[&str],
) -> Result<(), Error> {
    let root_final =
        final_path_for_handle(root.root_handle()?).map_err(|_| Error::ConfiguredRootChanged)?;
    let child_final = final_path_for_handle(child).map_err(|_| Error::ConfiguredRootChanged)?;
    let mut expected = root_final.clone();
    for component in components {
        expected.push(component);
    }
    if !windows_paths_equal(&child_final, &expected)
        || !windows_path_is_within(&child_final, &root_final)
    {
        return Err(Error::ConfiguredRootChanged);
    }
    for (handle, before) in parents {
        let now = root_snapshot(handle.0)?;
        if now.identity != before.identity
            || now.file_attributes != before.file_attributes
            || now.reparse_tag != before.reparse_tag
            || now.placeholder_state != before.placeholder_state
            || !valid_callback_directory_snapshot(now)
        {
            return Err(Error::ConfiguredRootChanged);
        }
    }
    Ok(())
}

fn enable_configured_directory_population(
    root: &OwnedConfiguredRoot,
    child: &crate::PlaceholderChild,
) -> Result<(), Error> {
    enable_configured_directory_population_at(root, child, &[child.name.as_str()])
}

fn enable_configured_directory_population_at(
    root: &OwnedConfiguredRoot,
    child: &crate::PlaceholderChild,
    components: &[&str],
) -> Result<(), Error> {
    // Retain every no-follow ancestor through the update and final proof.
    let (child_handle, before, parents) = pin_configured_directory_path(
        root,
        child,
        components,
        FILE_READ_ATTRIBUTES | FILE_WRITE_DATA,
    )?;
    verify_population_path(root, child_handle.0, &parents, components)?;
    let update_result = unsafe {
        CfUpdatePlaceholder(
            child_handle.0,
            null(),
            child.identity.as_ptr().cast(),
            child.identity.len() as u32,
            null(),
            0,
            CF_UPDATE_FLAG_ENABLE_ON_DEMAND_POPULATION,
            null_mut(),
            null_mut(),
        )
    };
    if update_result < 0 {
        return Err(native_error(
            "enable configured directory population",
            update_result,
        ));
    }
    verify_population_path(root, child_handle.0, &parents, components)?;
    let after = root_snapshot(child_handle.0)?;
    if after.identity != before.identity
        || after.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || after.reparse_tag & IO_REPARSE_TAG_CLOUD_MASK != IO_REPARSE_TAG_CLOUD
        || after.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
    {
        return Err(Error::ConfiguredRootChanged);
    }
    root.verify_identity(true)?;
    root.verify_registered()?;
    Ok(())
}

fn valid_placeholder_children(children: &[crate::PlaceholderChild]) -> bool {
    if children.len() > crate::MAX_DIRECTORY_CHILDREN {
        return false;
    }
    let mut names = HashSet::with_capacity(children.len());
    let mut identities = HashSet::with_capacity(children.len());
    children.iter().all(|child| {
        !child.identity.is_empty()
            && child.identity.len() <= 256
            && valid_component(&child.name)
            && names.insert(child.name.to_lowercase())
            && identities.insert(child.identity.as_slice())
            && (child.metadata.is_directory || child.metadata.length <= i64::MAX as u64)
    })
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && !value.ends_with('.')
        && !value.ends_with(' ')
        && !value.chars().any(|ch| {
            ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        })
        && !matches!(
            value
                .split('.')
                .next()
                .unwrap_or("")
                .to_ascii_uppercase()
                .as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
}

struct PlaceholderExecutionOutcome {
    hresult: HResult,
    entries_processed: usize,
    complete: bool,
    entry_failure: Option<HResult>,
}

fn execute_transfer_placeholders(
    info: &CfCallbackInfo,
    children: &[crate::PlaceholderChild],
    completion_status: i32,
    read_only: bool,
) -> PlaceholderExecutionOutcome {
    let names = children
        .iter()
        .map(|child| wide_literal(&child.name))
        .collect::<Vec<_>>();
    let identities = children
        .iter()
        .map(|child| child.identity.clone())
        .collect::<Vec<_>>();
    let mut entries = children
        .iter()
        .enumerate()
        .map(|(index, child)| CfPlaceholderCreateInfo {
            relative_file_name: names[index].as_ptr(),
            fs_metadata: CfFsMetadata {
                basic_info: FileBasicInfo {
                    creation_time: child.last_write_time,
                    last_access_time: child.last_write_time,
                    last_write_time: child.last_write_time,
                    change_time: child.last_write_time,
                    file_attributes: if child.metadata.is_directory {
                        FILE_ATTRIBUTE_DIRECTORY
                    } else {
                        FILE_ATTRIBUTE_ARCHIVE
                            | if read_only {
                                FILE_ATTRIBUTE_READONLY
                            } else {
                                0
                            }
                    },
                },
                file_size: if child.metadata.is_directory {
                    0
                } else {
                    child.metadata.length as i64
                },
            },
            file_identity: identities[index].as_ptr().cast_mut().cast(),
            file_identity_length: identities[index].len() as u32,
            flags: if child.metadata.is_directory {
                0
            } else {
                CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
            },
            result: 0,
            create_usn: 0,
        })
        .collect::<Vec<_>>();
    // A successful enumeration is a complete listing by the backend
    // contract. Tell Cloud Files the current directory population is finished;
    // without this terminal flag it may keep requesting pages and wait on the
    // original filesystem enumeration.
    let flags = if completion_status == STATUS_SUCCESS {
        CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION
    } else {
        CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE
    };
    let transfer = CfTransferPlaceholdersParameters {
        flags,
        completion_status,
        placeholder_total_count: children.len() as i64,
        placeholder_array: if entries.is_empty() {
            null_mut()
        } else {
            entries.as_mut_ptr()
        },
        placeholder_count: entries.len() as u32,
        entries_processed: 0,
    };
    let operation_info = CfOperationInfo {
        struct_size: size_of::<CfOperationInfo>() as u32,
        operation_type: CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS,
        connection_key: info.connection_key,
        transfer_key: info.transfer_key,
        correlation_vector: info.correlation_vector,
        sync_status: null(),
        request_key: info.request_key,
    };
    let mut parameters = CfOperationParameters {
        param_size: (std::mem::offset_of!(CfOperationParameters, data)
            + size_of::<CfTransferPlaceholdersParameters>()) as u32,
        data: CfOperationParameterData {
            transfer_placeholders: transfer,
        },
    };
    // SAFETY: all nested arrays/UTF-16 names and the output counter remain
    // alive through the synchronous CfExecute call. Counts are bounded and
    // all child names/identity lengths were validated before reaching here.
    let hresult = unsafe { CfExecute(&operation_info, &mut parameters) };
    // SAFETY: CfExecute synchronously writes the EntriesProcessed output field
    // in the selected TransferPlaceholders arm before returning.
    let reported_processed =
        unsafe { parameters.data.transfer_placeholders.entries_processed } as usize;
    let processed = reported_processed.min(entries.len());
    let results = entries
        .iter()
        .take(processed)
        .map(|entry| entry.result)
        .collect::<Vec<_>>();
    let entry_failure = entries
        .iter()
        .take(processed)
        .find(|entry| entry.result < 0)
        .map(|entry| entry.result);
    PlaceholderExecutionOutcome {
        hresult,
        entries_processed: if hresult >= 0 && reported_processed <= entries.len() {
            processed
        } else {
            0
        },
        complete: placeholder_population_completed(
            hresult,
            entries.len(),
            reported_processed,
            &results,
        ),
        entry_failure,
    }
}

unsafe extern "system" fn fetch_data_callback(
    info: *const CfCallbackInfo,
    parameters: *const CfCallbackParameters,
) {
    let Some(guard) = callback_guard(info) else {
        return;
    };
    if info.is_null() || parameters.is_null() {
        return;
    }
    // SAFETY: Cloud Files owns both callback structures for this callback's
    // duration. Their ABI layouts are checked above and no pointer fields other
    // than the opaque file-identity bytes are dereferenced.
    let info = unsafe { &*info };
    let parameters = unsafe { &*parameters };
    let param_size = parameters.param_size as usize;
    guard.0.record_fetch_callback(param_size);
    macro_rules! observe_fetch {
        ($stage:expr) => {{
            #[cfg(feature = "synthetic-agent-integration")]
            guard
                .0
                .fetch_validation_stage
                .store($stage, Ordering::Relaxed);
        }};
    }
    observe_fetch!(1);
    if !valid_fetch_data_param_size(param_size) {
        execute_transfer(info, 0, None, STATUS_UNSUCCESSFUL);
        return;
    }
    // SAFETY: FETCH_DATA callbacks provide the FetchData union arm, and the
    // documented ParamSize above covers every field used here.
    let fetch = unsafe { parameters.data.fetch_data };
    let identity_matches = info.file_identity_length > 0
        && info.file_identity_length <= 256
        && !info.file_identity.is_null();
    if !identity_matches || info.file_size < 0 {
        execute_transfer(info, 0, None, STATUS_UNSUCCESSFUL);
        return;
    }
    let range = match checked_fetch_range(
        info.file_size as u64,
        fetch.required_file_offset,
        fetch.required_length,
    ) {
        Ok(range) => range,
        Err(_) => {
            execute_transfer(info, 0, None, STATUS_UNSUCCESSFUL);
            return;
        }
    };
    guard.0.record_request(range);
    let Some(fetch_permit) = guard.0.begin_fetch(info.request_key.internal, range) else {
        execute_transfer(info, range.offset, None, STATUS_UNSUCCESSFUL);
        return;
    };
    // SAFETY: the bounded identity pointer is supplied by Cloud Files and is
    // valid for the duration of this callback.
    let identity = unsafe {
        std::slice::from_raw_parts(
            info.file_identity.cast::<u8>(),
            info.file_identity_length as usize,
        )
    };
    if range.is_empty() {
        match lookup_for_fetch(
            guard.0.backend.as_ref(),
            identity,
            &fetch_permit.cancellation,
        ) {
            Ok(Some(metadata))
                if !metadata.is_directory && metadata.length == info.file_size as u64 => {}
            Err(BackendError::Cancelled) => {
                execute_transfer(info, 0, None, STATUS_CANCELLED);
                return;
            }
            _ => {
                execute_transfer(info, range.offset, None, STATUS_UNSUCCESSFUL);
            }
        }
        return;
    }
    // Only verified vault identities require this path admission. Ordinary
    // callbacks keep their existing behavior. Keep all no-follow pins alive
    // through the final native publication; never reopen names per data slice.
    observe_fetch!(2);
    let tracked_path = match guard.0.backend.requires_hydration_inventory(identity) {
        Ok(false) => None,
        Ok(true) => {
            let admitted = (|| {
                observe_fetch!(3);
                let root = guard.0.root_identity?;
                if identity.len() != 16
                    || info.volume_serial_number != root.volume_serial
                    || info.sync_root_file_id as u64 != root.file_index
                    || info.file_id == 0
                {
                    return None;
                }
                observe_fetch!(4);
                let pinned = match callback_path(
                    guard.0.root_path.as_deref()?,
                    info.volume_dos_name,
                    info.normalized_path,
                    root,
                    info.file_id as u64,
                    info.file_size as u64,
                    &guard.0.last_close_path_common_prefix_bytes,
                ) {
                    Ok(pinned) => pinned,
                    Err(stage) => {
                        let _ = stage;
                        observe_fetch!(1000 + usize::from(stage));
                        return None;
                    }
                };
                observe_fetch!(5);
                let opaque: [u8; 16] = identity.try_into().ok()?;
                observe_fetch!(6);
                verify_completion_identity(pinned.entry.0, &opaque).ok()?;
                observe_fetch!(7);
                let final_path = final_path_for_handle(pinned.entry.0).ok()?;
                if !windows_path_is_within(&final_path, &pinned.root_final_path) {
                    return None;
                }
                let components = final_path
                    .components()
                    .skip(pinned.root_final_path.components().count())
                    .map(|part| match part {
                        std::path::Component::Normal(name) => name
                            .to_str()
                            .filter(|name| valid_component(name))
                            .map(str::to_owned),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()?;
                if components.is_empty() {
                    return None;
                }
                Some((pinned, components))
            })();
            match admitted {
                Some(path) => Some(path),
                None => {
                    if let Ok(mut inventory) = guard.0.hydrated_files.lock() {
                        inventory.mark_incomplete();
                    }
                    execute_transfer(info, range.offset, None, STATUS_UNSUCCESSFUL);
                    return;
                }
            }
        }
        Err(_) => {
            execute_transfer(info, range.offset, None, STATUS_UNSUCCESSFUL);
            return;
        }
    };
    observe_fetch!(8);
    let mut tracked = false;
    // The deadline starts before waiting for one of the two callback-wide
    // staging permits, so backpressure is part of the same bounded request.
    let staged_fetch_started = Instant::now();
    let Some(_staging_permit) = guard.0.reserve_staging(&fetch_permit.cancellation) else {
        guard
            .0
            .record_staged_duration(staged_fetch_started.elapsed());
        let status = if fetch_permit.cancellation.is_cancelled() {
            STATUS_CANCELLED
        } else {
            STATUS_UNSUCCESSFUL
        };
        execute_transfer(info, range.offset, None, status);
        return;
    };
    observe_fetch!(9);
    let result = stream_prepared_windows(
        guard.0.backend.as_ref(),
        identity,
        range,
        info.file_size as u64,
        &fetch_permit.cancellation,
        |offset, slice| {
            observe_fetch!(10);
            let _request_publish =
                fetch_permit
                    .begin_publish()
                    .map_err(|error| WindowStreamError {
                        offset,
                        error,
                        transfer_refused: false,
                    })?;
            observe_fetch!(11);
            if !tracked {
                if let Some((pinned, components)) = tracked_path.as_ref() {
                    let id: [u8; 16] = identity.try_into().map_err(|_| WindowStreamError {
                        offset,
                        error: BackendError::Unavailable,
                        transfer_refused: false,
                    })?;
                    // The stream's backend publication permit and request
                    // permit are both held here. Store BEFORE CfExecute and
                    // release the inventory mutex before calling Windows. Keep
                    // the row even if that call fails or transfers only a range.
                    guard
                        .0
                        .hydrated_files
                        .lock()
                        .map_err(|_| WindowStreamError {
                            offset,
                            error: BackendError::Unavailable,
                            transfer_refused: false,
                        })?
                        .record(
                            id,
                            pinned.snapshot.identity.file_index,
                            info.file_size as u64,
                            components.clone(),
                        )
                        .map_err(|_| WindowStreamError {
                            offset,
                            error: BackendError::Unavailable,
                            transfer_refused: false,
                        })?;
                }
                tracked = true;
            }
            observe_fetch!(12);
            let execute_result = execute_transfer(info, offset, Some(slice), STATUS_SUCCESS);
            observe_fetch!(13);
            guard.0.record_failed_hresult(execute_result);
            guard
                .0
                .commit_transfer_result(
                    info.request_key.internal,
                    offset,
                    slice.len(),
                    execute_result,
                )
                .ok_or(WindowStreamError {
                    offset,
                    error: BackendError::Unavailable,
                    transfer_refused: true,
                })?;
            Ok(())
        },
    );
    if result.is_ok() {
        observe_fetch!(14);
    }
    #[cfg(feature = "synthetic-agent-integration")]
    eprintln!("synthetic fetch stream result_ok={}", result.is_ok());
    guard
        .0
        .record_staged_duration(staged_fetch_started.elapsed());
    if let Err(error) = result {
        if !error.transfer_refused {
            let status = if error.error == BackendError::Cancelled {
                STATUS_CANCELLED
            } else {
                STATUS_UNSUCCESSFUL
            };
            execute_transfer(info, error.offset, None, status);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct WindowStreamError {
    offset: u64,
    error: BackendError,
    // A rejected CfExecute must not be followed by another transfer attempt.
    transfer_refused: bool,
}

/// The real callback and deterministic fixtures share this window loop.
/// One root/binding session and caller-owned staging/request permits span it.
fn stream_prepared_windows(
    backend: &dyn PlaceholderBackend,
    identity: &[u8],
    range: FetchRange,
    expected_size: u64,
    cancellation: &CancellationToken,
    mut publish: impl FnMut(u64, &[u8]) -> Result<(), WindowStreamError>,
) -> Result<(), WindowStreamError> {
    let fail = |offset, error| WindowStreamError {
        offset,
        error,
        transfer_refused: false,
    };
    if range.end < range.offset || range.end > expected_size || expected_size > MAX_FILE_BYTES {
        return Err(fail(range.offset, BackendError::InvalidRange));
    }
    let session = if range.len() > MAX_REQUEST_BYTES {
        let session = catch_unwind(AssertUnwindSafe(|| {
            backend.prepare_fetch_session(identity, cancellation)
        }))
        .unwrap_or(Err(BackendError::Unavailable))
        .map_err(|error| fail(range.offset, error))?;
        if session.metadata().is_directory || session.metadata().length != expected_size {
            return Err(fail(range.offset, BackendError::Unavailable));
        }
        Some(session)
    } else {
        None
    };
    let mut offset = range.offset;
    while offset < range.end {
        let window = FetchRange {
            offset,
            end: offset + (range.end - offset).min(MAX_REQUEST_BYTES),
        };
        let prepared = catch_unwind(AssertUnwindSafe(|| match &session {
            Some(session) => session.prepare_window(window, cancellation),
            None => backend.prepare_fetch(identity, window, cancellation),
        }))
        .unwrap_or(Err(BackendError::Unavailable))
        .map_err(|error| fail(offset, error))?;
        if prepared.metadata().is_directory
            || prepared.metadata().length != expected_size
            || prepared.bytes().len() as u64 != window.len()
        {
            return Err(fail(offset, BackendError::Unavailable));
        }
        let mut copied = 0;
        while copied < prepared.bytes().len() {
            // Both the backend authorization permit and the caller's request
            // publication permit remain held through each accepted slice.
            let _permit = prepared
                .begin_publish(cancellation)
                .map_err(|error| fail(offset, error))?;
            let count = next_chunk_len((prepared.bytes().len() - copied) as u64);
            publish(offset, &prepared.bytes()[copied..copied + count])?;
            copied += count;
            offset += count as u64;
        }
    }
    Ok(())
}

fn valid_fetch_data_param_size(param_size: usize) -> bool {
    param_size == CF_FETCH_DATA_PARAM_SIZE_DOCUMENTED
        || param_size == CF_FETCH_DATA_PARAM_SIZE_ALIGNED
}

fn lookup_for_fetch(
    backend: &dyn PlaceholderBackend,
    identity: &[u8],
    cancellation: &CancellationToken,
) -> Result<Option<PlaceholderMetadata>, BackendError> {
    if cancellation.is_cancelled() {
        return Err(BackendError::Cancelled);
    }
    let result = catch_unwind(AssertUnwindSafe(|| backend.lookup(identity)))
        .unwrap_or(Err(BackendError::Unavailable));
    if cancellation.is_cancelled() {
        Err(BackendError::Cancelled)
    } else {
        result
    }
}

fn checked_cancel_range(offset: i64, length: i64) -> Option<FetchRange> {
    let offset = u64::try_from(offset).ok()?;
    if length < 0 && length != -1 {
        return None;
    }
    let end = if length == -1 {
        u64::MAX
    } else {
        offset.checked_add(length as u64)?
    };
    Some(FetchRange { offset, end })
}

fn execute_transfer(
    info: &CfCallbackInfo,
    offset: u64,
    payload: Option<&[u8]>,
    completion_status: i32,
) -> HResult {
    let operation_info = CfOperationInfo {
        struct_size: size_of::<CfOperationInfo>() as u32,
        operation_type: CF_OPERATION_TYPE_TRANSFER_DATA,
        connection_key: info.connection_key,
        transfer_key: info.transfer_key,
        correlation_vector: info.correlation_vector,
        sync_status: null(),
        request_key: info.request_key,
    };
    let transfer = CfTransferDataParameters {
        flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
        completion_status,
        buffer: if let Some(payload) = payload {
            payload.as_ptr().cast()
        } else {
            null()
        },
        offset: offset as i64,
        length: payload.map_or(0, |payload| payload.len() as i64),
    };
    let mut parameters = CfOperationParameters {
        param_size: (std::mem::offset_of!(CfOperationParameters, data)
            + size_of::<CfTransferDataParameters>()) as u32,
        data: CfOperationParameterData {
            transfer_data: transfer,
        },
    };
    // SAFETY: operation info is copied from this live callback. The bounded
    // payload remains borrowed until CfExecute returns; sizes follow the SDK.
    unsafe { CfExecute(&operation_info, &mut parameters) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootIdentity {
    volume_serial: u32,
    file_index: u64,
}

// Reconnect safety is derived from the registered tree, not from process-local
// callback counters. The scan intentionally fails closed for any object it
// cannot prove is an untouched, unmaterialized Cloud Files placeholder.
const MAX_RECONNECT_SCAN_ENTRIES: usize = 10_000;
const MAX_RECONNECT_SCAN_DEPTH: usize = 64;

#[derive(Default)]
struct ReconnectScan {
    modified_files: usize,
    unresolved_objects: usize,
}

fn scan_registered_root(path: &Path, expected: RootIdentity) -> ReconnectScan {
    let mut result = ReconnectScan::default();
    let mut visited = 0usize;
    let root_handle = match open_root_for_identity_check(path) {
        Ok(handle) => handle,
        Err(_) => {
            result.unresolved_objects = 1;
            return result;
        }
    };
    match root_snapshot(root_handle.0) {
        Ok(snapshot)
            if snapshot.identity == expected
                && snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                && snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 => {}
        _ => {
            result.unresolved_objects = 1;
            return result;
        }
    }
    if scan_registered_directory(path, expected.volume_serial, 0, &mut visited, &mut result)
        .is_err()
    {
        result.unresolved_objects = result.unresolved_objects.saturating_add(1);
    }
    result
}

fn scan_registered_directory(
    directory: &Path,
    expected_volume: u32,
    depth: usize,
    visited: &mut usize,
    result: &mut ReconnectScan,
) -> Result<(), ()> {
    if depth > MAX_RECONNECT_SCAN_DEPTH {
        return Err(());
    }
    let entries = fs::read_dir(directory).map_err(|_| ())?;
    for entry in entries {
        let entry = entry.map_err(|_| ())?;
        *visited = visited.checked_add(1).ok_or(())?;
        if *visited > MAX_RECONNECT_SCAN_ENTRIES {
            return Err(());
        }
        let path = entry.path();
        let path_wide = wide_path(&path).map_err(|_| ())?;
        // Open the reparse point itself and omit FILE_SHARE_DELETE so the
        // name cannot be replaced while its identity and any range metadata
        // are checked. Never follow an unknown reparse target.
        let raw = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(());
        }
        let child_handle = RawOwnedHandle(raw);
        let snapshot = root_snapshot(child_handle.0).map_err(|_| ())?;
        if snapshot.identity.volume_serial != expected_volume {
            return Err(());
        }
        let is_directory = snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let is_reparse = snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let is_cloud_placeholder = is_reparse
            && snapshot.reparse_tag & IO_REPARSE_TAG_CLOUD_MASK
                == (IO_REPARSE_TAG_CLOUD & IO_REPARSE_TAG_CLOUD_MASK)
            && snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER != 0;

        if is_directory {
            // Cloud directory placeholders can contain files that are not
            // locally enumerable. Conservatively block unregister rather
            // than infer that their descendants are clean after restart.
            if is_reparse || snapshot.reparse_tag != 0 || snapshot.placeholder_state != 0 {
                result.unresolved_objects = result.unresolved_objects.saturating_add(1);
                continue;
            }
            // A materialized ordinary directory could be a hydrated clean
            // folder or a user-created folder. Without a durable baseline we
            // cannot distinguish them, so retain registration even when the
            // bounded child scan succeeds.
            result.unresolved_objects = result.unresolved_objects.saturating_add(1);
            scan_registered_directory(&path, expected_volume, depth + 1, visited, result)?;
            continue;
        }
        if is_cloud_placeholder {
            match modified_ranges_for_handle(child_handle.0) {
                Ok(true) => {
                    result.modified_files = result.modified_files.saturating_add(1);
                }
                Ok(false) => {}
                Err(()) => {
                    result.unresolved_objects = result.unresolved_objects.saturating_add(1);
                }
            }
            continue;
        }
        // Hydrated files lose the Cloud reparse tag. Any such bytes are
        // potentially user edits, even if they may also be a clean hydration;
        // only an exact later recovery mechanism can safely clear this doubt.
        result.unresolved_objects = result.unresolved_objects.saturating_add(1);
    }
    Ok(())
}

fn modified_ranges_for_handle(handle: Handle) -> Result<bool, ()> {
    let mut ranges = [CfFileRange {
        starting_offset: 0,
        length: 0,
    }; 64];
    let mut returned = 0_u32;
    let hr = unsafe {
        CfGetPlaceholderRangeInfo(
            handle,
            CF_PLACEHOLDER_RANGE_INFO_MODIFIED,
            0,
            -1,
            ranges.as_mut_ptr().cast(),
            size_of::<CfFileRange>()
                .checked_mul(ranges.len())
                .ok_or(())? as u32,
            &mut returned,
        )
    };
    if hr < 0 || returned as usize > std::mem::size_of_val(&ranges) {
        return Err(());
    }
    let returned = returned as usize;
    if returned % size_of::<CfFileRange>() != 0 {
        return Err(());
    }
    let count = returned / size_of::<CfFileRange>();
    for range in ranges.iter().take(count) {
        if range.starting_offset < 0
            || range.length <= 0
            || range.starting_offset.checked_add(range.length).is_none()
        {
            return Err(());
        }
    }
    Ok(count != 0)
}

pub(super) struct RootInspectionLease {
    pub(super) identity: crate::ConfiguredRootIdentity,
    _pinned: Vec<RawOwnedHandle>,
}

struct RawOwnedHandle(Handle);

impl RawOwnedHandle {
    fn invalid() -> Self {
        Self(null_mut())
    }
}

impl Drop for RawOwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this wrapper exclusively owns the valid Win32 handle.
            unsafe { CloseHandle(self.0) };
            self.0 = null_mut();
        }
    }
}

fn create_private_test_root() -> Result<PathBuf, Error> {
    let base = env::temp_dir();
    for _ in 0..32 {
        let sequence = TEST_ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = base.join(format!(
            "Raiun-CfApi-Synthetic-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        if create_directory_current_user_only(&path)? {
            wide_path(&path)?;
            return Ok(path);
        }
    }
    Err(Error::Io {
        operation: "create unique private synthetic root",
        kind: std::io::ErrorKind::AlreadyExists,
    })
}

fn create_directory_current_user_only(path: &Path) -> Result<bool, Error> {
    let sid = current_user_sid_string()?;
    let sddl = wide_literal(&format!("D:P(A;;FA;;;{sid})"));
    let mut descriptor = null_mut();
    // SAFETY: SDDL is valid NUL-terminated UTF-16 and output is initialized.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(win32_io_error("build private root ACL"));
    }
    let security = SecurityAttributes {
        length: size_of::<SecurityAttributes>() as u32,
        security_descriptor: descriptor,
        inherit_handle: 0,
    };
    let wide_path = wide_path(path)?;
    // SAFETY: the descriptor remains valid until LocalFree below and path is
    // a bounded NUL-terminated UTF-16 path generated by this module.
    let created = unsafe { CreateDirectoryW(wide_path.as_ptr(), &security) };
    let error = if created == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    // SAFETY: `descriptor` was allocated by the matching Windows API.
    unsafe { LocalFree(descriptor) };
    if created != 0 {
        Ok(true)
    } else if error == 183 {
        Ok(false)
    } else {
        Err(Error::Io {
            operation: "create private synthetic root",
            kind: std::io::Error::from_raw_os_error(error as i32).kind(),
        })
    }
}

fn current_user_sid_string() -> Result<String, Error> {
    let mut token = null_mut();
    // SAFETY: current process pseudo-handle is valid and token is an output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(win32_io_error("open current-user token"));
    }
    let token = RawOwnedHandle(token);
    let mut needed = 0_u32;
    // SAFETY: this first call requests the exact required size.
    unsafe {
        GetTokenInformation(token.0, TOKEN_USER_CLASS, null_mut(), 0, &mut needed);
    }
    if needed == 0 || needed > 64 * 1024 {
        return Err(Error::InvalidSyntheticPath);
    }
    let mut buffer = vec![0_u64; (needed as usize).div_ceil(size_of::<u64>())];
    // SAFETY: aligned buffer is at least `needed` bytes and the token handle is valid.
    if unsafe {
        GetTokenInformation(
            token.0,
            TOKEN_USER_CLASS,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(win32_io_error("read current-user token"));
    }
    // SAFETY: TOKEN_USER is the documented result layout for TokenUser.
    let user = unsafe { &*buffer.as_ptr().cast::<TokenUser>() };
    if user.user.sid.is_null() {
        return Err(Error::InvalidSyntheticPath);
    }
    let mut sid_string = null_mut();
    // SAFETY: SID points into the live token information buffer.
    if unsafe { ConvertSidToStringSidW(user.user.sid, &mut sid_string) } == 0 {
        return Err(win32_io_error("format current-user SID"));
    }
    let sid = unsafe {
        let mut length = 0_usize;
        while *sid_string.add(length) != 0 && length < 256 {
            length += 1;
        }
        if length == 256 {
            LocalFree(sid_string.cast());
            return Err(Error::InvalidSyntheticPath);
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(sid_string, length))
    };
    // SAFETY: the string was allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(sid_string.cast()) };
    Ok(sid)
}

fn open_owned_root(path: &Path) -> Result<RawOwnedHandle, Error> {
    open_root(
        path,
        FILE_READ_ATTRIBUTES | DELETE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
}

fn open_root_for_identity_check(path: &Path) -> Result<RawOwnedHandle, Error> {
    open_root(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
}

pub(super) fn inspect_configured_root(
    path: &Path,
    require_empty: bool,
) -> Result<crate::ConfiguredRootIdentity, Error> {
    inspect_configured_root_chain(path, require_empty)?
        .0
        .last()
        .copied()
        .ok_or(Error::InvalidConfiguredRoot)
}

pub(super) fn pin_configured_root(path: &Path) -> Result<RootInspectionLease, Error> {
    let (identities, pinned) = inspect_configured_root_chain(path, true)?;
    let identity = identities
        .last()
        .copied()
        .ok_or(Error::InvalidConfiguredRoot)?;
    Ok(RootInspectionLease {
        identity,
        _pinned: pinned,
    })
}

pub(super) fn pin_registered_configured_root(
    path: &Path,
    expected: crate::ConfiguredRootIdentity,
) -> Result<RootInspectionLease, Error> {
    let (identities, pinned) = inspect_configured_root_chain_for_registration(path, expected)?;
    let identity = identities
        .last()
        .copied()
        .ok_or(Error::InvalidConfiguredRoot)?;
    if identity != expected {
        return Err(Error::ConfiguredRootChanged);
    }
    verify_sync_root_registration(
        path,
        RootIdentity {
            volume_serial: identity.volume_serial,
            file_index: identity.file_index,
        },
    )?;
    Ok(RootInspectionLease {
        identity,
        _pinned: pinned,
    })
}

fn verify_sync_root_registration(path: &Path, expected: RootIdentity) -> Result<(), Error> {
    verify_sync_root_registration_identity(
        path,
        expected,
        &configured_sync_root_identity(expected),
        "Raiun Internal Cloud Files Root",
        "0.0.0-internal",
    )
}

fn verify_synthetic_sync_root_registration(
    path: &Path,
    expected: RootIdentity,
) -> Result<(), Error> {
    verify_sync_root_registration_identity(
        path,
        expected,
        &synthetic_sync_root_identity(expected),
        "Raiun Synthetic Cloud Files Test",
        "test-only",
    )
    .map_err(|_| Error::SyntheticRootChanged)
}

fn verify_sync_root_registration_identity(
    path: &Path,
    expected: RootIdentity,
    expected_root_identity: &[u8],
    provider_name: &str,
    provider_version: &str,
) -> Result<(), Error> {
    let path = wide_path(path)?;
    let header_len = size_of::<CfSyncRootStandardInfoHeader>();
    let identity_offset =
        std::mem::offset_of!(CfSyncRootStandardInfoHeader, sync_root_identity_length)
            + size_of::<u32>();
    let buffer_len = header_len
        .checked_add(CF_SYNC_ROOT_IDENTITY_MAX)
        .ok_or(Error::InvalidConfiguredRoot)?;
    let mut buffer = vec![0_u64; buffer_len.div_ceil(size_of::<u64>())];
    let mut returned_length = 0_u32;
    // SAFETY: the queried path is independently held by the caller's no-follow
    // lease. The aligned bounded buffer is large enough for the fixed standard
    // info header plus the maximum documented 64 KiB opaque root identity.
    let result = unsafe {
        CfGetSyncRootInfoByPath(
            path.as_ptr(),
            CF_SYNC_ROOT_INFO_STANDARD,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * size_of::<u64>()) as u32,
            &mut returned_length,
        )
    };
    if result < 0 {
        return Err(native_error("query registered Cloud Files root", result));
    }
    let returned_length = returned_length as usize;
    if returned_length < identity_offset || returned_length > buffer.len() * size_of::<u64>() {
        return Err(Error::ConfiguredRootChanged);
    }
    // SAFETY: the fixed header is fully within the checked returned buffer and
    // has the x64 SDK layout asserted above.
    let header =
        unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<CfSyncRootStandardInfoHeader>()) };
    let identity_len = header.sync_root_identity_length as usize;
    let identity_end = identity_offset
        .checked_add(identity_len)
        .ok_or(Error::ConfiguredRootChanged)?;
    if identity_len == 0
        || identity_len > CF_SYNC_ROOT_IDENTITY_MAX
        || identity_end > returned_length
        || header.sync_root_file_id as u64 != expected.file_index
        || !wide_array_matches(&header.provider_name, provider_name)
        || !wide_array_matches(&header.provider_version, provider_version)
    {
        return Err(Error::ConfiguredRootChanged);
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>().add(identity_offset),
            identity_len,
        )
    };
    if bytes != expected_root_identity {
        return Err(Error::ConfiguredRootChanged);
    }
    Ok(())
}

fn wide_array_matches(actual: &[u16], expected: &str) -> bool {
    let expected = wide_literal(expected);
    actual.len() >= expected.len()
        && actual[..expected.len()] == expected
        && actual[expected.len()..].iter().all(|unit| *unit == 0)
}

pub(super) fn configured_roots_overlap(left: &Path, right: &Path) -> Result<bool, Error> {
    let (left, _left_handles) = inspect_configured_root_chain(left, false)?;
    let (right, _right_handles) = inspect_configured_root_chain(right, false)?;
    root_identity_chains_overlap(&left, &right)
}

pub(super) fn registered_configured_root_overlaps(
    registered: &Path,
    expected: crate::ConfiguredRootIdentity,
    plain: &Path,
) -> Result<bool, Error> {
    let (left, _left_handles) =
        inspect_configured_root_chain_for_registration(registered, expected)?;
    let (right, _right_handles) = inspect_configured_root_chain(plain, false)?;
    root_identity_chains_overlap(&left, &right)
}

pub(super) fn registered_configured_roots_overlap(
    left: &Path,
    expected_left: crate::ConfiguredRootIdentity,
    right: &Path,
    expected_right: crate::ConfiguredRootIdentity,
) -> Result<bool, Error> {
    // Reuse exact OS-registration admission for both roots, retaining its
    // handles while the ancestry snapshots recheck both expected identities.
    let _left_lease = pin_registered_configured_root(left, expected_left)?;
    let _right_lease = pin_registered_configured_root(right, expected_right)?;
    let (left, _left_handles) =
        inspect_configured_root_chain_for_registration(left, expected_left)?;
    let (right, _right_handles) =
        inspect_configured_root_chain_for_registration(right, expected_right)?;
    root_identity_chains_overlap(&left, &right)
}

fn root_identity_chains_overlap(
    left: &[crate::ConfiguredRootIdentity],
    right: &[crate::ConfiguredRootIdentity],
) -> Result<bool, Error> {
    let left_root = left.last().ok_or(Error::InvalidConfiguredRoot)?;
    let right_root = right.last().ok_or(Error::InvalidConfiguredRoot)?;
    let same = |left: &crate::ConfiguredRootIdentity, right: &crate::ConfiguredRootIdentity| {
        left.volume_serial == right.volume_serial && left.file_index == right.file_index
    };
    Ok(right.iter().any(|identity| same(left_root, identity))
        || left.iter().any(|identity| same(right_root, identity)))
}

fn inspect_configured_root_chain(
    path: &Path,
    require_empty: bool,
) -> Result<(Vec<crate::ConfiguredRootIdentity>, Vec<RawOwnedHandle>), Error> {
    inspect_configured_root_chain_inner(path, require_empty, None)
}

fn inspect_configured_root_chain_for_registration(
    path: &Path,
    expected: crate::ConfiguredRootIdentity,
) -> Result<(Vec<crate::ConfiguredRootIdentity>, Vec<RawOwnedHandle>), Error> {
    inspect_configured_root_chain_inner(path, false, Some(expected))
}

fn inspect_configured_root_chain_inner(
    path: &Path,
    require_empty: bool,
    registered_identity: Option<crate::ConfiguredRootIdentity>,
) -> Result<(Vec<crate::ConfiguredRootIdentity>, Vec<RawOwnedHandle>), Error> {
    use std::path::{Component, Prefix};

    if path.as_os_str().is_empty() || path.as_os_str().encode_wide().count() > 32_000 {
        return Err(Error::InvalidConfiguredRoot);
    }
    let mut components = path.components().peekable();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(Error::InvalidConfiguredRoot);
    };
    if !matches!(prefix.kind(), Prefix::Disk(_)) || components.next() != Some(Component::RootDir) {
        // UNC and device namespaces are deliberately outside the supported
        // configuration contract for this first Windows root slice.
        return Err(Error::InvalidConfiguredRoot);
    }

    let mut current = PathBuf::from(prefix.as_os_str());
    current.push("\\");
    let mut pinned = Vec::new();
    let mut identities = Vec::new();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            // CurDir and ParentDir are rejected rather than canonicalized.
            return Err(Error::InvalidConfiguredRoot);
        };
        current.push(name);
        let handle = open_root(&current, FILE_READ_ATTRIBUTES, FILE_SHARE_READ)?;
        let snapshot = root_snapshot(handle.0)?;
        // Only the final registered root may carry Cloud Files reparse state.
        // Ancestors remain ordinary directories; the caller verifies the exact
        // OS registration while all these no-follow handles remain held.
        let registered_final = registered_identity.filter(|_| components.peek().is_none());
        let valid = if let Some(expected) = registered_final {
            if snapshot.identity.volume_serial != expected.volume_serial
                || snapshot.identity.file_index != expected.file_index
            {
                return Err(Error::ConfiguredRootChanged);
            }
            valid_root_snapshot(
                snapshot,
                RootIdentity {
                    volume_serial: expected.volume_serial,
                    file_index: expected.file_index,
                },
                RootSnapshotState::RegisteredDisconnected,
            )
        } else {
            snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                && snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && snapshot.reparse_tag == 0
        };
        if !valid || snapshot.identity.file_index == 0 {
            return Err(Error::InvalidConfiguredRoot);
        }
        identities.push(crate::ConfiguredRootIdentity {
            volume_serial: snapshot.identity.volume_serial,
            file_index: snapshot.identity.file_index,
        });
        // Keep every validated component open while inspecting the path. A
        // path-based directory enumeration follows below, so the path chain
        // is re-opened and compared afterward rather than assuming these
        // handles alone prevent every rename operation on every filesystem.
        pinned.push(handle);
    }
    if identities.is_empty() {
        return Err(Error::InvalidConfiguredRoot);
    }
    if require_empty {
        if fs::read_dir(path)
            .map_err(|error| io_error("inspect configured root contents", error))?
            .next()
            .is_some()
        {
            return Err(Error::ConfiguredRootNotEmpty);
        }
        let (after_scan, _after_scan_handles) = inspect_configured_root_chain(path, false)?;
        if after_scan != identities {
            return Err(Error::InvalidConfiguredRoot);
        }
    }
    Ok((identities, pinned))
}

fn open_root(path: &Path, access: u32, sharing: u32) -> Result<RawOwnedHandle, Error> {
    let path = wide_path(path)?;
    // FILE_SHARE_DELETE is intentionally omitted. This narrows concurrent
    // replacement on filesystems that honor the sharing mode, but callers
    // still revalidate path identity around path-based operations.
    // SAFETY: path is valid for the call and no handle is inherited.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            sharing,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(win32_io_error("open synthetic root identity handle"));
    }
    let owned = RawOwnedHandle(handle);
    let mut info: ByHandleFileInformation = unsafe { zeroed() };
    // SAFETY: valid handle and writable output structure.
    if unsafe { GetFileInformationByHandle(owned.0, &mut info) } == 0 {
        return Err(win32_io_error("inspect synthetic root handle"));
    }
    if info.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || ((u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low)) == 0
    {
        return Err(Error::SyntheticRootChanged);
    }
    Ok(owned)
}

fn root_identity(handle: Handle) -> Result<RootIdentity, Error> {
    let snapshot = root_snapshot(handle)?;
    if snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || snapshot.placeholder_state != 0
        || snapshot.reparse_tag != 0
    {
        return Err(Error::SyntheticRootChanged);
    }
    Ok(snapshot.identity)
}

// Registration and connection are separate capabilities: disconnect keeps
// the registered root and its Cloud Files reparse state intact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootSnapshotState {
    PlainUnregistered,
    RegisteredDisconnected,
    Connected,
}

fn root_snapshot_state(registered: bool, connected: bool) -> Option<RootSnapshotState> {
    match (registered, connected) {
        (false, false) => Some(RootSnapshotState::PlainUnregistered),
        (true, false) => Some(RootSnapshotState::RegisteredDisconnected),
        (true, true) => Some(RootSnapshotState::Connected),
        (false, true) => None,
    }
}

fn valid_root_snapshot(
    snapshot: RootSnapshot,
    expected_identity: RootIdentity,
    state: RootSnapshotState,
) -> bool {
    if snapshot.identity != expected_identity
        || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return false;
    }
    let plain = snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && snapshot.reparse_tag == 0
        && snapshot.placeholder_state == 0;
    let cloud = snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && snapshot.reparse_tag & IO_REPARSE_TAG_CLOUD_MASK == IO_REPARSE_TAG_CLOUD
        && valid_registered_root_state(snapshot.placeholder_state);
    match state {
        RootSnapshotState::PlainUnregistered => plain,
        // CfRegister does not necessarily convert the directory into a cloud
        // placeholder until connection/population. CfDisconnect may retain
        // either form. Callers separately verify the exact OS registration.
        RootSnapshotState::RegisteredDisconnected => plain || cloud,
        RootSnapshotState::Connected => cloud,
    }
}

fn valid_registered_root_state(state: u32) -> bool {
    let required = CF_PLACEHOLDER_STATE_PLACEHOLDER | CF_PLACEHOLDER_STATE_SYNC_ROOT;
    let documented = required
        | 0x4 // CF_PLACEHOLDER_STATE_ESSENTIAL_PROP_PRESENT
        | 0x8 // CF_PLACEHOLDER_STATE_IN_SYNC
        | CF_PLACEHOLDER_STATE_PARTIAL
        | CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK;
    state & required == required
        && state & !documented == 0
        && (state & CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK == 0
            || state & CF_PLACEHOLDER_STATE_PARTIAL != 0)
}

fn valid_fixture_entry(
    snapshot: RootSnapshot,
    is_directory: bool,
    expected_len: u64,
    expect_placeholder: bool,
) -> bool {
    if (snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != is_directory
        || (!is_directory && snapshot.file_size != expected_len)
    {
        return false;
    }
    let placeholder = snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && snapshot.reparse_tag & IO_REPARSE_TAG_CLOUD_MASK == IO_REPARSE_TAG_CLOUD
        && snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER != 0
        && snapshot.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT == 0
        && snapshot.placeholder_state & !0x3f == 0;
    let hydrated_file = !is_directory
        && snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && snapshot.reparse_tag == 0
        && snapshot.placeholder_state == 0
        && snapshot.file_attributes & FILE_ATTRIBUTE_ARCHIVE != 0;
    let fully_hydrated_placeholder = !is_directory
        && snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && snapshot.reparse_tag & IO_REPARSE_TAG_CLOUD_MASK == IO_REPARSE_TAG_CLOUD
        && snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER != 0
        && snapshot.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT == 0
        && snapshot.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC != 0
        && snapshot.placeholder_state
            & (CF_PLACEHOLDER_STATE_PARTIAL | CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK)
            == 0
        && snapshot.placeholder_state & !0x3f == 0;
    if expect_placeholder {
        placeholder || hydrated_file || fully_hydrated_placeholder
    } else {
        hydrated_file || fully_hydrated_placeholder
    }
}

fn fixture_identity_matches(expected: Option<RootIdentity>, actual: RootIdentity) -> bool {
    expected == Some(actual)
}

fn fixture_names_match_expected(
    actual: &HashSet<String>,
    expect_placeholders: bool,
    allow_unregistered_files_missing: bool,
) -> bool {
    if !expect_placeholders {
        return actual.is_empty();
    }
    FIXTURE_ITEMS.iter().all(|item| {
        actual.contains(item.name) || (allow_unregistered_files_missing && !item.is_directory)
    }) && actual
        .iter()
        .all(|name| FIXTURE_ITEMS.iter().any(|item| item.name == name))
}

fn valid_materialized_directory(snapshot: RootSnapshot) -> bool {
    snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        && snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && snapshot.reparse_tag == 0
        && snapshot.placeholder_state == 0
}

fn entry_snapshot(path: &Path, directory: bool) -> Result<RootSnapshot, Error> {
    let path = wide_path(path)?;
    // SAFETY: the exact entry path comes from the already-validated expected
    // file name within the held synthetic root. OPEN_REPARSE_POINT ensures the
    // handle describes the tag itself rather than following a substitute.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(win32_io_error("open synthetic entry for tag validation"));
    }
    let owned = RawOwnedHandle(handle);
    root_snapshot(owned.0)
}

fn open_fixture_entry(
    path: &Path,
    expected_identity: RootIdentity,
    access: u32,
    directory: bool,
    expected_len: u64,
    allow_materialized_directory: bool,
) -> Result<RawOwnedHandle, Error> {
    let path = wide_path(path)?;
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    } else {
        FILE_FLAG_OPEN_REPARSE_POINT
    };
    // SAFETY: path is a bounded child name from the fixed fixture. Opening the
    // reparse point itself prevents following a substituted link before its
    // file ID and Cloud Files tag are checked. Omitting FILE_SHARE_DELETE pins
    // the exact entry while any subsequent content open uses the same path.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(win32_io_error("open verified synthetic child"));
    }
    let owned = RawOwnedHandle(handle);
    let snapshot = root_snapshot(owned.0)?;
    if snapshot.identity != expected_identity {
        eprintln!(
            "synthetic entry identity mismatch: expected={expected_identity:?} actual={:?}",
            snapshot.identity
        );
        return Err(Error::SyntheticRootChanged);
    }
    if (snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
        eprintln!(
            "synthetic entry type mismatch: expected_directory={directory} attrs={:#x}",
            snapshot.file_attributes
        );
        return Err(Error::SyntheticRootChanged);
    }
    if !valid_fixture_entry(snapshot, directory, expected_len, true)
        && !(allow_materialized_directory && directory && valid_materialized_directory(snapshot))
    {
        eprintln!(
            "synthetic entry state mismatch: directory={directory} allow_materialized={allow_materialized_directory} attrs={:#x} tag={:#x} placeholder={:#x} size={} expected_size={expected_len}",
            snapshot.file_attributes,
            snapshot.reparse_tag,
            snapshot.placeholder_state,
            snapshot.file_size
        );
        return Err(Error::SyntheticRootChanged);
    }
    Ok(owned)
}

fn open_fixture_content(
    path: &Path,
    expected_identity: RootIdentity,
    expected_len: usize,
) -> Result<RawOwnedHandle, Error> {
    let name = path.file_name().map(|name| name.to_string_lossy());
    let path = wide_path(path)?;
    // SAFETY: the caller retains a no-follow handle to this exact directory
    // entry without FILE_SHARE_DELETE, so the path cannot be substituted
    // between identity verification and this read-capable open.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        let code = unsafe { GetLastError() };
        eprintln!("synthetic content open failed: name={name:?} win32_error={code}");
        return Err(Error::Io {
            operation: "open verified synthetic file contents",
            kind: std::io::Error::from_raw_os_error(code as i32).kind(),
        });
    }
    let owned = RawOwnedHandle(handle);
    let snapshot = root_snapshot(owned.0)?;
    if snapshot.identity != expected_identity
        || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || snapshot.file_size != expected_len as u64
    {
        eprintln!(
            "synthetic content handle mismatch: identity_match={} attrs={:#x} size={} expected_size={expected_len}",
            snapshot.identity == expected_identity,
            snapshot.file_attributes,
            snapshot.file_size
        );
        return Err(Error::SyntheticRootChanged);
    }
    Ok(owned)
}

fn read_open_file(handle: RawOwnedHandle, len: usize) -> Result<(Vec<u8>, RootSnapshot), Error> {
    // Synthetic fixture readback is a whole-file comparison, separate from
    // the 16 MiB callback window and edit-recovery limits. Keep allocation
    // bounded while allowing the 17 MiB + 7-byte native hydration fixture.
    const MAX_FIXTURE_READ_BYTES: usize = 32 * 1024 * 1024;
    if len > MAX_FIXTURE_READ_BYTES {
        return Err(Error::SyntheticRootChanged);
    }
    let mut handle = handle;
    let raw = std::mem::replace(&mut handle.0, null_mut());
    // SAFETY: the raw handle was exclusively owned by `handle`, was opened for
    // read access, and is transferred to this File exactly once.
    let mut file = unsafe { std::fs::File::from_raw_handle(raw) };
    let mut bytes = vec![0_u8; len];
    file.read_exact(&mut bytes).map_err(|error| {
        eprintln!(
            "synthetic read_exact failed: requested_bytes={len} raw_os_error={:?} kind={:?}",
            error.raw_os_error(),
            error.kind()
        );
        io_error("read verified synthetic file", error)
    })?;
    let snapshot = root_snapshot(file.as_raw_handle())?;
    Ok((bytes, snapshot))
}

fn same_edit_snapshot(left: RootSnapshot, right: RootSnapshot) -> bool {
    left.identity == right.identity
        && left.file_attributes == right.file_attributes
        && left.reparse_tag == right.reparse_tag
        && left.placeholder_state == right.placeholder_state
        && left.file_size == right.file_size
        && left.last_write_time == right.last_write_time
}

fn verify_completion_identity(handle: Handle, expected: &[u8; 16]) -> Result<(), Error> {
    const IDENTITY_OFFSET: usize = 28;
    let mut storage = [0_u64; 8];
    let mut returned = 0_u32;
    // SAFETY: aligned, bounded output buffer; API retains no pointers.
    let result = unsafe {
        CfGetPlaceholderInfo(
            handle,
            CF_PLACEHOLDER_INFO_BASIC,
            storage.as_mut_ptr().cast(),
            size_of_val(&storage) as u32,
            &mut returned,
        )
    };
    if result < 0 {
        return Err(native_error("read edit completion identity", result));
    }
    let returned = returned as usize;
    if !(IDENTITY_OFFSET + 16..=size_of_val(&storage)).contains(&returned) {
        return Err(Error::ConfiguredRootChanged);
    }
    // SAFETY: returned is bounded by the initialized storage above.
    let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned) };
    let length = u32::from_le_bytes(
        bytes[24..28]
            .try_into()
            .map_err(|_| Error::ConfiguredRootChanged)?,
    );
    if length != 16 || bytes[IDENTITY_OFFSET..IDENTITY_OFFSET + 16] != *expected {
        return Err(Error::ConfiguredRootChanged);
    }
    Ok(())
}

// CF_PLACEHOLDER_BASIC_INFO: PinState/InSyncState DWORDs, two file IDs,
// identity length DWORD, then bytes. Require the exact root/file/opaque tuple.
fn clean_dehydrate_identity(
    handle: Handle,
    root_id: u64,
    file_id: u64,
    identity: &[u8; 16],
) -> Result<(), Error> {
    let mut storage = [0_u64; 8];
    let mut returned = 0;
    let hr = unsafe {
        CfGetPlaceholderInfo(
            handle,
            CF_PLACEHOLDER_INFO_BASIC,
            storage.as_mut_ptr().cast(),
            size_of_val(&storage) as u32,
            &mut returned,
        )
    };
    if hr < 0 {
        return Err(native_error("inspect vault cleanup identity", hr));
    }
    if !(44..=size_of_val(&storage)).contains(&(returned as usize)) {
        return Err(Error::ConfiguredRootChanged);
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned as usize) };
    let u32_at = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
    let u64_at = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
    // Unknown, PINNED, EXCLUDED and unresolved INHERIT states all refuse.
    if !matches!(u32_at(0), 0 | 2)
        || u32_at(4) != 1
        || u64_at(8) != file_id
        || u64_at(16) != root_id
        || u32_at(24) != 16
        || bytes[28..44] != *identity
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok(())
}

// CfOpenFileWithOplock returns an asynchronous opaque handle. The Win32
// handle below is borrowed, never wrapped in File or independently closed.
struct ProtectedCompletionFile {
    protected: Handle,
    raw: Handle,
}
impl ProtectedCompletionFile {
    fn open(path: &[u16]) -> Result<Self, Error> {
        let mut protected = null_mut();
        // SAFETY: NUL-terminated pinned path, owned output; EXCLUSIVE (1) and
        // WRITE_ACCESS (2), without FOREGROUND or share-all fallback.
        let hr = unsafe { CfOpenFileWithOplock(path.as_ptr(), 1 | 2, &mut protected) };
        if hr < 0 {
            return Err(native_error("open protected edit completion", hr));
        }
        if protected.is_null() || protected == INVALID_HANDLE_VALUE {
            return Err(Error::EditRecoveryUnavailable);
        }
        // SAFETY: owned Cf handle; successful reference prevents automatic
        // underlying-handle closure until all proof I/O and CAS have drained.
        if unsafe { CfReferenceProtectedHandle(protected) } == 0 {
            unsafe { CfCloseHandle(protected) };
            return Err(Error::EditRecoveryUnavailable);
        }
        let raw = unsafe { CfGetWin32HandleFromProtectedHandle(protected) };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            unsafe {
                CfReleaseProtectedHandle(protected);
                CfCloseHandle(protected);
            }
            return Err(Error::EditRecoveryUnavailable);
        }
        Ok(Self { protected, raw })
    }
    fn read_complete(&self, bytes: &mut [u8]) -> Result<(), Error> {
        if bytes.is_empty() {
            return Ok(());
        }
        let length = u32::try_from(bytes.len()).map_err(|_| Error::EditRecoveryUnavailable)?;
        let mut io = CompletionIo::new()?;
        // SAFETY: reference and caller buffer remain live until wait completes;
        // offset zero, exact bounded length, distinct owned manual-reset event.
        let result = unsafe {
            ReadFile(
                self.raw,
                bytes.as_mut_ptr().cast(),
                length,
                null_mut(),
                &mut io.overlapped,
            )
        };
        if io.finish(self.raw, result)? != length {
            return Err(Error::EditRecoveryUnavailable);
        }
        Ok(())
    }
}
impl Drop for ProtectedCompletionFile {
    fn drop(&mut self) {
        // All asynchronous operations completed before returning from their
        // methods. Release the borrow before closing only the opaque Cf owner.
        unsafe {
            CfReleaseProtectedHandle(self.protected);
            CfCloseHandle(self.protected);
        }
    }
}

#[repr(C)]
struct CompletionOverlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: Handle,
}
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<CompletionOverlapped>() == 32);
    assert!(std::mem::align_of::<CompletionOverlapped>() == 8);
};
struct CompletionIo {
    overlapped: CompletionOverlapped,
    _event: RawOwnedHandle,
}
impl CompletionIo {
    fn new() -> Result<Self, Error> {
        // SAFETY: unnamed event, manual reset, initially nonsignaled.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(win32_io_error("create completion I/O event"));
        }
        Ok(Self {
            overlapped: CompletionOverlapped {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                event,
            },
            _event: RawOwnedHandle(event),
        })
    }
    fn finish(&mut self, handle: Handle, result: i32) -> Result<u32, Error> {
        // Capture the submission error before any other Win32 call.
        if result == 0 && unsafe { GetLastError() } != 997 {
            // ERROR_IO_PENDING
            return Err(win32_io_error("submit edit completion I/O"));
        }
        let mut returned = 0;
        // SAFETY: exact submitted OVERLAPPED, event, referenced handle and all
        // buffers remain alive. Wait for definitive completion, including on
        // I/O error, before any referenced storage can be dropped. This is a
        // blocking disk operation, not a timeout or cancellation acknowledgement.
        if unsafe { GetOverlappedResult(handle, &mut self.overlapped, &mut returned, 1) } == 0 {
            return Err(win32_io_error("finish edit completion I/O"));
        }
        Ok(returned)
    }
}

fn completion_usn(handle: Handle, expected_file_id: u64) -> Result<i64, Error> {
    // FSCTL_READ_FILE_USN_DATA, V2 only. This borrowed protected handle is
    // asynchronous: retain aligned output, OVERLAPPED and event to completion.
    const FSCTL_READ_FILE_USN_DATA: u32 = 0x0009_00eb;
    let mut storage = vec![0_u64; 8192];
    let mut io = CompletionIo::new()?;
    // SAFETY: referenced live file, aligned bounded output and exact stable
    // OVERLAPPED; no output inspected before definitive I/O completion.
    let result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_READ_FILE_USN_DATA,
            null(),
            0,
            storage.as_mut_ptr().cast(),
            (storage.len() * size_of::<u64>()) as u32,
            null_mut(),
            (&mut io.overlapped as *mut CompletionOverlapped).cast(),
        )
    };
    let returned = io.finish(handle, result)?;
    let returned = returned as usize;
    if returned < 60 || returned > storage.len() * size_of::<u64>() {
        return Err(Error::EditRecoveryUnavailable);
    }
    // SAFETY: returned is bounded by the initialized storage above.
    let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned) };
    let length = u32::from_le_bytes(
        bytes[0..4]
            .try_into()
            .map_err(|_| Error::EditRecoveryUnavailable)?,
    ) as usize;
    let major = u16::from_le_bytes(
        bytes[4..6]
            .try_into()
            .map_err(|_| Error::EditRecoveryUnavailable)?,
    );
    if length < 60 || length > returned || major != 2 {
        return Err(Error::EditRecoveryUnavailable);
    }
    let file_id = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| Error::EditRecoveryUnavailable)?,
    );
    let usn = i64::from_le_bytes(
        bytes[24..32]
            .try_into()
            .map_err(|_| Error::EditRecoveryUnavailable)?,
    );
    if file_id != expected_file_id || usn <= 0 {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok(usn)
}

type PlaceholderRecoveryRead = Result<(Zeroizing<Vec<u8>>, RootSnapshot), (usize, i32)>;

fn read_placeholder_for_recovery(handle: RawOwnedHandle, len: usize) -> PlaceholderRecoveryRead {
    if len > MAX_REQUEST_BYTES as usize {
        return Err((21, 0));
    }
    let mut handle = handle;
    let raw = std::mem::replace(&mut handle.0, null_mut());
    // SAFETY: the handle was opened for read access to the exact validated
    // placeholder and is transferred to this File exactly once.
    let mut file = unsafe { std::fs::File::from_raw_handle(raw) };
    let mut bytes = Zeroizing::new(vec![0_u8; len]);
    file.read_exact(&mut bytes)
        .map_err(|error| (22, error.raw_os_error().unwrap_or(0)))?;
    let snapshot = root_snapshot(file.as_raw_handle()).map_err(|_| (23, 0))?;
    match modified_ranges_for_handle(file.as_raw_handle()) {
        Ok(true) => {}
        Ok(false) | Err(()) => return Err((24, 0)),
    }
    Ok((bytes, snapshot))
}

fn delete_by_handle(handle: Handle) -> Result<(), Error> {
    let disposition = FileDispositionInfo { delete_file: 1 };
    // SAFETY: caller supplies an owned handle opened with DELETE access after
    // comparing its volume/file ID to the recorded synthetic object identity.
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FILE_DISPOSITION_INFO_CLASS,
            (&disposition as *const FileDispositionInfo).cast(),
            size_of::<FileDispositionInfo>() as u32,
        )
    } == 0
    {
        return Err(win32_io_error("delete verified synthetic handle"));
    }
    Ok(())
}

fn root_snapshot(handle: Handle) -> Result<RootSnapshot, Error> {
    let mut info: ByHandleFileInformation = unsafe { zeroed() };
    // SAFETY: valid owned handle and writable output structure.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(win32_io_error("read synthetic root identity"));
    }
    let mut tag_info: FileAttributeTagInfo = unsafe { zeroed() };
    // SAFETY: `tag_info` has the SDK FILE_ATTRIBUTE_TAG_INFO layout and the
    // buffer size exactly matches the structure expected for information class 9.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FILE_ATTRIBUTE_TAG_INFO_CLASS,
            (&mut tag_info as *mut FileAttributeTagInfo).cast(),
            size_of::<FileAttributeTagInfo>() as u32,
        )
    } == 0
    {
        return Err(win32_io_error("read synthetic root attribute tag"));
    }
    let placeholder_state = unsafe {
        CfGetPlaceholderStateFromAttributeTag(tag_info.file_attributes, tag_info.reparse_tag)
    };
    Ok(RootSnapshot {
        identity: RootIdentity {
            volume_serial: info.volume_serial_number,
            file_index: (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low),
        },
        file_attributes: tag_info.file_attributes,
        reparse_tag: tag_info.reparse_tag,
        placeholder_state,
        file_size: (u64::from(info.file_size_high) << 32) | u64::from(info.file_size_low),
        last_write_time: ((i64::from(info.last_write_time.high)) << 32)
            | i64::from(info.last_write_time.low),
    })
}

fn register_root(path: &Path) -> Result<(), Error> {
    let handle = open_root_for_identity_check(path)?;
    let identity = root_identity(handle.0)?;
    let entries = fs::read_dir(path).map_err(|error| io_error("verify synthetic root", error))?;
    if entries.into_iter().next().is_some() {
        return Err(Error::SyntheticRootNotEmpty);
    }
    register_root_with_identity(
        path,
        &synthetic_sync_root_identity(identity),
        None,
        "Raiun Synthetic Cloud Files Test",
        "test-only",
    )
}

fn synthetic_sync_root_identity(identity: RootIdentity) -> [u8; 24] {
    let mut root_identity = [0_u8; 24];
    root_identity[..8].copy_from_slice(b"RaiunSy1");
    root_identity[8..12].copy_from_slice(&identity.volume_serial.to_le_bytes());
    root_identity[12..20].copy_from_slice(&identity.file_index.to_le_bytes());
    root_identity
}

#[allow(dead_code)]
fn configured_sync_root_identity(identity: RootIdentity) -> [u8; 24] {
    let mut root_identity = [0_u8; 24];
    root_identity[..8].copy_from_slice(b"RaiunCF1");
    root_identity[8..12].copy_from_slice(&identity.volume_serial.to_le_bytes());
    root_identity[12..20].copy_from_slice(&identity.file_index.to_le_bytes());
    root_identity
}

fn register_root_with_identity(
    path: &Path,
    root_identity: &[u8],
    file_identity: Option<&[u8]>,
    provider_name: &str,
    provider_version: &str,
) -> Result<(), Error> {
    if root_identity.is_empty() || root_identity.len() > 256 {
        return Err(Error::InvalidConfiguredRoot);
    }
    if file_identity.is_some_and(|identity| identity.is_empty() || identity.len() > 4096) {
        return Err(Error::InvalidConfiguredRoot);
    }
    let mut entries = fs::read_dir(path)
        .map_err(|error| io_error("verify sync root before registration", error))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| io_error("read sync root before registration", error))?
        .is_some()
    {
        return Err(Error::ConfiguredRootNotEmpty);
    }
    let provider_name = wide_literal(provider_name);
    let provider_version = wide_literal(provider_version);
    let registration = CfSyncRegistration {
        struct_size: size_of::<CfSyncRegistration>() as u32,
        provider_name: provider_name.as_ptr(),
        provider_version: provider_version.as_ptr(),
        sync_root_identity: root_identity.as_ptr().cast(),
        sync_root_identity_length: root_identity.len() as u32,
        file_identity: file_identity.map_or(null(), |identity| identity.as_ptr().cast()),
        file_identity_length: file_identity.map_or(0, |identity| identity.len() as u32),
        provider_id: Guid {
            data1: 0x2d5b8b01,
            data2: 0x84c3,
            data3: 0x4e20,
            data4: [0x9b, 0x41, 0x36, 0x2f, 0x51, 0x70, 0x00, 0x01],
        },
    };
    let policies = CfSyncPolicies {
        struct_size: size_of::<CfSyncPolicies>() as u32,
        hydration: CfHydrationPolicy {
            primary: CF_HYDRATION_POLICY_FULL,
            modifier: 0,
        },
        population: CfPopulationPolicy {
            primary: CF_POPULATION_POLICY_FULL,
            modifier: 0,
        },
        in_sync: 0,
        hard_link: 0,
        placeholder_management: 0,
    };
    let path = wide_path(path)?;
    // SAFETY: all structure pointers and strings remain alive for the sync call.
    let result = unsafe {
        CfRegisterSyncRoot(
            path.as_ptr(),
            &registration,
            &policies,
            // Both paths eagerly create the complete immediate namespace.
            // Fetch admission stays closed until that initialization finishes;
            // only child directories use on-demand population.
            CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT,
        )
    };
    if result < 0 {
        return Err(native_error("CfRegisterSyncRoot", result));
    }
    Ok(())
}

struct SyntheticBackend;

#[cfg(test)]
struct OpenCloudFixtureBackend {
    remote: Arc<dyn PlaceholderBackend>,
    remote_identity: Vec<u8>,
}

#[cfg(test)]
impl PlaceholderBackend for OpenCloudFixtureBackend {
    fn lookup(&self, identity: &[u8]) -> Result<Option<PlaceholderMetadata>, BackendError> {
        if identity == FILE_IDENTITY {
            self.remote.lookup(&self.remote_identity)
        } else {
            SyntheticBackend.lookup(identity)
        }
    }

    fn prepare_edit_binding<'a>(
        &'a self,
        identity: &[u8],
    ) -> Result<Box<dyn crate::PreparedEditBinding + 'a>, BackendError> {
        if identity == FILE_IDENTITY {
            self.remote.prepare_edit_binding(&self.remote_identity)
        } else {
            Err(BackendError::Unavailable)
        }
    }

    fn enumerate(
        &self,
        identity: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Vec<crate::PlaceholderChild>, BackendError> {
        SyntheticBackend.enumerate(identity, cancellation)
    }

    fn read_range(
        &self,
        identity: &[u8],
        offset: u64,
        output: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<usize, BackendError> {
        if identity == FILE_IDENTITY {
            self.remote
                .read_range(&self.remote_identity, offset, output, cancellation)
        } else {
            SyntheticBackend.read_range(identity, offset, output, cancellation)
        }
    }

    fn prepare_fetch<'a>(
        &'a self,
        identity: &[u8],
        range: FetchRange,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PreparedFetch + 'a>, BackendError> {
        if identity == FILE_IDENTITY {
            self.remote
                .prepare_fetch(&self.remote_identity, range, cancellation)
        } else {
            SyntheticBackend.prepare_fetch(identity, range, cancellation)
        }
    }

    fn prepare_fetch_session<'a>(
        &'a self,
        identity: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PreparedFetchSession + 'a>, BackendError> {
        if identity == FILE_IDENTITY {
            self.remote
                .prepare_fetch_session(&self.remote_identity, cancellation)
        } else {
            Err(BackendError::Unavailable)
        }
    }
}

impl PlaceholderBackend for SyntheticBackend {
    fn lookup(&self, identity: &[u8]) -> Result<Option<PlaceholderMetadata>, BackendError> {
        let item = fixture_item(identity);
        Ok(item.map(|item| PlaceholderMetadata {
            is_directory: item.is_directory,
            length: item.len as u64,
        }))
    }

    fn enumerate(
        &self,
        identity: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Vec<crate::PlaceholderChild>, BackendError> {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        let item = if identity == FIRST_FOLDER_IDENTITY {
            &NESTED_FIXTURE_ITEM
        } else {
            #[cfg(test)]
            if identity == SECOND_FOLDER_IDENTITY {
                return Ok(vec![fixture_placeholder_child(
                    &SECOND_FOLDER_CHILD_FIXTURE_ITEM,
                )]);
            }
            return Ok(Vec::new());
        };
        Ok(vec![fixture_placeholder_child(item)])
    }

    fn read_range(
        &self,
        identity: &[u8],
        offset: u64,
        output: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<usize, BackendError> {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if output.len() > MAX_RANGE_BYTES {
            return Err(BackendError::InvalidRange);
        }
        let item = fixture_item(identity)
            .filter(|item| !item.is_directory)
            .ok_or(BackendError::NotFound)?;
        let offset = usize::try_from(offset).map_err(|_| BackendError::InvalidRange)?;
        let end = offset
            .checked_add(output.len())
            .ok_or(BackendError::InvalidRange)?;
        if end > item.len {
            return Err(BackendError::InvalidRange);
        }
        for (index, byte) in output.iter_mut().enumerate() {
            if cancellation.is_cancelled() {
                return Err(BackendError::Cancelled);
            }
            let absolute = (offset + index) as u32;
            *byte = if item.identity == &FILE_IDENTITY {
                ((absolute * 31 + 7) % 256) as u8
            } else {
                ((absolute * 17 + 19) % 256) as u8
            };
        }
        Ok(output.len())
    }
}

fn fixture_item(identity: &[u8]) -> Option<&'static FixtureItem> {
    if identity == NESTED_FILE_IDENTITY {
        return Some(&NESTED_FIXTURE_ITEM);
    }
    #[cfg(test)]
    if identity == SECOND_FOLDER_CHILD_IDENTITY {
        return Some(&SECOND_FOLDER_CHILD_FIXTURE_ITEM);
    }
    FIXTURE_ITEMS
        .iter()
        .find(|item| item.identity.as_slice() == identity)
}

fn fixture_placeholder_child(item: &FixtureItem) -> crate::PlaceholderChild {
    crate::PlaceholderChild {
        name: item.name.to_owned(),
        identity: item.identity.to_vec(),
        metadata: PlaceholderMetadata {
            is_directory: item.is_directory,
            length: item.len as u64,
        },
        last_write_time: 0,
    }
}

fn directory_cloud_identity(name: &str) -> Option<&'static [u8; 16]> {
    match name {
        FIRST_FOLDER_NAME => Some(&FIRST_FOLDER_IDENTITY),
        #[cfg(test)]
        SECOND_FOLDER_NAME => Some(&SECOND_FOLDER_IDENTITY),
        _ => None,
    }
}

fn synthetic_payload_for(identity: &[u8; 16], len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| {
            let index = index as u32;
            if identity == &FILE_IDENTITY {
                ((index * 31 + 7) % 256) as u8
            } else {
                ((index * 17 + 19) % 256) as u8
            }
        })
        .collect()
}

fn wide_literal(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path(path: &Path) -> Result<Vec<u16>, Error> {
    let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.is_empty() || encoded.len() >= 32_767 || encoded.contains(&0) {
        return Err(Error::InvalidSyntheticPath);
    }
    Ok(encoded.into_iter().chain(std::iter::once(0)).collect())
}

fn native_error(operation: &'static str, hresult: HResult) -> Error {
    Error::Native { operation, hresult }
}

fn win32_io_error(operation: &'static str) -> Error {
    let code = unsafe { GetLastError() } as i32;
    #[cfg(feature = "synthetic-agent-integration")]
    eprintln!("synthetic_native_io_error operation={operation} win32={code}");
    Error::Io {
        operation,
        kind: std::io::Error::from_raw_os_error(code).kind(),
    }
}

fn io_error(operation: &'static str, error: std::io::Error) -> Error {
    Error::Io {
        operation,
        kind: error.kind(),
    }
}

#[cfg(test)]
mod backend_tests {
    use super::{
        CF_FETCH_DATA_PARAM_SIZE_ALIGNED, CF_FETCH_DATA_PARAM_SIZE_DOCUMENTED,
        CF_PLACEHOLDER_STATE_PARTIAL, CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK,
        CF_PLACEHOLDER_STATE_PLACEHOLDER, CF_PLACEHOLDER_STATE_SYNC_ROOT, CallbackState,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_IDENTITY,
        FIRST_FOLDER_IDENTITY, IO_REPARSE_TAG_CLOUD, IO_REPARSE_TAG_CLOUD_MASK, MAX_RANGE_BYTES,
        MAX_REQUEST_BYTES, NormalizedPathForm, RootIdentity, RootSnapshot, RootSnapshotState,
        SECOND_FILE_IDENTITY, SECOND_PAYLOAD_LEN, SyntheticBackend, callback_path_suffix,
        checked_cancel_range, is_supported_local_drive_path, lookup_for_fetch,
        normalized_path_form, root_snapshot_state, stream_prepared_windows,
        valid_callback_directory_snapshot, valid_callback_entry_snapshot,
        valid_fetch_data_param_size, valid_registered_root_state, valid_root_snapshot,
    };
    use crate::{
        BackendError, CancellationToken, FetchRange, MAX_CONCURRENT_FETCHES, MAX_STAGED_CALLBACKS,
        PlaceholderBackend,
    };
    use std::{
        path::Path,
        sync::{Arc, Condvar, Mutex, atomic::Ordering, mpsc},
        thread,
    };

    #[test]
    #[ignore = "requires isolated native Windows Cloud Files API; ordinary synthetic file only"]
    fn protected_completion_reference_excludes_writer_until_drop() {
        use std::{fs, fs::OpenOptions, io::Write, sync::mpsc, thread, time::Duration};

        let root = super::create_private_test_root().expect("create private synthetic directory");
        // No TempDir/Drop cleanup: preserve the synthetic root on every failure.
        eprintln!("protected completion writer test root: {}", root.display());
        let path = root.join("protected-completion.bin");
        let original = b"original synthetic bytes";
        let replacement = b"modified synthetic bytes";
        assert_eq!(original.len(), replacement.len());
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("create ordinary synthetic file");
            file.write_all(original).expect("write initial bytes");
            file.sync_all().expect("sync initial bytes");
        }
        let wide = super::wide_path(&path).expect("bounded synthetic path");
        let guard =
            super::ProtectedCompletionFile::open(&wide).expect("open and reference protected file");
        enum Outcome {
            SharingDenied,
            Completed(Result<(), String>),
        }
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (outcome_tx, outcome_rx) = mpsc::sync_channel(2);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let writer_path = path.clone();
        let writer = thread::spawn(move || {
            if entered_tx.send(()).is_err() {
                return;
            }
            let opened = OpenOptions::new().write(true).open(&writer_path);
            let opened = match opened {
                Err(error) if error.raw_os_error() == Some(32) => {
                    if outcome_tx.send(Outcome::SharingDenied).is_err() {
                        return;
                    }
                    if release_rx.recv().is_err() {
                        return;
                    }
                    OpenOptions::new().write(true).open(&writer_path)
                }
                other => other,
            };
            let result = opened
                .and_then(|mut file| {
                    file.write_all(replacement)?;
                    file.sync_all()
                })
                .map_err(|error| error.to_string());
            let _ = outcome_tx.send(Outcome::Completed(result));
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("writer announced attempt");
        let mut denial_seen = false;
        match outcome_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Outcome::SharingDenied) => {
                denial_seen = true;
                eprintln!("writer denied with ERROR_SHARING_VIOLATION while referenced")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                eprintln!("writer not completed during held-reference observation")
            }
            Ok(Outcome::Completed(result)) => {
                panic!("writer completed before guard release: {result:?}")
            }
            Err(error) => panic!("writer channel disconnected before guard release: {error}"),
        }
        // A second ordinary read-open can itself block on this oplock. Read via
        // the existing guard's actual overlapped reader instead.
        let mut held_bytes = vec![0; original.len()];
        guard
            .read_complete(&mut held_bytes)
            .expect("read under protected reference");
        assert_eq!(held_bytes, original);
        drop(guard);
        // Required only for the immediate sharing-denial branch; a blocked open
        // may already have completed after the guard dropped.
        let _ = release_tx.send(());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match outcome_rx
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("writer completes after guard release")
            {
                Outcome::Completed(result) => {
                    result.expect("writer succeeds after guard release");
                    break;
                }
                Outcome::SharingDenied if !denial_seen => denial_seen = true,
                Outcome::SharingDenied => panic!("duplicate sharing-denial observation"),
            }
        }
        writer.join().expect("writer thread exits");
        assert_eq!(
            fs::read(&path).expect("read modified synthetic file"),
            replacement
        );
        fs::remove_file(&path).expect("remove successful synthetic file");
        fs::remove_dir(&root).expect("remove successful empty synthetic directory");
    }

    #[test]
    fn initialization_fence_rejects_fetches_without_hiding_dirty_recovery() {
        let state = Arc::new(CallbackState::new_for_root(
            Arc::new(SyntheticBackend),
            std::path::PathBuf::from(r"C:\Synthetic"),
            RootIdentity {
                volume_serial: 1,
                file_index: 2,
            },
            None,
        ));
        let range = FetchRange { offset: 0, end: 1 };
        assert!(state.begin_fetch(1, range).is_none());
        assert_eq!(state.readiness_fetch_rejections.load(Ordering::Acquire), 1);
        state.record_reconnect_scan(super::ReconnectScan {
            modified_files: 1,
            unresolved_objects: 0,
        });
        assert!(state.has_unresolved_placeholder_data());
        state.publish_initial_readiness().unwrap();
        let permit = state.begin_fetch(1, range).expect("ready request admitted");
        drop(permit);
        state.close_readiness();
        assert!(state.begin_fetch(2, range).is_none());
        assert!(state.publish_initial_readiness().is_err());
        assert!(state.has_unresolved_placeholder_data());
        let failed = CallbackState::new_for_root(
            Arc::new(SyntheticBackend),
            std::path::PathBuf::from(r"C:\Synthetic"),
            RootIdentity {
                volume_serial: 1,
                file_index: 2,
            },
            None,
        );
        failed.fail_initial_readiness();
        failed.close_readiness();
        assert_eq!(
            failed.readiness.load(Ordering::Acquire),
            super::CALLBACK_FAILED
        );
        assert!(failed.publish_initial_readiness().is_err());
    }

    #[test]
    fn configured_root_validation_pins_identity_and_rejects_existing_contents() {
        let path = super::create_private_test_root().expect("create unique synthetic directory");
        let identity = super::inspect_configured_root(&path, true)
            .expect("empty ordinary directory is configurable");
        let verified = super::inspect_configured_root(&path, false)
            .expect("configured identity remains verifiable");
        assert_eq!(identity.volume_serial, verified.volume_serial);
        assert_eq!(identity.file_index, verified.file_index);

        let child = path.join("do-not-adopt.txt");
        std::fs::write(&child, b"synthetic existing file").expect("create test content");
        assert_eq!(
            super::inspect_configured_root(&path, true),
            Err(crate::Error::ConfiguredRootNotEmpty)
        );
        assert_eq!(
            super::inspect_configured_root(&path, false)
                .expect("nonempty root identity stays verifiable")
                .file_index,
            identity.file_index
        );
        std::fs::remove_file(child).expect("remove own synthetic test file");
        std::fs::remove_dir(path).expect("remove own empty synthetic root");
    }

    #[test]
    fn normalized_path_form_is_structural_and_volume_bound() {
        assert_eq!(
            normalized_path_form("\\Device\\HarddiskVolume1\\root\\file", "C:"),
            NormalizedPathForm::Device
        );
        assert_eq!(
            normalized_path_form("\\??\\C:\\root\\file", "C:"),
            NormalizedPathForm::NtDos
        );
        assert_eq!(
            normalized_path_form("\\\\?\\C:\\root\\file", "C:"),
            NormalizedPathForm::Win32Dos
        );
        assert_eq!(
            normalized_path_form("C:\\root\\file", "C:"),
            NormalizedPathForm::DriveAbsolute
        );
        assert_eq!(
            normalized_path_form("\\root\\file", "C:"),
            NormalizedPathForm::VolumeRooted
        );
        assert_eq!(
            normalized_path_form("D:\\root\\file", "C:"),
            NormalizedPathForm::Other
        );
    }

    #[test]
    fn callback_path_suffix_accepts_only_volume_bound_absolute_forms() {
        let device = "\\Device\\HarddiskVolume1";
        for normalized in [
            "\\Device\\HarddiskVolume1\\root\\file",
            "\\??\\C:\\root\\file",
            "\\\\?\\C:\\root\\file",
            "C:\\root\\file",
            "\\root\\file",
        ] {
            assert_eq!(
                callback_path_suffix(normalized, "C:", device),
                Ok("\\root\\file")
            );
        }
        assert_eq!(
            callback_path_suffix("D:\\root\\file", "C:", device),
            Err(NormalizedPathForm::Other)
        );
        assert_eq!(
            callback_path_suffix("\\\\server\\share\\file", "C:", device),
            Err(NormalizedPathForm::VolumeRooted)
        );
    }

    #[test]
    fn configured_root_validation_rejects_drive_root_and_relative_paths() {
        assert_eq!(
            super::inspect_configured_root(Path::new("C:\\"), false),
            Err(crate::Error::InvalidConfiguredRoot)
        );
        assert_eq!(
            super::inspect_configured_root(Path::new("relative"), false),
            Err(crate::Error::InvalidConfiguredRoot)
        );
    }

    #[test]
    fn default_temp_path_spelling_diagnostic_keeps_containment_strict() {
        let root = super::create_private_test_root().expect("create unique default-TEMP root");
        let child = root.join("synthetic-path-probe.txt");
        std::fs::write(&child, b"synthetic path spelling probe")
            .expect("create synthetic path probe");
        let canonical_root = std::fs::canonicalize(&root).expect("canonicalize synthetic root");
        let canonical_child = std::fs::canonicalize(&child).expect("canonicalize synthetic child");
        let short_root = super::short_windows_path(&root);
        let short_child = super::short_windows_path(&child);
        let short_differs = short_root.as_ref().is_some_and(|value| value != &root)
            || short_child.as_ref().is_some_and(|value| value != &child);
        let canonical_matches = super::windows_path_is_within(&canonical_child, &root);
        let canonical_pair_matches =
            super::windows_path_is_within(&canonical_child, &canonical_root);
        let short_matches = short_child
            .as_ref()
            .is_some_and(|value| super::windows_path_is_within(value, &root));
        let short_pair_matches = short_child.as_ref().is_some_and(|child| {
            short_root
                .as_ref()
                .is_some_and(|root| super::windows_path_is_within(child, root))
        });

        // Print only booleans: default TEMP usernames and paths stay private.
        println!(
            "default_temp_path_diagnostic raw_matches={} canonical_vs_raw_root={} canonical_pair_matches={} short_alias_available={} short_alias_differs={} short_vs_raw_root={} short_pair_matches={}",
            super::windows_path_is_within(&child, &root),
            canonical_matches,
            canonical_pair_matches,
            short_child.is_some(),
            short_differs,
            short_matches,
            short_pair_matches,
        );
        assert!(super::windows_path_is_within(&child, &root));
        assert!(canonical_root.is_dir());
        assert!(canonical_matches || canonical_child.starts_with(&canonical_root));
        assert!(canonical_pair_matches);
        assert!(short_pair_matches);
        std::fs::remove_file(&child).expect("remove synthetic path probe");
        std::fs::remove_dir(&root).expect("remove owned synthetic root");
    }

    #[test]
    fn containment_treats_only_extended_local_drive_prefixes_as_equivalent() {
        let extended_root = Path::new(r"\\?\C:\Synthetic\Root");
        let dos_child = Path::new(r"C:\Synthetic\Root\child.bin");
        let nt_child = Path::new(r"\??\C:\Synthetic\Root\child.bin");
        assert!(super::windows_path_is_within(dos_child, extended_root));
        assert!(super::windows_path_is_within(nt_child, extended_root));
        assert!(super::windows_path_is_within(
            Path::new(r"\\?\C:\Synthetic\Root\child.bin"),
            Path::new(r"C:\Synthetic\Root")
        ));
        assert!(!super::windows_path_is_within(
            Path::new(r"D:\Synthetic\Root\child.bin"),
            extended_root
        ));
        assert!(!super::windows_path_is_within(
            Path::new(r"C:\Synthetic\RootSibling\child.bin"),
            extended_root
        ));
        let alias_root = Path::new(r"C:\Users\RAIUN~1\AppData\Local\Temp\Root");
        let alias_child = alias_root.join("edited.bin");
        assert!(super::windows_path_is_within(&alias_child, alias_root));
        assert!(is_supported_local_drive_path(&alias_child));
        assert!(!is_supported_local_drive_path(Path::new(
            r"\\server\share\Root\file"
        )));
        assert!(!is_supported_local_drive_path(Path::new(
            r"\\?\C:\Root\file"
        )));
        assert!(!is_supported_local_drive_path(Path::new(
            r"\\.\C:\Root\file"
        )));
    }

    #[test]
    fn callback_identity_guard_rejects_sibling_reparse_and_root_swap() {
        let root_identity = RootIdentity {
            volume_serial: 7,
            file_index: 11,
        };
        let root = RootSnapshot {
            identity: root_identity,
            file_attributes: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            reparse_tag: IO_REPARSE_TAG_CLOUD,
            placeholder_state: CF_PLACEHOLDER_STATE_PLACEHOLDER | CF_PLACEHOLDER_STATE_SYNC_ROOT,
            file_size: 0,
            last_write_time: 1,
        };
        let child = RootSnapshot {
            identity: RootIdentity {
                volume_serial: 7,
                file_index: 12,
            },
            file_attributes: FILE_ATTRIBUTE_REPARSE_POINT,
            reparse_tag: IO_REPARSE_TAG_CLOUD,
            placeholder_state: CF_PLACEHOLDER_STATE_PLACEHOLDER,
            file_size: 64,
            last_write_time: 2,
        };
        assert!(valid_callback_entry_snapshot(
            root,
            child,
            root_identity,
            12,
            64
        ));
        assert!(!valid_callback_entry_snapshot(
            root,
            child,
            root_identity,
            13,
            64
        ));
        assert!(!valid_callback_entry_snapshot(
            root,
            child,
            RootIdentity {
                volume_serial: 7,
                file_index: 99,
            },
            12,
            64,
        ));
        assert!(!valid_callback_entry_snapshot(
            root,
            RootSnapshot {
                reparse_tag: 0xA000_000C,
                ..child
            },
            root_identity,
            12,
            64,
        ));
        assert_eq!(
            IO_REPARSE_TAG_CLOUD & IO_REPARSE_TAG_CLOUD_MASK,
            child.reparse_tag & IO_REPARSE_TAG_CLOUD_MASK
        );

        let plain_dir = RootSnapshot {
            identity: RootIdentity {
                volume_serial: 7,
                file_index: 21,
            },
            file_attributes: FILE_ATTRIBUTE_DIRECTORY,
            reparse_tag: 0,
            placeholder_state: 0,
            file_size: 0,
            last_write_time: 0,
        };
        assert!(valid_callback_directory_snapshot(plain_dir));
        assert!(valid_callback_directory_snapshot(RootSnapshot {
            file_attributes: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            reparse_tag: IO_REPARSE_TAG_CLOUD,
            placeholder_state: CF_PLACEHOLDER_STATE_PLACEHOLDER,
            ..plain_dir
        }));
        assert!(!valid_callback_directory_snapshot(RootSnapshot {
            file_attributes: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            reparse_tag: 0xA000_000C,
            placeholder_state: CF_PLACEHOLDER_STATE_PLACEHOLDER,
            ..plain_dir
        }));
    }

    #[test]
    fn configured_root_overlap_uses_root_ancestry_not_shared_parent_identity() {
        let base = super::create_private_test_root().expect("create synthetic first root");
        let child = base.join("child");
        std::fs::create_dir(&child).expect("create synthetic nested root");
        let sibling = super::create_private_test_root().expect("create synthetic sibling root");

        assert!(super::configured_roots_overlap(&base, &base).expect("same root"));
        assert!(super::configured_roots_overlap(&base, &child).expect("nested roots"));
        assert!(super::configured_roots_overlap(&child, &base).expect("nested roots reverse"));
        assert!(!super::configured_roots_overlap(&base, &sibling).expect("separate roots"));

        std::fs::remove_dir(&child).expect("remove owned synthetic child root");
        std::fs::remove_dir(&base).expect("remove owned synthetic root");
        std::fs::remove_dir(sibling).expect("remove owned synthetic sibling");
    }

    #[test]
    fn configured_root_lease_detects_a_path_replacement() {
        let path = super::create_private_test_root().expect("create unique synthetic directory");
        let renamed = path.with_file_name(format!(
            "{}-renamed",
            path.file_name().unwrap().to_string_lossy()
        ));
        let lease = crate::pin_configured_root(&path).expect("pin validated root");
        if std::fs::rename(&path, &renamed).is_ok() {
            std::fs::create_dir(&path).expect("create a replacement at the selected name");
            let replacement = crate::verify_configured_root_identity(&path)
                .expect("inspect replacement directory");
            assert_ne!(replacement, lease.identity);
            std::fs::remove_dir(&path).expect("remove synthetic replacement");
            std::fs::rename(&renamed, &path).expect("restore original synthetic root");
        } else {
            assert_eq!(
                crate::verify_configured_root_identity(&path).expect("verify pinned root"),
                lease.identity
            );
        }
        drop(lease);
        std::fs::remove_dir(&path).expect("remove owned synthetic root");
    }

    #[test]
    fn registered_disconnected_root_preserves_identity_without_accepting_unregistered_reparse() {
        let identity = RootIdentity {
            volume_serial: 7,
            file_index: 11,
        };
        let plain = RootSnapshot {
            identity,
            file_attributes: FILE_ATTRIBUTE_DIRECTORY,
            reparse_tag: 0,
            placeholder_state: 0,
            file_size: 0,
            last_write_time: 0,
        };
        let cloud = RootSnapshot {
            file_attributes: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            reparse_tag: IO_REPARSE_TAG_CLOUD,
            placeholder_state: CF_PLACEHOLDER_STATE_PLACEHOLDER
                | CF_PLACEHOLDER_STATE_SYNC_ROOT
                | CF_PLACEHOLDER_STATE_PARTIAL
                | CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK,
            ..plain
        };
        assert!(valid_root_snapshot(
            plain,
            identity,
            RootSnapshotState::PlainUnregistered
        ));
        assert!(!valid_root_snapshot(
            cloud,
            identity,
            RootSnapshotState::PlainUnregistered
        ));
        for state in [
            RootSnapshotState::RegisteredDisconnected,
            RootSnapshotState::Connected,
        ] {
            assert!(valid_root_snapshot(cloud, identity, state));
            assert_eq!(
                valid_root_snapshot(plain, identity, state),
                state == RootSnapshotState::RegisteredDisconnected
            );
            assert!(!valid_root_snapshot(
                RootSnapshot {
                    reparse_tag: 0xa0000003,
                    ..cloud
                },
                identity,
                state
            ));
            assert!(!valid_root_snapshot(
                RootSnapshot {
                    placeholder_state: cloud.placeholder_state | 0x40,
                    ..cloud
                },
                identity,
                state
            ));
            assert!(!valid_root_snapshot(
                cloud,
                RootIdentity {
                    file_index: 12,
                    ..identity
                },
                state
            ));
        }
        assert_eq!(root_snapshot_state(false, true), None);
        assert_eq!(
            root_snapshot_state(true, false),
            Some(RootSnapshotState::RegisteredDisconnected)
        );
    }

    #[test]
    fn registered_root_accepts_only_documented_population_states() {
        let required = CF_PLACEHOLDER_STATE_PLACEHOLDER | CF_PLACEHOLDER_STATE_SYNC_ROOT;
        assert!(valid_registered_root_state(required));
        assert!(valid_registered_root_state(
            required | CF_PLACEHOLDER_STATE_PARTIAL | CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK
        ));
        assert!(!valid_registered_root_state(
            required | CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK
        ));
        assert!(!valid_registered_root_state(required | 0x40));
        assert!(!valid_registered_root_state(
            CF_PLACEHOLDER_STATE_PLACEHOLDER
        ));
    }

    #[test]
    fn failed_cfexecute_slice_does_not_advance_or_count_later_bytes() {
        let state = Arc::new(CallbackState::new(Arc::new(SyntheticBackend)));
        let request_key = 91;
        let first_len = 64 * 1024;
        let _permit = state
            .begin_fetch(
                request_key,
                FetchRange {
                    offset: 0,
                    end: (first_len * 3) as u64,
                },
            )
            .expect("register bounded fetch");

        assert_eq!(
            state.commit_transfer_result(request_key, 0, first_len, 0),
            Some(first_len as u64)
        );
        assert_eq!(
            state.commit_transfer_result(request_key, first_len as u64, first_len, -1),
            None
        );

        assert_eq!(state.transferred_bytes.load(Ordering::Relaxed), first_len);
        let activity = state
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fetch = activity.requests.get(&request_key).expect("active fetch");
        assert_eq!(fetch.remaining.offset, first_len as u64);
        assert_eq!(fetch.remaining.end, (first_len * 3) as u64);
    }

    #[test]
    fn unregister_may_evict_only_expected_regular_file_placeholders() {
        let mut names = super::FIXTURE_ITEMS
            .iter()
            .map(|item| item.name.to_string())
            .collect::<std::collections::HashSet<_>>();
        names.remove(super::SECOND_FILE_NAME);
        assert!(!super::fixture_names_match_expected(&names, true, false));
        assert!(super::fixture_names_match_expected(&names, true, true));

        names.remove(super::FIRST_FOLDER_NAME);
        assert!(!super::fixture_names_match_expected(&names, true, true));
        names.insert("unexpected-child".to_string());
        assert!(!super::fixture_names_match_expected(&names, true, true));
    }

    #[test]
    fn recorded_fixture_identity_rejects_replacement() {
        let original = super::RootIdentity {
            volume_serial: 7,
            file_index: 11,
        };
        let replacement = super::RootIdentity {
            volume_serial: 7,
            file_index: 12,
        };
        assert!(super::fixture_identity_matches(Some(original), original));
        assert!(!super::fixture_identity_matches(
            Some(original),
            replacement
        ));
        assert!(!super::fixture_identity_matches(None, original));
    }

    #[test]
    fn synthetic_backend_has_multiple_files_and_directories_and_reads_ranges() {
        let backend = SyntheticBackend;
        assert_eq!(
            backend.lookup(&FIRST_FOLDER_IDENTITY).unwrap(),
            Some(crate::PlaceholderMetadata {
                is_directory: true,
                length: 0,
            })
        );
        assert_eq!(
            backend.lookup(&FILE_IDENTITY).unwrap(),
            Some(crate::PlaceholderMetadata {
                is_directory: false,
                length: 4096,
            })
        );
        assert_eq!(
            backend.lookup(&SECOND_FILE_IDENTITY).unwrap(),
            Some(crate::PlaceholderMetadata {
                is_directory: false,
                length: SECOND_PAYLOAD_LEN as u64,
            })
        );
        assert_eq!(backend.lookup(b"unknown identity").unwrap(), None);

        let token = CancellationToken::new();
        let mut bytes = [0_u8; 8];
        assert_eq!(
            backend
                .read_range(&SECOND_FILE_IDENTITY, 4096, &mut bytes, &token)
                .unwrap(),
            bytes.len()
        );
        assert_eq!(bytes[0], ((4096_u32 * 17 + 19) % 256) as u8);
        assert_eq!(
            backend.read_range(&FIRST_FOLDER_IDENTITY, 0, &mut bytes, &token),
            Err(BackendError::NotFound)
        );
        assert_eq!(
            backend.read_range(
                &SECOND_FILE_IDENTITY,
                SECOND_PAYLOAD_LEN as u64,
                &mut bytes,
                &token
            ),
            Err(BackendError::InvalidRange)
        );
        token.cancel();
        assert_eq!(
            backend.read_range(&SECOND_FILE_IDENTITY, 0, &mut bytes, &token),
            Err(BackendError::Cancelled)
        );
    }

    #[test]
    fn fetch_param_size_accepts_only_documented_and_runtime_aligned_layouts() {
        assert!(valid_fetch_data_param_size(
            CF_FETCH_DATA_PARAM_SIZE_DOCUMENTED
        ));
        assert!(valid_fetch_data_param_size(
            CF_FETCH_DATA_PARAM_SIZE_ALIGNED
        ));
        assert!(!valid_fetch_data_param_size(0));
        assert!(!valid_fetch_data_param_size(56));
        assert!(!valid_fetch_data_param_size(65));
    }

    #[test]
    fn callback_fetch_slots_are_bounded_and_cancellation_is_scoped() {
        let state = Arc::new(CallbackState::new(Arc::new(SyntheticBackend)));
        let mut permits = (0..MAX_CONCURRENT_FETCHES)
            .map(|request| {
                state
                    .begin_fetch(
                        request as i64,
                        FetchRange {
                            offset: 0,
                            end: 4096,
                        },
                    )
                    .expect("fetch slot")
            })
            .collect::<Vec<_>>();
        assert!(
            state
                .begin_fetch(
                    999,
                    FetchRange {
                        offset: 0,
                        end: 4096
                    }
                )
                .is_none()
        );

        state.cancel_request(
            3,
            FetchRange {
                offset: 0,
                end: 2048,
            },
        );
        assert!(!permits[3].cancellation.is_cancelled());
        state.advance_fetch(3, 2048);
        state.cancel_request(
            3,
            FetchRange {
                offset: 0,
                end: 2048,
            },
        );
        assert!(!permits[3].cancellation.is_cancelled());
        state.cancel_request(
            3,
            FetchRange {
                offset: 2048,
                end: 4096,
            },
        );
        assert!(permits[3].cancellation.is_cancelled());
        assert!(!permits[2].cancellation.is_cancelled());

        permits.pop();
        assert!(
            state
                .begin_fetch(
                    999,
                    FetchRange {
                        offset: 0,
                        end: 4096
                    }
                )
                .is_some()
        );
        drop(permits);
        state.wait_for_callbacks();
    }

    #[test]
    fn callback_staging_is_capped_and_cancel_wakes_a_waiting_fetch() {
        let state = Arc::new(CallbackState::new(Arc::new(SyntheticBackend)));
        let permits = (0..MAX_STAGED_CALLBACKS)
            .map(|_| {
                state
                    .reserve_staging(&CancellationToken::new())
                    .expect("staging slot")
            })
            .collect::<Vec<_>>();
        let fetch = state
            .begin_fetch(
                77,
                FetchRange {
                    offset: 0,
                    end: 4096,
                },
            )
            .expect("fetch slot");
        let cancellation = fetch.cancellation.clone();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let waiter = {
            let state = state.clone();
            thread::spawn(move || {
                entered_tx.send(()).unwrap();
                state.reserve_staging(&cancellation).is_some()
            })
        };
        entered_rx.recv().unwrap();
        state.cancel_request(
            77,
            FetchRange {
                offset: 0,
                end: 4096,
            },
        );
        assert!(!waiter.join().unwrap());
        drop(fetch);
        drop(permits);
        state.wait_for_callbacks();
    }

    #[test]
    fn callback_staging_deadline_includes_slot_wait() {
        let state = Arc::new(CallbackState::new(Arc::new(SyntheticBackend)));
        let permits = (0..MAX_STAGED_CALLBACKS)
            .map(|_| {
                state
                    .reserve_staging(&CancellationToken::new())
                    .expect("staging slot")
            })
            .collect::<Vec<_>>();
        let cancellation = CancellationToken::with_timeout(std::time::Duration::from_millis(40));
        let started = std::time::Instant::now();
        assert!(state.reserve_staging(&cancellation).is_none());
        assert!(started.elapsed() >= std::time::Duration::from_millis(30));
        assert!(started.elapsed() < std::time::Duration::from_millis(250));
        drop(permits);
    }

    #[test]
    fn cancel_ranges_reject_invalid_values_and_support_eof() {
        assert_eq!(checked_cancel_range(-1, 4096), None);
        assert_eq!(checked_cancel_range(0, -2), None);
        assert_eq!(
            checked_cancel_range(0, 4096),
            Some(FetchRange {
                offset: 0,
                end: 4096
            })
        );
        assert_eq!(
            checked_cancel_range(4096, -1),
            Some(FetchRange {
                offset: 4096,
                end: u64::MAX
            })
        );
    }

    struct BlockingLookupBackend {
        entered: mpsc::SyncSender<()>,
        release: Arc<(Mutex<bool>, Condvar)>,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl PlaceholderBackend for BlockingLookupBackend {
        fn lookup(
            &self,
            _identity: &[u8],
        ) -> Result<Option<crate::PlaceholderMetadata>, BackendError> {
            self.entered.send(()).unwrap();
            let (lock, ready) = &*self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = ready.wait(released).unwrap();
            }
            Ok(Some(crate::PlaceholderMetadata {
                is_directory: false,
                length: 4096,
            }))
        }

        fn read_range(
            &self,
            _identity: &[u8],
            _offset: u64,
            _output: &mut [u8],
            _cancellation: &CancellationToken,
        ) -> Result<usize, BackendError> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(0)
        }
    }

    #[test]
    fn cancel_during_blocked_identity_lookup_prevents_following_range_read() {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let backend = Arc::new(BlockingLookupBackend {
            entered: entered_tx,
            release: Arc::clone(&release),
            reads: std::sync::atomic::AtomicUsize::new(0),
        });
        let state = Arc::new(CallbackState::new(backend.clone()));
        let worker_state = Arc::clone(&state);
        let worker = thread::spawn(move || {
            let permit = worker_state
                .begin_fetch(
                    77,
                    FetchRange {
                        offset: 0,
                        end: 4096,
                    },
                )
                .expect("fetch permit before lookup");
            lookup_for_fetch(
                worker_state.backend.as_ref(),
                &FILE_IDENTITY,
                &permit.cancellation,
            )
        });

        entered_rx.recv().expect("lookup started");
        state.cancel_request(
            77,
            FetchRange {
                offset: 0,
                end: 4096,
            },
        );
        let (lock, ready) = &*release;
        *lock.lock().unwrap() = true;
        ready.notify_all();

        assert_eq!(worker.join().unwrap(), Err(BackendError::Cancelled));
        assert_eq!(backend.reads.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    // Exercise the large-fetch callback's session/window/chunk contract with
    // a deterministic backend. The native CfExecute boundary is intentionally
    // not invoked by these tests; this small harness records the exact slices
    // the callback is expected to publish.
    #[derive(Default)]
    struct SessionTrace {
        windows: Vec<FetchRange>,
        published: Vec<(u64, usize)>,
        bytes_published: u64,
        read_range_calls: usize,
    }

    struct WindowBackend {
        trace: Arc<Mutex<SessionTrace>>,
        length: u64,
        fail_window: Option<usize>,
    }

    impl PlaceholderBackend for WindowBackend {
        fn lookup(
            &self,
            _identity: &[u8],
        ) -> Result<Option<crate::PlaceholderMetadata>, BackendError> {
            Ok(Some(crate::PlaceholderMetadata {
                is_directory: false,
                length: self.length,
            }))
        }

        fn read_range(
            &self,
            _identity: &[u8],
            _offset: u64,
            _output: &mut [u8],
            _cancellation: &CancellationToken,
        ) -> Result<usize, BackendError> {
            self.trace.lock().unwrap().read_range_calls += 1;
            Err(BackendError::Unavailable)
        }

        fn prepare_fetch_session<'a>(
            &'a self,
            _identity: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn crate::PreparedFetchSession + 'a>, BackendError> {
            if cancellation.is_cancelled() {
                return Err(BackendError::Cancelled);
            }
            Ok(Box::new(WindowSession {
                trace: Arc::clone(&self.trace),
                length: self.length,
                fail_window: self.fail_window,
            }))
        }
    }

    struct WindowSession {
        trace: Arc<Mutex<SessionTrace>>,
        length: u64,
        fail_window: Option<usize>,
    }

    impl crate::PreparedFetchSession for WindowSession {
        fn metadata(&self) -> crate::PlaceholderMetadata {
            crate::PlaceholderMetadata {
                is_directory: false,
                length: self.length,
            }
        }

        fn prepare_window<'a>(
            &'a self,
            range: FetchRange,
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn crate::PreparedFetch + 'a>, BackendError> {
            let mut trace = self.trace.lock().unwrap();
            let index = trace.windows.len();
            trace.windows.push(range);
            if cancellation.is_cancelled() {
                return Err(BackendError::Cancelled);
            }
            if self.fail_window == Some(index) {
                return Err(BackendError::Unavailable);
            }
            if range.end < range.offset
                || range.end > self.length
                || range.len() > MAX_REQUEST_BYTES
            {
                return Err(BackendError::InvalidRange);
            }
            let count = usize::try_from(range.len()).map_err(|_| BackendError::InvalidRange)?;
            let bytes = (0..count)
                .map(|index| ((range.offset + index as u64) % 251) as u8)
                .collect();
            Ok(Box::new(WindowFetch {
                metadata: self.metadata(),
                bytes,
            }))
        }
    }

    struct WindowFetch {
        metadata: crate::PlaceholderMetadata,
        bytes: Vec<u8>,
    }

    impl crate::PreparedFetch for WindowFetch {
        fn metadata(&self) -> crate::PlaceholderMetadata {
            self.metadata
        }

        fn bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum HarnessStop {
        Complete,
        Failed {
            unsent_offset: u64,
            error: BackendError,
        },
        Cancelled {
            unsent_offset: u64,
        },
    }

    fn run_window_harness(
        backend: &dyn PlaceholderBackend,
        trace: &Mutex<SessionTrace>,
        length: u64,
        cancellation: &CancellationToken,
        cancel_after_first_window: bool,
    ) -> HarnessStop {
        match stream_prepared_windows(
            backend,
            &FILE_IDENTITY,
            FetchRange {
                offset: 0,
                end: length,
            },
            length,
            cancellation,
            |offset, bytes| {
                assert!(!bytes.is_empty() && bytes.len() <= MAX_RANGE_BYTES);
                assert!(
                    bytes
                        .iter()
                        .enumerate()
                        .all(|(index, byte)| { *byte == ((offset + index as u64) % 251) as u8 })
                );
                let mut recorded = trace.lock().unwrap();
                recorded.published.push((offset, bytes.len()));
                recorded.bytes_published += bytes.len() as u64;
                drop(recorded);
                if cancel_after_first_window && offset + bytes.len() as u64 == MAX_REQUEST_BYTES {
                    cancellation.cancel();
                }
                Ok(())
            },
        ) {
            Ok(()) => HarnessStop::Complete,
            Err(error) if error.error == BackendError::Cancelled => HarnessStop::Cancelled {
                unsent_offset: error.offset,
            },
            Err(error) => HarnessStop::Failed {
                unsent_offset: error.offset,
                error: error.error,
            },
        }
    }

    #[test]
    fn large_fetch_session_splits_and_publishes_exact_bounded_offsets() {
        let length = MAX_REQUEST_BYTES + 2 * MAX_RANGE_BYTES as u64;
        let trace = Arc::new(Mutex::new(SessionTrace::default()));
        let backend = WindowBackend {
            trace: Arc::clone(&trace),
            length,
            fail_window: None,
        };
        let cancellation = CancellationToken::new();

        assert_eq!(
            run_window_harness(&backend, &trace, length, &cancellation, false),
            HarnessStop::Complete
        );
        let trace = trace.lock().unwrap();
        assert_eq!(
            trace.windows,
            [
                FetchRange {
                    offset: 0,
                    end: MAX_REQUEST_BYTES,
                },
                FetchRange {
                    offset: MAX_REQUEST_BYTES,
                    end: length,
                },
            ]
        );
        assert_eq!(trace.bytes_published, length);
        assert_eq!(
            trace.published.len(),
            (MAX_REQUEST_BYTES / MAX_RANGE_BYTES as u64) as usize + 2
        );
        let mut expected_offset = 0;
        for (offset, size) in &trace.published {
            assert_eq!(*offset, expected_offset);
            assert!(*size <= MAX_RANGE_BYTES);
            expected_offset += *size as u64;
        }
        assert_eq!(expected_offset, length);
    }

    #[test]
    fn failed_later_window_reports_unsent_offset_and_stops_fetching() {
        let length = 2 * MAX_REQUEST_BYTES + 1;
        let trace = Arc::new(Mutex::new(SessionTrace::default()));
        let backend = WindowBackend {
            trace: Arc::clone(&trace),
            length,
            fail_window: Some(1),
        };
        let cancellation = CancellationToken::new();

        assert_eq!(
            run_window_harness(&backend, &trace, length, &cancellation, false),
            HarnessStop::Failed {
                unsent_offset: MAX_REQUEST_BYTES,
                error: BackendError::Unavailable,
            }
        );
        let trace = trace.lock().unwrap();
        assert_eq!(trace.windows.len(), 2);
        assert_eq!(trace.windows[1].offset, MAX_REQUEST_BYTES);
        assert_eq!(trace.bytes_published, MAX_REQUEST_BYTES);
        assert!(
            trace
                .published
                .iter()
                .all(|(offset, size)| { *offset + *size as u64 <= MAX_REQUEST_BYTES })
        );
    }

    #[test]
    fn cancellation_between_windows_prevents_further_publication() {
        let length = MAX_REQUEST_BYTES + MAX_RANGE_BYTES as u64;
        let trace = Arc::new(Mutex::new(SessionTrace::default()));
        let backend = WindowBackend {
            trace: Arc::clone(&trace),
            length,
            fail_window: None,
        };
        let cancellation = CancellationToken::new();

        assert_eq!(
            run_window_harness(&backend, &trace, length, &cancellation, true),
            HarnessStop::Cancelled {
                unsent_offset: MAX_REQUEST_BYTES,
            }
        );
        let trace = trace.lock().unwrap();
        assert_eq!(trace.windows.len(), 2);
        assert_eq!(trace.windows[1].offset, MAX_REQUEST_BYTES);
        assert_eq!(trace.bytes_published, MAX_REQUEST_BYTES);
        assert!(
            trace
                .published
                .iter()
                .all(|(offset, size)| { *offset + *size as u64 <= MAX_REQUEST_BYTES })
        );
    }

    #[test]
    fn unsupported_default_session_refuses_large_fetch_before_transfer() {
        let trace = Arc::new(Mutex::new(SessionTrace::default()));
        let backend = WindowBackendWithoutSession {
            trace: Arc::clone(&trace),
            length: MAX_REQUEST_BYTES + 1,
        };
        let cancellation = CancellationToken::new();

        assert_eq!(
            run_window_harness(&backend, &trace, backend.length, &cancellation, false,),
            HarnessStop::Failed {
                unsent_offset: 0,
                error: BackendError::Unavailable,
            }
        );
        let trace = trace.lock().unwrap();
        assert!(trace.windows.is_empty());
        assert!(trace.published.is_empty());
        assert_eq!(trace.bytes_published, 0);
        assert_eq!(trace.read_range_calls, 0);
    }

    struct WindowBackendWithoutSession {
        trace: Arc<Mutex<SessionTrace>>,
        length: u64,
    }

    impl PlaceholderBackend for WindowBackendWithoutSession {
        fn lookup(
            &self,
            _identity: &[u8],
        ) -> Result<Option<crate::PlaceholderMetadata>, BackendError> {
            Ok(Some(crate::PlaceholderMetadata {
                is_directory: false,
                length: self.length,
            }))
        }

        fn read_range(
            &self,
            _identity: &[u8],
            _offset: u64,
            _output: &mut [u8],
            _cancellation: &CancellationToken,
        ) -> Result<usize, BackendError> {
            self.trace.lock().unwrap().read_range_calls += 1;
            Err(BackendError::Unavailable)
        }
    }
}
