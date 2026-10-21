// Compile this fixture in an x64 Windows SDK developer shell before changing
// the Rust CFAPI declarations. It has no runtime behavior.
#include <stddef.h>
#include <windows.h>
#include <cfapi.h>
#include <type_traits>

static_assert(sizeof(void*) == 8, "the adapter supports x64 Windows only");
static_assert(sizeof(CF_CONNECTION_KEY) == 8);
static_assert(sizeof(CF_TRANSFER_KEY) == 8);
static_assert(sizeof(CF_REQUEST_KEY) == 8);

static_assert(sizeof(CF_SYNC_REGISTRATION) == 72);
static_assert(sizeof(CF_SYNC_POLICIES) == 24);
static_assert(sizeof(CF_CALLBACK_REGISTRATION) == 16);
static_assert(sizeof(CF_CALLBACK_INFO) == 152);
static_assert(offsetof(CF_CALLBACK_INFO, ConnectionKey) == 8);
static_assert(offsetof(CF_CALLBACK_INFO, CallbackContext) == 16);
static_assert(offsetof(CF_CALLBACK_INFO, FileIdentity) == 88);
static_assert(offsetof(CF_CALLBACK_INFO, TransferKey) == 112);
static_assert(offsetof(CF_CALLBACK_INFO, RequestKey) == 144);
static_assert(sizeof(CF_CALLBACK_PARAMETERS) == 64);
static_assert(CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION == 6);
static_assert(sizeof(((CF_CALLBACK_PARAMETERS*)0)->CloseCompletion) == 4);
static_assert(sizeof(((CF_CALLBACK_PARAMETERS*)0)->CloseCompletion) + sizeof(ULONG) == 8);
static_assert(sizeof(CF_FILE_RANGE) == 16);
static_assert(sizeof(CF_PLACEHOLDER_RANGE_INFO_CLASS) == 4);
using CfGetPlaceholderRangeInfoSignature = HRESULT (WINAPI*)(
    HANDLE,
    CF_PLACEHOLDER_RANGE_INFO_CLASS,
    LARGE_INTEGER,
    LARGE_INTEGER,
    PVOID,
    DWORD,
    PDWORD);
static_assert(std::is_same_v<decltype(&CfGetPlaceholderRangeInfo), CfGetPlaceholderRangeInfoSignature>);
static_assert(sizeof(((CF_CALLBACK_PARAMETERS*)0)->FetchData) == 56);
static_assert(offsetof(CF_CALLBACK_PARAMETERS, FetchData) == 8);
static_assert(offsetof(CF_CALLBACK_PARAMETERS, FetchData) + sizeof(((CF_CALLBACK_PARAMETERS*)0)->FetchData) == 64);
static_assert(sizeof(CF_OPERATION_INFO) == 48);
static_assert(offsetof(CF_OPERATION_INFO, ConnectionKey) == 8);
static_assert(offsetof(CF_OPERATION_INFO, TransferKey) == 16);
static_assert(offsetof(CF_OPERATION_INFO, RequestKey) == 40);
static_assert(sizeof(CF_OPERATION_PARAMETERS) == 48);
static_assert(sizeof(((CF_OPERATION_PARAMETERS*)0)->TransferPlaceholders) == 32);
static_assert(sizeof(((CF_OPERATION_PARAMETERS*)0)->TransferPlaceholders.PlaceholderTotalCount) == 8);
static_assert(offsetof(CF_OPERATION_PARAMETERS, TransferPlaceholders.PlaceholderTotalCount) == 16);
static_assert(offsetof(CF_OPERATION_PARAMETERS, TransferPlaceholders.PlaceholderArray) == 24);
static_assert(offsetof(CF_OPERATION_PARAMETERS, TransferPlaceholders.PlaceholderCount) == 32);
static_assert(offsetof(CF_OPERATION_PARAMETERS, TransferPlaceholders.EntriesProcessed) == 36);
static_assert(sizeof(CF_FS_METADATA) == 48);
static_assert(sizeof(CF_PLACEHOLDER_CREATE_INFO) == 88);

int main() { return 0; }
