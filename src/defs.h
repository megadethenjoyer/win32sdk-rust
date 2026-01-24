#include <stdint.h>
#include <stddef.h>

#define _In_
#define _In_opt_
#define _Inout_

typedef uint32_t NTSTATUS;

typedef void VOID;

typedef char CHAR;
typedef unsigned char UCHAR;

typedef int16_t SHORT;
typedef uint16_t USHORT;

typedef int32_t LONG;
typedef uint32_t ULONG;

typedef int64_t LONGLONG;
typedef uint64_t ULONGLONG;
typedef uintptr_t UINT_PTR;
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
typedef SIZE_T *PSIZE_T;

typedef USHORT WORD;

typedef ULONG DWORD;
typedef ULONGLONG DWORD64;
typedef DWORD64 QWORD;
typedef USHORT WCHAR;

typedef WCHAR *PWCH;

typedef VOID *PVOID;

typedef PVOID HANDLE;

typedef UCHAR BOOLEAN;
typedef BOOLEAN *PBOOLEAN;

typedef void *PLDRP_LOAD_CONTEXT;
typedef void *PSLIST_HEADER;
typedef void *PKERNEL_CALLBACK_TABLE;
typedef void *PAPI_SET_NAMESPACE;
typedef void *PCPTABLEINFO;
typedef void *PNLSTABLEINFO;
typedef void *PAPPCOMPAT_EXE_DATA;
typedef void *PRTL_BITMAP;
typedef void *PSILO_USER_SHARED_DATA;
typedef void *PGDI_HANDLE_ENTRY;
typedef void *PPS_POST_PROCESS_INIT_ROUTINE;
typedef void *PWER_PEB_HEADER_BLOCK;
typedef void *PTELEMETRY_COVERAGE_HEADER;
typedef void *PLEAP_SECOND_DATA;

typedef int64_t LARGE_INTEGER;
typedef uint64_t ULARGE_INTEGER;

typedef ULONG_PTR  KAFFINITY;

typedef char *PCHAR;

typedef uint8_t BYTE;

typedef ULONGLONG *PULONGLONG;

#define RTL_MAX_DRIVE_LETTERS 32
typedef ULONG GDI_HANDLE_BUFFER[34];

typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;


typedef struct _IMAGE_IMPORT_DESCRIPTOR {
  union {
    ULONG Characteristics;
    ULONG OriginalFirstThunk;
  } DUMMYUNIONNAME;
  ULONG TimeDateStamp;
  ULONG ForwarderChain;
  ULONG Name;
  ULONG FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

 typedef struct _IMAGE_EXPORT_DIRECTORY {
     DWORD   Characteristics;
     DWORD   TimeDateStamp;
     WORD    MajorVersion;
     WORD    MinorVersion;
     DWORD   Name;
     DWORD   Base;
     DWORD   NumberOfFunctions;
     DWORD   NumberOfNames;
     DWORD   AddressOfFunctions;     // RVA from base of image
     DWORD   AddressOfNames;         // RVA from base of image
     DWORD   AddressOfNameOrdinals;  // RVA from base of image
 } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;


typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  ULONGLONG            ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  ULONGLONG            SizeOfStackReserve;
  ULONGLONG            SizeOfStackCommit;
  ULONGLONG            SizeOfHeapReserve;
  ULONGLONG            SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

//
// Strings
//

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;


typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;


typedef struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset; // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
    ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
    ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
    ULONG Flags; // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _ASSEMBLY_STORAGE_MAP
{
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY *AssemblyArray;
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;


typedef 
VOID (*ACTIVATION_CONTEXT_NOTIFY_ROUTINE)(
    _In_ ULONG NotificationType, // ACTIVATION_CONTEXT_NOTIFICATION_*
    _In_ struct _ACTIVATION_CONTEXT *ActivationContext,
    _In_ struct _ACTIVATION_CONTEXT_DATA *ActivationContextData,
    _In_opt_ PVOID NotificationContext,
    _In_opt_ PVOID NotificationData,
    _Inout_ PBOOLEAN DisableThisNotification
    );

typedef ACTIVATION_CONTEXT_NOTIFY_ROUTINE* PACTIVATION_CONTEXT_NOTIFY_ROUTINE;

typedef struct _ACTIVATION_CONTEXT
{
    LONG RefCount;
    ULONG Flags;
    PACTIVATION_CONTEXT_DATA ActivationContextData;
    PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine;
    PVOID NotificationContext;
    ULONG SentNotifications[8];
    ULONG DisabledNotifications[8];
    ASSEMBLY_STORAGE_MAP StorageMap;
    PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries[32];
} ACTIVATION_CONTEXT, *PACTIVATION_CONTEXT;


typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE *Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE *Left;
            struct _RTL_BALANCED_NODE *Right;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    } DUMMYUNIONNAME2;
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, PRLIST_ENTRY;

// LoadReason
typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonUnknown = -1,
    LoadReasonStaticDependency = 0,
    LoadReasonStaticForwarderDependency = 1,
    LoadReasonDynamicForwarderDependency = 2,
    LoadReasonDelayloadDependency = 3,
    LoadReasonDynamicLoad = 4,
    LoadReasonAsImageLoad = 5,
    LoadReasonAsDataLoad = 6,
    LoadReasonEnclavePrimary = 7, // since REDSTONE3
    LoadReasonEnclaveDependency = 8,
    LoadReasonPatchImage = 9, // since WIN11
} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

// HotPatchState
typedef enum _LDR_HOT_PATCH_STATE
{
    LdrHotPatchBaseImage,
    LdrHotPatchNotApplied,
    LdrHotPatchAppliedReverse,
    LdrHotPatchAppliedForward,
    LdrHotPatchFailedToPatch,
    LdrHotPatchStateMax,
} LDR_HOT_PATCH_STATE, *PLDR_HOT_PATCH_STATE;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

// private
typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;


typedef struct _SINGLE_LIST_ENTRY {
  struct _SINGLE_LIST_ENTRY *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;
// private
typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, *PLDRP_CSLIST;



// private
typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD *Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;


// private
typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount; // ReferenceCount before WIN10
    ULONG LowestLink; // DependencyCount before WIN10
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;


// symbols
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint; // PDLL_INIT_ROUTINE
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG VerifierProvider : 1; // 24H2
            ULONG ShimEngineCalloutSent : 1; // 24H2
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1; // WIN10
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1; // WINBLUE
            ULONG AuxIatCopyPrivate : 1; // 24H2
            ULONG ReservedFlags3 : 1;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG ScpInExceptionTable : 1; // CorDeferredValidate before 24H2
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1; // RS4
            ULONG ChpeEmulatorImage : 1; // WIN11
            ULONG ReservedFlags5 : 1;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    PACTIVATION_CONTEXT EntryPointActivationContext;
    PVOID Lock; // RtlAcquireSRWLockExclusive
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    PLDRP_LOAD_CONTEXT LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    PVOID OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions; // since WINBLUE
    ULONG ReferenceCount; // since WIN10
    ULONG DependentLoadFlags; // since RS1
    UCHAR SigningLevel; // since RS2
    ULONG CheckSum; // since WIN11
    PVOID ActivePatchImageBase;
    LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName; // REDSTONE4
    UNICODE_STRING HeapPartitionName; // 19H1
    PULONGLONG DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; // WIN11
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

//
// Process information structures
//

/**
 * The PEB_LDR_DATA structure contains information about the loaded modules for the process.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
 */
typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct _PEB
{
    //
    // The process was cloned with an inherited address space.
    //
    BOOLEAN InheritedAddressSpace;

    //
    // The process has image file execution options (IFEO).
    //
    BOOLEAN ReadImageFileExecOptions;

    //
    // The process has a debugger attached.
    //
    BOOLEAN BeingDebugged;

    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;            // The process uses large image regions (4 MB).
            BOOLEAN IsProtectedProcess : 1;             // The process is a protected process.
            BOOLEAN IsImageDynamicallyRelocated : 1;    // The process image base address was relocated.
            BOOLEAN SkipPatchingUser32Forwarders : 1;   // The process skipped forwarders for User32.dll functions. 1 for 64-bit, 0 for 32-bit.
            BOOLEAN IsPackagedProcess : 1;              // The process is a packaged store process (APPX/MSIX).
            BOOLEAN IsAppContainerProcess : 1;          // The process has an AppContainer token.
            BOOLEAN IsProtectedProcessLight : 1;        // The process is a protected process (light).
            BOOLEAN IsLongPathAwareProcess : 1;         // The process is long path aware.
        };
    };

    //
    // Handle to a mutex for synchronization.
    //
    HANDLE Mutant;

    //
    // Pointer to the base address of the process image.
    //
    PVOID ImageBaseAddress;

    //
    // Pointer to the process loader data.
    //
    PPEB_LDR_DATA Ldr;

    //
    // Pointer to the process parameters.
    //
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;

    //
    // Reserved.
    //
    PVOID SubSystemData;

    //
    // Pointer to the process default heap.
    //
    PVOID ProcessHeap;

    //
    // Pointer to a critical section used to synchronize access to the PEB.
    //
    PRTL_CRITICAL_SECTION FastPebLock;

    //
    // Pointer to a singly linked list used by ATL.
    //
    PSLIST_HEADER AtlThunkSListPtr;

    //
    // Handle to the Image File Execution Options key.
    //
    HANDLE IFEOKey;

    //
    // Cross process flags.
    //
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;                 // The process is part of a job.
            ULONG ProcessInitializing : 1;          // The process is initializing.
            ULONG ProcessUsingVEH : 1;              // The process is using VEH.
            ULONG ProcessUsingVCH : 1;              // The process is using VCH.
            ULONG ProcessUsingFTH : 1;              // The process is using FTH.
            ULONG ProcessPreviouslyThrottled : 1;   // The process was previously throttled.
            ULONG ProcessCurrentlyThrottled : 1;    // The process is currently throttled.
            ULONG ProcessImagesHotPatched : 1;      // The process images are hot patched. // RS5
            ULONG ReservedBits0 : 24;
        };
    };

    //
    // User32 KERNEL_CALLBACK_TABLE (ntuser.h)
    //
    union
    {
        PKERNEL_CALLBACK_TABLE KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };

    //
    // Reserved.
    //
    ULONG SystemReserved;

    //
    // Pointer to the Active Template Library (ATL) singly linked list (32-bit)
    //
    ULONG AtlThunkSListPtr32;

    //
    // Pointer to the API Set Schema.
    //
    PAPI_SET_NAMESPACE ApiSetMap;

    //
    // Counter for TLS expansion.
    //
    ULONG TlsExpansionCounter;

    //
    // Pointer to the TLS bitmap.
    //
    PRTL_BITMAP TlsBitmap;

    //
    // Bits for the TLS bitmap.
    //
    ULONG TlsBitmapBits[2];

    //
    // Reserved for CSRSS.
    //
    PVOID ReadOnlySharedMemoryBase;

    //
    // Pointer to the USER_SHARED_DATA for the current SILO.
    //
    PSILO_USER_SHARED_DATA SharedData;

    //
    // Reserved for CSRSS.
    //
    PVOID* ReadOnlyStaticServerData;

    //
    // Pointer to the ANSI code page data.
    //
    PCPTABLEINFO AnsiCodePageData;

    //
    // Pointer to the OEM code page data.
    //
    PCPTABLEINFO OemCodePageData;

    //
    // Pointer to the Unicode case table data.
    //
    PNLSTABLEINFO UnicodeCaseTableData;

    //
    // The total number of system processors.
    //
    ULONG NumberOfProcessors;

    //
    // Global flags for the system.
    //
    union
    {
        ULONG NtGlobalFlag;
        struct
        {
            ULONG StopOnException : 1;          // FLG_STOP_ON_EXCEPTION
            ULONG ShowLoaderSnaps : 1;          // FLG_SHOW_LDR_SNAPS
            ULONG DebugInitialCommand : 1;      // FLG_DEBUG_INITIAL_COMMAND
            ULONG StopOnHungGUI : 1;            // FLG_STOP_ON_HUNG_GUI
            ULONG HeapEnableTailCheck : 1;      // FLG_HEAP_ENABLE_TAIL_CHECK
            ULONG HeapEnableFreeCheck : 1;      // FLG_HEAP_ENABLE_FREE_CHECK
            ULONG HeapValidateParameters : 1;   // FLG_HEAP_VALIDATE_PARAMETERS
            ULONG HeapValidateAll : 1;          // FLG_HEAP_VALIDATE_ALL
            ULONG ApplicationVerifier : 1;      // FLG_APPLICATION_VERIFIER
            ULONG MonitorSilentProcessExit : 1; // FLG_MONITOR_SILENT_PROCESS_EXIT
            ULONG PoolEnableTagging : 1;        // FLG_POOL_ENABLE_TAGGING
            ULONG HeapEnableTagging : 1;        // FLG_HEAP_ENABLE_TAGGING
            ULONG UserStackTraceDb : 1;         // FLG_USER_STACK_TRACE_DB
            ULONG KernelStackTraceDb : 1;       // FLG_KERNEL_STACK_TRACE_DB
            ULONG MaintainObjectTypeList : 1;   // FLG_MAINTAIN_OBJECT_TYPELIST
            ULONG HeapEnableTagByDll : 1;       // FLG_HEAP_ENABLE_TAG_BY_DLL
            ULONG DisableStackExtension : 1;    // FLG_DISABLE_STACK_EXTENSION
            ULONG EnableCsrDebug : 1;           // FLG_ENABLE_CSRDEBUG
            ULONG EnableKDebugSymbolLoad : 1;   // FLG_ENABLE_KDEBUG_SYMBOL_LOAD
            ULONG DisablePageKernelStacks : 1;  // FLG_DISABLE_PAGE_KERNEL_STACKS
            ULONG EnableSystemCritBreaks : 1;   // FLG_ENABLE_SYSTEM_CRIT_BREAKS
            ULONG HeapDisableCoalescing : 1;    // FLG_HEAP_DISABLE_COALESCING
            ULONG EnableCloseExceptions : 1;    // FLG_ENABLE_CLOSE_EXCEPTIONS
            ULONG EnableExceptionLogging : 1;   // FLG_ENABLE_EXCEPTION_LOGGING
            ULONG EnableHandleTypeTagging : 1;  // FLG_ENABLE_HANDLE_TYPE_TAGGING
            ULONG HeapPageAllocs : 1;           // FLG_HEAP_PAGE_ALLOCS
            ULONG DebugInitialCommandEx : 1;    // FLG_DEBUG_INITIAL_COMMAND_EX
            ULONG DisableDbgPrint : 1;          // FLG_DISABLE_DBGPRINT
            ULONG CritSecEventCreation : 1;     // FLG_CRITSEC_EVENT_CREATION
            ULONG LdrTopDown : 1;               // FLG_LDR_TOP_DOWN
            ULONG EnableHandleExceptions : 1;   // FLG_ENABLE_HANDLE_EXCEPTIONS
            ULONG DisableProtDlls : 1;          // FLG_DISABLE_PROTDLLS
        } NtGlobalFlags;
    };

    //
    // Timeout for critical sections.
    //
    LARGE_INTEGER CriticalSectionTimeout;

    //
    // Reserved size for heap segments.
    //
    SIZE_T HeapSegmentReserve;

    //
    // Committed size for heap segments.
    //
    SIZE_T HeapSegmentCommit;

    //
    // Threshold for decommitting total free heap.
    //
    SIZE_T HeapDeCommitTotalFreeThreshold;

    //
    // Threshold for decommitting free heap blocks.
    //
    SIZE_T HeapDeCommitFreeBlockThreshold;

    //
    // Number of process heaps.
    //
    ULONG NumberOfHeaps;

    //
    // Maximum number of process heaps.
    //
    ULONG MaximumNumberOfHeaps;

    //
    // Pointer to an array of process heaps. ProcessHeaps is initialized
    // to point to the first free byte after the PEB and MaximumNumberOfHeaps
    // is computed from the page size used to hold the PEB, less the fixed
    // size of this data structure.
    //
    PVOID* ProcessHeaps;

    //
    // Pointer to the system GDI shared handle table.
    //
    PGDI_HANDLE_ENTRY GdiSharedHandleTable;

    //
    // Pointer to the process starter helper.
    //
    PVOID ProcessStarterHelper;

    //
    // The maximum number of GDI function calls during batch operations (GdiSetBatchLimit)
    //
    ULONG GdiDCAttributeList;

    //
    // Pointer to the loader lock critical section.
    //
    PRTL_CRITICAL_SECTION LoaderLock;

    //
    // Major version of the operating system.
    //
    ULONG OSMajorVersion;

    //
    // Minor version of the operating system.
    //
    ULONG OSMinorVersion;

    //
    // Build number of the operating system.
    //
    USHORT OSBuildNumber;

    //
    // CSD version of the operating system.
    //
    USHORT OSCSDVersion;

    //
    // Platform ID of the operating system.
    //
    ULONG OSPlatformId;

    //
    // Subsystem version of the current process image (PE Headers).
    //
    ULONG ImageSubsystem;

    //
    // Major version of the current process image subsystem (PE Headers).
    //
    ULONG ImageSubsystemMajorVersion;

    //
    // Minor version of the current process image subsystem (PE Headers).
    //
    ULONG ImageSubsystemMinorVersion;

    //
    // Affinity mask for the current process.
    //
    KAFFINITY ActiveProcessAffinityMask;

    //
    // Temporary buffer for GDI handles accumulated in the current batch.
    //
    GDI_HANDLE_BUFFER GdiHandleBuffer;

    //
    // Pointer to the post-process initialization routine available for use by the application.
    //
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;

    //
    // Pointer to the TLS expansion bitmap.
    //
    PRTL_BITMAP TlsExpansionBitmap;

    //
    // Bits for the TLS expansion bitmap. TLS_EXPANSION_SLOTS
    //
    ULONG TlsExpansionBitmapBits[32];

    //
    // Session ID of the current process.
    //
    ULONG SessionId;

    //
    // Application compatibility flags. KACF_*
    //
    ULARGE_INTEGER AppCompatFlags;

    //
    // Application compatibility flags. KACF_*
    //
    ULARGE_INTEGER AppCompatFlagsUser;

    //
    // Pointer to the Application SwitchBack Compatibility Engine.
    //
    PVOID pShimData;

    //
    // Pointer to the Application Compatibility Engine.
    //
    PAPPCOMPAT_EXE_DATA AppCompatInfo;

    //
    // CSD version string of the operating system.
    //
    UNICODE_STRING CSDVersion;

    //
    // Pointer to the process activation context.
    //
    PACTIVATION_CONTEXT_DATA ActivationContextData;

    //
    // Pointer to the process assembly storage map.
    //
    PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;

    //
    // Pointer to the system default activation context.
    //
    PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;

    //
    // Pointer to the system assembly storage map.
    //
    PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;

    //
    // Minimum stack commit size.
    //
    SIZE_T MinimumStackCommit;

    //
    // since 19H1 (previously FlsCallback to FlsHighIndex)
    //
    PVOID SparePointers[2];

    //
    // Pointer to the patch loader data.
    //
    PVOID PatchLoaderData;

    //
    // Pointer to the CHPE V2 process information. CHPEV2_PROCESS_INFO
    //
    PVOID ChpeV2ProcessInfo;

    //
    // Packaged process feature state.
    //
    ULONG AppModelFeatureState;

    //
    // SpareUlongs
    //
    ULONG SpareUlongs[2];

    //
    // Active code page.
    //
    USHORT ActiveCodePage;

    //
    // OEM code page.
    //
    USHORT OemCodePage;

    //
    // Code page case mapping.
    //
    USHORT UseCaseMapping;

    //
    // Unused NLS field.
    //
    USHORT UnusedNlsField;

    //
    // Pointer to the application WER registration data.
    //
    PWER_PEB_HEADER_BLOCK WerRegistrationData;

    //
    // Pointer to the application WER assert pointer.
    //
    PVOID WerShipAssertPtr;

    //
    // Pointer to the EC bitmap on ARM64. (Windows 11 and above)
    //
    union
    {
        PVOID pContextData; // Pointer to the switchback compatibility engine (Windows 7 and below)
        PVOID EcCodeBitMap; // Pointer to the EC bitmap on ARM64 (Windows 11 and above) // since WIN11
    };

    //
    // Reserved.
    //
    PVOID ImageHeaderHash;

    //
    // ETW tracing flags.
    //
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;       // ETW heap tracing enabled.
            ULONG CritSecTracingEnabled : 1;    // ETW lock tracing enabled.
            ULONG LibLoaderTracingEnabled : 1;  // ETW loader tracing enabled.
            ULONG SpareTracingBits : 29;
        };
    };

    //
    // Reserved for CSRSS.
    //
    ULONGLONG CsrServerReadOnlySharedMemoryBase;

    //
    // Pointer to the thread pool worker list lock.
    //
    PRTL_CRITICAL_SECTION TppWorkerpListLock;

    //
    // Pointer to the thread pool worker list.
    //
    LIST_ENTRY TppWorkerpList;

    //
    // Wait on address hash table. (RtlWaitOnAddress)
    //
    PVOID WaitOnAddressHashTable[128];

    //
    // Pointer to the telemetry coverage header. // since RS3
    //
    PTELEMETRY_COVERAGE_HEADER TelemetryCoverageHeader;

    //
    // Cloud file flags. (ProjFs and Cloud Files) // since RS4
    //
    ULONG CloudFileFlags;

    //
    // Cloud file diagnostic flags.
    //
    ULONG CloudFileDiagFlags;

    //
    // Placeholder compatibility mode. (ProjFs and Cloud Files)
    //
    CHAR PlaceholderCompatibilityMode;

    //
    // Reserved for placeholder compatibility mode.
    //
    CHAR PlaceholderCompatibilityModeReserved[7];

    //
    // Pointer to leap second data. // since RS5
    //
    PLEAP_SECOND_DATA LeapSecondData;

    //
    // Leap second flags.
    //
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1; // Leap seconds enabled.
            ULONG Reserved : 31;
        };
    };

    //
    // Global flags for the process.
    //
    ULONG NtGlobalFlag2;

    //
    // Extended feature disable mask (AVX). // since WIN11
    //
    ULONGLONG ExtendedFeatureDisableMask;
} PEB, *PPEB;

#define PAGE_NOACCESS 0x01              // Disables all access to the committed region of pages. An attempt to read from, write to, or execute the committed region results in an access violation.
#define PAGE_READONLY 0x02              // Enables read-only access to the committed region of pages. An attempt to write or execute the committed region results in an access violation.
#define PAGE_READWRITE 0x04             // Enables read-only or read/write access to the committed region of pages.
#define PAGE_WRITECOPY 0x08             // Enables read-only or copy-on-write access to a mapped view of a file mapping object.
#define PAGE_EXECUTE 0x10               // Enables execute access to the committed region of pages. An attempt to write to the committed region results in an access violation.
#define PAGE_EXECUTE_READ 0x20          // Enables execute or read-only access to the committed region of pages. An attempt to write to the committed region results in an access violation.
#define PAGE_EXECUTE_READWRITE 0x40     // Enables execute, read-only, or read/write access to the committed region of pages.
#define PAGE_EXECUTE_WRITECOPY 0x80     // Enables execute, read-only, or copy-on-write access to a mapped view of a file mapping object.
#define PAGE_GUARD 0x100                // Pages in the region become guard pages. Any attempt to access a guard page causes the system to raise a STATUS_GUARD_PAGE_VIOLATION exception.
#define PAGE_NOCACHE 0x200              // Sets all pages to be non-cachable. Applications should not use this attribute. Using interlocked functions with memory that is mapped with SEC_NOCACHE can result in an EXCEPTION_ILLEGAL_INSTRUCTION exception.
#define PAGE_WRITECOMBINE 0x400         // Sets all pages to be write-combined. Applications should not use this attribute. Using interlocked functions with memory that is mapped with SEC_NOCACHE can result in an EXCEPTION_ILLEGAL_INSTRUCTION exception.

#define PAGE_REVERT_TO_FILE_MAP     0x80000000 // Pages in the region can revert modified copy-on-write pages to the original unmodified page when using the mapped view of a file mapping object.
#define PAGE_ENCLAVE_THREAD_CONTROL 0x80000000 // Pages in the region contain a thread control structure (TCS) from the Intel Software Guard Extensions programming model.
#define PAGE_TARGETS_NO_UPDATE      0x40000000 // Pages in the region will not update the CFG bitmap when the protection changes. The default behavior for VirtualProtect is to mark all locations as valid call targets for CFG.
#define PAGE_TARGETS_INVALID        0x40000000 // Pages in the region are excluded from the CFG bitmap as valid targets. Any indirect call to locations in those pages will terminate the process using the __fastfail intrinsic.
#define PAGE_ENCLAVE_UNVALIDATED    0x20000000 // Pages in the region are excluded from measurement with the EEXTEND instruction of the Intel Software Guard Extensions programming model.
#define PAGE_ENCLAVE_NO_CHANGE      0x20000000
#define PAGE_ENCLAVE_MASK           0x10000000
#define PAGE_ENCLAVE_DECOMMIT       (PAGE_ENCLAVE_MASK | 0)
#define PAGE_ENCLAVE_SS_FIRST       (PAGE_ENCLAVE_MASK | 1)
#define PAGE_ENCLAVE_SS_REST        (PAGE_ENCLAVE_MASK | 2)

#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_DECOMMIT 0x00004000
#define MEM_RELEASE 0x00008000
#define MEM_FREE 0x00010000
#define MEM_PRIVATE 0x00020000
#define MEM_MAPPED 0x00040000
#define MEM_RESET 0x00080000
#define MEM_TOP_DOWN 0x00100000
#define MEM_WRITE_WATCH 0x00200000
#define MEM_PHYSICAL 0x00400000
#define MEM_ROTATE 0x00800000
#define MEM_DIFFERENT_IMAGE_BASE_OK 0x00800000
#define MEM_RESET_UNDO 0x01000000
#define MEM_LARGE_PAGES 0x20000000
#define MEM_DOS_LIM 0x40000000
#define MEM_4MB_PAGES 0x80000000
#define MEM_64K_PAGES (MEM_LARGE_PAGES | MEM_PHYSICAL)

#define TOKEN_ASSIGN_PRIMARY    (0x0001)
#define TOKEN_DUPLICATE         (0x0002)
#define TOKEN_IMPERSONATE       (0x0004)
#define TOKEN_QUERY             (0x0008)
#define TOKEN_QUERY_SOURCE      (0x0010)
#define TOKEN_ADJUST_PRIVILEGES (0x0020)
#define TOKEN_ADJUST_GROUPS     (0x0040)
#define TOKEN_ADJUST_DEFAULT    (0x0080)
#define TOKEN_ADJUST_SESSIONID  (0x0100)

typedef struct _SID_IDENTIFIER_AUTHORITY {
  UCHAR Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID {
  UCHAR                    Revision;
  UCHAR                    SubAuthorityCount;
  SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
  ULONG                    SubAuthority[1];
} SID, *PISID;

typedef struct _SID_AND_ATTRIBUTES {
  PISID Sid;
  ULONG Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

/**
 * The TOKEN_MANDATORY_POLICY structure specifies the mandatory integrity policy for a token.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_policy
 */
typedef struct _TOKEN_MANDATORY_LABEL
{
    SID_AND_ATTRIBUTES Label;
} TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;

/**
 * The TOKEN_INFORMATION_CLASS enumeration contains values that specify the type of information
 * being assigned to or retrieved from an access token.
 *
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
 */
typedef enum _TOKEN_INFORMATION_CLASS
{
    TokenUser = 1,                        // q: TOKEN_USER, SE_TOKEN_USER
    TokenGroups,                          // q: TOKEN_GROUPS
    TokenPrivileges,                      // q: TOKEN_PRIVILEGES
    TokenOwner,                           // qs: TOKEN_OWNER
    TokenPrimaryGroup,                    // qs: TOKEN_PRIMARY_GROUP
    TokenDefaultDacl,                     // qs: TOKEN_DEFAULT_DACL
    TokenSource,                          // q: TOKEN_SOURCE
    TokenType,                            // q: TOKEN_TYPE
    TokenImpersonationLevel,              // q: SECURITY_IMPERSONATION_LEVEL
    TokenStatistics,                      // q: TOKEN_STATISTICS // 10
    TokenRestrictedSids,                  // q: TOKEN_GROUPS
    TokenSessionId,                       // qs: ULONG (requires SeTcbPrivilege)
    TokenGroupsAndPrivileges,             // q: TOKEN_GROUPS_AND_PRIVILEGES
    TokenSessionReference,                // s: ULONG (requires SeTcbPrivilege)
    TokenSandBoxInert,                    // q: ULONG
    TokenAuditPolicy,                     // qs: TOKEN_AUDIT_POLICY (requires SeSecurityPrivilege/SeTcbPrivilege)
    TokenOrigin,                          // qs: TOKEN_ORIGIN (requires SeTcbPrivilege)
    TokenElevationType,                   // q: TOKEN_ELEVATION_TYPE
    TokenLinkedToken,                     // qs: TOKEN_LINKED_TOKEN (requires SeCreateTokenPrivilege)
    TokenElevation,                       // q: TOKEN_ELEVATION // 20
    TokenHasRestrictions,                 // q: ULONG
    TokenAccessInformation,               // q: TOKEN_ACCESS_INFORMATION
    TokenVirtualizationAllowed,           // qs: ULONG (requires SeCreateTokenPrivilege)
    TokenVirtualizationEnabled,           // qs: ULONG
    TokenIntegrityLevel,                  // qs: TOKEN_MANDATORY_LABEL
    TokenUIAccess,                        // qs: ULONG (requires SeTcbPrivilege)
    TokenMandatoryPolicy,                 // qs: TOKEN_MANDATORY_POLICY (requires SeTcbPrivilege)
    TokenLogonSid,                        // q: TOKEN_GROUPS
    TokenIsAppContainer,                  // q: ULONG // since WIN8
    TokenCapabilities,                    // q: TOKEN_GROUPS // 30
    TokenAppContainerSid,                 // q: TOKEN_APPCONTAINER_INFORMATION
    TokenAppContainerNumber,              // q: ULONG
    TokenUserClaimAttributes,             // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenDeviceClaimAttributes,           // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenRestrictedUserClaimAttributes,   // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenRestrictedDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    TokenDeviceGroups,                    // q: TOKEN_GROUPS
    TokenRestrictedDeviceGroups,          // q: TOKEN_GROUPS
    TokenSecurityAttributes,              // qs: TOKEN_SECURITY_ATTRIBUTES_[AND_OPERATION_]INFORMATION (requires SeTcbPrivilege)
    TokenIsRestricted,                    // q: ULONG // 40
    TokenProcessTrustLevel,               // q: TOKEN_PROCESS_TRUST_LEVEL // since WINBLUE
    TokenPrivateNameSpace,                // qs: ULONG (requires SeTcbPrivilege) // since THRESHOLD
    TokenSingletonAttributes,             // q: TOKEN_SECURITY_ATTRIBUTES_INFORMATION // since REDSTONE
    TokenBnoIsolation,                    // q: TOKEN_BNO_ISOLATION_INFORMATION // since REDSTONE2
    TokenChildProcessFlags,               // s: ULONG  (requires SeTcbPrivilege) // since REDSTONE3
    TokenIsLessPrivilegedAppContainer,    // q: ULONG // since REDSTONE5
    TokenIsSandboxed,                     // q: ULONG // since 19H1
    TokenIsAppSilo,                       // q: ULONG // since WIN11 22H2 // previously TokenOriginatingProcessTrustLevel // q: TOKEN_PROCESS_TRUST_LEVEL
    TokenLoggingInformation,              // q: TOKEN_LOGGING_INFORMATION // since 24H2
    TokenLearningMode,                    // q: // since 25H2
    MaxTokenInfoClass
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

#define STATUS_BUFFER_TOO_SMALL			0xC0000023L
#define STATUS_INFO_LENGTH_MISMATCH     0xC0000004L