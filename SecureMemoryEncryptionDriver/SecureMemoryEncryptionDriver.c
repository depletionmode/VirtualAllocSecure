//
// @depletionmode 2019
//

#include <Wdm.h>

#include "SecureMemoryEncryptionDriver.h"

static const UNICODE_STRING SmepDeviceName = RTL_CONSTANT_STRING(L"\\Device\\Sme");
static const UNICODE_STRING SmepWin32DeviceName = RTL_CONSTANT_STRING(L"\\??\\Sme");

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD SmeDriverUnload;

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

VOID
SmeDriverUnload (
    _In_ PDRIVER_OBJECT DriverObject
    );

NTSTATUS
SmeDispatchCreate (
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

BOOLEAN
SmeDispatchFastIoDeviceControl (
    _In_ struct _FILE_OBJECT *FileObject,
    _In_ BOOLEAN Wait,
    _In_opt_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _In_ ULONG IoControlCode,
    _Out_ PIO_STATUS_BLOCK IoStatus,
    _In_ struct _DEVICE_OBJECT *DeviceObject
    );

NTSTATUS
SmepGetCapabilities (
    _In_ PSME_GET_CAPABILITIES_RESPONSE CapabilitiesResponse
    );

NTSTATUS
SmepAllocate (
    _In_ PSME_ALLOCATE_REQUEST AllocateRequest,
    _In_ PSME_ALLOCATE_RESPONSE AllocateResponse
    );

NTSTATUS
SmepFree (
    _In_ PSME_FREE_REQUEST FreeRequest
    );

FORCEINLINE
VOID
_readPhysicalMemory (
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _Out_writes_bytes_(Size) PVOID BufferNonPaged
    );

FORCEINLINE
PVOID
_getPteVaForUserModeVa (
    _In_ PVOID Address,
    _Inout_ PULONG_PTR NonPagedStorage
    );

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SmeDriverUnload)
#pragma alloc_text(PAGE, SmeDispatchCreate)
#pragma alloc_text(PAGE, SmeDispatchFastIoDeviceControl)
#pragma alloc_text(PAGE, SmepGetCapabilities)
#pragma alloc_text(PAGE, SmepAllocate)
#pragma alloc_text(PAGE, SmepFree)

typedef struct _SME_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    FAST_IO_DISPATCH FastIoDispatchTbl;

    SME_GET_CAPABILITIES_RESPONSE Capabilities;

    LIST_ENTRY MdlList;

    PULONG_PTR NonPagedBuffer;

} SME_CONTEXT, *PSME_CONTEXT;

typedef struct _SME_MDL_NODE {
    PVOID Address;
    PMDL Mdl;

    BOOLEAN Locked;

    LIST_ENTRY ListEntry;

} SME_MDL_NODE, *PSME_MDL_NODE;

static SME_CONTEXT SmeContext = { 0 };

#define POOL_TAG_(n) #@n    // https://docs.microsoft.com/en-us/cpp/preprocessor/charizing-operator-hash-at
#define POOL_TAG(n) POOL_TAG_(n##saV)

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    PAGED_CODE();

    SmeContext.FastIoDispatchTbl.SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);
    SmeContext.FastIoDispatchTbl.FastIoDeviceControl = (PFAST_IO_DEVICE_CONTROL)SmeDispatchFastIoDeviceControl;
    
    DriverObject->DriverUnload = SmeDriverUnload;
    DriverObject->FastIoDispatch = &SmeContext.FastIoDispatchTbl;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = SmeDispatchCreate;
    
    status = IoCreateDevice(DriverObject,
                            0,
                            (PUNICODE_STRING)&SmepDeviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &SmeContext.DeviceObject);
    if (!NT_SUCCESS(status)) {
        goto end;
    }

    status = IoCreateSymbolicLink((PUNICODE_STRING)&SmepWin32DeviceName, 
                                  (PUNICODE_STRING)&SmepDeviceName);
    if (!NT_SUCCESS(status)) {
        goto end;
    }

    //
    // Linked-list for persisting MDLs describing allocated memory regions.
    //

    InitializeListHead(&SmeContext.MdlList);

    //
    // This PoC does not currently support 5-level paging
    // (not sure if supported by any current AMD CPUs).
    // https://en.wikipedia.org/wiki/Intel_5-level_paging
    //

#define CR4_LA57_MASK (1 << 12)
    if (0 != (__readcr4() & CR4_LA57_MASK)) {
        status = STATUS_UNSUCCESSFUL;
        goto end;
    }

    //
    // Allocate NonPagedPoolNx storage for _getPteVaForUserModeVa.
    //

    SmeContext.NonPagedBuffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                                      sizeof(ULONG_PTR),
                                                      POOL_TAG(B));
    if (NULL == SmeContext.NonPagedBuffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    //
    // Populate SmeContext.Capabilities.
    //

    status = SmepGetCapabilities(&SmeContext.Capabilities);
    if (!NT_SUCCESS(status)) {
        goto end;
    }

end:
    return status;
}

VOID
SmeDriverUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();

    if (NULL != SmeContext.NonPagedBuffer) {
        ExFreePoolWithTag(SmeContext.NonPagedBuffer, POOL_TAG(B));
        SmeContext.NonPagedBuffer = NULL;
    }

    if (NULL != SmeContext.DeviceObject) {
        IoDeleteSymbolicLink((PUNICODE_STRING)&SmepWin32DeviceName);
        IoDeleteDevice(SmeContext.DeviceObject);
        SmeContext.DeviceObject = NULL;
    }
}

NTSTATUS
SmeDispatchCreate (
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

BOOLEAN
SmeDispatchFastIoDeviceControl (
    _In_ struct _FILE_OBJECT *FileObject,
    _In_ BOOLEAN Wait,
    _In_opt_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _In_ ULONG IoControlCode,
    _Out_ PIO_STATUS_BLOCK IoStatus,
    _In_ struct _DEVICE_OBJECT *DeviceObject
    )
{
    NTSTATUS status;
    ULONG responseLength = 0;

    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    switch (IoControlCode) {
    case SME_IOCTL_GET_CAPABILITIES:
        if (OutputBufferLength < sizeof(SME_GET_CAPABILITIES_RESPONSE)) {
            status = STATUS_INVALID_PARAMETER;
            goto end;
        }

        __try {
            ProbeForWrite(OutputBuffer, 
                          sizeof(SME_GET_CAPABILITIES_RESPONSE), 
                          1);

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();

            goto end;
        }

        status = SmepGetCapabilities(OutputBuffer);
        if (NT_SUCCESS(status)) {
            responseLength = sizeof(SME_GET_CAPABILITIES_RESPONSE);
        }

        break;
    case SME_IOCTL_ALLOCATE:
        if (InputBufferLength < sizeof(SME_ALLOCATE_REQUEST) ||
            OutputBufferLength < sizeof(SME_ALLOCATE_RESPONSE)) {
            status = STATUS_INVALID_PARAMETER;
            goto end;
        }

        __try {
            ProbeForRead(InputBuffer, 
                         InputBufferLength, 
                         1);

            ProbeForWrite(OutputBuffer,
                          sizeof(SME_ALLOCATE_RESPONSE),
                          1);

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();

            goto end;
        }

        status = SmepAllocate(InputBuffer, OutputBuffer);
        if (NT_SUCCESS(status)) {
            responseLength = sizeof(SME_ALLOCATE_RESPONSE);
        }

        break;
    case SME_IOCTL_FREE:
        if (InputBufferLength < sizeof(SME_FREE_REQUEST)) {
            status = STATUS_INVALID_PARAMETER;
            goto end;
        }

        __try {
            ProbeForRead(InputBuffer,
                InputBufferLength,
                1);

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();

            goto end;
        }

        status = SmepFree(InputBuffer);

        break;
    default:
        status = STATUS_INVALID_PARAMETER;
    }

end:
    IoStatus->Information = responseLength;
    IoStatus->Status = status;

    return status == STATUS_SUCCESS;
}

NTSTATUS
SmepGetCapabilities (
    _In_ PSME_GET_CAPABILITIES_RESPONSE CapabilitiesResponse
    )
{
    NTSTATUS status;
    int cpuInfo[4];

    UNREFERENCED_PARAMETER(CapabilitiesResponse);

    RtlZeroMemory(CapabilitiesResponse, sizeof(SME_GET_CAPABILITIES_RESPONSE));

    PAGED_CODE();

    __try {
        //
        // AMD64 Architecture Programmer's Manual Volume 2: System Programming
        // https://www.amd.com/system/files/TechDocs/24593.pdf
        //

        __cpuid(cpuInfo, 0x8000001f);

        CapabilitiesResponse->Supported = cpuInfo[0] & 1;
        CapabilitiesResponse->PageTableCbitIdx = cpuInfo[1] & 0x3f;
        CapabilitiesResponse->PhysicalAddressSpaceReduction = (cpuInfo[1] >> 6) & 0x3f;

#define SYSCFG_MSR 0xc0010010
        CapabilitiesResponse->MemoryEncryptionModeEnabled = (__readmsr(SYSCFG_MSR) >> 23) & 1;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();

        goto end;
    }

    status = STATUS_SUCCESS;

end:
    return status;
}

NTSTATUS
SmepAllocate (
    _In_ PSME_ALLOCATE_REQUEST AllocateRequest,
    _In_ PSME_ALLOCATE_RESPONSE AllocateResponse
    )
{
    NTSTATUS status;
    ULONG_PTR end;
    ULONG_PTR address;
    ULONG pageCount;
    PVOID pte;
    PVOID kernelModeBuffer = NULL;
    BOOLEAN releaseNeeded = FALSE;
    PSME_MDL_NODE mdlNode = NULL;

    //
    // This function is called during a fast io dispatch so we should 
    // already be running in the context of the caller process.
    //

    PAGED_CODE();

    //
    // Unfortunately as Mm does not (yet) support SME, the C-bit could 
    // fall in the range that describes the physical base address of 
    // the memory region in the PTE. This means that operations (such 
    // as paging) get seriously messed up as Mm is working on a 
    // corrupt physical base address. To (attempt) to mitigate this, 
    // we allocate off the NonPagedPool and then Probe+Lock the physical pages 
    // for good measure.
    // Truthfully, any kernel operation that attempts to look up the Pfn in 
    // the database will likely fail as the index will be off.
    //

    pageCount = (ULONG)((AllocateRequest->Size / PAGE_SIZE) +
                        (AllocateRequest->Size % PAGE_SIZE == 0 ? 0 : 1));

    kernelModeBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, 
                                             pageCount * PAGE_SIZE, POOL_TAG(K));
    if (NULL == kernelModeBuffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    releaseNeeded = TRUE;

    mdlNode = ExAllocatePoolWithTag(PagedPool, 
                                    sizeof(SME_MDL_NODE), POOL_TAG(M));
    if (NULL == mdlNode) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    RtlZeroMemory(mdlNode, sizeof(SME_MDL_NODE));

    mdlNode->Mdl = IoAllocateMdl(kernelModeBuffer,
                                 PAGE_SIZE,
                                 FALSE, 
                                 FALSE, 
                                 NULL);
    if (NULL == mdlNode->Mdl) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    __try {
        MmProbeAndLockPages(mdlNode->Mdl, KernelMode, IoModifyAccess);
        mdlNode->Locked = TRUE;

        //
        // Map buffer into user-space. No need to attach to the process 
        // context as we're running via FastIo and therefore are already 
        // running in the correct context.
        //

        address = (ULONG_PTR)MmMapLockedPagesSpecifyCache(mdlNode->Mdl,
                                                          UserMode,
                                                          MmNonCached,
                                                          NULL,
                                                          FALSE,
                                                          NormalPagePriority);
    }__except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNSUCCESSFUL;
        goto end;
    }

    end = address + (pageCount * PAGE_SIZE) - 1;

    //
    // Write a magic value to the page prior to enabling SME on the page 
    // to enable testing of functioning encryption.
    //

    *(ULONG*)address = ENCRYPTION_TEST_MAGIC;

    AllocateResponse->Address = (PVOID)address;

    do {
        pte = _getPteVaForUserModeVa((PVOID)address, 
                                     SmeContext.NonPagedBuffer);

        //
        // Set C-bit in PTE to enable encryption on the page.
        //

        *(ULONG_PTR*)pte |= 1i64 << SmeContext.Capabilities.PageTableCbitIdx;

        KeMemoryBarrier();
        _mm_clflush((PVOID)address);
        __invlpg(address);

        address += PAGE_SIZE;

    } while (address < end);

    __wbinvd();

    //
    // Test magic value. If encryption is now enabled, it should not match the 
    // value previously written (as this value is now 'decrypted').
    //

    if (*(ULONG*)AllocateResponse->Address == ENCRYPTION_TEST_MAGIC) {
        status = STATUS_UNSUCCESSFUL;

        goto end;
    }

    RtlSecureZeroMemory(AllocateResponse->Address, pageCount * PAGE_SIZE);
    
    //
    // Store MDL for later release.
    //

    mdlNode->Address = AllocateResponse->Address;

    InsertTailList(&SmeContext.MdlList, &mdlNode->ListEntry);

    //
    // Disable cleanups.
    //

    mdlNode = NULL;
    releaseNeeded = FALSE;

    status = STATUS_SUCCESS;

end:
    if (NULL != mdlNode) {
        if (NULL != mdlNode->Mdl) {
            if (NULL != mdlNode->Address) {
                MmUnmapLockedPages(mdlNode->Address, mdlNode->Mdl);
            }
            if (mdlNode->Locked) {
                MmUnlockPages(mdlNode->Mdl);
            }
            IoFreeMdl(mdlNode->Mdl);
        }

        ExFreePoolWithTag(mdlNode, POOL_TAG(M));
        mdlNode = NULL;
    }

    if (releaseNeeded) {
        ExFreePoolWithTag(kernelModeBuffer, POOL_TAG(K));
        kernelModeBuffer = NULL;
        AllocateResponse->Address = NULL;
    }

    return status;
}

NTSTATUS
SmepFree (
    _In_ PSME_FREE_REQUEST FreeRequest
    )
{
    NTSTATUS status;
    ULONG_PTR end;
    ULONG_PTR address;
    PVOID pte;
    PMDL mdl = NULL;
    PVOID kernelModeAddress;
    PLIST_ENTRY entry;
    PSME_MDL_NODE mdlNode;

    //
    // This function is called during a fast io dispatch so we should 
    // already be running in the context of the caller process.
    //

    PAGED_CODE();

    entry = SmeContext.MdlList.Flink;
    while (entry != &SmeContext.MdlList) {
        //
        // Locate MDL describing this address.
        //

        mdlNode = CONTAINING_RECORD(entry, SME_MDL_NODE, ListEntry);

        if (mdlNode->Address == FreeRequest->Address) {
            mdl = mdlNode->Mdl;
            RemoveEntryList(&mdlNode->ListEntry);

            ExFreePoolWithTag(mdlNode, POOL_TAG(M));
            break;
        }

        entry = entry->Flink;
    }

    if (NULL == mdl) {
        //
        // Not previously allocated by us.
        //

        status = STATUS_NOT_FOUND;

        goto end;
    }

    kernelModeAddress = mdl->StartVa;

    address = (ULONG_PTR)FreeRequest->Address;
    end = address + mdl->Size - 1;

    do {
        pte = _getPteVaForUserModeVa((PVOID)address, 
                                     SmeContext.NonPagedBuffer);

        //
        // Clear C-bit in PTE to disable encryption on the page.
        //

        *(ULONG_PTR*)pte &= ~(1i64 << SmeContext.Capabilities.PageTableCbitIdx);

        KeMemoryBarrier();
        _mm_clflush((PVOID)address);
        __invlpg(address);

        address += PAGE_SIZE;

    } while (address < end);

    __wbinvd();

    MmUnmapLockedPages(FreeRequest->Address, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    ExFreePoolWithTag(kernelModeAddress, POOL_TAG(K));

    status = STATUS_SUCCESS;

end:
    return status;
}

#pragma warning (disable:4201)
typedef struct _MM_COPY_ADDRESS {
    union {
        PVOID            VirtualAddress;
        PHYSICAL_ADDRESS PhysicalAddress;
    };
} MM_COPY_ADDRESS, *PMMCOPY_ADDRESS;

NTSTATUS
MmCopyMemory (
    PVOID TargetAddress,
    MM_COPY_ADDRESS SourceAddress,
    SIZE_T NumberOfBytes,
    ULONG Flags,
    PSIZE_T NumberOfBytesTransferred
    );

FORCEINLINE
VOID
_readPhysicalMemory (
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _Out_writes_bytes_(Size) PVOID BufferNonPaged
    )
{
    MM_COPY_ADDRESS address;

    address.PhysicalAddress.QuadPart = (LONGLONG)Address;

    //
    // Ignore failures and trust that the inputs are valid.
    //

    MmCopyMemory(BufferNonPaged, 
                 address, 
                 Size, 
                 1 /*MM_COPY_MEMORY_PHYSICAL*/,
                 &Size);
}

PVOID
MmGetVirtualForPhysical (
    _In_ PHYSICAL_ADDRESS Address
    );

FORCEINLINE
PVOID
_getPteVaForUserModeVa (
    _In_ PVOID Address,
    _Inout_ PULONG_PTR NonPagedStorage
    )
{
    ULONG_PTR address;
    ULONG pml4Idx, pdptIdx, pdtIdx, ptIdx;
    ULONG_PTR pml4, pdpt, pdt, pt;
    ULONG_PTR pte;
    PHYSICAL_ADDRESS pa;

    //
    // Locate the PTE.
    // Note: We read from physical memory, but it'd probably be 
    //       cleaner just to locate the virtual addresses for the 
    //       below and act upon them (which is exactly what we do for 
    //       the PTE itself).
    //       I'm interleaving both methods here for prosperity.
    //

    address = (ULONG_PTR)Address;

    pml4Idx = (address >> 39i64) & 0x1ff;
    pdptIdx = (address >> 30i64) & 0x1ff;
    pdtIdx = (address >> 21i64) & 0x1ff;
    ptIdx = (address >> 12i64) & 0x1ff;

#define ENTRY_SIZE 8
#define ENTRY() (*NonPagedStorage)
#define ENTRY_ADDRESS(b, i) (PVOID)(b + (i * ENTRY_SIZE))
#define READ_ENTRY(b,i) _readPhysicalMemory(ENTRY_ADDRESS(b, i), ENTRY_SIZE, NonPagedStorage)
#define TABLE_BASE_ADDRESS_BITS 0xffffffffff000

    pml4 = __readcr3() & TABLE_BASE_ADDRESS_BITS;

    READ_ENTRY(pml4, pml4Idx);
    pdpt = ENTRY() & TABLE_BASE_ADDRESS_BITS;

    READ_ENTRY(pdpt, pdptIdx);
    pdt = ENTRY() & TABLE_BASE_ADDRESS_BITS;

    READ_ENTRY(pdt, pdtIdx);
    pt = ENTRY() & TABLE_BASE_ADDRESS_BITS;

    pa.QuadPart = pt + (ptIdx * 8);
    pte = (ULONG_PTR)MmGetVirtualForPhysical(pa);

    return (PVOID)pte;
}
