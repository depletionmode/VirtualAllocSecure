//
// @depletionmode 2019
//

#include <Wdm.h>

#include "SecureMemoryEncryptionDriver.h"

static const UNICODE_STRING SmepDeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
static const UNICODE_STRING SmepWin32DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);

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

NTSTATUS
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
SmepSetCbit (
    _In_ PSME_SET_CBIT_REQUEST SetCbitRequest
 );

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SmeDriverUnload)
#pragma alloc_text(PAGE, SmeDispatchCreate)
#pragma alloc_text(PAGE, SmeDispatchFastIoDeviceControl)
#pragma alloc_text(PAGE, SmepGetCapabilities)
#pragma alloc_text(PAGE, SmepSetCbit)

typedef struct _SME_DATA {
    PDEVICE_OBJECT DeviceObject;
    FAST_IO_DISPATCH FastIoDispatchTbl;

    SME_GET_CAPABILITIES_RESPONSE Capabilities;

} SME_DATA, *PSME_DATA;

static SME_DATA SmeContext = { 0 };

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

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

NTSTATUS
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
    case SME_IOCTL_SET_CBIT:
        if (InputBufferLength < sizeof(SME_SET_CBIT_REQUEST)) {
            status = STATUS_INVALID_PARAMETER;
            goto end;
        }

        __try {
            ProbeForRead(InputBuffer, 
                         InputBufferLength, 
                         1);

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();

            goto end;
        }

        status = SmepSetCbit(InputBuffer);

        break;
    default:
        status = STATUS_INVALID_PARAMETER;
    }

end:
    IoStatus->Information = responseLength;
    IoStatus->Status = status;

    return status;
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
SmepSetCbit (
    _In_ PSME_SET_CBIT_REQUEST SetCbitRequest
    )
{
    NTSTATUS status;
    ULONG_PTR end;
    ULONG_PTR address;
    ULONG pml4Idx, pdptIdx, pdeIdx, pteIdx;
    ULONG_PTR pml4, pdpt, pd, pt;
    ULONG_PTR pml4e, pdpe, pde;
    PULONG_PTR pte;
    SME_GET_CAPABILITIES_RESPONSE capabilities = { 0 };

    //
    // This function is called during a fast io dispatch so we should 
    // already be running in the context of the caller process.
    //

    PAGED_CODE();

    //
    // Ensure SmeContext.Capabilities is populated.
    //

    status = SmepGetCapabilities(&capabilities);
    if (!NT_SUCCESS(status)) {
        goto end;
    }

    //todo: test address page aligned

    //
    // Set C-bit on each page in the allocated region.
    //

    address = (ULONG_PTR)SetCbitRequest->Address;
    end = address + SetCbitRequest->Size - 1;

    do {
        //
        // Access to ensure physical memory is allocated to back the page.
        //

#pragma warning (suppress:4189)
        volatile ULONG whocares = *(ULONG*)address;

        //
        // Locate the PTE.
        //

        pml4Idx = (address >> 39i64) & 0x1ff;
        pdptIdx = (address >> 30i64) & 0x1ff;
        pdeIdx = (address >> 21i64) & 0x1ff;
        pteIdx = (address >> 12i64) & 0x1ff;

#define ENTRY_SIZE 8
#define ENTRY_ADDRESS(b, i) (b + (i * ENTRY_SIZE))
#define ENTRY(b,i) ((ULONG_PTR*)ENTRY_ADDRESS(b,i))
#define READ_ENTRY(b,i) (*ENTRY(b,i))

        pml4 = __readcr3() & ~0x1f;
        pml4e = READ_ENTRY(pml4, pml4Idx);
        pdpt = pml4e >> 12;
        pdpe = READ_ENTRY(pdpt, pdptIdx);
        pd = pdpe >> 12;
        pde = READ_ENTRY(pd, pdeIdx);
        pt = pde >> 12;
        pte = ENTRY(pt, pteIdx);

        //
        // Set C-bit in PTE to enable encryption on the page.
        //

        *pte |= 1i64 << capabilities.PageTableCbitIdx;

        address += PAGE_SIZE;
    } while (address < end);

end:
    return status;
}
