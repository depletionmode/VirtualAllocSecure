//
// @depletionmode 2019
//

#include <Windows.h>

#include "SecureMemoryEncryptionDriver.h"

__declspec(dllexport)
PVOID
VirtualAllocSecure (
    _In_ SIZE_T Size,
    _In_ ULONG Protect /* ignored for now */
    );

__declspec(dllexport)
VOID
VirtualFreeSecure(
    _In_ PVOID Address
);

BOOLEAN _testSystemSmeCapable();

#define DEVICE_NAME "\\\\.\\Sme"

#include <stdio.h>
PVOID
VirtualAllocSecure (
    _In_ SIZE_T Size,
    _In_ ULONG Protect
    )
{
    PVOID address = NULL;
    BOOLEAN result;
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    BOOLEAN releaseNeeded = FALSE;

    UNREFERENCED_PARAMETER(Protect); // TODO

    SME_ALLOCATE_REQUEST request = { 0 };
    SME_ALLOCATE_RESPONSE response = { 0 };

    //
    // Check if system is Secure Memory Encryption capable.
    //

    if (!_testSystemSmeCapable()) {
        SetLastError(ERROR_NOT_SUPPORTED);

        goto end;
    }
    
    //
    // Call driver to allocate secure memory region.
    //

    hDevice = CreateFile((LPCSTR)DEVICE_NAME,
                         GENERIC_WRITE, 
                         0, 
                         NULL, 
                         OPEN_EXISTING, 
                         0, 
                         NULL);
    if (INVALID_HANDLE_VALUE == hDevice) {
        goto end;
    }

    request.Size = Size;

    result = DeviceIoControl(hDevice,
                             SME_IOCTL_ALLOCATE,
                             &request,
                             sizeof(request),
                             &response,
                             sizeof(response),
                             NULL,
                             NULL);
    if (!result) {
        goto end;
    } else if (NULL == response.Address) {
        SetLastError(ERROR_MEMORY_HARDWARE);

        goto end;
    }
    releaseNeeded = TRUE;

    FlushInstructionCache(GetCurrentProcess(), response.Address, Size);

    //
    // Test magic value. If encryption is now enabled, it should not match the 
    // value previously written (as this value is now 'decrypted').
    //
    
    if (*(ULONG*)response.Address == 0xf00d3333) {
        SetLastError(ERROR_ENCRYPTION_FAILED);

        goto end;
    }

    //ZeroMemory(address, Size);

    releaseNeeded = FALSE;

    address = response.Address;

end:
    if (releaseNeeded) {
        //VirtualFreeSecure(response.Address);
    }

    if (INVALID_HANDLE_VALUE != hDevice) {
        CloseHandle(hDevice);
    }

    return address;
}

VOID
VirtualFreeSecure(
    _In_ PVOID Address
    )
{
    BOOLEAN result;
    HANDLE hDevice = INVALID_HANDLE_VALUE;

    SME_FREE_REQUEST request = { 0 };
    
    //
    // Call driver to free secure memory region.
    //

    hDevice = CreateFile((LPCSTR)DEVICE_NAME,
                         GENERIC_WRITE, 
                         0, 
                         NULL, 
                         OPEN_EXISTING, 
                         0, 
                         NULL);
    if (INVALID_HANDLE_VALUE == hDevice) {
        goto end;
    }

    request.Address = Address;

    result = DeviceIoControl(hDevice,
                             SME_IOCTL_ALLOCATE,
                             &request,
                             sizeof(request),
                             NULL,
                             0,
                             NULL,
                             NULL);
    if (!result) {
        goto end;
    }

end:
    if (INVALID_HANDLE_VALUE != hDevice) {
        CloseHandle(hDevice);
    }
}

BOOLEAN _testSystemSmeCapable()
{
    HANDLE hDevice;
    BOOLEAN result;
    static SME_GET_CAPABILITIES_RESPONSE response = { 0 };

    if (0 == response.Supported) {
        //
        // Capabilites might not have previously been retrieved, populate 
        // from driver.
        //

        hDevice = CreateFileA(DEVICE_NAME,
                             GENERIC_READ | GENERIC_WRITE, 
                             0, 
                             NULL, 
                             CREATE_ALWAYS, 
                             FILE_ATTRIBUTE_NORMAL, 
                             NULL);
        if (INVALID_HANDLE_VALUE == hDevice) {
            return FALSE;
        }

        result = DeviceIoControl(hDevice,
                                 SME_IOCTL_GET_CAPABILITIES,
                                 NULL,
                                 0,
                                 &response,
                                 sizeof(response),
                                 NULL,
                                 NULL);
        if (!result) {
            response.Supported = 0; // make sure false returned when control exits
        }

        CloseHandle(hDevice);
    }

    return (1 == response.Supported);
}
