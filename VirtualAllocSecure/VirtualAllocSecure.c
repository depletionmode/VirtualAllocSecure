//
// @depletionmode 2019
//

#include <Windows.h>

#include "SecureMemoryEncryptionDriver.h"

__declspec(dllexport)
PVOID
VirtualAllocSecure (
    _In_ SIZE_T Size,
    _In_ ULONG Protect
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

    SME_SET_CBIT_REQUEST request = { 0 };

    //
    // Check if system is Secure Memory Encryption capable.
    //

    if (!_testSystemSmeCapable()) {
        SetLastError(ERROR_NOT_SUPPORTED);

        goto end;
    }
    
    //
    // Request virtual memory allocation. Memory is reserved + committed.
    //

    address = VirtualAlloc(NULL, 
                           Size, 
                           MEM_COMMIT | MEM_RESERVE,
                           Protect);
    if (NULL == address) {
        goto end;
    }

    releaseNeeded = TRUE;
    printf("address=0x%p\n", address);
    //
    // Write a magic value to the page prior to enabling SME on the page 
    // to enable testing of functioning encryption.
    //

    *(ULONG*)address = 0xf00d3333;
    
    //
    // Call driver to set C-bit on each page in the allocated region.
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

    request.Address = address;
    request.Size = Size;

    result = DeviceIoControl(hDevice,
                             SME_IOCTL_SET_CBIT,
                             &request,
                             sizeof(request),
                             NULL,
                             0,
                             NULL,
                             NULL);
    if (!result) {
        goto end;
    }

    FlushInstructionCache(GetCurrentProcess(), address, Size);

    //
    // Test magic value. If encryption is now enabled, it should not match the 
    // value previously written (as this value is now 'decrypted').
    //
    
    if (*(ULONG*)address == 0xf00d3333) {
        SetLastError(ERROR_ENCRYPTION_FAILED);

        goto end;
    }

    //ZeroMemory(address, Size);

    releaseNeeded = FALSE;

end:
    if (INVALID_HANDLE_VALUE != hDevice) {
        CloseHandle(hDevice);
    }

    if (releaseNeeded) {
        //VirtualFree(address, 0, MEM_RELEASE);
        address = NULL;
    }

    return address;
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
