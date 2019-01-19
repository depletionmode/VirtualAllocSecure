//
// @depletionmode 2019
//

#pragma once

#define DEVICE_NAME L"\\Device\\VirtualAllocSecure"

#define SME_IOCTL_GET_CAPABILITIES CTL_CODE(FILE_DEVICE_UNKNOWN, 0xa80, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma warning (disable:4201)
typedef struct _SME_GET_CAPABILITIES_RESPONSE {
    union {
        int Flags;

        struct {
            int Supported : 1;
            int PageTableCbitIdx : 1;
            int PhysicalAddressSpaceReduction : 1;
            int MemoryEncryptionModeEnabled : 1;

        };

    };

} SME_GET_CAPABILITIES_RESPONSE, *PSME_GET_CAPABILITIES_RESPONSE;

#define SME_IOCTL_SET_CBIT CTL_CODE(FILE_DEVICE_UNKNOWN, 0xa81, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _SME_SET_CBIT_REQUEST {
    PVOID Address;
    SIZE_T Size;

} SME_SET_CBIT_REQUEST, *PSME_SET_CBIT_REQUEST;

//#define STATUS_SUCCESS 0
