//
// @depletionmode 2019
//

#include <Windows.h>
#include <stdio.h>

typedef PVOID(*VirtualAllocSecure)(SIZE_T, ULONG);

char vanity[] =
"       _      _               _   _   _ _            __                           \n"
"/\\   /(_)_ __| |_ _   _  __ _| | /_\\ | | | ___   ___/ _\\ ___  ___ _   _ _ __ ___  \n"
"\\ \\ / / | '__| __| | | |/ _` | |//_\\\\| | |/ _ \\ / __\\ \\ / _ \\/ __| | | | '__/ _ \\ \n"
" \\ V /| | |  | |_| |_| | (_| | /  _  \\ | | (_) | (___\\ \\  __/ (__| |_| | | |  __/ \n"
"  \\_/ |_|_|   \\__|\\__,_|\\__,_|_\\_/ \\_/_|_|\\___/ \\___\\__/\\___|\\___|\\__,_|_|  \\___| \n"
"AMD Secure Memory Encryption PoC by @depletionmode                                \n\n";

int main(int ac, char *av[])
{
    printf(vanity);

    HMODULE lib = LoadLibraryA("VirtualAllocSecure.dll");
    if (!lib) {
        fprintf(stderr, "[!] Failed to load library\n");
        return -1;
    }

    printf("[+] VirtualAllocSecure library loaded successfully @ 0x%p.\n", lib);

    VirtualAllocSecure pVirtualAllocSecure = (VirtualAllocSecure)GetProcAddress(lib, "VirtualAllocSecure");

#define BUFFER_SIZE 0x100
    printf("[-] Attempting to allocate encrypted memory...\n");
    PCHAR buffer = pVirtualAllocSecure(BUFFER_SIZE, PAGE_READWRITE);
    if (buffer == NULL) {
        printf("[!] ...buffer allocation failed (error=0x%x!)\n", GetLastError());

        while (1);
        return -1;
    }
    printf("[+] ...buffer allocated @0x%p!\n", buffer);

    printf("[-] Writing \"ArthurMorgan\" to memory region...\n");
    strcpy_s(buffer, BUFFER_SIZE, "ArthurMorgan");
    printf("[+] ...read \"%s\" from memory region!\n", buffer);

    VirtualFree(buffer, 0, MEM_RELEASE);
    printf("[-] Memory released.\n");

    return 0;
}
