# VirtualAllocSecure

VirtualAllocSecure is a Proof-of-Concept for Windows that hacks page table entries to enable AMD's Secure Memory Encryption on supported processors.

![Demo gif](demo.gif)

## Background

Secure Memory Encryption is a technology available on certain SKUs of AMDs recent processors that transparently encrypts memory contents before writing to DRAM. This technology could be valuable in protecting secrets from physical attacks on the memory bus and is used in AMD's Secure Encrypted Virtualization technology.

## PoC

The dynamically-linked library (VirtualAllocSecure.dll) exposes *VirtualAllocSecure* and *VirtualFreeSecure* functions which call into a companion driver (SecureMemoryEncryptionDriver) to allocate encrypted memory usable by the caller process.
When *VirtualAllocSecure* is called, the driver will allocate a non-paged region of memory and map this region into the user-mode process. It will then enable memory encryption (for the user-mode mapping only) by manually setting the C-bit in the relevant PTEs.
VirtualFreeSecure* reverses this process.

The reason a kernel pool allocation is used instead of calling VirtualAlloc to allocate user-mode pages before fiddling with the relevant PTE bits is because Mm will periodically enumerate the working set (in order to age + trim). This is unfortunately true even if the backing physical pages are locked in memory. During this process, the page tables are walked which will result in a bugcheck since SME uses what Mm considers to be valid PFN bits and hence will cause an invalid lookup in the PFN database).
Anything that walks the page tables of the pool might similarly result in a bugcheck but at least this doesn't happen as immediately as using an allocation off the process working set.

**NOTE:** This is extremely hacky and ~could~ will lead to system instability!

*Tested on my Ryzen 2700X with virtualization functionality disabled in the BIOS*

## Library usage

    typedef PVOID(*VirtualAllocSecure)(SIZE_T Size, ULONG Protect);
	typedef PVOID(*VirtualFreeSecure)(PVOID Address);

    HMODULE lib = LoadLibraryA("VirtualAllocSecure.dll");
	
    VirtualAllocSecure pVirtualAllocSecure = (VirtualAllocSecure)GetProcAddress(lib, "VirtualAllocSecure");
    VirtualFreeSecure pVirtualFreeSecure = (VirtualFreeSecure)GetProcAddress(lib, "VirtualFreeSecure");

    PCHAR buffer = pVirtualAllocSecure(size, PAGE_READWRITE);
    pVirtualFreeSecure(buffer);
