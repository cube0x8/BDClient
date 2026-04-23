#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>
#include <search.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "codealloc.h"
#include "Memory.h"
#include "instrumentation.h"
#include "../../allocation_tracker.h"

#ifdef __cplusplus
extern "C" {
#endif

extern bool SCAN_STARTED;


// Define a structure to store memory region information
struct MemoryRegion {
    void *ptr;
    size_t size;
};

// Maximum number of memory regions
#define MAX_REGIONS 1024

// Array to store memory region information
struct MemoryRegion regions[MAX_REGIONS];
int regionCount = 0;

void *allocateMemory(size_t dwSize) {
    if (regionCount >= MAX_REGIONS) {
        fprintf(stderr, "Reached maximum number of memory regions.\n");
        return NULL;
    }

    // Allocate memory using mmap
    void *ptr = mmap(NULL, dwSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    DebugLog("Memory %p-%p allocated. Size: {%#x}", ptr, (void *)((char *) ptr + dwSize), dwSize);

    // Store the size and address in the regions array
    regions[regionCount].ptr = ptr;
    regions[regionCount].size = dwSize;
    regionCount++;

    return ptr;
}

bool deallocateMemory(void *ptr) {
    for (int i = 0; i < regionCount; i++) {
        if (regions[i].ptr == ptr) {
            // Deallocate memory using munmap
            munmap(ptr, regions[i].size);
            DebugLog("Memory %p-%p deallocated. Size: {%#x}", ptr, (void *)((char *) ptr + regions[i].size), regions[i].size);

            // just in case
            regions[i].ptr = 0;
            regions[i].size = 0;

            // Remove the region from the array
            for (int j = i; j < regionCount - 1; j++) {
                regions[j] = regions[j + 1];
            }
            regionCount--;
            return true;
        }
    }
    return false;
}

#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_READ 0x20

#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000

#define MEM_RELEASE 0x8000

static bool shouldTrackVirtualAllocations(void) {
    return SCAN_STARTED;
}

static bool shouldReleaseVirtualAllocations(void) {
    return true;
}


PVOID WINAPI VirtualAlloc(PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    PVOID result = NULL;
    DebugLog("%p %#x", lpAddress, dwSize);

    size_t rounded_up_size = ROUND_UP(dwSize, PAGE_SIZE);
    DebugLog("Memory size (rounded): %#x", rounded_up_size);

    if (flAllocationType & ~(MEM_COMMIT | MEM_RESERVE)) {
        DebugLog("AllocationType %#x not implemnted", flAllocationType);
        return NULL;
    }

    // This VirtualAlloc() always returns PAGE_EXECUTE_READWRITE memory.
    if (flProtect & PAGE_READWRITE){
        if (shouldTrackVirtualAllocations()) {
            result = allocateMemory(rounded_up_size);
            allocation_tracker_record_alloc(result, rounded_up_size, ALLOCATION_KIND_VIRTUAL);
        } else {
            result = mmap(NULL, rounded_up_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        }

        DebugLog("Virtual memory zone from %p to %p, size %#x", result, (uintptr_t)result + rounded_up_size, rounded_up_size);
    }
    else if (flProtect & PAGE_EXECUTE_READWRITE) {
        DebugLog("JIT PAGE_EXECUTE_READWRITE Allocation Requested");

        if (shouldTrackVirtualAllocations()) {
            result = allocateMemory(rounded_up_size);
            allocation_tracker_record_alloc(result, rounded_up_size, ALLOCATION_KIND_VIRTUAL);
        } else {
            result = mmap(NULL, rounded_up_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        }

        DebugLog("Virtual memory zone from %p to %p", result, (uintptr_t)result + rounded_up_size);
    }
    else {
        DebugLog("flProtect flags %#x not implemented", flProtect);
        return NULL;
    }

    return result;
}

BOOL WINAPI VirtualProtect(PVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    DebugLog("%p, %#x, %#x", lpAddress, dwSize, flNewProtect);
    
    if (!SCAN_STARTED) {
        // Check if we are protecting a XMD plugin
        if (strncmp(&((char *)(lpAddress))[2], "XMDbegin", 8) == 0) {
            // Discard 0x20 padding
            int i = 10;
            while (((char *)(lpAddress))[i] == '\x20'){
                i++;
                continue;
            }

            const char *plugin_name_start = &((char *)(lpAddress))[i];

            // Calculate plugin name string length
            size_t plugin_name_length = 0;
            while (((char *)(lpAddress))[i] != '\x0D'){
                i++;
                plugin_name_length++;
            }

            char *plugin_name = (char *) calloc(plugin_name_length + 1, sizeof(char));

            strncpy(plugin_name, plugin_name_start, plugin_name_length);

            DebugLog("Plugin name: %s", plugin_name);

            // this checks it's here only to be sure optimization is not in place and the args 
            // are  passed to the callback so we can use them in libafl/pintool
            if (!ModuleInstrumentationCallback2(plugin_name, plugin_name_length, lpAddress, dwSize)){
                return false;
            }

    #ifdef LOG_VIRTUAL_MEM_RANGE
            char memory_range_fmt[255] = "Memory range for %s: %p - %p. Size: %#x\n";
            char memory_range_str[255] = { 0 };
            FILE *fp = fopen( "./virtual_mem_range.txt", "a+" );
            snprintf(memory_range_str, 255, memory_range_fmt, plugin_name, lpAddress, (uintptr_t)lpAddress + dwSize, dwSize);
            fputs(memory_range_str, fp);
            fclose(fp);
    #endif

    #ifdef DUMP_PLUGINS
            char decrypted_plugin_fmt[255] = "./%s/%s";
            char decrypted_plugin_str[255] = { 0 };
            snprintf(decrypted_plugin_str, 255, decrypted_plugin_fmt, "./decrypted_plugins/", plugin_name);
            FILE *decrypted_plugin = fopen(decrypted_plugin_str, "wb");
            fwrite(lpAddress, 1, dwSize, decrypted_plugin);
            fclose(decrypted_plugin);
    #endif
            free(plugin_name);
        }
    }

    /*
    size_t rounded_up_size = ROUND_UP(dwSize, PAGE_SIZE);
    if (!SCAN_STARTED) {
        if ((flNewProtect & PAGE_EXECUTE_READ) != 0) {
            if (mprotect(lpAddress, rounded_up_size, PROT_READ | PROT_EXEC) != 0) {
                DebugLog("Cannot protect memory at %p size %#x", lpAddress, rounded_up_size);
                return false;
            }
            DebugLog("Memory at %p of size %#x protected (RX)", lpAddress, rounded_up_size);
        }
        else if ((flNewProtect & PAGE_EXECUTE_READWRITE) != 0) {
            if (mprotect(lpAddress, rounded_up_size, PROT_READ | PROT_EXEC | PROT_WRITE) != 0) {
                DebugLog("Cannot protect memory at %p size %#x", lpAddress, rounded_up_size);
                return false;
            }
            DebugLog("Memory at %p of size %#x protected (RWX)", lpAddress, rounded_up_size);
        }
    }
    */
    return true;
}

STATIC BOOL WINAPI VirtualUnlock(PVOID lpAddress, SIZE_T dwSize) {
    return TRUE;
}

STATIC BOOL WINAPI VirtualFree(PVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    DebugLog("Memory addr [%p] Size to free [%#x]", lpAddress, dwSize);
    
    if (dwFreeType == MEM_RELEASE && shouldReleaseVirtualAllocations()) {
        allocation_tracker_record_free(lpAddress);
        if (!deallocateMemory(lpAddress) && dwSize != 0U) {
            size_t rounded_up_size = ROUND_UP(dwSize, PAGE_SIZE);
            munmap(lpAddress, rounded_up_size);
            DebugLog("Memory %p-%p deallocated via fallback munmap. Size: {%#x}", lpAddress,
                (void *)((char *)lpAddress + rounded_up_size), rounded_up_size);
        } else {
            DebugLog("Unmapped memory at %p", lpAddress);
        }
    }
    return TRUE;
}

STATIC BOOL WINAPI PrefetchVirtualMemory(HANDLE hProcess,
                                         ULONG_PTR NumberOfEntries,
                                         PVOID VirtualAddresses,
                                         ULONG Flags) {
    DebugLog("");
    return true;
}

#ifdef __cplusplus
}
#endif

DECLARE_CRT_EXPORT("VirtualAlloc", VirtualAlloc);

DECLARE_CRT_EXPORT("VirtualProtect", VirtualProtect);

DECLARE_CRT_EXPORT("VirtualUnlock", VirtualUnlock);

DECLARE_CRT_EXPORT("VirtualFree", VirtualFree);

DECLARE_CRT_EXPORT("PrefetchVirtualMemory", PrefetchVirtualMemory);
