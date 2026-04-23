#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "Heap.h"
#include "../../allocation_tracker.h"

extern bool SCAN_STARTED;

static bool shouldTrackHeapAllocations(void) {
    return SCAN_STARTED;
}

#define HEAP_ZERO_MEMORY 8
int heap_free_count = 0;
int heap_alloc_count = 0;
int heap_realloc_count = 0;

STATIC HANDLE WINAPI GetProcessHeap(void) {
    DebugLog("");
    return (HANDLE) 'HEAP';
}

STATIC HANDLE WINAPI HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
    DebugLog("%#x, %u, %u", flOptions, dwInitialSize, dwMaximumSize);
    return (HANDLE) 'HEAP';
}

PVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    PVOID Buffer;

    if (dwFlags & HEAP_ZERO_MEMORY) {
        Buffer = calloc(dwBytes, 1);
    } else {
        Buffer = malloc(dwBytes);
    }

    DebugLog("%p, %#x, %u Allocated => %p, %d", hHeap, dwFlags, dwBytes, Buffer, heap_alloc_count);
    //LogMessage("%p, %#x, %u Allocated => %p, %d", hHeap, dwFlags, dwBytes, Buffer, heap_alloc_count);
    heap_alloc_count += 1;
    if (shouldTrackHeapAllocations()) {
        allocation_tracker_record_alloc(Buffer, dwBytes, ALLOCATION_KIND_HEAP);
    }
    
    return Buffer;
}

BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, PVOID lpMem) {
    DebugLog("%p, %#x, %p, %d", hHeap, dwFlags, lpMem, heap_free_count);
    //LogMessage("%p, %#x, %p, %d", hHeap, dwFlags, lpMem, heap_free_count);
    heap_free_count += 1;
    allocation_tracker_record_free(lpMem);
    free(lpMem);

    return TRUE;
}

STATIC BOOL WINAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress) {
    //DebugLog("%p, %#x, %p", HeapHandle, Flags, BaseAddress);

    allocation_tracker_record_free(BaseAddress);
    free(BaseAddress);

    return TRUE;
}

STATIC SIZE_T WINAPI HeapSize(HANDLE hHeap, DWORD dwFlags, PVOID lpMem) {
    DebugLog("");
    return malloc_usable_size(lpMem);
}

STATIC PVOID WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, PVOID lpMem, SIZE_T dwBytes) {
    void *buf = realloc(lpMem, dwBytes);
    DebugLog("%p reallocated at => %p %#x Flags: %#x, %d", lpMem, buf, dwBytes, dwFlags, heap_realloc_count);
    heap_realloc_count += 1;
    if (shouldTrackHeapAllocations() || lpMem != NULL) {
        allocation_tracker_record_realloc(lpMem, buf, dwBytes, ALLOCATION_KIND_HEAP);
    }
    return buf;
}

STATIC PVOID WINAPI LocalAlloc(UINT uFlags, SIZE_T uBytes) {
    PVOID Buffer = malloc(uBytes);
    assert(uFlags == 0);

    DebugLog("%#x, %u => %p", uFlags, uBytes, Buffer);
    if (shouldTrackHeapAllocations()) {
        allocation_tracker_record_alloc(Buffer, uBytes, ALLOCATION_KIND_HEAP);
    }

    return Buffer;
}

STATIC PVOID WINAPI LocalFree(PVOID hMem) {
    DebugLog("%p", hMem);
    allocation_tracker_record_free(hMem);
    free(hMem);
    return NULL;
}

STATIC PVOID WINAPI RtlCreateHeap(ULONG Flags,
                                  PVOID HeapBase,
                                  SIZE_T ReserveSize,
                                  SIZE_T CommitSize,
                                  PVOID Lock,
                                  PVOID Parameters) {
    DebugLog("%#x, %p, %#x, %#x, %p, %p",
            Flags,
            HeapBase,
            ReserveSize,
            CommitSize,
            Lock,
            Parameters);

    return (HANDLE) 'HEAP';
}

STATIC PVOID WINAPI RtlAllocateHeap(PVOID HeapHandle,
                                    ULONG Flags,
                                    SIZE_T Size) {

    void *BlockPtr = malloc(Size);
    //DebugLog("%p, %#x, %u, (Allocated: %p)", HeapHandle, Flags, Size, BlockPtr);
    if (shouldTrackHeapAllocations()) {
        allocation_tracker_record_alloc(BlockPtr, Size, ALLOCATION_KIND_HEAP);
    }
    return BlockPtr;
}

STATIC NTSTATUS WINAPI RtlSetHeapInformation(PVOID Heap,
                                             HEAP_INFORMATION_CLASS HeapInformationClass,
                                             PVOID HeapInformation,
                                             SIZE_T HeapInformationLength) {
    DebugLog("%p, %d", Heap, HeapInformationLength);
    return 0;
}

STATIC PVOID WINAPI GlobalAlloc(UINT uFlags, SIZE_T uBytes) {
    PVOID Buffer = malloc(uBytes);
    assert(uFlags == 0);

    DebugLog("%#x, %u => %p", uFlags, uBytes, Buffer);
    if (shouldTrackHeapAllocations()) {
        allocation_tracker_record_alloc(Buffer, uBytes, ALLOCATION_KIND_HEAP);
    }

    return Buffer;
}

STATIC PVOID WINAPI GlobalFree(PVOID hMem) {
    DebugLog("%p", hMem);
    allocation_tracker_record_free(hMem);
    free(hMem);
    return NULL;
}

STATIC PVOID WINAPI RtlReAllocateHeap(HANDLE hHeap, ULONG uFlags, PVOID ptr, SIZE_T size)
{
    DebugLog("%p, %#x, %p, %#x", hHeap, uFlags, ptr, size);
    PVOID NewHeapBlock = realloc(ptr, size);
    if (shouldTrackHeapAllocations() || ptr != NULL) {
        allocation_tracker_record_realloc(ptr, NewHeapBlock, size, ALLOCATION_KIND_HEAP);
    }
    return NewHeapBlock;
}

STATIC BOOL WINAPI HeapSetInformation(HANDLE hHeap, int HeapInformationClass, PVOID HeapInformation, size_t HeapInformationLength)
{
    DebugLog("%p, %#x, %p, %#x", hHeap, HeapInformationClass, HeapInformation, HeapInformationLength);
    return true;
}


DECLARE_CRT_EXPORT("HeapCreate", HeapCreate);

DECLARE_CRT_EXPORT("GetProcessHeap", GetProcessHeap);

DECLARE_CRT_EXPORT("HeapAlloc", HeapAlloc);

DECLARE_CRT_EXPORT("HeapFree", HeapFree);

DECLARE_CRT_EXPORT("RtlFreeHeap", RtlFreeHeap);

DECLARE_CRT_EXPORT("RtlSetHeapInformation", RtlSetHeapInformation);

DECLARE_CRT_EXPORT("HeapSize", HeapSize);

DECLARE_CRT_EXPORT("HeapReAlloc", HeapReAlloc);

DECLARE_CRT_EXPORT("LocalAlloc", LocalAlloc);

DECLARE_CRT_EXPORT("LocalFree", LocalFree);

DECLARE_CRT_EXPORT("RtlCreateHeap", RtlCreateHeap);

DECLARE_CRT_EXPORT("RtlAllocateHeap", RtlAllocateHeap);

DECLARE_CRT_EXPORT("GlobalAlloc", GlobalAlloc);

DECLARE_CRT_EXPORT("GlobalFree", GlobalFree);

DECLARE_CRT_EXPORT("RtlReAllocateHeap", RtlReAllocateHeap);

DECLARE_CRT_EXPORT("HeapSetInformation", HeapSetInformation);
