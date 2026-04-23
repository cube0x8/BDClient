#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "strings.h"

extern bool SCAN_STARTED;

#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)

#include "shared_mem_file_handling.h"

#endif

STATIC BOOL WINAPI
DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, PHANDLE lpTargetHandle,
                DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
    DebugLog("%p, %p, %p, %p, %#x, %u, %#x", hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);

    // lol i dunno
    *lpTargetHandle = hSourceProcessHandle;
    return TRUE;
}

STATIC UINT WINAPI SetHandleCount(UINT handleCount) {
    DebugLog("%u", handleCount);
    return handleCount;
}

STATIC BOOL WINAPI GetFileInformationByHandle(FILE *hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation)
{
    int64_t size;
    int64_t curpos;

    union size {
        int64_t size;
        struct {
            int32_t low;
            int32_t high;
        };
    } Size;

    DebugLog("%p, %p", hFile, lpFileInformation);
#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)
    if (SCAN_STARTED) {
        if (hFile == (FILE *)g_mmap_file.data) {
            DebugLog("Shared memory mapped file: Content[%p] Size[%#x] Name[%s] Seek ptr[%d]", 
                g_mmap_file.data, 
                g_mmap_file.size, 
                g_mmap_file.filename, 
                g_mmap_file.position);

            size = g_mmap_file.size;

            goto init_struct;
        }
    }
#endif
    curpos = ftell(hFile);
    fseek(hFile, 0, SEEK_END);
    size = ftell(hFile);
    fseek(hFile, curpos, SEEK_SET);

init_struct:
    Size.size = size;

    lpFileInformation->dwFileAttributes = FILE_ATTRIBUTE_COMPRESSED;
    lpFileInformation->ftCreationTime.dwLowDateTime = 0x3AACDE5A;
    lpFileInformation->ftCreationTime.dwHighDateTime = 0x01D6E798;
    lpFileInformation->ftLastAccessTime.dwLowDateTime = 0xDCBD7A00;
    lpFileInformation->ftLastAccessTime.dwHighDateTime = 0x01D6E8C3;
    lpFileInformation->ftLastWriteTime.dwLowDateTime = 0xDCBD7A00;
    lpFileInformation->ftLastWriteTime.dwHighDateTime = 0x01D6E8C3;
    lpFileInformation->dwVolumeSerialNumber = 0x01D6E8C3;
    lpFileInformation->nFileSizeHigh = Size.high;
    lpFileInformation->nFileSizeLow = Size.low;
    lpFileInformation->nNumberOfLinks = 0;
    lpFileInformation->nFileIndexHigh = 0xA;
    lpFileInformation->nFileIndexLow = 0xB;

    return true;
}

DECLARE_CRT_EXPORT("DuplicateHandle", DuplicateHandle);

DECLARE_CRT_EXPORT("SetHandleCount", SetHandleCount);

DECLARE_CRT_EXPORT("GetFileInformationByHandle", GetFileInformationByHandle);
