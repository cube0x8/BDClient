#include <stdint.h>
#include <stddef.h>
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


STATIC UINT WINAPI GetSystemDirectoryW(PWCHAR Buffer, UINT uSize) {
    DebugLog("%p, %u", Buffer, uSize);

    static wchar_t SystemDirectoryW[19] = L"C:\\DUMMY\\SYSTEM32\\";
    static char SystemDirectoryA[] = "C:\\DUMMY\\SYSTEM32\\";

    // Srsly?!
    if (uSize >= ARRAY_SIZE(SystemDirectoryW)) {
        memcpy(Buffer, SystemDirectoryW, sizeof(SystemDirectoryW));
        return ARRAY_SIZE(SystemDirectoryW) - 1;
    } else {
        return ARRAY_SIZE(SystemDirectoryW);
    }
}

STATIC UINT WINAPI GetSystemDirectoryA(LPSTR Buffer, UINT uSize)
{
    DebugLog("%p, %u", Buffer, uSize);

    static wchar_t SystemDirectoryW[19] = L"C:\\DUMMY\\SYSTEM32\\";
    static char SystemDirectoryA[] = "C:\\DUMMY\\SYSTEM32\\";
    
    // Srsly?!
    if (uSize >= ARRAY_SIZE(SystemDirectoryA)) {
        memcpy(Buffer, SystemDirectoryA, sizeof(SystemDirectoryA));
        return ARRAY_SIZE(SystemDirectoryA) - 1;
    } else {
        return ARRAY_SIZE(SystemDirectoryA);
    }
}

STATIC UINT WINAPI GetSystemWindowsDirectoryW(PWCHAR Buffer, UINT uSize) {
    DebugLog("%p, %u", Buffer, uSize);

    static wchar_t SystemDirectoryW[19] = L"C:\\DUMMY\\SYSTEM32\\";
    static char SystemDirectoryA[] = "C:\\DUMMY\\SYSTEM32\\";

    // Srsly?!
    if (uSize >= ARRAY_SIZE(SystemDirectoryW)) {
        memcpy(Buffer, SystemDirectoryW, sizeof(SystemDirectoryW));
        return ARRAY_SIZE(SystemDirectoryW) - 1;
    } else {
        return ARRAY_SIZE(SystemDirectoryW);
    }
}

STATIC UINT WINAPI GetSystemWow64DirectoryW(PWCHAR lpBuffer, UINT uSize) {
    DebugLog("%p, %u", lpBuffer, uSize);
    return 0;
}


DECLARE_CRT_EXPORT("GetSystemDirectoryW", GetSystemDirectoryW);

DECLARE_CRT_EXPORT("GetSystemDirectoryA", GetSystemDirectoryA);

DECLARE_CRT_EXPORT("GetSystemWindowsDirectoryW", GetSystemWindowsDirectoryW);

DECLARE_CRT_EXPORT("GetSystemWow64DirectoryW", GetSystemWow64DirectoryW);
