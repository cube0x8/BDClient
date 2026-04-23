#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdlib.h>
#include <wchar.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"
#include "Files.h"

static const wchar_t kTempPath[12] = L".\\FAKETEMP\\";
static const wchar_t kFakePath[19] = L"C:\\dummy\\dummy.exe";
static const char kTempPathA[12] = ".\\FAKETEMP\\";
static const char kFakeBasePathA[4] = "C:\\";

DWORD WINAPI GetTempPathW(DWORD nBufferLength, PVOID lpBuffer) {
    DebugLog("%u, %p", nBufferLength, lpBuffer);

    memcpy(lpBuffer, kTempPath, sizeof(kTempPath));

    return sizeof(kTempPath) - 2;
}

STATIC DWORD WINAPI GetTempPathA(DWORD nBufferLength, PVOID lpBuffer)
{
    DebugLog("%u, %p", nBufferLength, lpBuffer);

    memcpy(lpBuffer, kTempPathA, strlen(kTempPathA));
    ((char *) lpBuffer)[strlen(kTempPathA)] = '\0';

    return strlen(kTempPathA);
}

STATIC DWORD WINAPI GetLogicalDrives(void)
{
    DebugLog("");

    return 1 << 2;
}

#define DRIVE_FIXED 3

STATIC UINT WINAPI GetDriveTypeW(PWCHAR lpRootPathName) {
    char *path = CreateAnsiFromWide(lpRootPathName);
    DebugLog("%p [%s]", lpRootPathName, path);
    free(path);
    return DRIVE_FIXED;
}

STATIC DWORD WINAPI GetLongPathNameA(LPCSTR lpszShortPath,
                              LPSTR lpszLongPath,
                              DWORD cchBuffer) {
    // For now we just return the 8.3 format path as the long path
    if (cchBuffer > strlen(lpszShortPath)) {
        memcpy(lpszLongPath, lpszShortPath, strlen(lpszShortPath));
    }

    return strlen(lpszShortPath);
}

STATIC DWORD WINAPI GetLongPathNameW(LPCWSTR lpszShortPath,
                              LPWSTR lpszLongPath,
                              DWORD cchBuffer) {
    // For now we just return the 8.3 format path as the long path
    if (cchBuffer > CountWideChars(lpszShortPath)) {
        memcpy(lpszLongPath, lpszShortPath, CountWideChars(lpszShortPath) * sizeof(WCHAR));
    }

    return CountWideChars(lpszShortPath);
}

STATIC DWORD WINAPI RtlGetFullPathName_U(LPCWSTR lpFileName,
                                         DWORD nBufferLength,
                                         LPWSTR lpBuffer,
                                         LPWSTR *lpFilePart)
{
    char *lpFileNameA = CreateAnsiFromWide(lpFileName);
    size_t pathLen = CountWideChars(lpFileName);
    size_t filePartIndex = 0;

    DebugLog("%p [%s], %d, %p, %p", lpFileName, lpFileNameA, nBufferLength, lpBuffer, lpFilePart);

    if (lpFilePart) {
        *lpFilePart = NULL;
    }

    if (nBufferLength > pathLen) {
        memcpy(lpBuffer, lpFileName, pathLen * sizeof(WCHAR));
        if (lpFilePart) {
            for (size_t i = 0; i < pathLen; i++) {
                if (lpBuffer[i] == L'\\') {
                    filePartIndex = i + 1;
                }
            }
            *lpFilePart = lpBuffer + filePartIndex;
        }
    }
    return (DWORD)(pathLen * sizeof(WCHAR));
}

STATIC DWORD WINAPI GetFinalPathNameByHandleW(HANDLE hFile,
                                              LPWSTR lpszFilePath,
                                              DWORD cchFilePath,
                                              DWORD dwFlags)
{
    DebugLog("%p, %p, %#x", hFile, lpszFilePath, dwFlags);

    if (cchFilePath > CountWideChars(kFakePath)) {
        memcpy(lpszFilePath, kFakePath, CountWideChars(kFakePath)*sizeof(WCHAR));
    }

    return CountWideChars(kFakePath);
}

STATIC DWORD WINAPI GetFullPathNameA(LPCSTR lpFileName,
                                     DWORD nBufferLength,
                                     LPSTR lpBuffer,
                                     LPSTR *lpFilePart)
{
    DebugLog("%p [%s], %#x, %p, %p", lpFileName, lpFileName, nBufferLength, lpBuffer, lpFilePart);
    int index = 0;
    char FullPath[MAX_PATH_LENGTH];
    int FullPathLen;

    if (lpFilePart) {
        *lpFilePart = NULL;
    }

    for (int i = 0; i< strlen(lpFileName); i++) {
        if (lpFileName[i] == '\\')
            index = i;
    }
    if (index != 0)
        index = index + 1;
    
    size_t fullPathSize = strlen(kFakeBasePathA)+strlen(&lpFileName[index]) + 1;
    if (fullPathSize >= sizeof(FullPath)) {
        DebugLog("FullPath length is > MAX_PATH_LEGTH. Choose shorter paths.");
        abort();
    }

    memset(FullPath, 0, fullPathSize);
    
    strncpy(FullPath, kFakeBasePathA, strlen(kFakeBasePathA));

    strncpy(&FullPath[strlen(kFakeBasePathA)], &lpFileName[index], strlen(&lpFileName[index]));
    FullPathLen = strlen(FullPath);

    if (nBufferLength > (DWORD)FullPathLen && lpBuffer) {
        memcpy(lpBuffer, FullPath, FullPathLen + 1);
        if (lpFilePart) {
            LPSTR last = (LPSTR)strrchr((const char *)lpBuffer, '\\');
            *lpFilePart = last ? last + 1 : lpBuffer;
        }
        DebugLog("Full path name -> %s", FullPath);
    }
    else {
        DebugLog("Buffer is not big enough. Returning new size %d", FullPathLen);
        FullPathLen = FullPathLen + 1;
    }

    return FullPathLen;
}

static DWORD WINAPI GetFullPathNameW(
        PWCHAR lpFileName,
        DWORD nBufferLength,
        PWCHAR lpBuffer,
        PWCHAR *lpFilePart) {
    DebugLog("FileName [%p] Buffer Length [%#x] Dest buffer [%p]", lpFileName, nBufferLength, lpBuffer);
    size_t pathLen = CountWideChars(lpFileName);
    size_t requiredLen = pathLen + 1;
    size_t filePartIndex = 0;

    if (lpFilePart) {
        *lpFilePart = NULL;
    }

    if (nBufferLength < requiredLen || lpBuffer == NULL) {
        return (DWORD)requiredLen;
    }

    memcpy(lpBuffer, lpFileName, requiredLen * sizeof(WCHAR));

    if (lpFilePart) {
        for (size_t i = 0; i < pathLen; i++) {
            if (lpBuffer[i] == L'\\') {
                filePartIndex = i + 1;
            }
        }
        *lpFilePart = lpBuffer + filePartIndex;
    }

    return (DWORD)pathLen;
}


DECLARE_CRT_EXPORT("GetTempPathW", GetTempPathW);

DECLARE_CRT_EXPORT("GetTempPathA", GetTempPathA);

DECLARE_CRT_EXPORT("GetLogicalDrives", GetLogicalDrives);

DECLARE_CRT_EXPORT("GetDriveTypeW", GetDriveTypeW);

DECLARE_CRT_EXPORT("GetLongPathNameA", GetLongPathNameA);

DECLARE_CRT_EXPORT("GetLongPathNameW", GetLongPathNameW);

DECLARE_CRT_EXPORT("RtlGetFullPathName_U", RtlGetFullPathName_U);

DECLARE_CRT_EXPORT("GetFinalPathNameByHandleW", GetFinalPathNameByHandleW);

DECLARE_CRT_EXPORT("GetFullPathNameA", GetFullPathNameA);

DECLARE_CRT_EXPORT("GetFullPathNameW", GetFullPathNameW);
