#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>

#include "winnt_types.h"
#include "codealloc.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"
#include "Files.h"
#include "file_mapping.h"

extern bool SCAN_STARTED;

#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)

#include "shared_mem_file_handling.h"

#endif


typedef struct _WIN32_FILE_ATTRIBUTE_DATA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA, *LPWIN32_FILE_ATTRIBUTE_DATA;

extern void WINAPI SetLastError(DWORD dwErrCode);

#define FILE_ATTRIBUTE_NORMAL 128
#define FILE_ATTRIBUTE_DIRECTORY 16

#define INVALID_FILE_ATTRIBUTES -1;

static FILE *open_existing_with_plugins_fallback(const char *path) {
    FILE *handle = fopen(path, "r");
    const char *basename = NULL;
    size_t dir_len;
    size_t fallback_len;
    char *fallback_path;

    if (handle != NULL) {
        return handle;
    }

    if (strstr(path, "/Plugins/") != NULL) {
        return NULL;
    }

    basename = strrchr(path, '/');
    if (basename == NULL || basename[1] == '\0') {
        return NULL;
    }
    basename += 1;
    dir_len = (size_t)(basename - path);
    if (dir_len == 0) {
        return NULL;
    }

    fallback_len = dir_len + strlen("Plugins/") + strlen(basename) + 1;
    fallback_path = (char *)malloc(fallback_len);
    if (fallback_path == NULL) {
        return NULL;
    }

    memcpy(fallback_path, path, dir_len);
    memcpy(fallback_path + dir_len, "Plugins/", strlen("Plugins/"));
    memcpy(fallback_path + dir_len + strlen("Plugins/"), basename, strlen(basename) + 1);

    handle = fopen(fallback_path, "r");
    if (handle != NULL) {
        DebugLog("CreateFile fallback: %s => %p", fallback_path, handle);
    }
    free(fallback_path);
    return handle;
}

static DWORD WINAPI GetFileAttributesW(PVOID lpFileName) {
    DWORD Result = FILE_ATTRIBUTE_NORMAL;
    char *filename = CreateAnsiFromWide((LPCWSTR) lpFileName);
    DebugLog("%p [%s]", lpFileName, filename);

    if (strstr(filename, "RebootActions") || strstr(filename, "RtSigs")
            ) {
        Result = INVALID_FILE_ATTRIBUTES;
        goto finish;
    }

    finish:
    free(filename);
    return Result;
}

STATIC BOOL WINAPI SetFileAttributesA(LPCSTR lpFileName,
                                      DWORD dwFileAttributes)
{
    DebugLog("%p [%s]", lpFileName, lpFileName);

    SetLastError(0);
    return true;
}

STATIC BOOL WINAPI SetFileAttributesW(LPWSTR lpFileName, DWORD dwFileAttributes)
{
    char *lpFileNameA = CreateAnsiFromWide((LPCWSTR) lpFileName);
    DebugLog("%p [%s], %#x", lpFileName, lpFileNameA, dwFileAttributes);

    SetLastError(0);

    return true;
}

static DWORD WINAPI
GetFileAttributesExW(PWCHAR lpFileName, DWORD fInfoLevelId, LPWIN32_FILE_ATTRIBUTE_DATA lpFileInformation) {
    char *filename = CreateAnsiFromWide(lpFileName);
    DebugLog("%p [%s], %u, %p", lpFileName, filename, fInfoLevelId, lpFileInformation);

    assert(fInfoLevelId == 0);

    lpFileInformation->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    free(filename);
    return TRUE;
}

static HANDLE WINAPI CreateFileA(PCHAR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, PVOID lpSecurityAttributes,
                                 DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    void *FileHandle = NULL;

    DebugLog("%p [%s], %#x, %#x, %p, %#x, %#x, %p", lpFileName, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    char filename_copy[MAX_PATH_LENGTH];
    int filename_index = 0;
    memset(filename_copy, 0, MAX_PATH_LENGTH);
    if (strlen(lpFileName) > MAX_PATH_LENGTH) {
        perror("Filenames can't be longer than MAX_PATH_LENGTH. Exit.");
        abort();
    }

    strncpy(filename_copy, lpFileName, MAX_PATH_LENGTH);

    // Translate path seperator.
    while (strchr(filename_copy, '\\'))
        *strchr(filename_copy, '\\') = '/';

    /*
    if (strstr(filename_copy, "krnl.xmd")) {
        __debugbreak();
    }

    if (strstr(filename_copy, "dummyarch.xmd")) {
        __debugbreak();
    }
    */

    if ((filename_copy[0] == 'c' || filename_copy[0] == 'C') && filename_copy[1] == ':' && filename_copy[2] == '/') {
        filename_index = 3;
    }

#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)
    if (SCAN_STARTED) {
        if (strncmp(&filename_copy[filename_index], g_mmap_file.filename, strlen(g_mmap_file.filename)) == 0) {
            FileHandle = g_mmap_file.data;
            goto exit;
        }
    }
#endif

    switch (dwCreationDisposition) {
        case OPEN_EXISTING:
            FileHandle = open_existing_with_plugins_fallback(&filename_copy[filename_index]);
            break;
        case CREATE_ALWAYS:
            FileHandle = fopen(&filename_copy[filename_index], "wb");
            break;
            // This is the disposition used by CreateTempFile().
        case CREATE_NEW:
            if (strstr(filename_copy, "/faketemp/")) {
                FileHandle = fopen(&filename_copy[filename_index], "w");
                // Unlink it immediately so it's cleaned up on exit.
                unlink(filename_copy);
            } else {
                FileHandle = fopen("/dev/null", "w");
            }
            break;
        default:
            abort();
    }

exit:
    DebugLog("%s => %p", &filename_copy[filename_index], FileHandle);

    FileHandle ? SetLastError(0) : SetLastError(ERROR_FILE_NOT_FOUND);
    return FileHandle ? FileHandle : INVALID_HANDLE_VALUE;
}


static HANDLE WINAPI
CreateFileW(PWCHAR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, PVOID lpSecurityAttributes,
            DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    FILE *FileHandle;
    PCHAR filename = CreateAnsiFromWide(lpFileName);
    PCHAR filename_copy;

    DebugLog("%p [%s], %#x, %#x, %p, %#x, %#x, %p", lpFileName, filename, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    // Translate path seperator.
    while (strchr(filename, '\\'))
        *strchr(filename, '\\') = '/';

    /*
    // I'm just going to tolower() everything.
    for (char *t = filename; *t; t++)
        *t = tolower(*t);
    */
    //LogMessage("%u %s", dwCreationDisposition, filename);

    if ((filename[0] == 'c' || filename[0] == 'C') && filename[1] == ':' && filename[2] == '/') {
        filename_copy = &filename[3];
    }
    else if(filename[0] == '/' && filename[1] == '/' && filename[2] == '?' && filename[3] == '/') {
        filename_copy = &filename[4];
    }
    else {
        filename_copy = filename;
    }

#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)
    if (SCAN_STARTED) {
        if (strncmp(filename_copy, g_mmap_file.filename, strlen(g_mmap_file.filename)) == 0) {
            FileHandle = (FILE *)g_mmap_file.data;
            goto exit;
        }
    }
#endif

    switch (dwCreationDisposition) {
        case OPEN_EXISTING:
            if (strncmp(filename_copy, "//?/", 4) == 0) {
                FileHandle = fopen("/dev/null", "r");
            }
            else {
                FileHandle = open_existing_with_plugins_fallback(filename_copy);
            }
            
            break;
        case CREATE_ALWAYS:
            FileHandle = fopen("/dev/null", "w");
            break;
            // This is the disposition used by CreateTempFile().
        case CREATE_NEW:
            if (strstr(filename_copy, "/faketemp/")) {
                FileHandle = fopen(filename_copy, "w");
                // Unlink it immediately so it's cleaned up on exit.
                unlink(filename_copy);
                /*
            } else if (strstr(filename, "mpcache-")) {
                FileHandle = fopen(filename, "w");
                 */
            } else {
                FileHandle = fopen("/dev/null", "w");
            }
            break;
        default:
            abort();
    }

exit:
    DebugLog("%s => %p", filename, FileHandle);

    free(filename);

    FileHandle ? SetLastError(0) : SetLastError(ERROR_FILE_NOT_FOUND);
    return FileHandle ? FileHandle : INVALID_HANDLE_VALUE;
}

/**
 * TODO: handle 64 bit 
 */
static DWORD WINAPI
SetFilePointer(HANDLE hFile, LONG liDistanceToMove, LONG *lpDistanceToMoveHigh, DWORD dwMoveMethod) {
    int result;
    DWORD pos;

    DebugLog("%p, %#x, %p, %u", hFile, liDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);

    // we shouldn't test this kind of huge files
    if (lpDistanceToMoveHigh) {
        *lpDistanceToMoveHigh = 0;
    }

#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)
    if (SCAN_STARTED) {
        if (hFile == g_mmap_file.data) {
            int seek_result = mmap_seek(liDistanceToMove, dwMoveMethod);
            if (seek_result == -1) {
                SetLastError(131); // ERROR_NEGATIVE_SEEK
            }
            pos = seek_result;
            goto exit;
        }
    }
#endif

    result = fseek((FILE *)hFile, liDistanceToMove, dwMoveMethod);
    if (result == -1) {
        SetLastError(131); // ERROR_NEGATIVE_SEEK
        pos = -1;
        goto exit;
    }
    pos = ftell((FILE *)hFile);

exit:
    return pos;
}


static BOOL WINAPI
SetFilePointerEx(HANDLE hFile, uint64_t liDistanceToMove, uint64_t *lpNewFilePointer, DWORD dwMoveMethod) {
    int result;

    DebugLog("%p, %llu, %p, %u", hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);

    result = fseek((FILE *)hFile, liDistanceToMove, dwMoveMethod);

    // dwMoveMethod maps onto SEEK_SET/SEEK_CUR/SEEK_END perfectly.
    if (lpNewFilePointer) {
        *lpNewFilePointer = ftell((FILE *)hFile);
    }

    // Windows is permissive here.
    return TRUE;
    //return result != -1;
}


static BOOL WINAPI CloseHandle(HANDLE hObject) {
    DebugLog("%p", hObject);
#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)
    if (SCAN_STARTED) {
        DebugLog("Memory mapped file. Ignoring CloseHandle...");
        return TRUE;
    }
#endif
    if (DeleteMappedFile((MappedFileEntry *)hObject, FileMappingList)) {
        return TRUE;
    }
    if (hObject != (HANDLE) 'EVNT'
        && hObject != INVALID_HANDLE_VALUE
        && hObject != (HANDLE) 'SEMA')
        fclose((FILE *)hObject);
    return TRUE;
}


static BOOL WINAPI
ReadFile(HANDLE hFile, PVOID lpBuffer, DWORD nNumberOfBytesToRead, PDWORD lpNumberOfBytesRead, PVOID lpOverlapped) {
    DebugLog("%p %p %#x %p", hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead);
#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)
    if (SCAN_STARTED) {
        if (hFile == g_mmap_file.data) {
            DebugLog("Memory mapped file: Content[%p] Size[%#x] Name[%s] Seek ptr[%d]", 
                g_mmap_file.data, 
                g_mmap_file.size, 
                g_mmap_file.filename, 
                g_mmap_file.position);
            return mmap_read(lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead);
        }
    }
#endif
    *lpNumberOfBytesRead = fread(lpBuffer, 1, nNumberOfBytesToRead, (FILE *)hFile);
    return TRUE;
}

STATIC BOOL WINAPI WriteFile(HANDLE hFile, PVOID lpBuffer, DWORD nNumberOfBytesToWrite, PDWORD lpNumberOfBytesWritten, PVOID lpOverlapped)
{
    DebugLog("%p, %p, %#x", hFile, lpBuffer, nNumberOfBytesToWrite);
    *lpNumberOfBytesWritten = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, (FILE *)hFile);
    return TRUE;
}


static BOOL WINAPI DeleteFileW(PWCHAR lpFileName) {
    char *AnsiFilename = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s]", lpFileName, AnsiFilename);

    free(AnsiFilename);
    return TRUE;
}

STATIC BOOL WINAPI DeleteFileA(LPCSTR lpFileName)
{
    DebugLog("%p [%s]", lpFileName, lpFileName);
    return TRUE;
}

static BOOL WINAPI GetFileSizeEx(FILE *hFile, uint64_t *lpFileSize) {
    long curpos = ftell(hFile);

    fseek(hFile, 0, SEEK_END);

    *lpFileSize = ftell(hFile);

    fseek(hFile, curpos, SEEK_SET);

    DebugLog("%p, %p => %llu", (void *)hFile, lpFileSize, *lpFileSize);


    return TRUE;
}

STATIC DWORD WINAPI GetFileSize(FILE *hFile, DWORD *lpFileSizeHigh)
{
    union Size FileSize;
#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)
    if (SCAN_STARTED) {
        if (hFile == (FILE *)g_mmap_file.data) {
            DebugLog("Shared memory mapped file: Content[%p] Size[%#x] Name[%s] Seek ptr[%d]", 
                g_mmap_file.data, 
                g_mmap_file.size, 
                g_mmap_file.filename, 
                g_mmap_file.position);

            FileSize.size = g_mmap_file.size;

            if (lpFileSizeHigh != NULL)
                *lpFileSizeHigh = FileSize.high;
            
            return g_mmap_file.size;
        }
    }
#endif
    long curpos = ftell(hFile);

    fseek(hFile, 0, SEEK_END);

    size_t size = ftell(hFile);

    FileSize.size = size;

    fseek(hFile, curpos, SEEK_SET);

    DebugLog("%p => %#x", (void *) hFile, FileSize);

    if (lpFileSizeHigh != NULL)
        *lpFileSizeHigh = FileSize.high;

    return size;
}

static DWORD WINAPI NtOpenSymbolicLinkObject(PHANDLE LinkHandle, DWORD DesiredAccess, PVOID ObjectAttributes) {
    DebugLog("");
    *LinkHandle = (HANDLE) 'SYMB';
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI NtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength) {
    DebugLog("");
    return STATUS_SUCCESS;
}

STATIC NTSTATUS WINAPI NtClose(HANDLE Handle)
{
    DebugLog("");
    return STATUS_SUCCESS;
}

static BOOL WINAPI DeviceIoControl(
        HANDLE hDevice,
        DWORD dwIoControlCode,
        PVOID lpInBuffer,
        DWORD nInBufferSize,
        PVOID lpOutBuffer,
        DWORD nOutBufferSize,
        PDWORD lpBytesReturned,
        PVOID lpOverlapped) {
    DebugLog("");
    return FALSE;
}

STATIC NTSTATUS WINAPI NtQueryVolumeInformationFile(HANDLE FileHandle,
                                             PVOID IoStatusBlock,
                                             PVOID FsInformation,
                                             ULONG Length,
                                             DWORD FsInformationClass)
{
    DebugLog("%p, %p, %#x", FileHandle, FsInformation, FsInformationClass);
    if (FsInformationClass == FileFsDeviceInformation){
        ((PFILE_FS_DEVICE_INFORMATION)FsInformation)->DeviceType = FILE_DEVICE_DISK;
        ((PFILE_FS_DEVICE_INFORMATION)FsInformation)->Characteristics = 0x0;
    }
    return 0;
}

static BOOL SetEndOfFile(FILE *hFile) {
    DebugLog("");
    return ftruncate(fileno(hFile), ftell(hFile)) != -1;
}

static DWORD WINAPI GetFileVersionInfoSizeExW(DWORD dwFlags, PWCHAR lptstrFilename, PDWORD lpdwHandle) {
    DebugLog("%#x, %p, %p", dwFlags, lptstrFilename, lpdwHandle);
    return 0;
}

static BOOL WINAPI
GetFileVersionInfoExW(DWORD dwFlags, PWCHAR lptstrFilename, DWORD dwHandle, DWORD dwLen, PVOID lpData) {
    DebugLog("");
    return FALSE;
}

static BOOL WINAPI VerQueryValueW(PVOID pBlock, PWCHAR lpSubBlock, PVOID *lplpBuffer, PDWORD puLen) {
    DebugLog("");
    return FALSE;
}

static DWORD WINAPI QueryDosDevice(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax) {

    char *device_name = CreateAnsiFromWide(lpDeviceName);
    DebugLog("%p [%s] %p", lpDeviceName, device_name, lpTargetPath);
    free(device_name);
    static const wchar_t dummy_path[] = L"\\Device\\HarddiskVolume3";
    DWORD required = (DWORD)(sizeof(dummy_path) / sizeof(dummy_path[0]));

    if (lpTargetPath == NULL || ucchMax < required) {
        return 0;
    }

    memcpy(lpTargetPath, dummy_path, sizeof(dummy_path));

    return required;
}

static BOOL WINAPI
GetDiskFreeSpaceExW(PWCHAR lpDirectoryName, PVOID lpFreeBytesAvailableToCaller, PVOID lpTotalNumberOfBytes,
                    QWORD *lpTotalNumberOfFreeBytes) {
    DebugLog("%S", lpDirectoryName);
    *lpTotalNumberOfFreeBytes = 0x000000000ULL;
    return FALSE;
}

STATIC NTSTATUS WINAPI NtQueryInformationFile(HANDLE FileHandle,
                                       PVOID IoStatusBlock,
                                       PVOID FileInformation,
                                       ULONG Length,
                                       DWORD FileInformationClass)
{
    DebugLog("%p, %#x, %#x", FileHandle, Length, FileInformationClass);
    if (FileInformationClass == FileStandardInformation) {
        fseek((FILE*)FileHandle, 0L, SEEK_END);
        size_t FileSize = ftell((FILE*)FileHandle);
        rewind((FILE*)FileHandle);
        ((PFILE_STANDARD_INFORMATION) FileInformation)->AllocationSize = FileSize;
        ((PFILE_STANDARD_INFORMATION) FileInformation)->EndOfFile = FileSize;
        ((PFILE_STANDARD_INFORMATION) FileInformation)->NumberOfLinks = 0;
        ((PFILE_STANDARD_INFORMATION) FileInformation)->DeletePending = FALSE;
        ((PFILE_STANDARD_INFORMATION) FileInformation)->Directory = FALSE; //TODO: Check if FileHandle is a directory
    }
    return 0;
}

STATIC BOOL WINAPI SetFileTime(HANDLE hFile,
                               const FILETIME *lpCreationTime,
                               const FILETIME *lpLastAccessTime,
                               const FILETIME *lpLastWriteTime)
{
    DebugLog("%p, %p, %p, %p", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);

    return true;
}

STATIC BOOL WINAPI GetFileTime(HANDLE hFile,
                               PFILETIME lpCreationTime,
                               PFILETIME lpLastAccessTime,
                               PFILETIME lpLastWriteTime) // TO FIX
{
    DebugLog("%p, %p, %p, %p", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
    lpCreationTime->dwHighDateTime = 0;
    lpCreationTime->dwLowDateTime = 0;
    lpLastAccessTime->dwHighDateTime = 0;
    lpLastAccessTime->dwLowDateTime = 0;
    lpLastWriteTime->dwLowDateTime = 0;
    lpLastWriteTime->dwLowDateTime = 0;
    return true;
}

STATIC DWORD WINAPI GetFileType(HANDLE hFile)
{
    DebugLog("%p", hFile);

    return FILE_TYPE_DISK;
}

STATIC BOOL WINAPI SetFileInformationByHandle(HANDLE hFile,
                                              FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
                                              LPVOID lpFileInformation,
                                              DWORD dwBufferSize) {
    DebugLog("%p %p %hhx", hFile, lpFileInformation, dwBufferSize);
    return true;
}

DECLARE_CRT_EXPORT("VerQueryValueW", VerQueryValueW);

DECLARE_CRT_EXPORT("GetFileVersionInfoExW", GetFileVersionInfoExW);

DECLARE_CRT_EXPORT("GetFileVersionInfoSizeExW", GetFileVersionInfoSizeExW);

DECLARE_CRT_EXPORT("GetFileAttributesW", GetFileAttributesW);

DECLARE_CRT_EXPORT("GetFileAttributesExW", GetFileAttributesExW);

DECLARE_CRT_EXPORT("CreateFileA", CreateFileA);

DECLARE_CRT_EXPORT("CreateFileW", CreateFileW);

DECLARE_CRT_EXPORT("SetFilePointer", SetFilePointer);

DECLARE_CRT_EXPORT("SetFilePointerEx", SetFilePointerEx);

DECLARE_CRT_EXPORT("CloseHandle", CloseHandle);

DECLARE_CRT_EXPORT("ReadFile", ReadFile);

DECLARE_CRT_EXPORT("WriteFile", WriteFile);

DECLARE_CRT_EXPORT("DeleteFileW", DeleteFileW);

DECLARE_CRT_EXPORT("GetFileSizeEx", GetFileSizeEx);

DECLARE_CRT_EXPORT("NtOpenSymbolicLinkObject", NtOpenSymbolicLinkObject);

DECLARE_CRT_EXPORT("NtQuerySymbolicLinkObject", NtQuerySymbolicLinkObject);

DECLARE_CRT_EXPORT("NtClose", NtClose);

DECLARE_CRT_EXPORT("DeviceIoControl", DeviceIoControl);

DECLARE_CRT_EXPORT("NtQueryVolumeInformationFile", NtQueryVolumeInformationFile);

DECLARE_CRT_EXPORT("SetEndOfFile", SetEndOfFile);

DECLARE_CRT_EXPORT("QueryDosDeviceW", QueryDosDevice);

DECLARE_CRT_EXPORT("GetDiskFreeSpaceExW", GetDiskFreeSpaceExW);

DECLARE_CRT_EXPORT("SetFileInformationByHandle", SetFileInformationByHandle);

DECLARE_CRT_EXPORT("GetFileSize", GetFileSize);

DECLARE_CRT_EXPORT("SetFileAttributesA", SetFileAttributesA);

DECLARE_CRT_EXPORT("SetFileAttributesW", SetFileAttributesW);

DECLARE_CRT_EXPORT("DeleteFileA", DeleteFileA);

DECLARE_CRT_EXPORT("NtQueryInformationFile", NtQueryInformationFile);

DECLARE_CRT_EXPORT("SetFileTime", SetFileTime);

DECLARE_CRT_EXPORT("GetFileTime", GetFileTime);

DECLARE_CRT_EXPORT("GetFileType", GetFileType);
