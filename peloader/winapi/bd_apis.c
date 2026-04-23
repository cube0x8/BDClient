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
#include <stdio.h>
#include <dirent.h>
#include <wchar.h>

#include "winnt_types.h"
#include "codealloc.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"
#include "IsProcessorFeaturePresent.h"
#include "Files.h"
#include "bd.h"
#include "../file_mapping.h"
#include "../file_translation.h"

#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)

#include "shared_mem_file_handling.h"

#endif

#define MAX_PATH_SIZE 255
extern bool SCAN_STARTED;

queue_t *PluginsQueue = NULL;

extern void WINAPI SetLastError(DWORD dwErrCode);

void* queue_read(queue_t *queue) {
    if (queue->tail == queue->head) {
        return NULL;
    }
    void* handle = queue->data[queue->tail];
    queue->data[queue->tail] = NULL;
    queue->tail = (queue->tail + 1) % queue->size;
    return handle;
}

int queue_write(queue_t *queue, void* handle) {
    if (((queue->head + 1) % queue->size) == queue->tail) {
        return -1;
    }
    queue->data[queue->head] = handle;
    queue->head = (queue->head + 1) % queue->size;
    return 0;
}

STATIC BOOL WINAPI FindClose(HANDLE hFindFile)
{
    DebugLog("%p", hFindFile);
    if (strncmp((char*) hFindFile, "PLGN", 4) == 0) {
        free(PluginsQueue);
    }

    return true;
}

STATIC HANDLE WINAPI FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
    union Size FileSize;
    DebugLog("%p [%s], %p", lpFileName, lpFileName, lpFindFileData);
    if (strstr(lpFileName, "Plugins\\*") != NULL) {

        int file_count = sizeof(filenames) / sizeof(char *);
        int count = 0;

        // allocate queue
        PluginsQueue = (queue_t*) malloc(sizeof(queue_t));
        PluginsQueue->head = 0;
        PluginsQueue->tail = 0;
        PluginsQueue->size = file_count + 1;
        PluginsQueue->data = (void **)malloc(sizeof(void*) * file_count);

        while (count < file_count) {
            char *filename = (char*) malloc(strlen(filenames[count]) + 1);
            memset(filename, 0, strlen(filenames[count]) + 1);
            strncpy(filename, filenames[count], strlen(filenames[count]));
            int res = queue_write(PluginsQueue, (void*)filename);
            count++;
        }

        // Unixify path
        char *ParentPath = (char *) calloc(strlen(lpFileName) + 1, sizeof(char));
        strncpy(ParentPath, lpFileName, strlen(lpFileName));

        while (strchr(ParentPath, '\\'))
            *strchr(ParentPath, '\\') = '/';

        if (ParentPath[strlen(ParentPath) - 1] == '*') {
            ParentPath[strlen(ParentPath) - 1] = '\0';
        }

        strncpy(PluginsFullPath, ParentPath, strlen(ParentPath));
        free(ParentPath);

        // Get first plugin from the queue
        char *FirstFileName = (char*) queue_read(PluginsQueue);
        DebugLog("\"%s\" got from the queue", FirstFileName);

        // Calculate full path to the plugin
        char *FullPath = (char*) malloc(strlen(PluginsFullPath) + strlen(FirstFileName) + 1);
        memset(FullPath, 0, strlen(PluginsFullPath) + strlen(FirstFileName) + 1);
        strncpy(FullPath, PluginsFullPath, strlen(PluginsFullPath));
        strncpy(&FullPath[strlen(PluginsFullPath)], FirstFileName, strlen(FirstFileName));

        if ((strcmp(FirstFileName, ".") == 0) || (strcmp(FirstFileName, "..") == 0)) {
            FileSize.size = (uint64_t) 0;
            lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        }
        else {
            lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
            // Get size of the plugin file
            FILE *fp = fopen(FullPath, "r");
            if (fp == NULL)
                goto error;
            fseek(fp, 0, SEEK_END);
            int64_t size = ftell(fp);

            fclose(fp);
            FileSize.size = size;
        }
        free(FullPath);

        lpFindFileData->ftCreationTime.dwLowDateTime = 0x3AACDE5A;
        lpFindFileData->ftCreationTime.dwHighDateTime = 0x01D6E798;
        lpFindFileData->ftLastAccessTime.dwLowDateTime = 0xDCBD7A00;
        lpFindFileData->ftLastAccessTime.dwHighDateTime = 0x01D6E8C3;
        lpFindFileData->ftLastWriteTime.dwLowDateTime = 0xDCBD7A00;
        lpFindFileData->ftLastWriteTime.dwHighDateTime = 0x01D6E8C3;
        lpFindFileData->nFileSizeHigh = FileSize.high;
        lpFindFileData->nFileSizeLow = FileSize.low;
        lpFindFileData->dwReserved0 = 0;
        lpFindFileData->dwReserved1 = 0;
        memcpy(lpFindFileData->cFileName, FirstFileName, strlen(FirstFileName));
        lpFindFileData->cFileName[strlen(FirstFileName)] = 0;
        lpFindFileData->cAlternateFileName[0] = 0;
        return (HANDLE) "PLGN";
    }
    else {
        lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;

        PCHAR filename_copy = (PCHAR) malloc(strlen(lpFileName) + 1);
        memset(filename_copy, 0, strlen(lpFileName) + 1);
        memcpy(filename_copy, lpFileName, strlen(lpFileName));
        uintptr_t filename_copy_original_ptr = (uintptr_t) filename_copy;
        // Translate path seperator.
        while (strchr(filename_copy, '\\'))
            *strchr(filename_copy, '\\') = '/';

        if ((filename_copy[0] == 'c' || filename_copy[0] == 'C') && filename_copy[1] == ':' && filename_copy[2] == '/') {
            filename_copy = &filename_copy[3];
        }

        int64_t size;

#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)
        if (SCAN_STARTED && strncmp(filename_copy, g_mmap_file.filename, strlen(g_mmap_file.filename)) == 0) {
                DebugLog("Using shared memory on FindFirstFileA");
                size = g_mmap_file.size;
        } else {
#endif
        // Get size of the file
        FILE *fp = fopen(filename_copy, "r");
        if (fp == NULL)
            goto error;
        fseek(fp, 0, SEEK_END);
        size = ftell(fp);

        fclose(fp);

#if defined(SHARED_MEM) || defined(HONGGFUZZ_FUZZING)
        }
#endif
        FileSize.size = size;

        lpFindFileData->ftCreationTime.dwLowDateTime = 0x3AACDE5A;
        lpFindFileData->ftCreationTime.dwHighDateTime = 0x01D6E798;
        lpFindFileData->ftLastAccessTime.dwLowDateTime = 0xDCBD7A00;
        lpFindFileData->ftLastAccessTime.dwHighDateTime = 0x01D6E8C3;
        lpFindFileData->ftLastWriteTime.dwLowDateTime = 0xDCBD7A00;
        lpFindFileData->ftLastWriteTime.dwHighDateTime = 0x01D6E8C3;
        lpFindFileData->nFileSizeHigh = FileSize.high;
        lpFindFileData->nFileSizeLow = FileSize.low;
        lpFindFileData->dwReserved0 = 0;
        lpFindFileData->dwReserved1 = 0;
        memcpy(lpFindFileData->cFileName, lpFileName, strlen(lpFileName));
        lpFindFileData->cFileName[strlen(lpFileName)] = 0;
        lpFindFileData->cAlternateFileName[0] = 0;

        filename_copy = (PCHAR) filename_copy_original_ptr;
        free(filename_copy);

        return (HANDLE) "FIND";
    }

error:
    SetLastError(ERROR_FILE_NOT_FOUND);
    return INVALID_HANDLE_VALUE;
}

STATIC BOOL WINAPI FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
    union Size FileSize;
    DebugLog("%p, %p", hFindFile, lpFindFileData);

    if (strncmp((char*)hFindFile, "PLGN", 4) == 0) {
        // Get plugin filename from the queue
        char* PluginFileName = (char*) queue_read(PluginsQueue);
        if (PluginFileName == NULL) {
            SetLastError(0x12); // ERROR_NO_MORE_FILES
            return false;
        }

        DebugLog("%s got from the queue", PluginFileName);

        // Calculate full path to the plugin
        char* FullPath = (char*) malloc(strlen(PluginsFullPath) + strlen(PluginFileName) + 1);
        memset(FullPath, 0, strlen(PluginsFullPath) + strlen(PluginFileName) + 1);
        strncpy(FullPath, PluginsFullPath, strlen(PluginsFullPath));
        strncpy(&FullPath[strlen(PluginsFullPath)], PluginFileName, strlen(PluginFileName));

        if ((strcmp(PluginFileName, ".") == 0) || (strcmp(PluginFileName, "..") == 0)) {
            lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
            FileSize.size = (uint64_t) 0;
        }
        else {
            lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
            // Get size of the plugin file
            FILE *fp = fopen(FullPath, "r");
            fseek(fp, 0, SEEK_END);
            int64_t size = ftell(fp);
            fclose(fp);
            FileSize.size = size;
        }

        lpFindFileData->ftCreationTime.dwLowDateTime = 0x3AACDE5A;
        lpFindFileData->ftCreationTime.dwHighDateTime = 0x01D6E798;
        lpFindFileData->ftLastAccessTime.dwLowDateTime = 0xDCBD7A00;
        lpFindFileData->ftLastAccessTime.dwHighDateTime = 0x01D6E8C3;
        lpFindFileData->ftLastWriteTime.dwLowDateTime = 0xDCBD7A00;
        lpFindFileData->ftLastWriteTime.dwHighDateTime = 0x01D6E8C3;
        lpFindFileData->nFileSizeHigh = FileSize.high;
        lpFindFileData->nFileSizeLow = FileSize.low;
        lpFindFileData->dwReserved0 = 0;
        lpFindFileData->dwReserved1 = 0;
        memcpy(lpFindFileData->cFileName, PluginFileName, strlen(PluginFileName));
        lpFindFileData->cFileName[strlen(PluginFileName)] = 0;
        lpFindFileData->cAlternateFileName[0] = 0;
        return true;
    }

    return false;

}

/*
STATIC HANDLE WINAPI CreateFileA(PCHAR lpFileName,
                                   DWORD dwDesiredAccess,
                                   DWORD dwShareMode,
                                   PVOID lpSecurityAttributes,
                                   DWORD dwCreationDisposition,
                                   DWORD dwFlagsAndAttributes,
                                   HANDLE hTemplateFile)
{
    DebugLog("%p [%s], %#x, %#x, %p, %#x, %#x, %p",
             lpFileName,
             lpFileName,
             dwDesiredAccess,
             dwShareMode,
             lpSecurityAttributes,
             dwCreationDisposition,
             dwFlagsAndAttributes,
             hTemplateFile);

    FILE *FileHandle;

    char *translated_name = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
    file_path_translation(lpFileName, translated_name);

    switch (dwCreationDisposition) {
        case OPEN_EXISTING:
            FileHandle = fopen(translated_name, "r");
            break;
        case CREATE_ALWAYS:
            FileHandle = fopen(translated_name, "w");
            break;
            // This is the disposition used by CreateTempFile().
        case CREATE_NEW:
            if (strstr(translated_name, "/faketemp/")) {
                FileHandle = fopen(translated_name, "w");
                // Unlink it immediately so it's cleaned up on exit.
                unlink(translated_name);
            } else {
                FileHandle = fopen("/dev/null", "w");
            }
            break;
        default:
            abort();
    }

    DebugLog("%s => %p", translated_name, FileHandle);

    FileHandle ? SetLastError(0) : SetLastError(ERROR_FILE_NOT_FOUND);
    return FileHandle ? FileHandle : INVALID_HANDLE_VALUE;

}

STATIC HANDLE WINAPI CreateFileW(PWCHAR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, PVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    FILE *FileHandle;
    char *filename = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s], %#x, %#x, %p, %#x, %#x, %p", lpFileName, filename, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    char *translated_name = (char *) malloc(sizeof(char) * 255);
    file_path_translation(filename, translated_name);

    switch (dwCreationDisposition) {
        case OPEN_EXISTING:
            FileHandle = fopen(translated_name, "r");
            break;
        case CREATE_ALWAYS:
            FileHandle = fopen(translated_name, "w");
            break;
            // This is the disposition used by CreateTempFile().
        case CREATE_NEW:
            if (strstr(translated_name, "/faketemp/")) {
                FileHandle = fopen(translated_name, "w");
                // Unlink it immediately so it's cleaned up on exit.
                unlink(translated_name);
            } else {
                FileHandle = fopen("/dev/null", "w");
            }
            break;
        default:
            abort();
    }

    DebugLog("%s => %p", translated_name, FileHandle);

    free(filename);
    free(translated_name);

    SetLastError(ERROR_FILE_NOT_FOUND);
    return FileHandle ? FileHandle : INVALID_HANDLE_VALUE;
}
*/
/*
static NTSTATUS WINAPI NtCreateFile(HANDLE *FileHandle,
                                    ACCESS_MASK DesiredAccess,
                                    POBJECT_ATTRIBUTES ObjectAttributes,
                                    PIO_STATUS_BLOCK IoStatusBlock,
                                    LARGE_INTEGER *AllocationSize,
                                    ULONG FileAttributes,
                                    ULONG ShareAccess,
                                    ULONG CreateDisposition,
                                    ULONG CreateOptions,
                                    PVOID EaBuffer,
                                    ULONG EaLength)
{
    LPSTR filename = CreateAnsiFromWide(ObjectAttributes->name->Buffer);

    DebugLog("%p, %#x, %p, [%s]", FileHandle, DesiredAccess, ObjectAttributes, filename);

    switch (CreateDisposition) {
        case FILE_SUPERSEDED:
            *FileHandle = fopen(translated_local_path, "r");
            break;
        case FILE_OPEN:
            if (access(translated_local_path, F_OK) == 0){
                *FileHandle = fopen(translated_local_path, "r+");
            }
            else {
                free(filename);
                free(translated_local_path);
                return STATUS_NO_SUCH_FILE;
            }
            break;
            // This is the disposition used by CreateTempFile().
        case FILE_CREATED:
            *FileHandle = fopen(translated_local_path, "w");
            // Unlink it immediately so it's cleaned up on exit.
            unlink(translated_local_path);
            break;
        default:
            abort();
    }

    DebugLog("%s => %p", translated_local_path, *FileHandle);

    free(filename);
    free(translated_local_path);

    return 0;
}
*/
STATIC DWORD WINAPI GetFileAttributesA(LPCSTR lpFileName)
{
    DebugLog("%p [%s]", lpFileName, lpFileName);
    DWORD Result;

    if (strstr(lpFileName, "tmp00000000") != NULL)
        Result = FILE_ATTRIBUTE_NORMAL;
    else if (strstr(lpFileName, "tmp") != NULL)
        Result = FILE_ATTRIBUTE_ARCHIVE;
    else if (strstr(lpFileName, "eicar.com") != NULL)
        Result = FILE_ATTRIBUTE_ARCHIVE;
    else if (strstr(lpFileName, "sample_1.exe") != NULL)
        Result = FILE_ATTRIBUTE_ARCHIVE;
    else if (strstr(lpFileName, "sample_1.zip") != NULL)
        Result = FILE_ATTRIBUTE_COMPRESSED;
    else if (strstr(lpFileName, "test.txt") != NULL)
        Result = FILE_ATTRIBUTE_ARCHIVE;
    else {
        Result = FILE_ATTRIBUTE_NORMAL;
    }
    return Result;
}

static HANDLE WINAPI LoadLibraryA(char *lpFileName)
{
    DebugLog("%p [%s]", lpFileName, lpFileName);

    if (strstr(lpFileName, "trufos.dll") != NULL)
        return (HANDLE) 0;

    return (HANDLE) 'LOAD';
}

STATIC BOOL WINAPI CreateDirectoryA(LPCSTR lpPathName, PVOID lpSecurityAttributes)
{
    DebugLog("%p [%s]", lpPathName, lpPathName);

    /*
    struct stat st = {0};

    PCHAR filename_copy = (PCHAR) malloc(strlen(lpPathName) + 1);
    memset(filename_copy, 0, strlen(lpPathName) + 1);
    memcpy(filename_copy, lpPathName, strlen(lpPathName));
    uintptr_t filename_copy_original_ptr = (uintptr_t) filename_copy;

    // Translate path seperator.
    while (strchr(filename_copy, '\\'))
        *strchr(filename_copy, '\\') = '/';

    // I'm just going to tolower() everything.
    for (char *t = filename_copy; *t; t++)
        *t = tolower(*t);

    if (filename_copy[0] == 'c' && filename_copy[1] == ':' && filename_copy[2] == '/') {
        filename_copy[1] = '.';
        filename_copy = &filename_copy[1];
    }

    if (stat(filename_copy, &st) == -1) {
        mkdir(filename_copy, 0700);
    }

    //filename_copy = filename_copy_original_ptr;
    //free(filename_copy);
    */
   
    return true;
}

HANDLE WINAPI FindFirstFileW(PWCHAR lpFileName, PVOID lpFindFileData)
{
    char *name = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s], %p", lpFileName, name, lpFindFileData);

    free(name);

    return (HANDLE) "FIND";
}

STATIC BOOL WINAPI GetComputerNameW(LPWSTR  lpBuffer,
                                    LPDWORD nSize) {
    DebugLog("");
    const wchar_t computer_name[6] = L"my-pc";
    if (*nSize < sizeof(computer_name)) {
        *nSize = sizeof(computer_name);
        SetLastError(0x6F); //ERROR_BUFFER_OVERFLOW
        return 0;
    }
    wcsncpy((wchar_t *) lpBuffer, computer_name, 6);
    *nSize = CountWideChars(computer_name);
    return 1;
}

DECLARE_CRT_EXPORT("FindFirstFileA", FindFirstFileA);
DECLARE_CRT_EXPORT("FindNextFileA", FindNextFileA);
DECLARE_CRT_EXPORT("FindClose", FindClose);
/*
DECLARE_CRT_EXPORT("CreateFileA", CreateFileA);
DECLARE_CRT_EXPORT("CreateFileW", CreateFileW);
DECLARE_CRT_EXPORT("NtCreateFile", NtCreateFile);
 */
DECLARE_CRT_EXPORT("GetFileAttributesA", GetFileAttributesA);
DECLARE_CRT_EXPORT("LoadLibraryA", LoadLibraryA);
DECLARE_CRT_EXPORT("CreateDirectoryA", CreateDirectoryA);
DECLARE_CRT_EXPORT("FindFirstFileW", FindFirstFileW);
DECLARE_CRT_EXPORT("GetComputerNameW", GetComputerNameW);
