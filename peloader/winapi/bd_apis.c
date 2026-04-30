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
#include <sys/stat.h>
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

typedef struct _find_handle {
    char magic[4];
    char *base_path;
    size_t count;
    size_t index;
    char **names;
    uint8_t *attrs;
    uint64_t *sizes;
} find_handle_t;

static void free_plugins_queue(void) {
    if (PluginsQueue == NULL) {
        return;
    }

    if (PluginsQueue->data != NULL) {
        for (size_t index = 0; index < PluginsQueue->size; index++) {
            free(PluginsQueue->data[index]);
        }
        free(PluginsQueue->data);
    }

    free(PluginsQueue);
    PluginsQueue = NULL;
}

static void free_find_handle(find_handle_t *handle) {
    size_t index;

    if (handle == NULL) {
        return;
    }

    free(handle->base_path);
    if (handle->names != NULL) {
        for (index = 0; index < handle->count; index++) {
            free(handle->names[index]);
        }
    }
    free(handle->names);
    free(handle->attrs);
    free(handle->sizes);
    free(handle);
}

static int compare_plugin_names(const void *lhs, const void *rhs) {
    const char *const *left = (const char *const *)lhs;
    const char *const *right = (const char *const *)rhs;
    return strcmp(*left, *right);
}

static char *translate_find_directory(const char *path) {
    char *translated = (char *)calloc(strlen(path) + 2, sizeof(char));
    size_t len;

    if (translated == NULL) {
        return NULL;
    }

    memcpy(translated, path, strlen(path));
    while (strchr(translated, '\\')) {
        *strchr(translated, '\\') = '/';
    }

    if ((translated[0] == 'c' || translated[0] == 'C') && translated[1] == ':' && translated[2] == '/') {
        memmove(translated, translated + 3, strlen(translated + 3) + 1);
    }

    len = strlen(translated);
    while (len > 0 && (translated[len - 1] == '*' || translated[len - 1] == '/')) {
        translated[len - 1] = '\0';
        len--;
    }

    if (len > 0) {
        translated[len] = '/';
        translated[len + 1] = '\0';
    }

    return translated;
}

static int enumerate_directory(const char *directory_path, find_handle_t **out_handle) {
    DIR *dir = opendir(directory_path);
    struct dirent *entry = NULL;
    char **filenames = NULL;
    uint8_t *attrs = NULL;
    uint64_t *sizes = NULL;
    size_t count = 0;
    size_t capacity = 0;
    find_handle_t *handle = NULL;

    if (dir == NULL) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        struct stat st;
        size_t name_len;
        char *full_path;
        char *filename_copy;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        name_len = strlen(entry->d_name);
        full_path = (char *)malloc(strlen(directory_path) + name_len + 1);
        if (full_path == NULL) {
            closedir(dir);
            goto error;
        }

        memcpy(full_path, directory_path, strlen(directory_path));
        memcpy(full_path + strlen(directory_path), entry->d_name, name_len + 1);

        if (stat(full_path, &st) != 0) {
            free(full_path);
            continue;
        }
        free(full_path);

        if (count == capacity) {
            size_t new_capacity = capacity == 0 ? 64 : capacity * 2;
            char **new_filenames = (char **)realloc(filenames, sizeof(char *) * new_capacity);
            uint8_t *new_attrs = (uint8_t *)realloc(attrs, sizeof(uint8_t) * new_capacity);
            uint64_t *new_sizes = (uint64_t *)realloc(sizes, sizeof(uint64_t) * new_capacity);
            if (new_filenames == NULL) {
                closedir(dir);
                goto error;
            }
            if (new_attrs == NULL || new_sizes == NULL) {
                free(new_filenames);
                closedir(dir);
                goto error;
            }
            filenames = new_filenames;
            attrs = new_attrs;
            sizes = new_sizes;
            capacity = new_capacity;
        }

        filename_copy = (char *)malloc(name_len + 1);
        if (filename_copy == NULL) {
            closedir(dir);
            goto error;
        }
        memcpy(filename_copy, entry->d_name, name_len + 1);
        filenames[count++] = filename_copy;
        attrs[count - 1] = S_ISDIR(st.st_mode) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
        sizes[count - 1] = S_ISDIR(st.st_mode) ? 0 : (uint64_t)st.st_size;
    }

    closedir(dir);
    qsort(filenames, count, sizeof(char *), compare_plugin_names);
    handle = (find_handle_t *)calloc(1, sizeof(find_handle_t));
    if (handle == NULL) {
        goto error;
    }
    memcpy(handle->magic, "FDIR", 4);
    handle->base_path = strdup(directory_path);
    handle->count = count;
    handle->index = 0;
    handle->names = filenames;
    handle->attrs = attrs;
    handle->sizes = sizes;
    *out_handle = handle;
    return (int)count;

error:
    free(attrs);
    free(sizes);
    if (filenames != NULL) {
        for (size_t index = 0; index < count; index++) {
            free(filenames[index]);
        }
        free(filenames);
    }
    return -1;
}

static BOOL populate_find_data(LPWIN32_FIND_DATAA lpFindFileData, const char *name, uint8_t attr, uint64_t size) {
    union Size file_size;
    size_t name_len = strlen(name);

    file_size.size = size;
    lpFindFileData->dwFileAttributes = attr;
    lpFindFileData->ftCreationTime.dwLowDateTime = 0x3AACDE5A;
    lpFindFileData->ftCreationTime.dwHighDateTime = 0x01D6E798;
    lpFindFileData->ftLastAccessTime.dwLowDateTime = 0xDCBD7A00;
    lpFindFileData->ftLastAccessTime.dwHighDateTime = 0x01D6E8C3;
    lpFindFileData->ftLastWriteTime.dwLowDateTime = 0xDCBD7A00;
    lpFindFileData->ftLastWriteTime.dwHighDateTime = 0x01D6E8C3;
    lpFindFileData->nFileSizeHigh = file_size.high;
    lpFindFileData->nFileSizeLow = file_size.low;
    lpFindFileData->dwReserved0 = 0;
    lpFindFileData->dwReserved1 = 0;
    memcpy(lpFindFileData->cFileName, name, name_len);
    lpFindFileData->cFileName[name_len] = 0;
    lpFindFileData->cAlternateFileName[0] = 0;
    return true;
}

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
    if (hFindFile != NULL && strncmp((char*) hFindFile, "FDIR", 4) == 0) {
        free_find_handle((find_handle_t *)hFindFile);
    }

    SetLastError(0);
    return true;
}

STATIC HANDLE WINAPI FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
    find_handle_t *find_handle = NULL;
    DebugLog("%p [%s], %p", lpFileName, lpFileName, lpFindFileData);
    if (strchr(lpFileName, '*') != NULL) {
        char *directory_path = translate_find_directory(lpFileName);
        if (directory_path == NULL) {
            goto error;
        }
        if (enumerate_directory(directory_path, &find_handle) <= 0) {
            free(directory_path);
            goto error;
        }
        free(directory_path);
        if (populate_find_data(lpFindFileData, find_handle->names[0], find_handle->attrs[0], find_handle->sizes[0]) == false) {
            free_find_handle(find_handle);
            goto error;
        }
        find_handle->index = 1;
        SetLastError(0);
        return (HANDLE)find_handle;
    }

error:
    SetLastError(ERROR_FILE_NOT_FOUND);
    return INVALID_HANDLE_VALUE;
}

STATIC BOOL WINAPI FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
    union Size FileSize;
    DebugLog("%p, %p", hFindFile, lpFindFileData);

    if (hFindFile != NULL && strncmp((char*)hFindFile, "FDIR", 4) == 0) {
        find_handle_t *find_handle = (find_handle_t *)hFindFile;
        if (find_handle->index >= find_handle->count) {
            SetLastError(0x12); // ERROR_NO_MORE_FILES
            return false;
        }
        populate_find_data(
            lpFindFileData,
            find_handle->names[find_handle->index],
            find_handle->attrs[find_handle->index],
            find_handle->sizes[find_handle->index]
        );
        find_handle->index += 1;
        SetLastError(0);
        return true;
    }

    SetLastError(ERROR_FILE_NOT_FOUND);
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
    struct stat st = {0};
    PCHAR filename_copy = (PCHAR)calloc(strlen(lpPathName) + 1, sizeof(char));
    BOOL result = true;
    if (filename_copy == NULL) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return false;
    }
    memcpy(filename_copy, lpPathName, strlen(lpPathName));

    // Translate path seperator.
    while (strchr(filename_copy, '\\'))
        *strchr(filename_copy, '\\') = '/';

    if ((filename_copy[0] == 'c' || filename_copy[0] == 'C') && filename_copy[1] == ':' && filename_copy[2] == '/') {
        memmove(filename_copy, filename_copy + 3, strlen(filename_copy + 3) + 1);
    }

    if (stat(filename_copy, &st) == -1) {
        if (mkdir(filename_copy, 0700) != 0) {
            result = false;
        }
    }

    free(filename_copy);
    result ? SetLastError(0) : SetLastError(ERROR_FILE_NOT_FOUND);
    return result;
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
