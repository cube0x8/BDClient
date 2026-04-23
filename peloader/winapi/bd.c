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

#include "winnt_types.h"
#include "codealloc.h"
#include "pe_linker.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"
#include "Files.h"
#include "Memory.h"
#include "file_mapping.h"
#include "file_translation.h"


/*
static NTSTATUS WINAPI ZwCreateFile(HANDLE *FileHandle,
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

    // Translate path seperator.
    while (strchr(filename, '\\'))
        *strchr(filename, '\\') = '/';

    // I'm just going to tolower() everything.
    for (char *t = filename; *t; t++)
        *t = tolower(*t);

    //LogMessage("%u %s", dwCreationDisposition, filename);

    // Let's replace the path with a local one
    char *dummy = strstr(filename, "/dummy/");
    int new_filepath_length = strlen(dummy) + sizeof("."); // Length of the substring + the additional "."
    char *new_filepath = (char*) malloc(new_filepath_length); // allocate space for the new relative path + null
    memset(new_filepath, 0, new_filepath_length);
    memcpy(new_filepath, ".", 1);
    memcpy(new_filepath+1, dummy, strlen(dummy));

    switch (CreateDisposition) {
        case FILE_SUPERSEDED:
            *FileHandle = fopen(new_filepath, "r");
            break;
        case FILE_OPEN:
            if (access(new_filepath, F_OK) == 0){
                *FileHandle = fopen(new_filepath, "r+");
            }
            else {
                free(filename);
                free(new_filepath);
                return STATUS_NO_SUCH_FILE;
            }
            break;
            // This is the disposition used by CreateTempFile().
        case FILE_CREATED:
            *FileHandle = fopen(new_filepath, "w");
            // Unlink it immediately so it's cleaned up on exit.
            unlink(filename);
            break;
        default:
            abort();
    }

    DebugLog("%s => %p", new_filepath, *FileHandle);

    free(filename);
    free(new_filepath);

    return 0;
}

static NTSTATUS WINAPI ZwReadFile(HANDLE FileHandle,
                                  HANDLE Event,
                                  PVOID ApcRoutine,
                                  PVOID ApcContext,
                                  PIO_STATUS_BLOCK IoStatusBlock,
                                  PVOID Buffer,
                                  ULONG Length,
                                  LARGE_INTEGER *ByteOffset,
                                  PULONG Key)
{
    DebugLog("%p, %p, %#x", FileHandle, Buffer, Length);
    ((PIO_STATUS_BLOCK) IoStatusBlock)->Information = fread(Buffer, 1, Length, FileHandle);
    ((PIO_STATUS_BLOCK) IoStatusBlock)->DUMMYUNIONNAME.Status = STATUS_SUCCESS;
    return 0;
}

static NTSTATUS WINAPI ZwWriteFile(HANDLE FileHandle,
                               HANDLE Event,
                               PVOID ApcRoutine,
                               PVOID ApcContext,
                               PIO_STATUS_BLOCK IoStatusBlock,
                               PVOID Buffer,
                               ULONG Length,
                               LARGE_INTEGER *ByteOffset,
                               PULONG Key)
{
    DebugLog("%p, %p, %#x, %#x", FileHandle, Buffer, *ByteOffset, Length);

    fseek(FileHandle, *ByteOffset, SEEK_SET);
    fwrite(Buffer, 1, Length, FileHandle);
    return 0;
}
*/

// * TO IMPLEMENT *

STATIC NTSTATUS

WINAPI RtlDestroyHeap(HANDLE hHeap) // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI HeapDestroy(HANDLE hHeap) // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC DWORD

WINAPI GetShortPathNameW(LPCWSTR lpszLongPath,
                         LPWSTR lpszShortPath,
                         DWORD cchBuffer
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC DWORD

WINAPI GetShortPathNameA(LPCSTR lpszLongPath,
                         LPSTR lpszShortPath,
                         DWORD cchBuffer
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC UINT

WINAPI GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC UINT

WINAPI GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC int WINAPI
lstrlenW(LPCWSTR
lpString)
{
LogMessage("IMPLEMENT ME");
exit(1);
}

STATIC PVOID

WINAPI MapViewOfFileEx(HANDLE hFileMappingObject,
                       DWORD dwDesiredAccess,
                       DWORD dwFileOffsetHigh,
                       DWORD dwFileOffsetLow,
                       SIZE_T dwNumberOfBytesToMap,
                       VOID *lpBaseAddress
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI MoveFileExA(LPCSTR lpExistingFileName,
                   LPCSTR lpNewFileName,
                   DWORD dwFlags
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI MoveFileExW(LPCWSTR lpExistingFileName,
                   LPCWSTR lpNewFileName,
                   DWORD dwFlags
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RemoveDirectoryW(LPCWSTR lpPathName) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetFileInformationByHandleEx(HANDLE hFile,
                                    VOID *FileInformationClass, // TO FIX
                                    PVOID lpFileInformation,
                                    DWORD dwBufferSize) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI SetFileInformationByHandle(HANDLE hFile,
                                  VOID *FileInformationClass, // TO FIX
                                  PVOID lpFileInformation,
                                  DWORD dwBufferSize) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI LookupPrivilegeValueA(LPCSTR lpSystemName,
                             LPCSTR lpName,
                             PLUID lpLuid) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI AdjustTokenPrivileges(HANDLE TokenHandle,
                             BOOL DisableAllPrivileges,
                             PVOID NewState, // TO FIX
                             DWORD BufferLength,
                             PVOID PreviousState, // TO FIX
                             PDWORD ReturnLength) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI AddAccessAllowedAce(PVOID pAcl, // TO FIX
                           DWORD dwAceRevision,
                           DWORD AccessMask,
                           PVOID pSid) // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI AddAce(PVOID pAcl, // TO FIX
              DWORD dwAceRevision,
              DWORD dwStartingAceIndex,
              PVOID pAceList,
              DWORD nAceListLength) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetAce(PVOID pAcl, // FIX ME
              DWORD dwAceIndex,
              PVOID *pAce) // FIX ME
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}


STATIC BOOL

WINAPI GetAclInformation(PVOID pAcl, // FIX ME
                         PVOID pAclInformation,
                         DWORD nAclInformationLength,
                         PVOID dwAclInformationClass) // FIX ME
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}


STATIC BOOL

WINAPI GetKernelObjectSecurity(HANDLE Handle,
                               SECURITY_INFORMATION RequestedInformation,
                               PVOID pSecurityDescriptor, // FIX ME
                               DWORD nLength,
                               PVOID lpnLengthNeeded) // FIX ME
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC DWORD

WINAPI GetLengthSid(PVOID pSid) // FIX ME
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetSecurityDescriptorDacl(
        PVOID pSecurityDescriptor, // FIX ME
        PVOID lpbDaclPresent, // FIX ME
        PVOID *pDacl, // FIX ME
        PVOID lpbDaclDefaulted) // FIX ME
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetUserNameA(
        LPSTR lpBuffer,
        PVOID pcbBuffer // FIX ME
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI InitializeAcl(
        PVOID pAcl, // FIX ME
        DWORD nAclLength,
        DWORD dwAclRevision
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI InitializeSecurityDescriptor(
        PVOID pSecurityDescriptor, // FIX ME
        DWORD dwRevision
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI LookupAccountNameA(
        LPCSTR lpSystemName,
        LPCSTR lpAccountName,
        PVOID Sid, // FIX ME
        PVOID cbSid, // FIX ME
        LPSTR ReferencedDomainName,
        PVOID cchReferencedDomainName, // FIX ME
        PVOID peUse // FIX ME
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RBTrueColor(DWORD arg1, DWORD args) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RBGrayscale() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RBCStrMatchW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RBCalcDev() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI FlushViewOfFile(PVOID lpBaseAddress,
                       SIZE_T dwNumberOfBytesToFlush
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI ImpersonateLoggedOnUser(HANDLE hToken
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RevertToSelf() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI SetKernelObjectSecurity(
        HANDLE Handle,
        VOID *SecurityInformation, // TO FIX
        VOID *SecurityDescriptor // TO FIX
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI SetSecurityDescriptorDacl(
        VOID *pSecurityDescriptor, // TO FIX
        BOOL bDaclPresent,
        VOID *pDacl, // TO FIX
        BOOL bDaclDefaulted
) {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI SetUnhandledExceptionFilter() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI FormatMessageA() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI FlushFileBuffers() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI FindNextFileW() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI DeleteFile() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CreateFileMapping() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CreateDirectoryW() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CopyFileW() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CopyFileA() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CompareStringW() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI NtWriteFile() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI NtQueryPerformanceCounter() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI NtQueryInformationThread() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RtlRemoveVectoredExceptionHandler() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RtlQueryEnvironmentVariable_U() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RtlAddVectoredExceptionHandler() // TO FIX
{
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI ConvertStringSidToSidA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI ConvertStringSidToSidW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetSecurityInfo() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI IsWellKnownSid() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI LookupAccountSidA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI LookupAccountSidW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegDeleteKeyA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegDeleteKeyValueA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegDeleteValueA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegEnumKeyExA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegEnumKeyExW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegEnumValueA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegOpenKeyA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegOpenKeyW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegQueryValueExA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegQueryInfoKeyA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegQueryValueExW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegSetValueExW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI SetProcessValidCallTargets() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}


STATIC BOOL

WINAPI OpenProcess() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI QueryFullProcessImageNameA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI ZwCreateFile() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI ZwReadFile() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI ZwWriteFile() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI OpenProcessToken() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI ExpandEnvironmentStringsA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI FindFirstVolumeA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI FindNextVolumeA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI FindVolumeClose() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetComputerNameA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetCurrentDirectoryA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetFileAttributesExA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetVolumeInformationA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetVolumeNameForVolumeMountPointA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetVolumeNameForVolumeMountPointW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetVolumePathNameA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetVolumePathNamesForVolumeNameA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI QueryDosDeviceA() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI GetWindowsDirectoryW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI egEnumValueW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegEnumKeyW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegDeleteKeyW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegDeleteValueW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI RegCreateKeyW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI SearchPathW() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CoreScan() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CoreInit() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CoreUninit() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CoreDisinfect() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CoreNew() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CoreFree() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}

STATIC BOOL

WINAPI CoreVersion() {
    LogMessage("IMPLEMENT ME");
    exit(1);
}
// * END TO IMPLEMENT *

DECLARE_CRT_EXPORT("GetShortPathNameW", GetShortPathNameW);
DECLARE_CRT_EXPORT("GetShortPathNameA", GetShortPathNameA);
//DECLARE_CRT_EXPORT("GetSystemDirectoryA", GetSystemDirectoryA);
DECLARE_CRT_EXPORT("GetWindowsDirectoryA", GetWindowsDirectoryA);
DECLARE_CRT_EXPORT("lstrlenW", lstrlenW);
DECLARE_CRT_EXPORT("MapViewOfFileEx", MapViewOfFileEx);
DECLARE_CRT_EXPORT("MoveFileA", MoveFileA);
DECLARE_CRT_EXPORT("MoveFileW", MoveFileW);
DECLARE_CRT_EXPORT("MoveFileExA", MoveFileExA);
DECLARE_CRT_EXPORT("MoveFileExW", MoveFileExW);
DECLARE_CRT_EXPORT("RemoveDirectoryW", RemoveDirectoryW);
DECLARE_CRT_EXPORT("GetFileInformationByHandleEx", GetFileInformationByHandleEx);
DECLARE_CRT_EXPORT("SetFileInformationByHandle", SetFileInformationByHandle);
DECLARE_CRT_EXPORT("LookupPrivilegeValueA", LookupPrivilegeValueA);
DECLARE_CRT_EXPORT("AdjustTokenPrivileges", AdjustTokenPrivileges);
DECLARE_CRT_EXPORT("AddAccessAllowedAce", AddAccessAllowedAce);
DECLARE_CRT_EXPORT("AddAce", AddAce);
DECLARE_CRT_EXPORT("GetAce", GetAce);
DECLARE_CRT_EXPORT("GetAclInformation", GetAclInformation);
DECLARE_CRT_EXPORT("GetKernelObjectSecurity", GetKernelObjectSecurity);
DECLARE_CRT_EXPORT("GetLengthSid", GetLengthSid);
DECLARE_CRT_EXPORT("GetSecurityDescriptorDacl", GetSecurityDescriptorDacl);
DECLARE_CRT_EXPORT("GetUserNameA", GetUserNameA);
DECLARE_CRT_EXPORT("InitializeAcl", InitializeAcl);
DECLARE_CRT_EXPORT("InitializeSecurityDescriptor", InitializeSecurityDescriptor);
DECLARE_CRT_EXPORT("LookupAccountNameA", LookupAccountNameA);
DECLARE_CRT_EXPORT("RBTrueColor", RBTrueColor);
DECLARE_CRT_EXPORT("RBGrayscale", RBGrayscale);
DECLARE_CRT_EXPORT("RBCStrMatchW", RBCStrMatchW);
DECLARE_CRT_EXPORT("RBCalcDev", RBCalcDev);
DECLARE_CRT_EXPORT("FlushViewOfFile", FlushViewOfFile);
DECLARE_CRT_EXPORT("ImpersonateLoggedOnUser", ImpersonateLoggedOnUser);
DECLARE_CRT_EXPORT("RevertToSelf", RevertToSelf);
DECLARE_CRT_EXPORT("SetKernelObjectSecurity", SetKernelObjectSecurity);
DECLARE_CRT_EXPORT("SetSecurityDescriptorDacl", SetSecurityDescriptorDacl);
DECLARE_CRT_EXPORT("SetUnhandledExceptionFilter", SetUnhandledExceptionFilter);
DECLARE_CRT_EXPORT("HeapDestroy", HeapDestroy);
DECLARE_CRT_EXPORT("FormatMessageA", FormatMessageA);
DECLARE_CRT_EXPORT("FlushFileBuffers", FlushFileBuffers);
DECLARE_CRT_EXPORT("FindNextFileW", FindNextFileW);
DECLARE_CRT_EXPORT("DeleteFile", DeleteFile);
DECLARE_CRT_EXPORT("CreateFileMapping", CreateFileMapping);
DECLARE_CRT_EXPORT("CreateDirectoryW", CreateDirectoryW);
DECLARE_CRT_EXPORT("CopyFileW", CopyFileW);
DECLARE_CRT_EXPORT("CopyFileA", CopyFileA);
DECLARE_CRT_EXPORT("CompareStringW", CompareStringW);
DECLARE_CRT_EXPORT("NtWriteFile", NtWriteFile);
DECLARE_CRT_EXPORT("NtQueryPerformanceCounter", NtQueryPerformanceCounter);
DECLARE_CRT_EXPORT("NtQueryInformationThread", NtQueryInformationThread);
DECLARE_CRT_EXPORT("RtlRemoveVectoredExceptionHandler", RtlRemoveVectoredExceptionHandler);
DECLARE_CRT_EXPORT("RtlQueryEnvironmentVariable_U", RtlQueryEnvironmentVariable_U);
DECLARE_CRT_EXPORT("RtlDestroyHeap", RtlDestroyHeap);
//DECLARE_CRT_EXPORT("RtlDeleteFunctionTable", RtlDeleteFunctionTable);
DECLARE_CRT_EXPORT("RtlAddVectoredExceptionHandler", RtlAddVectoredExceptionHandler);
//DECLARE_CRT_EXPORT("RtlAddFunctionTable", RtlAddFunctionTable);
DECLARE_CRT_EXPORT("ConvertStringSidToSidA", ConvertStringSidToSidA);
DECLARE_CRT_EXPORT("ConvertStringSidToSidW", ConvertStringSidToSidW);
DECLARE_CRT_EXPORT("GetSecurityInfo", GetSecurityInfo);
DECLARE_CRT_EXPORT("IsWellKnownSid", IsWellKnownSid);
DECLARE_CRT_EXPORT("LookupAccountSidA", LookupAccountSidA);
DECLARE_CRT_EXPORT("LookupAccountSidW", LookupAccountSidW);
DECLARE_CRT_EXPORT("RegDeleteKeyA", RegDeleteKeyA);
DECLARE_CRT_EXPORT("RegDeleteKeyValueA", RegDeleteKeyValueA);
DECLARE_CRT_EXPORT("RegDeleteValueA", RegDeleteValueA);
DECLARE_CRT_EXPORT("RegEnumKeyExA", RegEnumKeyExA);
DECLARE_CRT_EXPORT("RegEnumKeyExW", RegEnumKeyExW);
DECLARE_CRT_EXPORT("RegEnumValueA", RegEnumValueA);
DECLARE_CRT_EXPORT("RegOpenKeyW", RegOpenKeyW);
DECLARE_CRT_EXPORT("RegQueryValueExA", RegQueryValueExA);
DECLARE_CRT_EXPORT("RegQueryInfoKeyA", RegQueryInfoKeyA);
DECLARE_CRT_EXPORT("RegQueryValueExW", RegQueryValueExW);
DECLARE_CRT_EXPORT("RegSetValueExW", RegSetValueExW);
DECLARE_CRT_EXPORT("OpenProcess", OpenProcess);
DECLARE_CRT_EXPORT("QueryFullProcessImageNameA", QueryFullProcessImageNameA);
DECLARE_CRT_EXPORT("ZwCreateFile", ZwCreateFile);
DECLARE_CRT_EXPORT("ZwReadFile", ZwReadFile);
DECLARE_CRT_EXPORT("ZwWriteFile", ZwWriteFile);
DECLARE_CRT_EXPORT("OpenProcessToken", OpenProcessToken);
DECLARE_CRT_EXPORT("ExpandEnvironmentStringsA", ExpandEnvironmentStringsA);
DECLARE_CRT_EXPORT("FindFirstVolumeA", FindFirstVolumeA);
DECLARE_CRT_EXPORT("FindNextVolumeA", FindNextVolumeA);
DECLARE_CRT_EXPORT("FindVolumeClose", FindVolumeClose);
DECLARE_CRT_EXPORT("GetComputerNameA", GetComputerNameA);
DECLARE_CRT_EXPORT("GetCurrentDirectoryA", GetCurrentDirectoryA);
DECLARE_CRT_EXPORT("GetFileAttributesExA", GetFileAttributesExA);
DECLARE_CRT_EXPORT("GetVolumeInformationA", GetVolumeInformationA);
DECLARE_CRT_EXPORT("GetVolumeNameForVolumeMountPointA",GetVolumeNameForVolumeMountPointA);
DECLARE_CRT_EXPORT("GetVolumeNameForVolumeMountPointW", GetVolumeNameForVolumeMountPointW);
DECLARE_CRT_EXPORT("GetVolumePathNameA", GetVolumePathNameA);
DECLARE_CRT_EXPORT("GetVolumePathNamesForVolumeNameA", GetVolumePathNamesForVolumeNameA);
DECLARE_CRT_EXPORT("QueryDosDeviceA", QueryDosDeviceA);
//DECLARE_CRT_EXPORT("GetWindowsDirectoryW",GetWindowsDirectoryW);
DECLARE_CRT_EXPORT("egEnumValueW", egEnumValueW);
DECLARE_CRT_EXPORT("RegEnumKeyW", RegEnumKeyW);
DECLARE_CRT_EXPORT("RegDeleteKeyW", RegDeleteKeyW);
DECLARE_CRT_EXPORT("RegDeleteValueW", RegDeleteValueW);
DECLARE_CRT_EXPORT("RegCreateKeyW", RegCreateKeyW);
DECLARE_CRT_EXPORT("SearchPathW", SearchPathW);
DECLARE_CRT_EXPORT("CoreScan", CoreScan);
//DECLARE_CRT_EXPORT("CoreInit", CoreInit);
DECLARE_CRT_EXPORT("CoreUninit", CoreUninit);
DECLARE_CRT_EXPORT("CoreDisinfect", CoreDisinfect);
DECLARE_CRT_EXPORT("CoreNew", CoreNew);
DECLARE_CRT_EXPORT("CoreFree", CoreFree);
DECLARE_CRT_EXPORT("CoreVersion", CoreVersion);