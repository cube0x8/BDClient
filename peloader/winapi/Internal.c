#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>

#include "winnt_types.h"
#include "codealloc.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"
#include "Memory.h"
#include "instrumentation.h"

char *unpacker_modules[] = {
    "ACProtect.xmd",
    "ahpack.xmd",
    "armadillo.xmd",
    "ASProtect_New.xmd",
    "atcinject.xmd",
    "bepack.xmd",
    "cryexe.xmd",
    "crypt.xmd",
    "cryptcom.xmd",
    "diet.xmd",
    "dza.xmd",
    "eclipse.xmd",
    "enigma.xmd",
    "epack.xmd",
    "exe32pack.xmd",
    "exepack.xmd",
    "ezip.xmd",
    "ice.xmd",
    "kcuf.xmd",
    "krypton.xmd",
    "lzexe.xmd",
    "mew.xmd",
    "molebox.xmd",
    "morphine.xmd",
    "morphinep.xmd",
    "mpack.xmd",
    "mpress_msil.xmd",
    "nspack.xmd",
    "obsidium.xmd",
    "packman.xmd",
    "pcguard.xmd",
    "pcshrink.xmd",
    "pec3.xmd",
    "pecrypt32.xmd",
    "ped.xmd",
    "pelock.xmd",
    "pelocknt.xmd",
    "penguin.xmd",
    "pepack.xmd",
    "petite.xmd",
    "pex.xmd",
    "pklite.xmd",
    "pklite32.xmd",
    "protect.xmd",
    "relpack.xmd",
    "rjcrush.xmd",
    "secupack.xmd",
    "shcom.xmd",
    "shrinker.xmd",
    "softdefender.xmd",
    "spack.xmd",
    "sqr.xmd",
    "stpe.xmd",
    "tpack.xmd",
    "ucexe.xmd",
    "upolyx.xmd",
    "vgcrypt.xmd",
    "wwpack.xmd",
    "xcomor.xmd",
    "xpack.xmd",
    "apack.xmd",
    "aplib.xmd",
    "arm.xmd",
    "armadillo_2xx.xmd",
    "armp.xmd",
    "aspack.xmd",
    "aspack2k.xmd",
    "beria.xmd",
    "crunch.xmd",
    "dotfix.xmd",
    "dxpack.xmd",
    "expressor.xmd",
    "fakeneo.xmd",
    "fsg.xmd",
    "genpack.xmd",
    "hmimys.xmd",
    "jdpack.xmd",
    "krypton_old.xmd",
    "lamecrypt.xmd",
    "momma.xmd",
    "mslrh.xmd",
    "nakedpack.xmd",
    "nPack.xmd",
    "packlite.xmd",
    "pcpec.xmd",
    "pe_crypt.xmd",
    "pe_patch.xmd",
    "pec.xmd",
    "pencrypt.xmd",
    "peninja.xmd",
    "perplex.xmd",
    "peshield.xmd",
    "pespin.xmd",
    "polycrypt.xmd",
    "polyene.xmd",
    "porno.xmd",
    "rcryptor.xmd",
    "softcomp.xmd",
    "sue.xmd",
    "telock.xmd",
    "upack.xmd",
    "upc.xmd",
    "upx.xmd",
    "upxold.xmd",
    "winkript.xmd",
    "wonk.xmd.xmd",
    "wwpack32.xmd",
    "yoda.xmd"
};

#ifdef __cplusplus
extern "C" {
#endif

typedef struct XMD_HEADER {
    char begin[9];
    char *plugin_name;
} XMD_HEADER;


void WINAPI RtlAcquirePebLock(void) {
    DebugLog("");
    return;
}

void WINAPI RtlReleasePebLock(void) {
    DebugLog("");
    return;
}

NTSTATUS WINAPI LdrGetDllHandle(PWCHAR pwPath, PVOID unused, PUNICODE_STRING ModuleFileName, PHANDLE pHModule) {
    DebugLog("%S %p %p %p", pwPath, unused, ModuleFileName, pHModule);
    pHModule = (PHANDLE) 'LDRP';
    return 0;
}

NTSTATUS WINAPI EtwRegister(PVOID ProvideId, PVOID EnableCallback, PVOID CallbackContext, PVOID RegHandle) {
    DebugLog("");
    return 0;
}

NTSTATUS WINAPI EtwUnregister(HANDLE RegHandle) {
    DebugLog("");
    return 0;
}

ULONG WINAPI EtwEventWrite(HANDLE RegHAndle, PVOID EventDescriptor, ULONG UserDataCount, PVOID UserData, PVOID a5) {
    DebugLog("");
    return 0;
}

static NTSTATUS WINAPI LdrLoadDll(PWCHAR PathToFile,
                                  ULONG Flags,
                                  PUNICODE_STRING ModuleFilename,
                                  PHANDLE ModuleHandle) {
    char *PathToFileA = CreateAnsiFromWide(PathToFile);
    char *ModuleFilenameA = CreateAnsiFromWide(ModuleFilename->Buffer);

    DebugLog("%p [%s], %p [%s], %p, %#x", PathToFile, PathToFileA, ModuleFilename, ModuleFilenameA, ModuleHandle, Flags);

    *ModuleHandle = (HANDLE) 'LOAD';

    free(PathToFileA);
    free(ModuleFilenameA);

    return 0;
}

static NTSTATUS WINAPI LdrUnloadDll(HANDLE ModuleHandle) {
    DebugLog("%p", ModuleHandle);

    return 0;
}

static NTSTATUS WINAPI LdrGetProcedureAddress(HMODULE Module,
                                              PANSI_STRING Name,
                                              WORD Ordinal,
                                              PVOID *Address) {
    DebugLog("%p %s %hu %p", Module, Name->buf, Ordinal, Address);

    // Recognizable value to crash on.
    *Address = (PVOID) 'LDRZ';

    // Search if the requested function has been already exported.
    ENTRY e = {Name->buf, NULL}, *ep;
    hsearch_r(e, FIND, &ep, &crtexports);

    // If found, store the pointer and return.
    if (ep != NULL) {
        *Address = ep->data;
        return 0;
    }

    if (strcmp(Name->buf, "EtwEventRegister") == 0) {
        *Address = (PVOID) EtwRegister;
    }
    if (strcmp(Name->buf, "EtwEventUnregister") == 0) {
        *Address = (PVOID) EtwUnregister;
    }
    if (strcmp(Name->buf, "EtwEventWrite") == 0) {
        *Address = (PVOID) EtwEventWrite;
    }

    DebugLog("FIXME: %s unresolved", Name->buf);

    return 0;
}

static NTSTATUS WINAPI NtReadFile(FILE *FileHandle,
                                  HANDLE Event,
                                  PVOID ApcRoutine,
                                  PVOID ApcContext,
                                  PIO_STATUS_BLOCK IoStatusBlock,
                                  PVOID Buffer,
                                  ULONG Length,
                                  LARGE_INTEGER *ByteOffset,
                                  PULONG Key)
{
    DebugLog("%p, %p, %p, %#x", (void *)FileHandle, IoStatusBlock, Buffer, Length);
    ((PIO_STATUS_BLOCK) IoStatusBlock)->Information = fread(Buffer, 1, Length, FileHandle);
    ((PIO_STATUS_BLOCK) IoStatusBlock)->DUMMYUNIONNAME.Status = STATUS_SUCCESS;
    return 0;
}

STATIC BOOL WINAPI NtFreeVirtualMemory(HANDLE ProcessHandle,
                                       PVOID *BaseAddress,
                                       SIZE_T *RegionSize,
                                       ULONG FreeType)
{
    DebugLog("%p, %p, %#x", ProcessHandle, *BaseAddress, *RegionSize);

    if (FreeType == MEM_RELEASE){
#if defined(HONGGFUZZ_FUZZING)
        if (!deallocateMemory(*BaseAddress) && RegionSize != NULL && *RegionSize != 0U) {
            size_t SizeToDeallocate = ROUND_UP(*RegionSize, PAGE_SIZE);
            munmap(*BaseAddress, SizeToDeallocate);
        }
#else
        size_t SizeToDeallocate = ROUND_UP(*RegionSize, PAGE_SIZE);
        //munmap(*BaseAddress, SizeToDeallocate);
#endif
    }
    return TRUE;
}

static NTSTATUS WINAPI NtProtectVirtualMemory(HANDLE ProcessHandle,
                                              PVOID *BaseAddress,
                                              ULONG *NumberOfBytesToProtect,
                                              ULONG NewAccessProtection,
                                              ULONG *OldAccessProtection)
{
    DebugLog("%p, %p, %#x, %#x", ProcessHandle, *BaseAddress, *NumberOfBytesToProtect, NewAccessProtection);

    // Check if we are protecting a XMD plugin
    if (strncmp(&((char *)(*BaseAddress))[2], "XMDbegin", 8) == 0) {
        // Discard 0x20 padding
        int i = 10;
        while (((char *)(*BaseAddress))[i] == '\x20'){
            i++;
            continue;
        }

        const char *plugin_name_start = &((char *)(*BaseAddress))[i];

        // Calculate plugin name string length
        size_t plugin_name_length = 0;
        while (((char *)(*BaseAddress))[i] != '\x0D'){
            i++;
            plugin_name_length++;
        }

        char *plugin_name = (char *) calloc(plugin_name_length + 1, sizeof(char));

        strncpy(plugin_name, plugin_name_start, plugin_name_length);

        DebugLog("Plugin name: %s", plugin_name);

        ModuleInstrumentationCallback2(plugin_name, plugin_name_length, *BaseAddress, *NumberOfBytesToProtect);

#ifdef LOG_VIRTUAL_MEM_RANGE
        char memory_range_fmt[255] = "Memory range for %s: %p - %p. Size: %#x\n";
        char memory_range_str[255] = { 0 };
        FILE *fp = fopen( "./virtual_mem_range.txt", "a+" );
        snprintf(memory_range_str, 255, memory_range_fmt, plugin_name, *BaseAddress, (uintptr_t)*BaseAddress + *NumberOfBytesToProtect, *NumberOfBytesToProtect);
        fputs(memory_range_str, fp);
        fclose(fp);
#endif

#ifdef DUMP_PLUGINS
        char decrypted_plugin_fmt[255] = "./%s/%s";
        char decrypted_plugin_str[255] = { 0 };
        snprintf(decrypted_plugin_str, 255, decrypted_plugin_fmt, "./decrypted_plugins/", plugin_name);
        FILE *decrypted_plugin = fopen(decrypted_plugin_str, "wb");
        fwrite(*BaseAddress, 1, *NumberOfBytesToProtect, decrypted_plugin);
        fclose(decrypted_plugin);
#endif
        /*
        i = 0;
        while(i < sizeof(unpacker_modules) / sizeof(char *)) {
            if (strcmp(plugin_name, unpacker_modules[i]) == 0) {
                UnpackerModuleInstrumentationCallback(plugin_name, plugin_name_length, *BaseAddress, *NumberOfBytesToProtect);
                break;
            }
            i++;
        }
        */
    }

    return 0;
}

STATIC NTSTATUS WINAPI NtAllocateVirtualMemory(HANDLE ProcessHandle,
                                        PVOID *BaseAddress,
                                        ULONG_PTR ZeroBits,
                                        SIZE_T* RegionSize,
                                        ULONG AllocationType,
                                        ULONG Protect)
{

    DebugLog("%p, %p, %#x, %#x, %#x", ProcessHandle, BaseAddress, *RegionSize, AllocationType, Protect);

    size_t SizeToAllocate = ROUND_UP(*RegionSize, PAGE_SIZE);

    if (AllocationType & ~(MEM_COMMIT | MEM_RESERVE)) {
        DebugLog("AllocationType %#x not implemnted", AllocationType);
        return STATUS_NOT_IMPLEMENTED;
    }

    // This VirtualAlloc() always returns PAGE_EXECUTE_READWRITE memory.
    if (Protect & PAGE_READWRITE){
        *BaseAddress = mmap(NULL, SizeToAllocate, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1 ,0);
        *RegionSize = SizeToAllocate;
        DebugLog("Virtual memory zone from %p to %p", *BaseAddress, (uintptr_t)*BaseAddress + SizeToAllocate);
    }
    else if (Protect & PAGE_EXECUTE_READWRITE) {
        DebugLog("JIT PAGE_EXECUTE_READWRITE Allocation Requested");
        *BaseAddress = mmap(NULL, SizeToAllocate, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1 ,0);
        *RegionSize = SizeToAllocate;
        DebugLog("Virtual memory zone from %p to %p", *BaseAddress, (uintptr_t)*BaseAddress + SizeToAllocate);
    }
    else {
        DebugLog("flProtect flags %#x not implemented", Protect);
        return STATUS_NOT_IMPLEMENTED;
    }

    return 0;
}

STATIC NTSTATUS WINAPI LdrDisableThreadCalloutsForDll(HMODULE hDll)
{
    DebugLog("%p", hDll);

    return 0;
}

NTSTATUS WINAPI NtCreateFile(FILE **FileHandle,
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
    char *filename = CreateAnsiFromWide(ObjectAttributes->name->Buffer);
    DebugLog("%p, %#x, %p, [%s]", FileHandle, DesiredAccess, ObjectAttributes, filename);

    // Translate path seperator.
    while (strchr(filename, '\\'))
        *strchr(filename, '\\') = '/';

    uintptr_t filename_original_ptr = (uintptr_t) filename;

    if (filename[0] == '/' && filename[1] == '?' && filename[2] == '?' && filename[3] == '/') {
        filename = &filename[4];
    }

    if ((filename[0] == 'c' || filename[0] == 'C') && filename[1] == ':' && filename[2] == '/') {
        filename = &filename[3];
    }

    DebugLog("%s => %s", filename_original_ptr, filename);

    switch (CreateDisposition) {
        case FILE_SUPERSEDED:
            *FileHandle = fopen(filename, "r");
            break;
        case FILE_OPEN:
            if (access(filename, F_OK) == 0){
                *FileHandle = fopen(filename, "r+");
            }
            else {
                filename = (char *)filename_original_ptr;
                free(filename);
                return STATUS_NO_SUCH_FILE;
            }
            break;
            // This is the disposition used by CreateTempFile().
        case FILE_CREATED:
            *FileHandle = fopen(filename, "w");
            // Unlink it immediately so it's cleaned up on exit.
            unlink(filename);
            break;
        default:
            abort();
    }
    
    filename = (char *)filename_original_ptr;

    free(filename);

    return 0;
}

#ifdef __cplusplus
}
#endif


DECLARE_CRT_EXPORT("RtlAcquirePebLock", RtlAcquirePebLock);

DECLARE_CRT_EXPORT("RtlReleasePebLock", RtlReleasePebLock);

DECLARE_CRT_EXPORT("LdrGetDllHandle", LdrGetDllHandle);

DECLARE_CRT_EXPORT("LdrLoadDll", LdrLoadDll);

DECLARE_CRT_EXPORT("LdrUnloadDll", LdrUnloadDll);

DECLARE_CRT_EXPORT("LdrGetProcedureAddress", LdrGetProcedureAddress);

DECLARE_CRT_EXPORT("NtReadFile", NtReadFile);

DECLARE_CRT_EXPORT("NtFreeVirtualMemory", NtFreeVirtualMemory);

DECLARE_CRT_EXPORT("NtProtectVirtualMemory", NtProtectVirtualMemory);

DECLARE_CRT_EXPORT("NtAllocateVirtualMemory", NtAllocateVirtualMemory);

DECLARE_CRT_EXPORT("LdrDisableThreadCalloutsForDll", LdrDisableThreadCalloutsForDll);

DECLARE_CRT_EXPORT("NtCreateFile", NtCreateFile);
