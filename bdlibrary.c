#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/unistd.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <mcheck.h>
#include <err.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "hook.h"
#include "log.h"
#include "rsignal.h"
#include "engineboot.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "openscan.h"
#include "bdlibrary.h"
#include "winapi/Heap.h"
#include "allocation_tracker.h"

#if defined(SHARED_MEM) || defined(LIBAFL_FUZZING) || defined(HONGGFUZZ_FUZZING)
#include "shared_mem_file_handling.h"
#endif

int WINAPI (*CoreInit)(const char *root_dir, const char *plugin_dir);

void * WINAPI (*CoreNewInstance)();

int WINAPI (*CoreDeleteInstance)(void *core_instance);

int WINAPI (*CoreSet)(void *instance, unsigned int cmd, void *action, void *dummy1);

void * WINAPI (*CoreGet)(void *instance, unsigned int cmd, void *dummy);

struct pe_image image = {
        .name   = { 0 },
        .entry  = NULL,
        .image = NULL,
        .size = 0,
        .type = 0,
        .nt_hdr = NULL,
        .opt_hdr = NULL
};

// this is set to true before ScanFile is called. To false once ScanFile returned.
bool SCAN_STARTED = false;

#ifdef __cplusplus
extern "C" {
#endif

int LoadModule(const char *engine_path) {
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS PeHeader;

    if (engine_path != NULL) {
        strncpy(image.name, engine_path, strlen(engine_path));
    }

    // Load the bdcore module.
    if (pe_load_library(image.name, &image.image, &image.size) == false) {
        LogMessage("You must add the dll and vdm files to the engine directory");
        return -1;
    }

    // Handle relocations, imports, etc.
    link_pe_images(&image, 1);


    // Fetch the headers to get base offsets.
    DosHeader = (PIMAGE_DOS_HEADER) image.image;
    PeHeader = (PIMAGE_NT_HEADERS) ((uintptr_t)image.image + DosHeader->e_lfanew);

    // Load any additional exports.
    if (!process_extra_exports(image.image, PeHeader->OptionalHeader.BaseOfCode, "engine/bdcore.map")) {
#ifndef NDEBUG
        LogMessage("The map file wasn't found, symbols wont be available");
#endif
    } else {
        // Calculate the commands needed to get export and map symbols visible in gdb.
        if (IsGdbPresent()) {
            LogMessage("GDB: add-symbol-file %s %#p+%#x",
                       image.name,
                       image.image,
                       PeHeader->OptionalHeader.BaseOfCode);
            LogMessage("GDB: shell bash genmapsym.sh %#p+%#x symbols_%d.o < %s",
                       image.image,
                       PeHeader->OptionalHeader.BaseOfCode,
                       getpid(),
                       "engine/mpengine.map");
            LogMessage("GDB: add-symbol-file symbols_%d.o 0", getpid());
            __debugbreak();
        }
    }

    if (get_export("CoreInit4", &CoreInit) == -1) {
        errx(EXIT_FAILURE, "Failed to resolve CoreInit exported function");
    }

    if (get_export("CoreNewInstance", &CoreNewInstance) == -1) {
        errx(EXIT_FAILURE, "Failed to resolve CoreNewInstance exported function");
    }

    if (get_export("CoreDeleteInstance", &CoreDeleteInstance) == -1) {
        errx(EXIT_FAILURE, "Failed to resolve CoreDeleteInstance exported function");
    }

    if (get_export("CoreSet", &CoreSet) == -1) {
        errx(EXIT_FAILURE, "Failed to resolve CoreSet exported function");
    }

    if (get_export("CoreGet", &CoreGet) == -1) {
        errx(EXIT_FAILURE, "Failed to resolve CoreGet exported function");
    }

    // Call DllMain()
    image.entry((PVOID) 'BDCO', DLL_PROCESS_ATTACH, NULL);

    return 0;
}

int InitializeCore(const char *root_dir, const char *plugin_dir) {
    allocation_tracker_set_phase(ALLOCATION_PHASE_CORE_INIT);
    int init = (int) CoreInit(root_dir, plugin_dir);
    allocation_tracker_set_phase(ALLOCATION_PHASE_NONE);
    if (init != 0) {
        return -1;
    }
    return init;
}

void *CreateCoreNewInstance() {
    allocation_tracker_set_phase(ALLOCATION_PHASE_INSTANCE_CREATE);
    void *core_instance = CoreNewInstance();
    allocation_tracker_set_phase(ALLOCATION_PHASE_NONE);
    if (core_instance == NULL) {
        return NULL;
    }

    //CoreSet(core_instance, HEURISTICS, ENABLE, (void *)CoreSet);
    //CoreSet(core_instance, EXE_UNPACK, ENABLE, (void *)CoreSet);
    //CoreSet(core_instance, ARCHIVE_UNPACK, ENABLE, (void *)CoreSet);
    //CoreSet(core_instance, EMAIL_UNPACK, ENABLE, (void *)CoreSet);

    return core_instance;
}

int DeleteCoreInstance(void *core_instance) {
    int delete_instance_result = CoreDeleteInstance(core_instance);
    if(delete_instance_result != 0) {
        return -1;
    }

    return 0;
}

void ResetScanState(void) {
#if defined(SHARED_MEM) || defined(LIBAFL_FUZZING) || defined(HONGGFUZZ_FUZZING)
    delete_mmap_file();
#endif
    SCAN_STARTED = false;
}

#if defined(LIBAFL_FUZZING) || defined(HONGGFUZZ_FUZZING)
int ScanFile(void *core_instance, uint8_t *buf, size_t size, char *file_path) {
    SCAN_STARTED = true; 
    allocation_tracker_set_phase(ALLOCATION_PHASE_SCAN);
    heap_alloc_count = 0;
    heap_free_count = 0;
    heap_realloc_count = 0;

    new_mmap_buffer(buf, size, file_path);
    //LogMessage("Scan started: %p %#x %s", buf, size, file_path);
    CoreSet(core_instance, SCAN, 0x0, file_path);
    //LogMessage("Scan ended: %p %#x %s", buf, size, file_path);
    delete_mmap_file();
    SCAN_STARTED = false;
    allocation_tracker_set_phase(ALLOCATION_PHASE_NONE);
    return 0;
}

#elif SHARED_MEM
int ScanFile(void *core_instance, char *file_path) {
    SCAN_STARTED = true;
    allocation_tracker_set_phase(ALLOCATION_PHASE_SCAN);
    DebugLog("Scan started: %s, %p, %#x", file_path, g_mmap_file.data, g_mmap_file.size);
    heap_alloc_count = 0;
    heap_free_count = 0;
    heap_realloc_count = 0;

    CoreSet(core_instance, SCAN, 0x0, file_path);

    SCAN_STARTED = false;
    allocation_tracker_set_phase(ALLOCATION_PHASE_NONE);
    DebugLog("Scan ended");

    return 0;
}
#else

int ScanFile(void *core_instance, char *file_path) {
    SCAN_STARTED = true; 
    allocation_tracker_set_phase(ALLOCATION_PHASE_SCAN);
    heap_alloc_count = 0;
    heap_free_count = 0;
    heap_realloc_count = 0;
    CoreSet(core_instance, SCAN, 0x0, file_path);
    SCAN_STARTED = false;
    allocation_tracker_set_phase(ALLOCATION_PHASE_NONE);
    return 0;
}

#endif

int SetScanCallBack(void *core_instance, int (*func)(void *, SCAN_RESULT *) __attribute__((ms_abi))) {
    int set_callback = (int) CoreSet(core_instance, REGISTER_CALLBACK, (void *) func, NULL);
    return set_callback;
}

bool UnloadModule() {
    if (!pe_unload_library(image)) {
        return false;
    }

    return true;
}

#ifdef __cplusplus
} 
#endif
