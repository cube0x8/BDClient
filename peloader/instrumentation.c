#include<stddef.h>
#include<stdint.h>
#include<string.h>
#include<stdbool.h>
#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "instrumentation.h"
#include "module_ranges_shm.h"

BOOL __noinline FilenameInstrumentationCallback(char *filename)
{
    // Prevent the call from being optimized away.
    if (strlen(filename) == 0) {
        return FALSE;
    }

    asm volatile ("");
    return TRUE;
}

int __noinline ModuleInstrumentationCallback2(char *ModuleName, size_t ModuleNameLength, void *ModuleBaseAddress, size_t ModuleSize)
{
    // Prevent the call from being optimized away.
    if (strlen(ModuleName) != ModuleNameLength) {
        return 0;
    } 
    
    // useless check to be sure we get the right values in the right registers
    if ((uintptr_t) ModuleBaseAddress - ModuleSize == 0) {
        return 0;
    }

    module_ranges_shm_publish(ModuleName, (uintptr_t)ModuleBaseAddress, ModuleSize);

    asm volatile ("");
    return 1;
}
