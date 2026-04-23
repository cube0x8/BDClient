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
#include <sys/types.h>
#include <sys/stat.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "file_translation.h"
#include "winstrings.h"

BOOL WINAPI CreateDirectoryA(LPCSTR lpPathName, PVOID lpSecurityAttributes)
{
    DebugLog("%p [%s]", lpPathName, lpPathName);

    struct stat st = {0};
    if (stat(lpPathName, &st) == -1) {
        mkdir(lpPathName, 0700);
    }

    return true;
}

STATIC BOOL WINAPI RemoveDirectoryA(LPCSTR lpPathName)
{
    DebugLog("%p [%s]", lpPathName, lpPathName);
    // rmdir(lpPathName);
    return true;
}

//DECLARE_CRT_EXPORT("CreateDirectoryA", CreateDirectoryA);
DECLARE_CRT_EXPORT("RemoveDirectoryA", RemoveDirectoryA);
