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
#include "instrumentation.h"
#include "hook.h"
#include "log.h"
#include "bdlibrary.h"

#ifdef SHARED_MEM
#include "shared_mem_file_handling.h"
#endif

#define DEFUALT_ROOT_SYSTEM_DIR "dummy"
#define BDCORE_DIR "./engine/x64/bdcore.dll"

# ifndef FUZZ
int WINAPI MyScanCallback(void *arg1, SCAN_RESULT *Result)
{
    if (Result == NULL)
        return 0;
    if (Result->Flags == 0 || Result->Flags == 0x40)
        LogMessage("%s (%s) => No threat detected!", Result->TmpFileName, Result->RealFileName);
    else if (Result->Flags == 0x240)
        return 0;
    else if (Result->Flags == 0x200000)
        LogMessage("An error occured. File unreadable?");
    else if (Result->Flags == 0x800040)
        LogMessage("Unpacking archive: %s", Result->RealFileName);
    else if (Result->Flags == 0x800240)
        LogMessage("Unpacking binary: %s", Result->RealFileName);
    else if (Result->Flags == 0x40)
        LogMessage("An error occured: %s", Result->RealFileName);
    else if (Result->Flags & 0x40000000)
        LogMessage("Threat Detected! %s (%s) => %s", Result->TmpFileName, Result->RealFileName, Result->Signature);
    else
        LogMessage("Unknown flag");
    return 0;
}

# else
int WINAPI MyScanCallback(void *arg1, SCAN_RESULT *Result)
{
    return 0;
}
# endif

/*
// Any usage limits to prevent bugs disrupting system.
const struct rlimit kUsageLimits[] = {
        [RLIMIT_FSIZE]  = { .rlim_cur = 0x20000000, .rlim_max = 0x20000000 },
        [RLIMIT_CPU]    = { .rlim_cur = 3600,       .rlim_max = RLIM_INFINITY },
        [RLIMIT_CORE]   = { .rlim_cur = 0,          .rlim_max = 0 },
        [RLIMIT_NOFILE] = { .rlim_cur = 1024,         .rlim_max = 1024 },
};
*/

VOID ResourceExhaustedHandler(int Signal) {
    errx(EXIT_FAILURE, "Resource Limits Exhausted, Signal %s", strsignal(Signal));
}

char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = (char **) malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}

int main(int argc, char **argv, char **envp)
{
    if (argc < 2) {
        printf("Usage: ./bdclient_x64 [OPTIONS] file1 file2 ...\n \
        Options:\n \
        --root_dir: root directory path\n");
        return -1;
    }

    char root_system_dir[1000] = { 0 };
    int file_to_scan_start_index = 1;
    bool custom_root_dir = false;
    int file_index = -1;
    int file_count = 0;
    int loop = 0;

    // Iterate through the command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--root-system-dir") == 0) {
            // Check if there's a value provided after the switch
            if (i + 1 < argc) {
                strncpy(root_system_dir, argv[i+1], sizeof(root_system_dir));
                custom_root_dir = true;
                i++; // Move to the next argument
            } else {
                fprintf(stderr, "Error: Missing value for --root-system-dir.\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--loop") == 0) {
            loop = atoi(argv[i+1]);
            i++;
        } else if (strncmp(argv[i], "--", 2) == 0) {
            // If it starts with "--" but is not a recognized switch, fail
            fprintf(stderr, "Error: Unsupported switch: %s\n", argv[i]);
            return 1;
        } else {
            // If it's not a switch, assume it's the first file
            if (file_index == -1) {
                file_index = i;
            }
            file_count++;
            break;
        }
    }

    if (!custom_root_dir) {
        strncpy(root_system_dir, DEFUALT_ROOT_SYSTEM_DIR, strlen(DEFUALT_ROOT_SYSTEM_DIR));
    }

    srandom(time(NULL));

    /*
    // Install usage limits to prevent system crash.
    setrlimit(RLIMIT_CORE, &kUsageLimits[RLIMIT_CORE]);
    setrlimit(RLIMIT_CPU, &kUsageLimits[RLIMIT_CPU]);
    setrlimit(RLIMIT_FSIZE, &kUsageLimits[RLIMIT_FSIZE]);
    setrlimit(RLIMIT_NOFILE, &kUsageLimits[RLIMIT_NOFILE]);
    
    signal(SIGXCPU, ResourceExhaustedHandler);
    signal(SIGXFSZ, ResourceExhaustedHandler);
    */
# ifndef NDEBUG
    // Enable Maximum heap checking.
    mcheck_pedantic(NULL);
# endif
    char engine_path[1024] = { 0 };

    if (custom_root_dir){
        snprintf(engine_path, sizeof(engine_path), "%s/%s", root_system_dir, BDCORE_DIR);
    }
    else {
        strncpy(engine_path, BDCORE_DIR, sizeof(engine_path));
    }

    int LoadModuleResult = LoadModule(engine_path);
    if (LoadModuleResult != 0)
        return -1;

    LogMessage("Initializing the BitDefender core...");

    char plugins_dir[1024] = { 0 };
    if(custom_root_dir){
        snprintf(plugins_dir, sizeof(plugins_dir), "%s/%s", root_system_dir, DEFUALT_ROOT_SYSTEM_DIR);
    }
    else {
        strncpy(plugins_dir, root_system_dir, sizeof(plugins_dir));
    }

    int CoreInitializeResult = InitializeCore(plugins_dir, "Plugins");
    if (CoreInitializeResult != 0) {
        LogMessage("Error during core initialization. Exit.");
        return -1;
    }
    LogMessage("BitDefender core initialized!");

    LogMessage("Creating a core instance...");
    void *BDCoreInstance = CreateCoreNewInstance();
    if (BDCoreInstance == NULL) {
        LogMessage("Error during creating a core instance. Exit.");
        return -1;
    }
    LogMessage("Core instance created successfully!");

    int SetScanCallBackResult = SetScanCallBack(BDCoreInstance, MyScanCallback);
    if (SetScanCallBackResult != 0)
        return -1;

    LogMessage("*** Running a scan... ***");

#ifdef LIBAFL_FUZZING
    for (int i = file_index; i < argc; i++) {
        char filename[1024] = { 0 };
        strncpy(filename, argv[i], sizeof(filename));
        // Check if the filename is valid
        if (filename == NULL || strlen(filename) == 0) {
            fprintf(stderr, "Invalid filename\n");
            return -1;
        }

        FilenameInstrumentationCallback(filename);

        // Open the file
        FILE *file = fopen(filename, "rb");
        if (file == NULL) {
            perror("fopen");
            return -1;
        }

        // Get the file size
        fseek(file, 0, SEEK_END);
        size_t file_size = ftell(file);
        rewind(file);

        // Allocate memory for the data
        uint8_t *file_data = (uint8_t *)calloc(file_size, 1);
        if (file_data == NULL) {
            perror("malloc");
            fclose(file);
            return -1;
        }

        // Read the file data into memory
        if (fread(file_data, 1, file_size, file) != file_size) {
            perror("fread");
            free(file_data);
            fclose(file);
            return -1;
        }

        // Close the file
        fclose(file);
        int ScanResult = ScanFile(BDCoreInstance, file_data, file_size, filename);
    }
#else

#ifdef PE_MUTATOR
    peparse::parsed_pe pe = LoadFromPath(argv[file_to_scan_start_index + i]);

#endif

    int scan_counter = 0;

    for (int i = file_index; i < argc; i++) {
#ifdef SHARED_MEM
        new_mmap_file(argv[i]);
        int ScanResult = ScanFile(BDCoreInstance, argv[i]);
        delete_mmap_file();
#else
        int ScanResult = ScanFile(BDCoreInstance, argv[i]);
#endif
        if (i == argc-1) {
            // all files scanned
            scan_counter++;
            
            if (loop != -1 && scan_counter < loop) {
                i = file_index - 1;
            }
        }

        if (ScanResult != 0)
            return -1;
    }

    /*
     * The AFL persistent mode will use the same bdcore instance during all the loop.
     * It's up to the use how many loops are suitable based on the overall memory consumption 
    */
    LogMessage("Deleting the core instance...");
    int DeleteResult = DeleteCoreInstance(BDCoreInstance);
    if (DeleteResult != 0) {
        LogMessage("Error during deleting the core instance.");
        return -1;
    }
    LogMessage("Core instance delete successfully.");
#endif
    //free(root_system_dir);
    return 0;
}
