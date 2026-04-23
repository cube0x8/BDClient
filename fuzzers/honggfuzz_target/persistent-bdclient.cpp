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
#include <errno.h>
#include <sys/unistd.h>
#include <zlib.h>
#include <execinfo.h>
#include <setjmp.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "hook.h"
#ifdef __cplusplus
}
#endif
#include "log.h"
#include "rsignal.h"
#include "engineboot.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "openscan.h"
#include "bdlibrary.h"
#include "module_ranges_shm.h"
#include "shared_mem_file_handling.h"
#include "allocation_tracker.h"

#define DEFAULT_ROOT_SYSTEM_DIR "/home/user/Projects/bdclient"
#define DEFAULT_ENGINE_SUBPATH "engine/x64/bdcore.dll"
#define DEFAULT_PLUGINS_SUBDIR "dummy"
#define DEFAULT_INPUT_BASENAME "input"
#define MAX_TRAMPOLINES 64
#define FEEDBACK_BITMAP_WORDS 4
#define FEEDBACK_SHM_MAGIC 0x48464254U
#define FEEDBACK_SHM_VERSION 1U

int core_initialized = false;
void *BDCoreInstance;
static bool signal_handler_installed = false;
static bool custom_root_system_dir = false;
static bool g_debug_logging = false;
static bool g_verbose_tracking = false;
static char g_root_system_dir[1024] = DEFAULT_ROOT_SYSTEM_DIR;
static char g_engine_path[1024] = DEFAULT_ROOT_SYSTEM_DIR "/" DEFAULT_ENGINE_SUBPATH;
static char g_plugins_dir[1024] = DEFAULT_ROOT_SYSTEM_DIR "/" DEFAULT_PLUGINS_SUBDIR;
static char g_input_file_path[1024] = DEFAULT_ROOT_SYSTEM_DIR "/" DEFAULT_PLUGINS_SUBDIR "/" DEFAULT_INPUT_BASENAME;
static char g_trampoline_file_path[1024] = { 0 };

typedef enum trampoline_type {
    TRAMPOLINE_TYPE_FEEDBACK = 0,
    TRAMPOLINE_TYPE_EARLY_EXIT = 1,
} trampoline_type_t;

typedef struct trampoline_target {
    char module_name[HF_BTS_MODULES_NAME_MAX];
    uint64_t offset;
    trampoline_type_t type;
    bool installed;
    bool disabled;
    void *runtime_address;
    subhook_t hook;
    char label[128];
} trampoline_target_t;

typedef struct feedback_shm {
    uint32_t magic;
    uint32_t version;
    uint32_t iteration;
    int32_t exit_gate;
    uint32_t reserved;
    uint64_t bitmap[FEEDBACK_BITMAP_WORDS];
} feedback_shm_t;

static trampoline_target_t g_trampolines[MAX_TRAMPOLINES];
static size_t g_trampoline_count = 0U;
static volatile sig_atomic_t g_scan_jmp_active = 0;
static sigjmp_buf g_scan_jmp_env;
static int g_last_exit_gate = -1;
static feedback_shm_t *g_feedback_shm = NULL;
static int g_feedback_shm_fd = -1;
static char g_feedback_shm_name[64] = { 0 };
static uint32_t g_feedback_iteration = 0U;
static uint64_t g_iteration_count = 0U;
static uint64_t g_recycle_every = 0U;

static void normalize_module_name(const char *src, char *dst, size_t dst_size) {
    size_t idx = 0U;

    if (dst_size == 0U) {
        return;
    }

    while (src[idx] != '\0' && idx < (dst_size - 1U)) {
        dst[idx] = (char)tolower((unsigned char)src[idx]);
        idx++;
    }

    dst[idx] = '\0';
}

static void trim_ascii_whitespace(char *line) {
    size_t len;
    size_t start = 0U;

    if (line == NULL) {
        return;
    }

    len = strlen(line);
    while (line[start] != '\0' && isspace((unsigned char)line[start])) {
        start++;
    }

    if (start != 0U) {
        memmove(line, line + start, len - start + 1U);
        len = strlen(line);
    }

    while (len > 0U && isspace((unsigned char)line[len - 1U])) {
        line[len - 1U] = '\0';
        len--;
    }
}

static const char *trampoline_type_name(trampoline_type_t type) {
    return type == TRAMPOLINE_TYPE_EARLY_EXIT ? "ee" : "fb";
}

static void feedback_shm_cleanup(void) {
    if (g_feedback_shm != NULL) {
        munmap(g_feedback_shm, sizeof(*g_feedback_shm));
        g_feedback_shm = NULL;
    }
    if (g_feedback_shm_fd != -1) {
        close(g_feedback_shm_fd);
        g_feedback_shm_fd = -1;
    }
    if (g_feedback_shm_name[0] != '\0') {
        shm_unlink(g_feedback_shm_name);
        g_feedback_shm_name[0] = '\0';
    }
}

static bool feedback_shm_init(void) {
    int len;

    if (g_feedback_shm != NULL) {
        return true;
    }

    len = snprintf(g_feedback_shm_name, sizeof(g_feedback_shm_name), "/hf_bts_feedback_%d", getpid());
    if (len < 0 || (size_t)len >= sizeof(g_feedback_shm_name)) {
        fprintf(stderr, "feedback_shm: SHM name truncated\n");
        return false;
    }

    shm_unlink(g_feedback_shm_name);
    g_feedback_shm_fd = shm_open(g_feedback_shm_name, O_CREAT | O_RDWR, 0600);
    if (g_feedback_shm_fd == -1) {
        perror("feedback_shm shm_open");
        g_feedback_shm_name[0] = '\0';
        return false;
    }

    if (ftruncate(g_feedback_shm_fd, sizeof(*g_feedback_shm)) == -1) {
        perror("feedback_shm ftruncate");
        feedback_shm_cleanup();
        return false;
    }

    g_feedback_shm = (feedback_shm_t *)mmap(NULL, sizeof(*g_feedback_shm), PROT_READ | PROT_WRITE,
        MAP_SHARED, g_feedback_shm_fd, 0);
    if (g_feedback_shm == MAP_FAILED) {
        perror("feedback_shm mmap");
        g_feedback_shm = NULL;
        feedback_shm_cleanup();
        return false;
    }

    atexit(feedback_shm_cleanup);
    setenv("HF_BDCLIENT_FEEDBACK_SHM", g_feedback_shm_name, 1);
    return true;
}

static void feedback_shm_reset_iteration(void) {
    if (g_feedback_shm == NULL) {
        return;
    }

    g_feedback_iteration++;
    memset(g_feedback_shm, 0, sizeof(*g_feedback_shm));
    g_feedback_shm->magic = FEEDBACK_SHM_MAGIC;
    g_feedback_shm->version = FEEDBACK_SHM_VERSION;
    g_feedback_shm->iteration = g_feedback_iteration;
    g_feedback_shm->exit_gate = -1;
}

static void feedback_mark_hit(size_t trampoline_index) {
    size_t word_index = trampoline_index / 64U;
    size_t bit_index = trampoline_index % 64U;

    if (g_feedback_shm == NULL || word_index >= FEEDBACK_BITMAP_WORDS) {
        return;
    }

    g_feedback_shm->bitmap[word_index] |= (1ULL << bit_index);
}

static bool feedback_was_hit(size_t trampoline_index) {
    size_t word_index = trampoline_index / 64U;
    size_t bit_index = trampoline_index % 64U;

    if (g_feedback_shm == NULL || word_index >= FEEDBACK_BITMAP_WORDS) {
        return false;
    }

    return (g_feedback_shm->bitmap[word_index] & (1ULL << bit_index)) != 0ULL;
}

static void record_exit_gate(int gate_index) {
    g_last_exit_gate = gate_index;
    if (g_feedback_shm != NULL) {
        g_feedback_shm->exit_gate = gate_index;
    }
}

static void debug_dump_iteration_summary(void) {
#ifndef NDEBUG
    if (!g_debug_logging) {
        return;
    }

    fprintf(stderr, "[bdclient] scan summary for %s\n", g_input_file_path);
    fprintf(stderr, "[bdclient] hit trampolines:");
    if (g_feedback_shm == NULL) {
        fprintf(stderr, " none");
    } else {
        bool any_hit = false;
        for (size_t idx = 0; idx < g_trampoline_count; idx++) {
            if (!feedback_was_hit(idx)) {
                continue;
            }
            fprintf(stderr, " %s", g_trampolines[idx].label);
            any_hit = true;
        }
        if (!any_hit) {
            fprintf(stderr, " none");
        }
    }
    fprintf(stderr, "\n");

    if (g_last_exit_gate >= 0 && (size_t)g_last_exit_gate < g_trampoline_count) {
        fprintf(stderr, "[bdclient] exit point: %s\n", g_trampolines[g_last_exit_gate].label);
    } else if (g_last_exit_gate == -2) {
        fprintf(stderr, "[bdclient] exit point: scan-return\n");
    } else if (g_last_exit_gate == -3) {
        fprintf(stderr, "[bdclient] exit point: create-core-instance-failed\n");
    } else {
        fprintf(stderr, "[bdclient] exit point: unknown\n");
    }
#endif
}

static void handle_gate_hit(size_t trampoline_index) {
    if (trampoline_index >= g_trampoline_count) {
        return;
    }

    feedback_mark_hit(trampoline_index);

    if (g_trampolines[trampoline_index].type == TRAMPOLINE_TYPE_EARLY_EXIT) {
        record_exit_gate((int)trampoline_index);
        if (g_scan_jmp_active) {
            siglongjmp(g_scan_jmp_env, 1);
        }
    }
}

#define DECL_GATE_REDIRECT(IDX) \
    static void gate_redirect_##IDX(void) { handle_gate_hit((IDX)); }

DECL_GATE_REDIRECT(0) DECL_GATE_REDIRECT(1) DECL_GATE_REDIRECT(2) DECL_GATE_REDIRECT(3)
DECL_GATE_REDIRECT(4) DECL_GATE_REDIRECT(5) DECL_GATE_REDIRECT(6) DECL_GATE_REDIRECT(7)
DECL_GATE_REDIRECT(8) DECL_GATE_REDIRECT(9) DECL_GATE_REDIRECT(10) DECL_GATE_REDIRECT(11)
DECL_GATE_REDIRECT(12) DECL_GATE_REDIRECT(13) DECL_GATE_REDIRECT(14) DECL_GATE_REDIRECT(15)
DECL_GATE_REDIRECT(16) DECL_GATE_REDIRECT(17) DECL_GATE_REDIRECT(18) DECL_GATE_REDIRECT(19)
DECL_GATE_REDIRECT(20) DECL_GATE_REDIRECT(21) DECL_GATE_REDIRECT(22) DECL_GATE_REDIRECT(23)
DECL_GATE_REDIRECT(24) DECL_GATE_REDIRECT(25) DECL_GATE_REDIRECT(26) DECL_GATE_REDIRECT(27)
DECL_GATE_REDIRECT(28) DECL_GATE_REDIRECT(29) DECL_GATE_REDIRECT(30) DECL_GATE_REDIRECT(31)
DECL_GATE_REDIRECT(32) DECL_GATE_REDIRECT(33) DECL_GATE_REDIRECT(34) DECL_GATE_REDIRECT(35)
DECL_GATE_REDIRECT(36) DECL_GATE_REDIRECT(37) DECL_GATE_REDIRECT(38) DECL_GATE_REDIRECT(39)
DECL_GATE_REDIRECT(40) DECL_GATE_REDIRECT(41) DECL_GATE_REDIRECT(42) DECL_GATE_REDIRECT(43)
DECL_GATE_REDIRECT(44) DECL_GATE_REDIRECT(45) DECL_GATE_REDIRECT(46) DECL_GATE_REDIRECT(47)
DECL_GATE_REDIRECT(48) DECL_GATE_REDIRECT(49) DECL_GATE_REDIRECT(50) DECL_GATE_REDIRECT(51)
DECL_GATE_REDIRECT(52) DECL_GATE_REDIRECT(53) DECL_GATE_REDIRECT(54) DECL_GATE_REDIRECT(55)
DECL_GATE_REDIRECT(56) DECL_GATE_REDIRECT(57) DECL_GATE_REDIRECT(58) DECL_GATE_REDIRECT(59)
DECL_GATE_REDIRECT(60) DECL_GATE_REDIRECT(61) DECL_GATE_REDIRECT(62) DECL_GATE_REDIRECT(63)

typedef void (*gate_redirect_fn_t)(void);

static gate_redirect_fn_t g_gate_redirects[MAX_TRAMPOLINES] = {
    gate_redirect_0, gate_redirect_1, gate_redirect_2, gate_redirect_3,
    gate_redirect_4, gate_redirect_5, gate_redirect_6, gate_redirect_7,
    gate_redirect_8, gate_redirect_9, gate_redirect_10, gate_redirect_11,
    gate_redirect_12, gate_redirect_13, gate_redirect_14, gate_redirect_15,
    gate_redirect_16, gate_redirect_17, gate_redirect_18, gate_redirect_19,
    gate_redirect_20, gate_redirect_21, gate_redirect_22, gate_redirect_23,
    gate_redirect_24, gate_redirect_25, gate_redirect_26, gate_redirect_27,
    gate_redirect_28, gate_redirect_29, gate_redirect_30, gate_redirect_31,
    gate_redirect_32, gate_redirect_33, gate_redirect_34, gate_redirect_35,
    gate_redirect_36, gate_redirect_37, gate_redirect_38, gate_redirect_39,
    gate_redirect_40, gate_redirect_41, gate_redirect_42, gate_redirect_43,
    gate_redirect_44, gate_redirect_45, gate_redirect_46, gate_redirect_47,
    gate_redirect_48, gate_redirect_49, gate_redirect_50, gate_redirect_51,
    gate_redirect_52, gate_redirect_53, gate_redirect_54, gate_redirect_55,
    gate_redirect_56, gate_redirect_57, gate_redirect_58, gate_redirect_59,
    gate_redirect_60, gate_redirect_61, gate_redirect_62, gate_redirect_63
};

static void configure_root_system_dir(const char *root_system_dir)
{
    if (root_system_dir == NULL || root_system_dir[0] == '\0')
        return;

    snprintf(g_root_system_dir, sizeof(g_root_system_dir), "%s", root_system_dir);
    snprintf(g_engine_path, sizeof(g_engine_path), "%s/%s", root_system_dir, DEFAULT_ENGINE_SUBPATH);
    snprintf(g_plugins_dir, sizeof(g_plugins_dir), "%s/%s", root_system_dir, DEFAULT_PLUGINS_SUBDIR);
    snprintf(g_input_file_path, sizeof(g_input_file_path), "%s/%s/%s", root_system_dir, DEFAULT_PLUGINS_SUBDIR, DEFAULT_INPUT_BASENAME);
    custom_root_system_dir = true;
}

static void parse_trampoline_line(char *line, size_t line_number) {
    char *type_separator;
    char *offset_separator;
    char *type_str;
    char *offset_str;
    unsigned long long offset_value;
    trampoline_target_t *target;

    trim_ascii_whitespace(line);
    if (line[0] == '\0' || line[0] == '#') {
        return;
    }

    type_separator = strchr(line, ';');
    if (type_separator == NULL) {
        fprintf(stderr, "trampoline file: invalid line %zu\n", line_number);
        return;
    }

    *type_separator = '\0';
    type_str = type_separator + 1;
    trim_ascii_whitespace(type_str);

    offset_separator = strstr(line, ":+");
    if (offset_separator == NULL) {
        fprintf(stderr, "trampoline file: invalid offset line %zu\n", line_number);
        return;
    }

    *offset_separator = '\0';
    offset_str = offset_separator + 2;
    trim_ascii_whitespace(line);
    trim_ascii_whitespace(offset_str);

    if (g_trampoline_count >= MAX_TRAMPOLINES) {
        fprintf(stderr, "trampoline file: maximum of %u entries reached\n", MAX_TRAMPOLINES);
        return;
    }

    errno = 0;
    offset_value = strtoull(offset_str, NULL, 0);
    if (errno != 0) {
        fprintf(stderr, "trampoline file: invalid offset at line %zu\n", line_number);
        return;
    }

    target = &g_trampolines[g_trampoline_count];
    memset(target, 0, sizeof(*target));
    normalize_module_name(line, target->module_name, sizeof(target->module_name));
    target->offset = (uint64_t)offset_value;

    if (strcmp(type_str, "fb") == 0) {
        target->type = TRAMPOLINE_TYPE_FEEDBACK;
    } else if (strcmp(type_str, "ee") == 0) {
        target->type = TRAMPOLINE_TYPE_EARLY_EXIT;
    } else {
        fprintf(stderr, "trampoline file: invalid type at line %zu\n", line_number);
        return;
    }

    snprintf(target->label, sizeof(target->label), "%s:+0x%llx;%s",
        target->module_name, (unsigned long long)target->offset, trampoline_type_name(target->type));
    g_trampoline_count++;
}

static void load_trampoline_file(void) {
    FILE *fp;
    char line[256];
    size_t line_number = 0U;

    if (g_trampoline_file_path[0] == '\0') {
        return;
    }

    fp = fopen(g_trampoline_file_path, "r");
    if (fp == NULL) {
        err(EXIT_FAILURE, "failed to open trampoline file '%s'", g_trampoline_file_path);
    }

    g_trampoline_count = 0U;
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *comment = strchr(line, '#');
        line_number++;
        if (comment != NULL) {
            *comment = '\0';
        }
        parse_trampoline_line(line, line_number);
    }

    fclose(fp);
}

static void parse_honggfuzz_target_args(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose-tracking") == 0) {
            g_verbose_tracking = true;
            continue;
        }

        if (strcmp(argv[i], "--root-system-dir") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing value for --root-system-dir.\n");
                exit(EXIT_FAILURE);
            }
            configure_root_system_dir(argv[i + 1]);
            i++;
            continue;
        }

        if (strncmp(argv[i], "--root-system-dir=", strlen("--root-system-dir=")) == 0) {
            configure_root_system_dir(argv[i] + strlen("--root-system-dir="));
            continue;
        }

        if (strcmp(argv[i], "--trampoline-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing value for --trampoline-file.\n");
                exit(EXIT_FAILURE);
            }
            snprintf(g_trampoline_file_path, sizeof(g_trampoline_file_path), "%s", argv[i + 1]);
            i++;
            continue;
        }

        if (strncmp(argv[i], "--trampoline-file=", strlen("--trampoline-file=")) == 0) {
            snprintf(g_trampoline_file_path, sizeof(g_trampoline_file_path), "%s",
                argv[i] + strlen("--trampoline-file="));
            continue;
        }
    }
}

static void initialize_runtime_options(void) {
    const char *recycle_env = getenv("BDCLIENT_RECYCLE_EVERY");

    allocation_tracker_set_enabled(g_verbose_tracking);
    if (recycle_env != NULL && recycle_env[0] != '\0') {
        char *endptr = NULL;
        unsigned long long parsed = strtoull(recycle_env, &endptr, 0);
        if (endptr != recycle_env && endptr != NULL && *endptr == '\0') {
            g_recycle_every = (uint64_t)parsed;
        }
    }
}

static void uninstall_scan_trampolines(void) {
    for (size_t idx = 0; idx < g_trampoline_count; idx++) {
        trampoline_target_t *target = &g_trampolines[idx];

        if (!target->installed || target->type != TRAMPOLINE_TYPE_EARLY_EXIT) {
            continue;
        }

        if (target->hook != NULL) {
            remove_function_redirect(target->hook);
        }

        target->hook = NULL;
        target->installed = false;
    }
}

static void install_pending_trampolines(bool allow_early_exit) {
    hf_bts_module_entry_t entry;

    if (g_trampoline_count == 0U || !module_ranges_shm_is_ready()) {
        return;
    }

    for (size_t idx = 0; idx < g_trampoline_count; idx++) {
        trampoline_target_t *target = &g_trampolines[idx];
        uint32_t flags;

        if (target->installed || target->disabled) {
            continue;
        }
        if (target->type == TRAMPOLINE_TYPE_EARLY_EXIT && !allow_early_exit) {
            continue;
        }
        if (!module_ranges_shm_find(target->module_name, &entry)) {
            continue;
        }

        target->runtime_address = (void *)((uintptr_t)entry.start + (uintptr_t)target->offset);
        flags = target->type == TRAMPOLINE_TYPE_EARLY_EXIT ? HOOK_REPLACE_FUNCTION : HOOK_DEFAULT;
        target->hook = insert_function_redirect(target->runtime_address, (void *)g_gate_redirects[idx], flags);
        if (target->hook == NULL) {
            if (target->type == TRAMPOLINE_TYPE_FEEDBACK) {
                target->disabled = true;
            }
            fprintf(stderr, "failed to install trampoline: %s%s\n", target->label,
                target->type == TRAMPOLINE_TYPE_FEEDBACK ? " (disabled for future iterations)" : "");
            continue;
        }

        target->installed = true;
#ifndef NDEBUG
        if (g_debug_logging) {
            fprintf(stderr, "[bdclient] installed trampoline %s at %p\n",
                target->label, target->runtime_address);
        }
#endif
    }
}

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

int initialize_bitdefender_core() {
    module_ranges_shm_reset();

    LogMessage("Using root system dir: %s%s", g_root_system_dir,
        custom_root_system_dir ? " (custom)" : " (default)");

    if (LoadModule(g_engine_path) != 0) {
        return -1;
    }

    LogMessage("Initializing the BitDefender core...");
    if (InitializeCore(g_plugins_dir, "Plugins") != 0) {
        LogMessage("Error during core initialization. Exit.");
        return -1;
    }

    module_ranges_shm_mark_ready();
    install_pending_trampolines(false);
    LogMessage("BitDefender core initialized!");
    core_initialized = true;
    return 0;
}

void handler(int sig) {
    void *array[10];
    size_t size = backtrace(array, 10);

    fprintf(stderr, "Error: signal %d:\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

static void cleanup_after_scan(void) {
    allocation_tracker_scan_report_t report;

    uninstall_scan_trampolines();

    if (BDCoreInstance != NULL) {
        DebugLog("Deleting core instance");
        DeleteCoreInstance(BDCoreInstance);
        DebugLog("Core instance deleted");
        BDCoreInstance = NULL;
    }

    ResetScanState();
    allocation_tracker_set_phase(ALLOCATION_PHASE_NONE);
    if (g_verbose_tracking) {
        allocation_tracker_collect_scan_report(&report);
    } else {
        memset(&report, 0, sizeof(report));
    }
    g_scan_jmp_active = 0;

#ifndef NDEBUG
    if (g_debug_logging && g_verbose_tracking) {
        fprintf(stderr,
            "[bdclient] allocation tracker: born_in_scan=%zu (%zu bytes) touched_existing_in_scan=%zu (%zu bytes) live_total=%zu (%zu bytes)\n",
            report.born_in_scan_count,
            report.born_in_scan_bytes,
            report.touched_in_scan_existing_count,
            report.touched_in_scan_existing_bytes,
            report.total_live_count,
            report.total_live_bytes);
    }
#endif
}

#ifdef __cplusplus
extern "C" {
#endif

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    if (!signal_handler_installed) {
        signal(SIGSEGV, handler);
        signal_handler_installed = true;
    }
#ifndef NDEBUG
    g_debug_logging = true;
#endif
    parse_honggfuzz_target_args(*argc, *argv);
    initialize_runtime_options();
    load_trampoline_file();
    feedback_shm_init();
    return 0;
}

int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size) {
    g_iteration_count++;
    feedback_shm_reset_iteration();
    record_exit_gate(-1);

    if (!core_initialized) {
        allocation_tracker_reset();
        initialize_bitdefender_core();
    }

    install_pending_trampolines(false);

    DebugLog("*** Creating Instance ***");
    BDCoreInstance = CreateCoreNewInstance();
    if (BDCoreInstance == NULL) {
        DebugLog("*** Failed to create instance ***");
        record_exit_gate(-3);
        debug_dump_iteration_summary();
        cleanup_after_scan();
        return -1;
    }
    DebugLog("*** Instance created ***");

    SetScanCallBack(BDCoreInstance, MyScanCallback);
    g_scan_jmp_active = 1;

    if (sigsetjmp(g_scan_jmp_env, 1) == 0) {
        install_pending_trampolines(true);
        DebugLog("*** Running a scan ***\n");
        int ScanResult = ScanFile(BDCoreInstance, Data, Size, g_input_file_path);
        DebugLog("*** Scan completed with result: %d ***\n", ScanResult);
        (void)ScanResult;
        if (g_last_exit_gate < 0) {
            record_exit_gate(-2);
        }
    }

    DebugLog("Early exit triggerd: %s\n", g_last_exit_gate >= 0 ? g_trampolines[g_last_exit_gate].label : "none");
    //sleep(10);
    debug_dump_iteration_summary();
    cleanup_after_scan();
    if (g_recycle_every != 0U && (g_iteration_count % g_recycle_every) == 0U) {
#ifndef NDEBUG
        if (g_debug_logging) {
            fprintf(stderr, "[bdclient] recycle requested after %llu iterations\n",
                (unsigned long long)g_iteration_count);
        }
#endif
        _exit(0);
    }
    return 0;
}

#ifdef __cplusplus
}
#endif
