#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "module_ranges_shm.h"

static hf_bts_module_shm_t *g_module_ranges_shm = NULL;
static int                  g_module_ranges_shm_fd = -1;
static char                 g_module_ranges_shm_name[HF_BTS_MODULES_SHM_NAME_SIZE];
static bool                 g_module_ranges_cleanup_registered = false;
static bool                 g_module_ranges_full_warned = false;

static void module_ranges_shm_cleanup(void) {
    if (g_module_ranges_shm != NULL) {
        munmap(g_module_ranges_shm, sizeof(*g_module_ranges_shm));
        g_module_ranges_shm = NULL;
    }
    if (g_module_ranges_shm_fd != -1) {
        close(g_module_ranges_shm_fd);
        g_module_ranges_shm_fd = -1;
    }
    if (g_module_ranges_shm_name[0] != '\0') {
        shm_unlink(g_module_ranges_shm_name);
        g_module_ranges_shm_name[0] = '\0';
    }
}

static void module_ranges_shm_normalize_name(const char *src, char *dst, size_t dst_size) {
    size_t idx = 0;

    if (dst_size == 0U) {
        return;
    }

    while (src[idx] != '\0' && idx < (dst_size - 1U)) {
        dst[idx] = (char)tolower((unsigned char)src[idx]);
        idx++;
    }
    dst[idx] = '\0';
}

static bool module_ranges_shm_ensure(void) {
    if (g_module_ranges_shm != NULL) {
        return true;
    }

    int len = snprintf(g_module_ranges_shm_name, sizeof(g_module_ranges_shm_name), "%s%d",
        HF_BTS_MODULES_SHM_NAME_PREFIX, getpid());
    if (len < 0 || (size_t)len >= sizeof(g_module_ranges_shm_name)) {
        fprintf(stderr, "module_ranges_shm: SHM name truncated\n");
        g_module_ranges_shm_name[0] = '\0';
        return false;
    }

    shm_unlink(g_module_ranges_shm_name);
    g_module_ranges_shm_fd = shm_open(g_module_ranges_shm_name, O_CREAT | O_RDWR, 0600);
    if (g_module_ranges_shm_fd == -1) {
        perror("module_ranges_shm shm_open");
        g_module_ranges_shm_name[0] = '\0';
        return false;
    }

    if (ftruncate(g_module_ranges_shm_fd, sizeof(hf_bts_module_shm_t)) == -1) {
        perror("module_ranges_shm ftruncate");
        module_ranges_shm_cleanup();
        return false;
    }

    g_module_ranges_shm = mmap(NULL, sizeof(*g_module_ranges_shm), PROT_READ | PROT_WRITE,
        MAP_SHARED, g_module_ranges_shm_fd, 0);
    if (g_module_ranges_shm == MAP_FAILED) {
        perror("module_ranges_shm mmap");
        g_module_ranges_shm = NULL;
        module_ranges_shm_cleanup();
        return false;
    }

    if (!g_module_ranges_cleanup_registered) {
        atexit(module_ranges_shm_cleanup);
        g_module_ranges_cleanup_registered = true;
    }

    memset(g_module_ranges_shm, 0, sizeof(*g_module_ranges_shm));
    g_module_ranges_shm->magic   = HF_BTS_MODULES_SHM_MAGIC;
    g_module_ranges_shm->version = HF_BTS_MODULES_SHM_VERSION;
    return true;
}

void module_ranges_shm_reset(void) {
    if (!module_ranges_shm_ensure()) {
        return;
    }

    memset(g_module_ranges_shm, 0, sizeof(*g_module_ranges_shm));
    g_module_ranges_shm->magic   = HF_BTS_MODULES_SHM_MAGIC;
    g_module_ranges_shm->version = HF_BTS_MODULES_SHM_VERSION;
    g_module_ranges_full_warned  = false;
}

void module_ranges_shm_publish(const char *module_name, uintptr_t module_base, size_t module_size) {
    char normalized_name[HF_BTS_MODULES_NAME_MAX];

    if (module_name == NULL || module_size == 0U) {
        return;
    }
    if (!module_ranges_shm_ensure()) {
        return;
    }

    module_ranges_shm_normalize_name(module_name, normalized_name, sizeof(normalized_name));
    if (normalized_name[0] == '\0') {
        return;
    }

    uint64_t start = (uint64_t)module_base;
    uint64_t end   = start + (uint64_t)module_size;
    if (end < start) {
        return;
    }

    uint32_t count = __atomic_load_n(&g_module_ranges_shm->count, __ATOMIC_ACQUIRE);
    if (count > HF_BTS_MODULES_SHM_MAX_ENTRIES) {
        count = HF_BTS_MODULES_SHM_MAX_ENTRIES;
    }

    for (uint32_t idx = 0; idx < count; idx++) {
        if (g_module_ranges_shm->entries[idx].start == start &&
            g_module_ranges_shm->entries[idx].end == end &&
            strcmp(g_module_ranges_shm->entries[idx].name, normalized_name) == 0) {
            return;
        }
    }

    if (count >= HF_BTS_MODULES_SHM_MAX_ENTRIES) {
        if (!g_module_ranges_full_warned) {
            fprintf(stderr, "module_ranges_shm: too many modules, dropping extra entries\n");
            g_module_ranges_full_warned = true;
        }
        return;
    }

    g_module_ranges_shm->entries[count].start = start;
    g_module_ranges_shm->entries[count].end   = end;
    memcpy(g_module_ranges_shm->entries[count].name, normalized_name, sizeof(normalized_name));
    __atomic_store_n(&g_module_ranges_shm->count, count + 1U, __ATOMIC_RELEASE);
}

void module_ranges_shm_mark_ready(void) {
    if (!module_ranges_shm_ensure()) {
        return;
    }

    __atomic_store_n(&g_module_ranges_shm->ready, 1U, __ATOMIC_RELEASE);
}

bool module_ranges_shm_find(const char *module_name, hf_bts_module_entry_t *out_entry) {
    char normalized_name[HF_BTS_MODULES_NAME_MAX];

    if (module_name == NULL || out_entry == NULL) {
        return false;
    }
    if (!module_ranges_shm_ensure()) {
        return false;
    }

    module_ranges_shm_normalize_name(module_name, normalized_name, sizeof(normalized_name));
    if (normalized_name[0] == '\0') {
        return false;
    }

    uint32_t count = __atomic_load_n(&g_module_ranges_shm->count, __ATOMIC_ACQUIRE);
    if (count > HF_BTS_MODULES_SHM_MAX_ENTRIES) {
        count = HF_BTS_MODULES_SHM_MAX_ENTRIES;
    }

    for (uint32_t idx = 0; idx < count; idx++) {
        if (strcmp(g_module_ranges_shm->entries[idx].name, normalized_name) == 0) {
            *out_entry = g_module_ranges_shm->entries[idx];
            return true;
        }
    }

    return false;
}

bool module_ranges_shm_is_ready(void) {
    if (!module_ranges_shm_ensure()) {
        return false;
    }

    return __atomic_load_n(&g_module_ranges_shm->ready, __ATOMIC_ACQUIRE) != 0U;
}
