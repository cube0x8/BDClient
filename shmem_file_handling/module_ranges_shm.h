#ifndef MODULE_RANGES_SHM_H
#define MODULE_RANGES_SHM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HF_BTS_MODULES_SHM_MAGIC       0x4846424dU
#define HF_BTS_MODULES_SHM_VERSION     1U
#define HF_BTS_MODULES_SHM_NAME_PREFIX "/hf_bts_modules_"
#define HF_BTS_MODULES_SHM_NAME_SIZE   64U
#define HF_BTS_MODULES_SHM_MAX_ENTRIES 2048U
#define HF_BTS_MODULES_NAME_MAX        64U

typedef struct {
    uint64_t start;
    uint64_t end;
    char     name[HF_BTS_MODULES_NAME_MAX];
} hf_bts_module_entry_t;

typedef struct {
    uint32_t              magic;
    uint32_t              version;
    uint32_t              ready;
    uint32_t              count;
    hf_bts_module_entry_t entries[HF_BTS_MODULES_SHM_MAX_ENTRIES];
} hf_bts_module_shm_t;

#ifdef __cplusplus
extern "C" {
#endif

void module_ranges_shm_reset(void);
void module_ranges_shm_publish(const char *module_name, uintptr_t module_base, size_t module_size);
void module_ranges_shm_mark_ready(void);
bool module_ranges_shm_find(const char *module_name, hf_bts_module_entry_t *out_entry);
bool module_ranges_shm_is_ready(void);

#ifdef __cplusplus
}
#endif

#endif
