#ifndef ALLOCATION_TRACKER_H
#define ALLOCATION_TRACKER_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum allocation_kind {
    ALLOCATION_KIND_HEAP = 1,
    ALLOCATION_KIND_VIRTUAL = 2,
} allocation_kind_t;

typedef enum allocation_phase {
    ALLOCATION_PHASE_NONE = 0,
    ALLOCATION_PHASE_CORE_INIT = 1,
    ALLOCATION_PHASE_INSTANCE_CREATE = 2,
    ALLOCATION_PHASE_SCAN = 3,
} allocation_phase_t;

typedef struct allocation_tracker_scan_report {
    size_t born_in_scan_count;
    size_t born_in_scan_bytes;
    size_t touched_in_scan_existing_count;
    size_t touched_in_scan_existing_bytes;
    size_t total_live_count;
    size_t total_live_bytes;
} allocation_tracker_scan_report_t;

void allocation_tracker_set_enabled(bool enabled);
bool allocation_tracker_is_enabled(void);
void allocation_tracker_set_phase(allocation_phase_t phase);
allocation_phase_t allocation_tracker_get_phase(void);
void allocation_tracker_record_alloc(void *ptr, size_t size, allocation_kind_t kind);
void allocation_tracker_record_free(void *ptr);
void allocation_tracker_record_realloc(void *old_ptr, void *new_ptr, size_t size, allocation_kind_t kind);
size_t allocation_tracker_cleanup_residual(void);
void allocation_tracker_reset(void);
size_t allocation_tracker_count(void);
void allocation_tracker_collect_scan_report(allocation_tracker_scan_report_t *report);

#ifdef __cplusplus
}
#endif

#endif
