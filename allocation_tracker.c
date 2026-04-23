#include "allocation_tracker.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ALLOCATION_TRACKER_MAX_ENTRIES 32768U

typedef struct allocation_entry {
    void *ptr;
    size_t size;
    allocation_kind_t kind;
    allocation_phase_t birth_phase;
    allocation_phase_t last_touch_phase;
} allocation_entry_t;

static allocation_entry_t g_entries[ALLOCATION_TRACKER_MAX_ENTRIES];
static size_t g_entry_count = 0U;
static allocation_phase_t g_current_phase = ALLOCATION_PHASE_NONE;
static bool g_tracker_enabled = false;

static ssize_t allocation_tracker_find_index(void *ptr) {
    if (ptr == NULL) {
        return -1;
    }

    for (size_t idx = 0; idx < g_entry_count; idx++) {
        if (g_entries[idx].ptr == ptr) {
            return (ssize_t)idx;
        }
    }

    return -1;
}

static void allocation_tracker_remove_index(size_t idx) {
    if (idx >= g_entry_count) {
        return;
    }

    if (idx + 1U < g_entry_count) {
        memmove(&g_entries[idx], &g_entries[idx + 1U],
            (g_entry_count - idx - 1U) * sizeof(g_entries[0]));
    }

    g_entry_count--;
    memset(&g_entries[g_entry_count], 0, sizeof(g_entries[0]));
}

void allocation_tracker_set_enabled(bool enabled) {
    g_tracker_enabled = enabled;
}

bool allocation_tracker_is_enabled(void) {
    return g_tracker_enabled;
}

void allocation_tracker_set_phase(allocation_phase_t phase) {
    if (!g_tracker_enabled) {
        g_current_phase = ALLOCATION_PHASE_NONE;
        return;
    }
    g_current_phase = phase;
}

allocation_phase_t allocation_tracker_get_phase(void) {
    return g_current_phase;
}

void allocation_tracker_record_alloc(void *ptr, size_t size, allocation_kind_t kind) {
    if (!g_tracker_enabled) {
        return;
    }
    if (ptr == NULL || size == 0U) {
        return;
    }

    ssize_t existing_idx = allocation_tracker_find_index(ptr);
    if (existing_idx >= 0) {
        g_entries[existing_idx].size = size;
        g_entries[existing_idx].kind = kind;
        g_entries[existing_idx].last_touch_phase = g_current_phase;
        return;
    }

    if (g_entry_count >= ALLOCATION_TRACKER_MAX_ENTRIES) {
        return;
    }

    g_entries[g_entry_count].ptr = ptr;
    g_entries[g_entry_count].size = size;
    g_entries[g_entry_count].kind = kind;
    g_entries[g_entry_count].birth_phase = g_current_phase;
    g_entries[g_entry_count].last_touch_phase = g_current_phase;
    g_entry_count++;
}

void allocation_tracker_record_free(void *ptr) {
    if (!g_tracker_enabled) {
        return;
    }
    ssize_t idx = allocation_tracker_find_index(ptr);
    if (idx < 0) {
        return;
    }

    allocation_tracker_remove_index((size_t)idx);
}

void allocation_tracker_record_realloc(void *old_ptr, void *new_ptr, size_t size, allocation_kind_t kind) {
    if (!g_tracker_enabled) {
        return;
    }
    allocation_phase_t birth_phase = g_current_phase;
    ssize_t old_idx = allocation_tracker_find_index(old_ptr);

    if (old_idx >= 0) {
        birth_phase = g_entries[old_idx].birth_phase;
    }

    if (old_ptr != NULL && old_ptr != new_ptr && old_idx >= 0) {
        allocation_tracker_remove_index((size_t)old_idx);
    }

    if (new_ptr == NULL || size == 0U) {
        return;
    }

    ssize_t new_idx = allocation_tracker_find_index(new_ptr);
    if (new_idx >= 0) {
        g_entries[new_idx].size = size;
        g_entries[new_idx].kind = kind;
        g_entries[new_idx].birth_phase = birth_phase;
        g_entries[new_idx].last_touch_phase = g_current_phase;
        return;
    }

    if (g_entry_count >= ALLOCATION_TRACKER_MAX_ENTRIES) {
        return;
    }

    g_entries[g_entry_count].ptr = new_ptr;
    g_entries[g_entry_count].size = size;
    g_entries[g_entry_count].kind = kind;
    g_entries[g_entry_count].birth_phase = birth_phase;
    g_entries[g_entry_count].last_touch_phase = g_current_phase;
    g_entry_count++;
}

size_t allocation_tracker_cleanup_residual(void) {
    if (!g_tracker_enabled) {
        return 0U;
    }
    size_t released = 0U;

    while (g_entry_count > 0U) {
        allocation_entry_t entry = g_entries[g_entry_count - 1U];
        g_entry_count--;
        memset(&g_entries[g_entry_count], 0, sizeof(g_entries[0]));

        if (entry.ptr == NULL) {
            continue;
        }

        if (entry.kind == ALLOCATION_KIND_VIRTUAL) {
            size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
            size_t rounded_size = ((entry.size + page_size - 1U) / page_size) * page_size;
            munmap(entry.ptr, rounded_size);
        } else {
            free(entry.ptr);
        }

        released++;
    }

    return released;
}

void allocation_tracker_reset(void) {
    memset(g_entries, 0, sizeof(g_entries));
    g_entry_count = 0U;
    g_current_phase = ALLOCATION_PHASE_NONE;
}

size_t allocation_tracker_count(void) {
    return g_entry_count;
}

void allocation_tracker_collect_scan_report(allocation_tracker_scan_report_t *report) {
    if (report == NULL) {
        return;
    }

    memset(report, 0, sizeof(*report));
    if (!g_tracker_enabled) {
        return;
    }
    for (size_t idx = 0; idx < g_entry_count; idx++) {
        allocation_entry_t *entry = &g_entries[idx];

        if (entry->ptr == NULL) {
            continue;
        }

        report->total_live_count++;
        report->total_live_bytes += entry->size;

        if (entry->birth_phase == ALLOCATION_PHASE_SCAN) {
            report->born_in_scan_count++;
            report->born_in_scan_bytes += entry->size;
        } else if (entry->last_touch_phase == ALLOCATION_PHASE_SCAN) {
            report->touched_in_scan_existing_count++;
            report->touched_in_scan_existing_bytes += entry->size;
        }
    }
}
