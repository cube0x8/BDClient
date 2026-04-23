#ifndef __COVERAGE_H
#define __COVERAGE_H

typedef struct _module_coverage_result {
    uint64_t instructions;
    uint64_t blockcount;
    uint64_t totalinstructions;
    uint64_t totalblocks;
} module_coverage_result;

extern module_coverage_result coverage_results;

#else
#warning coverage.h multiple inclusion
#endif