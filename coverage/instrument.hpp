#ifndef __INSTRUMENT_H
#define __INSTRUMENT_H

VOID PIN_FAST_ANALYSIS_CALL InstrumentBasicBlock(ADDRINT address, UINT32 size, tree_t *blocks, char *module_name);
VOID InstrumentFiniCallback(INT32 code, VOID *v);
void store_coverage_stats_socket();
void store_coverage_stats_to_file();

VOID instrument_repz_cmps_pre(ADDRINT address, ADDRINT count, UINT32 width);
VOID instrument_repz_cmps_post(ADDRINT address, ADDRINT count, UINT32 width);

VOID instrument_cmp_reg_imm(ADDRINT address, ADDRINT reg, UINT32 imm);

#else
#warning instrument.h multiple inclusion
#endif
