#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <iostream>
#include <unordered_map>

#include "pin.H"
#include "modules_manager.hpp"
#include "instrument.hpp"

using namespace std;

extern "C" {
    #include "xed-interface.h"
}

typedef struct _selected_module {
    int n_modules;
    char *module_names[10] = { 0 };
} selected_module;

char g_file_path[4096] = { 0 };
bool scan_is_started = false;

selected_module selected_modules = {
    .n_modules = 0,
    .module_names = { 0 }
};

VOID SaveModulesParameters(char *ModuleName, size_t ModuleNameLength, ADDRINT ModuleStart, ADDRINT Size)
{
    ADDRINT ModuleEnd = ModuleStart + Size;

    // if --module_name was used, then we store only the modules we are interested into
    if (selected_modules.n_modules > 0) {
        for (int i = 0; i < selected_modules.n_modules; i++) {
            if (strncmp(ModuleName, selected_modules.module_names[i], strlen(selected_modules.module_names[i])) == 0)
                AddModule(ModuleName, ModuleStart, ModuleEnd);
        }
    }
    else {
        AddModule(ModuleName, ModuleStart, ModuleEnd);
    }


    return;
}

VOID ScanEnded()
{
    scan_is_started = false;
    PIN_RemoveInstrumentation();
    store_coverage_stats_to_file();
    ResetBlocksTree();
    return;
}

VOID SaveFilename(char *file_path) {
    memset(g_file_path, 0, sizeof(g_file_path));
    if (strlen(file_path) > sizeof(g_file_path)){
        printf("File path too long. Max allowed: %ld\n", sizeof(g_file_path));
        exit(1);
    }
    strncpy(g_file_path, file_path, strlen(file_path));
    return;
}

VOID ScanStarted(void *core, char *file_path)
{
    scan_is_started = true;
    return;
}

// Pin calls this function everytime an instruction is executed
VOID Instruction(INS ins, void* v)
{
    if (!scan_is_started)
        return;

    ADDRINT ins_address = INS_Address(ins);

    // Check if this insn is in a module
    BitDefenderModule *module = FindModuleByAddress(ins_address);
    if (module == nullptr)
        return;

    if (INS_IsDirectControlFlow(ins))
    {
        ETYPE type = INS_IsCall(ins) ? ETYPE_CALL : ETYPE_BRANCH;

        // static targets can map here once
        COUNTER* pedg = Lookup(
            EDGE(ins_address, INS_DirectControlFlowTargetAddress(ins), INS_NextAddress(ins), type), 
            &(module->EdgeSet));
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)docount, IARG_ADDRINT, pedg, IARG_END);
    }
    else if (INS_IsIndirectControlFlow(ins))
    {
        ETYPE type = ETYPE_IBRANCH;

        if (INS_IsRet(ins))
        {
            type = ETYPE_RETURN;
        }
        else if (INS_IsCall(ins))
        {
            type = ETYPE_ICALL;
        }

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount2, 
                        IARG_INST_PTR, 
                        IARG_BRANCH_TARGET_ADDR, 
                        IARG_ADDRINT, INS_NextAddress(ins), 
                        IARG_UINT32, type, 
                        IARG_BRANCH_TAKEN,
                        IARG_ADDRINT, &(module->EdgeSet),
                        IARG_END);
    }
    else if (INS_IsSyscall(ins))
    {
        COUNTER* pedg = Lookup(EDGE(ins_address, ADDRINT(~0), INS_NextAddress(ins), ETYPE_SYSCALL), &(module->EdgeSet));
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_ADDRINT, pedg, IARG_END);
    }
}

// Pin calls this function every time a new basic block is encountered
VOID Trace(TRACE trace, VOID *ptr)
{
    ADDRINT BBLRva = 0;

    if (!scan_is_started)
        return;

    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        // Check if this block is in our module hash table
        BitDefenderModule *module = FindModuleByAddress(BBL_Address(bbl));
        if (module == nullptr)
            continue;

        BBLRva = BBL_Address(bbl) - (ADDRINT) module->Start;

        // Insert a call in every bbl, passing the address of the basic block
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(InstrumentBasicBlock),
            IARG_FAST_ANALYSIS_CALL,
            IARG_ADDRINT, BBLRva,
            IARG_UINT32, BBL_NumIns(bbl),
            IARG_PTR, module->Blocks,
            IARG_PTR, module->ModuleName.c_str(),
            IARG_END);
    }
}

VOID LoadImage(IMG img, VOID *ptr)
{
    RTN ModuleCallback = RTN_FindByName(img, "ModuleInstrumentationCallback2");

    if (RTN_Valid(ModuleCallback)) {
        RTN_Open(ModuleCallback);
        RTN_InsertCall(ModuleCallback, IPOINT_BEFORE, (AFUNPTR) SaveModulesParameters,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_END);
        RTN_Close(ModuleCallback);
    }

    RTN ScanFileCallback = RTN_FindByName(img, "ScanFile");

    if (RTN_Valid(ScanFileCallback)) {
        RTN_Open(ScanFileCallback);
        RTN_InsertCall(ScanFileCallback, IPOINT_BEFORE, (AFUNPTR) ScanStarted,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_END);
        RTN_InsertCall(ScanFileCallback, IPOINT_AFTER, (AFUNPTR) ScanEnded,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_END);
        RTN_Close(ScanFileCallback);
    }

    RTN FilenameInstrumentationCallback = RTN_FindByName(img, "FilenameInstrumentationCallback");

    if (RTN_Valid(FilenameInstrumentationCallback)) {
        RTN_Open(FilenameInstrumentationCallback);
        RTN_InsertCall(FilenameInstrumentationCallback, IPOINT_BEFORE, (AFUNPTR) SaveFilename,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_END);
        RTN_Close(FilenameInstrumentationCallback);
    }
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strstr(argv[i], "--")) {
            // we reached "--", so target params from now on
            if (strlen(argv[i]) == 2) {
                break;
            }
            if (strncmp(argv[i], "--module_name", 13) != 0) {
                printf("Command line switch \"%s\" not allowed.", argv[i]);
            }

            char *switch_start = strstr(argv[i], "");
            if (switch_start != argv[i]) {
                goto CMDLINE_ERROR;
            }

            char *module_name = (char *) calloc(100, sizeof(char));
            selected_modules.module_names[selected_modules.n_modules] = module_name;
            
            strncpy(module_name, argv[i+1], 100);

            selected_modules.n_modules += 1;
        }
    }

    // Initialize pin
    PIN_Init(argc, argv);

    // Initialize Symbols
    PIN_InitSymbols();

    // Monitor Image loads
    IMG_AddInstrumentFunction(LoadImage, NULL);

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, NULL);

    // Register function to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, NULL);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(InstrumentFiniCallback, NULL);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;

CMDLINE_ERROR:
    printf("cmdline error");
    return -1;
}

