#ifndef _MODULE_MANAGER_
#define _MODULE_MANAGER_

#include <search.h>
#include "edges.hpp"

extern "C" {
    #include "tree.h"
}

extern char g_file_path[4096];
extern bool scan_is_started;

class BitDefenderModule {
    public:
        std::string ModuleName;
        ADDRINT Start;
        ADDRINT End;
        tree_t *Blocks;
        EDG_HASH_SET EdgeSet;

        BitDefenderModule(std::string n, ADDRINT s, ADDRINT e) : 
        ModuleName(n), Start(s), End(e)
        {
            tree_create(&(this->Blocks), compare, free);
        }
};

typedef unordered_map<string, BitDefenderModule> MODULE_HASH_SET;
extern MODULE_HASH_SET ModuleSet;

void AddModule(char *module_name, ADDRINT module_start, ADDRINT module_end);
void ResetBlocksTree();

BitDefenderModule *FindModuleByAddress(ADDRINT address) ;
BitDefenderModule *FindModuleByIndex(size_t index);
size_t ModuleSetSize();

#else
#warning modules_manager.h multiple inclusion
#endif
