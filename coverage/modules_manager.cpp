#include <iostream>
#include <string.h>
#include <string>

#include "modules_manager.hpp"

using namespace std;

MODULE_HASH_SET ModuleSet;

void AddModule(char *module_name, ADDRINT module_start, ADDRINT module_end)
{
    string key(module_name);
    
    // Create module
    BitDefenderModule *module = new BitDefenderModule(
        string (module_name), 
        module_start, 
        module_end
        );
    
    // Add module descriptor entry into hashtable
    pair<string, BitDefenderModule> module_entry(key, *module);
    ModuleSet.insert(module_entry);
    
    return;
}

void ResetBlocksTree() {
    for (auto& kv : ModuleSet) {
        BitDefenderModule& module = kv.second;
        if (module.Blocks == NULL)
            continue;

        tree_destroy(module.Blocks);
        module.EdgeSet.clear();

        module = BitDefenderModule(module.ModuleName, module.Start, module.End);
    }
    
    return;
}

BitDefenderModule *FindModuleByAddress(ADDRINT address) {
    BitDefenderModule *module = nullptr;
    unordered_map<string, BitDefenderModule>:: iterator itr;
    // Check if this address belongs to some module
    for (itr = ModuleSet.begin(); itr != ModuleSet.end(); itr++) {
        //printf("Module name: %s Starts at %p Ends at %p\n", itr->second->module_name, itr->second->start, itr->second->end);
        if (address > itr->second.Start && address < itr->second.End) {
            //printf("Address %p found in module %s\n", (void *)address, itr->second->module_name);
            module = &itr->second;
            break;
        }
    }
    return module;
}

BitDefenderModule *FindModuleByIndex(size_t index) {
    BitDefenderModule *module = nullptr;
    unordered_map<string, BitDefenderModule>:: iterator itr;
    size_t count = 0;
    for (itr = ModuleSet.begin(); itr != ModuleSet.end(); itr++) {
        if (count == index) {
            module = &itr->second;
            break;
        }
        count++;
    }
    return module;
}

size_t ModuleSetSize() {
    return ModuleSet.size();
}

