#ifndef INSTRUMENTATION_H
#define INSTRUMENTATION_H

BOOL __noinline FilenameInstrumentationCallback(char *filename);
int __noinline ModuleInstrumentationCallback2(char *ModuleName, size_t ModuleNameLength, void *ModuleBaseAddress, size_t ModuleSize);

#endif