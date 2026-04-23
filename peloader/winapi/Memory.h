#ifndef LOADLIBRARY_MEMORY_H
#define LOADLIBRARY_MEMORY_H

#endif //LOADLIBRARY_MEMORY_H

#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READWRITE 0x40

#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000

#define MEM_RELEASE 0x8000

void *allocateMemory(size_t dwSize);
bool deallocateMemory(void *ptr);
