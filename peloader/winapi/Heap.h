#ifndef LOADLIBRARY_HEAP_H
#define LOADLIBRARY_HEAP_H

extern int heap_free_count;
extern int heap_alloc_count;
extern int heap_realloc_count;

PVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, PVOID lpMem);

#endif //LOADLIBRARY_HEAP_H
