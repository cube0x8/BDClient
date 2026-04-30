#ifndef LOADLIBRARY_BD_H
#define LOADLIBRARY_BD_H

#include <stddef.h>
#include <stdint.h>

static char PluginsFullPath[4096] = { 0 };

typedef struct {
    size_t head;
    size_t tail;
    size_t size;
    void **data;
} queue_t;

void *queue_read(queue_t *queue);
int queue_write(queue_t *queue, void *handle);

extern queue_t *PluginsQueue;

#endif
