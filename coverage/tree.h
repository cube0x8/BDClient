#ifndef __TREE_H
#define __TREE_H

typedef struct {
    void *root;
    int (*compare)(const void *, const void *);
    void (*free)(void *);
} tree_t;

typedef struct {
    uintptr_t address;      // Address of block
    size_t    size;         // Size of block
    uint32_t  count;        // Number of times I've been here
    char      *module_name; // Name of the module that contains this block
} execution_record_t;

// Routines for managing the execution record using POSIX binary search trees.
int compare(const void *a, const void *b);
bool tree_create(tree_t **tree, int (*compare)(const void *, const void *), void (*free)(void *));
bool tree_destroy(tree_t *tree);
void tree_walk(tree_t *tree, void (*function)(const void *));
bool tree_add(tree_t *tree, const void *data, void ***node);
bool tree_find(tree_t *tree, const void *data, void ***node);

#else
#warning tree.h multiple inclusion
#endif
