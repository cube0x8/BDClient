#ifndef _EDGES_
#define _EDGES_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <iostream>
#include <unordered_map>

#include "pin.H"

using namespace std;


class COUNTER
{
  public:
    UINT64 _count; // number of times the edge was traversed

    COUNTER() : _count(0) {}
};

typedef enum
{
    ETYPE_INVALID,
    ETYPE_CALL,
    ETYPE_ICALL,
    ETYPE_BRANCH,
    ETYPE_IBRANCH,
    ETYPE_RETURN,
    ETYPE_SYSCALL,
    ETYPE_LAST
} ETYPE;

class EDGE
{
  public:
    ADDRINT _src;
    ADDRINT _dst;
    ADDRINT _next_ins;
    ETYPE _type; // must be integer to make stl happy

    EDGE(ADDRINT s, ADDRINT d, ADDRINT n, ETYPE t) : _src(s), _dst(d), _next_ins(n), _type(t) {}

    bool operator<(const EDGE& edge) const { return _src < edge._src || (_src == edge._src && _dst < edge._dst); }
};

string StringFromEtype(ETYPE etype);

typedef map< EDGE, COUNTER* > EDG_HASH_SET;

/*!
  An Edge might have been previously instrumented, If so reuse the previous entry
  otherwise create a new one.
 */

COUNTER* Lookup(EDGE edge, EDG_HASH_SET *EdgeSet);

/* ===================================================================== */

VOID docount(COUNTER* pedg);

/* ===================================================================== */
// for indirect control flow we do not know the edge in advance and
// therefore must look it up

VOID docount2(ADDRINT src, ADDRINT dst, ADDRINT n, ETYPE type, INT32 taken, EDG_HASH_SET *EdgeSet);

#else
#warning edges.hpp multiple inclusion
#endif