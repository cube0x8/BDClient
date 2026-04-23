#include "edges.hpp"

VOID docount(COUNTER* pedg) { pedg->_count++; }

/* ===================================================================== */
// for indirect control flow we do not know the edge in advance and
// therefore must look it up

VOID docount2(ADDRINT src, ADDRINT dst, ADDRINT n, ETYPE type, INT32 taken, EDG_HASH_SET *EdgeSet)
{
    if (!taken) return;
    COUNTER* pedg = Lookup(EDGE(src, dst, n, type), EdgeSet);
    pedg->_count++;
}


COUNTER* Lookup(EDGE edge, EDG_HASH_SET *EdgeSet)
{
    COUNTER*& ref = (*EdgeSet)[edge];

    if (ref == 0)
    {
        ref = new COUNTER();
    }

    return ref;
}

string StringFromEtype(ETYPE etype)
{
    switch (etype)
    {
        case ETYPE_CALL:
            return "C";
        case ETYPE_ICALL:
            return "c";
        case ETYPE_BRANCH:
            return "B";
        case ETYPE_IBRANCH:
            return "b";
        case ETYPE_RETURN:
            return "r";
        case ETYPE_SYSCALL:
            return "s";
        default:
            ASSERTX(0);
            return "INVALID";
    }
}
