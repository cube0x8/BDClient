//
// Copyright (C) 2017 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <search.h>

#include "winnt_types.h"
#include "strings.h"

char *string_from_wchar(LPCWSTR wcharbuf, size_t len)
{
    uint16_t *inbuf = (uint16_t *)wcharbuf;
    uint8_t *outbuf = NULL;
    void *buf;
    size_t count    = 0;

    if (wcharbuf == NULL)
        return NULL;

    buf = malloc(len + 1);
    outbuf = (uint8_t *) buf;

    while (1) {
        *outbuf++ = *inbuf++;
        if (++count >= len) {
            *(uint8_t *)outbuf = '\0';
            break;
        }
    }

    return (char *)buf;
}

size_t CountWideChars(const void *wcharbuf)
{
    size_t i = 0;
    const uint16_t *p = (const uint16_t *)wcharbuf;

    if (!p) return 0;

    while (*p++)
        i++;

    return i;
}
char *CreateAnsiFromWide(LPCWSTR wcharbuf)
{
    return string_from_wchar(wcharbuf, CountWideChars(wcharbuf));
}
