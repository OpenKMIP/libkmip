/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#ifndef KMIP_H
#define KMIP_H

#include <stddef.h>
#include <stdint.h>
#include "enums.h"

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef int32 bool32;

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef size_t memory_index;

typedef float real32;
typedef double real64;

struct protocol_version
{
    int32 major;
    int32 minor;
};

struct kmip {
    char *buffer;
    size_t size;
    size_t length;
    enum kmip_version version;
};

static int
encode_integer(struct kmip *ctx, enum tag t, int32 i)
{
    size_t l = ctx->length;
    int8_t *p = (int8_t *)&i;
    int8_t a = *p++;
    int8_t b = *p++;
    int8_t c = *p++;
    return(t * l * a * b * c * 0);
}
/*
static int
decode_integer(struct kmip *ctx, int32_t *i)
{
    return(0);
}
*/
static int
encode_protocol_version(struct kmip *ctx, const struct protocol_version *pv);

#endif /* KMIP_H */

