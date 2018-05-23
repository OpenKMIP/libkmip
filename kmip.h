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
#include <string.h>
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

#define KMIP_TRUE 1
#define KMIP_FALSE 0

#define KMIP_OK 0
#define KMIP_NOT_IMPLEMENTED -1
#define KMIP_ERROR_BUFFER_FULL -2

struct protocol_version
{
    int32 major;
    int32 minor;
};

struct error_frame
{
    char function[100];
    int line;
};

struct kmip
{
    uint8 *buffer;
    uint8 *index;
    size_t size;
    enum kmip_version version;
    struct error_frame errors[20];
    struct error_frame *frame_index;
};

#define ARRAY_LENGTH(A) (sizeof((A)) / sizeof((A)[0]))
#define CHECK_BUFFER_FULL(A, B)                         \
do                                                      \
{                                                       \
    if(((A)->size - ((A)->index - (A)->buffer)) < (B))  \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_ERROR_BUFFER_FULL);                 \
    }                                                   \
} while(0)
#define CHECK_RESULT(A, B)                              \
do                                                      \
{                                                       \
    if((B) != KMIP_OK)                                  \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return((B));                                    \
    }                                                   \
} while(0)

void
kmip_clear_errors(struct kmip *ctx)
{
    for(size_t i = 0; i < ARRAY_LENGTH(ctx->errors); i++)
    {
        ctx->errors[i] = (struct error_frame){0};
    }
    ctx->frame_index = ctx->errors;
}

void
kmip_init(struct kmip *ctx, uint8 *buffer, size_t buffer_size, 
          enum kmip_version v)
{
    ctx->buffer = buffer;
    ctx->index = ctx->buffer;
    ctx->size = buffer_size;
    ctx->version = v;
    
    kmip_clear_errors(ctx);
}

void
kmip_reset(struct kmip *ctx)
{
    uint8 *index = ctx->buffer;
    for(size_t i = 0; i < ctx->size; i++)
    {
        *index++ = 0;
    }
    ctx->index = ctx->buffer;
    
    kmip_clear_errors(ctx);
}

void
kmip_set_buffer(struct kmip *ctx, uint8 *buffer, size_t buffer_size)
{
    ctx->buffer = buffer;
    ctx->index = ctx->buffer;
    ctx->size = buffer_size;
}

void
kmip_push_error_frame(struct kmip *ctx, const char *function, const int line)
{
    for(size_t i = 0; i < 20; i++)
    {
        struct error_frame *frame = &ctx->errors[i];
        if(frame->line == 0)
        {
            strncpy(frame->function, function, sizeof(frame->function) - 1);
            frame->line = line;
            break;
        }
    }
}

int
encode_int8_be(struct kmip *ctx, int8 value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int8));
    
    *ctx->index++ = value;
    
    return(KMIP_OK);
}

int
encode_int32_be(struct kmip *ctx, int32 value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int32));
    
    *ctx->index++ = (value << 0) >> 24;
    *ctx->index++ = (value << 8) >> 24;
    *ctx->index++ = (value << 16) >> 24;
    *ctx->index++ = (value << 24) >> 24;
    
    return(KMIP_OK);
}

int
encode_int64_be(struct kmip *ctx, int64 value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int64));
    
    *ctx->index++ = (value << 0) >> 56;
    *ctx->index++ = (value << 8) >> 56;
    *ctx->index++ = (value << 16) >> 56;
    *ctx->index++ = (value << 24) >> 56;
    *ctx->index++ = (value << 32) >> 56;
    *ctx->index++ = (value << 40) >> 56;
    *ctx->index++ = (value << 48) >> 56;
    *ctx->index++ = (value << 56) >> 56;
    
    return(KMIP_OK);
}

int
encode_integer(struct kmip *ctx, enum tag t, int32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, (t << 8) | (uint8)KMIP_TYPE_INTEGER);
    encode_int32_be(ctx, 4);
    encode_int32_be(ctx, value);
    encode_int32_be(ctx, 0);
    
    return(KMIP_OK);
}

int
encode_long(struct kmip *ctx, enum tag t, int64 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, (t << 8) | (uint8)KMIP_TYPE_LONG_INTEGER);
    encode_int32_be(ctx, 8);
    encode_int64_be(ctx, value);
    
    return(KMIP_OK);
}

/*
int
encode_big(struct kmip *ctx, enum tag t, int8 *value, uint32 length)
{
    return(KMIP_NOT_IMPLEMENTED);
}
*/

int
encode_enum(struct kmip *ctx, enum tag t, int32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, (t << 8) | (uint8)KMIP_TYPE_ENUMERATION);
    encode_int32_be(ctx, 4);
    encode_int32_be(ctx, value);
    encode_int32_be(ctx, 0);
    
    return(KMIP_OK);
}

int
encode_bool(struct kmip *ctx, enum tag t, int32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, (t << 8) | (uint8)KMIP_TYPE_BOOLEAN);
    encode_int32_be(ctx, 8);
    encode_int32_be(ctx, 0);
    encode_int32_be(ctx, value);
    
    return(KMIP_OK);
}

int
encode_text_string(struct kmip *ctx, enum tag t, const char *value, uint32 length)
{
    uint8 padding = 8 - (length % 8);
    CHECK_BUFFER_FULL(ctx, 8 + length + padding);
    
    encode_int32_be(ctx, (t << 8) | (uint8)KMIP_TYPE_TEXT_STRING);
    encode_int32_be(ctx, length);
    
    for(uint32 i = 0; i < length; i++)
    {
        encode_int8_be(ctx, value[i]);
    }
    for(uint8 i = 0; i < padding; i++)
    {
        encode_int8_be(ctx, 0);
    }
    
    return(KMIP_OK);
}

int
encode_byte_string(struct kmip *ctx, enum tag t, const int8 *value, uint32 length)
{
    uint8 padding = 8 - (length % 8);
    CHECK_BUFFER_FULL(ctx, 8 + length + padding);
    
    encode_int32_be(ctx, (t << 8) | (uint8)KMIP_TYPE_BYTE_STRING);
    encode_int32_be(ctx, length);
    
    for(uint32 i = 0; i < length; i++)
    {
        encode_int8_be(ctx, value[i]);
    }
    for(uint8 i = 0; i < padding; i++)
    {
        encode_int8_be(ctx, 0);
    }
    
    return(KMIP_OK);
}

int
encode_date_time(struct kmip *ctx, enum tag t, uint64 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, (t << 8) | (uint8)KMIP_TYPE_DATE_TIME);
    encode_int32_be(ctx, 8);
    encode_int64_be(ctx, value);
    
    return(KMIP_OK);
}

int
encode_interval(struct kmip *ctx, enum tag t, uint32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, (t << 8) | (uint8)KMIP_TYPE_INTERVAL);
    encode_int32_be(ctx, 4);
    encode_int32_be(ctx, value);
    encode_int32_be(ctx, 0);
    
    return(KMIP_OK);
}

int
encode_protocol_version(struct kmip *ctx, const struct protocol_version *pv)
{
    CHECK_BUFFER_FULL(ctx, 40);
    
    encode_int32_be(
        ctx, 
        (KMIP_TAG_PROTOCOL_VERSION << 8) | (uint8)KMIP_TYPE_STRUCTURE);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    encode_integer(ctx, KMIP_TAG_PROTOCOL_VERSION_MAJOR, pv->major);
    encode_integer(ctx, KMIP_TAG_PROTOCOL_VERSION_MINOR, pv->minor);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

#endif /* KMIP_H */
