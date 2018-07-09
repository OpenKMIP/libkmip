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
#include <stdlib.h>
#include <string.h>
#include "enums.h"
#include "structs.h"

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
#define TAG_TYPE(A, B) (((A) << 8) | (uint8)(B))
#define CHECK_TAG_TYPE(A, B, C, D)                         \
do                                                         \
{                                                          \
    if((int32)((B) >> 8) != (int32)(C))                    \
    {                                                      \
        kmip_push_error_frame((A), __func__, __LINE__);    \
        return(KMIP_TAG_MISMATCH);                         \
    }                                                      \
    else if((int32)(((B) << 24) >> 24) != (int32)(D))      \
    {                                                      \
        kmip_push_error_frame((A), __func__, __LINE__);    \
        return(KMIP_TYPE_MISMATCH);                        \
    }                                                      \
} while(0)
#define CHECK_LENGTH(A, B, C)                           \
do                                                      \
{                                                       \
    if((B) != (C))                                      \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_LENGTH_MISMATCH);                   \
    }                                                   \
} while(0)
#define CHECK_PADDING(A, B)                             \
do                                                      \
{                                                       \
    if((B) != 0)                                        \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_PADDING_MISMATCH);                  \
    }                                                   \
} while(0)
#define CHECK_BOOLEAN(A, B)                             \
do                                                      \
{                                                       \
    if(((B) != KMIP_TRUE) && ((B) != KMIP_FALSE))       \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_BOOLEAN_MISMATCH);                  \
    }                                                   \
} while(0)

void *
kmip_malloc(void *state, size_t size)
{
    (void)state;
    
    void *ptr = malloc(size);
    
    if(ptr != NULL)
    {
        uint8* index = (uint8*)ptr;
        for(size_t i = 0; i < size; i++)
        {
            *index++ = 0;
        }
    }
    
    return(ptr);
}

void *
kmip_memset(void *state, void *ptr, int value, size_t size)
{
    (void)state;
    
    memset(ptr, value, size);
    
    return(ptr);
}

void
kmip_free(void *state, void *ptr)
{
    (void)state;
    
    free(ptr);
    
    return;
}

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
    
    if(ctx->malloc_func == NULL)
    {
        ctx->malloc_func = &kmip_malloc;
    }
    if(ctx->memset_func == NULL)
    {
        ctx->memset_func = &kmip_memset;
    }
    if(ctx->free_func == NULL)
    {
        ctx->free_func = &kmip_free;
    }
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
kmip_rewind(struct kmip *ctx)
{
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
kmip_push_error_frame(struct kmip *ctx, const char *function, 
                      const int line)
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
decode_int8_be(struct kmip *ctx, int8 *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int8));
    
    
    *value = 0;
    *value = *ctx->index++;
    
    return(KMIP_OK);
}

int
decode_uint8_be(struct kmip *ctx, uint8 *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(uint8));
    
    *value = 0;
    *value = *ctx->index++;
    
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
decode_int32_be(struct kmip *ctx, int32 *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int32));
    
    *value = 0;
    *value |= ((int32)*ctx->index++ << 24);
    *value |= ((int32)*ctx->index++ << 16);
    *value |= ((int32)*ctx->index++ << 8);
    *value |= ((int32)*ctx->index++ << 0);
    
    return(KMIP_OK);
}

int
decode_uint32_be(struct kmip *ctx, uint32 *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(uint32));
    
    *value = 0;
    *value |= ((uint32)*ctx->index++ << 24);
    *value |= ((uint32)*ctx->index++ << 16);
    *value |= ((uint32)*ctx->index++ << 8);
    *value |= ((uint32)*ctx->index++ << 0);
    
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
decode_int64_be(struct kmip *ctx, int64 *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int64));
    
    *value = 0;
    *value |= ((int64)*ctx->index++ << 56);
    *value |= ((int64)*ctx->index++ << 48);
    *value |= ((int64)*ctx->index++ << 40);
    *value |= ((int64)*ctx->index++ << 32);
    *value |= ((int64)*ctx->index++ << 24);
    *value |= ((int64)*ctx->index++ << 16);
    *value |= ((int64)*ctx->index++ << 8);
    *value |= ((int64)*ctx->index++ << 0);
    
    return(KMIP_OK);
}

int
decode_uint64_be(struct kmip *ctx, uint64 *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(uint64));
    
    *value = 0;
    *value |= ((uint64)*ctx->index++ << 56);
    *value |= ((uint64)*ctx->index++ << 48);
    *value |= ((uint64)*ctx->index++ << 40);
    *value |= ((uint64)*ctx->index++ << 32);
    *value |= ((uint64)*ctx->index++ << 24);
    *value |= ((uint64)*ctx->index++ << 16);
    *value |= ((uint64)*ctx->index++ << 8);
    *value |= ((uint64)*ctx->index++ << 0);
    
    return(KMIP_OK);
}

int
encode_integer(struct kmip *ctx, enum tag t, int32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_INTEGER));
    encode_int32_be(ctx, 4);
    encode_int32_be(ctx, value);
    encode_int32_be(ctx, 0);
    
    return(KMIP_OK);
}

int
validate_integer(struct kmip *ctx, enum tag t)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    int32 length = 0;
    int32 value = 0;
    int32 padding = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_INTEGER);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 4);
    
    decode_int32_be(ctx, &value);
    
    decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
    return(KMIP_OK);
}

int
decode_integer(struct kmip *ctx, enum tag t, int32 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    int32 length = 0;
    int32 padding = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_INTEGER);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 4);
    
    decode_int32_be(ctx, value);
    
    decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
    return(KMIP_OK);
}

int
encode_long(struct kmip *ctx, enum tag t, int64 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_LONG_INTEGER));
    encode_int32_be(ctx, 8);
    encode_int64_be(ctx, value);
    
    return(KMIP_OK);
}

int
validate_long(struct kmip *ctx, enum tag t)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    int32 length = 0;
    int64 value = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_LONG_INTEGER);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 8);
    
    decode_int64_be(ctx, &value);
    
    return(KMIP_OK);
}

int
decode_long(struct kmip *ctx, enum tag t, int64 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    int32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_LONG_INTEGER);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 8);
    
    decode_int64_be(ctx, value);
    
    return(KMIP_OK);
}

int
encode_enum(struct kmip *ctx, enum tag t, int32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_ENUMERATION));
    encode_int32_be(ctx, 4);
    encode_int32_be(ctx, value);
    encode_int32_be(ctx, 0);
    
    return(KMIP_OK);
}

int
validate_enum(struct kmip *ctx, enum tag t)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    int32 length = 0;
    int32 value = 0;
    int32 padding = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_ENUMERATION);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 4);
    
    decode_int32_be(ctx, &value);
    /* TODO (peter-hamilton) Add validate_enum_value call here. */
    
    decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
    return(KMIP_OK);
}

int
decode_enum(struct kmip *ctx, enum tag t, int32 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    int32 length = 0;
    int32 padding = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_ENUMERATION);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 4);
    
    decode_int32_be(ctx, value);
    
    decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
    return(KMIP_OK);
}

int
encode_bool(struct kmip *ctx, enum tag t, bool32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_BOOLEAN));
    encode_int32_be(ctx, 8);
    encode_int32_be(ctx, 0);
    encode_int32_be(ctx, value);
    
    return(KMIP_OK);
}

int
decode_bool(struct kmip *ctx, enum tag t, bool32 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    int32 length = 0;
    int32 padding = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_BOOLEAN);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 8);
    
    decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
    decode_int32_be(ctx, value);
    CHECK_BOOLEAN(ctx, *value);
    
    return(KMIP_OK);
}

int
encode_text_string(struct kmip *ctx, enum tag t,
                   const struct text_string *value)
{
    uint8 padding = (8 - (value->size % 8)) % 8;
    CHECK_BUFFER_FULL(ctx, 8 + value->size + padding);
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_TEXT_STRING));
    encode_int32_be(ctx, value->size);
    
    for(uint32 i = 0; i < value->size; i++)
    {
        encode_int8_be(ctx, value->value[i]);
    }
    for(uint8 i = 0; i < padding; i++)
    {
        encode_int8_be(ctx, 0);
    }
    
    return(KMIP_OK);
}

int
decode_text_string(struct kmip *ctx, enum tag t, struct text_string *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int32 tag_type = 0;
    int32 length = 0;
    int32 padding = 0;
    int8 spacer = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_TEXT_STRING);
    
    decode_int32_be(ctx, &length);
    padding = (8 - (length % 8)) % 8;
    CHECK_BUFFER_FULL(ctx, (uint32)(length + padding));
    
    value->value = ctx->malloc_func(ctx->state, length);
    value->size = length;
    
    char *index = value->value;
    
    for(int32 i = 0; i < length; i++)
    {
        decode_int8_be(ctx, (int8*)index++);
    }
    for(int32 i = 0; i < padding; i++)
    {
        decode_int8_be(ctx, &spacer);
        CHECK_PADDING(ctx, spacer);
    }
    
    return(KMIP_OK);
}

int
free_text_string(struct kmip *ctx, struct text_string *value)
{
    ctx->memset_func(ctx->state, value->value, 0, value->size);
    ctx->free_func(ctx->state, value->value);
    
    value->value = NULL;
    value->size = 0;
    
    return(KMIP_OK);
}

int
encode_byte_string(struct kmip *ctx, enum tag t,
                   const struct byte_string *value)
{
    uint8 padding = (8 - (value->size % 8)) % 8;
    CHECK_BUFFER_FULL(ctx, 8 + value->size + padding);
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_BYTE_STRING));
    encode_int32_be(ctx, value->size);
    
    for(uint32 i = 0; i < value->size; i++)
    {
        encode_int8_be(ctx, value->value[i]);
    }
    for(uint8 i = 0; i < padding; i++)
    {
        encode_int8_be(ctx, 0);
    }
    
    return(KMIP_OK);
}

int
decode_byte_string(struct kmip *ctx, enum tag t, struct byte_string *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int32 tag_type = 0;
    int32 length = 0;
    int32 padding = 0;
    int8 spacer = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_BYTE_STRING);
    
    decode_int32_be(ctx, &length);
    padding = (8 - (length % 8)) % 8;
    CHECK_BUFFER_FULL(ctx, (uint32)(length + padding));
    
    value->value = ctx->malloc_func(ctx->state, length);
    value->size = length;
    
    uint8 *index = value->value;
    
    for(int32 i = 0; i < length; i++)
    {
        decode_uint8_be(ctx, index++);
    }
    for(int32 i = 0; i < padding; i++)
    {
        decode_int8_be(ctx, &spacer);
        CHECK_PADDING(ctx, spacer);
    }
    
    return(KMIP_OK);
}

int
free_byte_string(struct kmip *ctx, struct byte_string *value)
{
    ctx->memset_func(ctx->state, value->value, 0, value->size);
    ctx->free_func(ctx->state, value->value);
    
    value->value = NULL;
    value->size = 0;
    
    return(KMIP_OK);
}

int
encode_date_time(struct kmip *ctx, enum tag t, uint64 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_DATE_TIME));
    encode_int32_be(ctx, 8);
    encode_int64_be(ctx, value);
    
    return(KMIP_OK);
}

int
decode_date_time(struct kmip *ctx, enum tag t, uint64 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    int32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_DATE_TIME);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 8);
    
    decode_uint64_be(ctx, value);
    
    return(KMIP_OK);
}

int
encode_interval(struct kmip *ctx, enum tag t, uint32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_INTERVAL));
    encode_int32_be(ctx, 4);
    encode_int32_be(ctx, value);
    encode_int32_be(ctx, 0);
    
    return(KMIP_OK);
}

int
decode_interval(struct kmip *ctx, enum tag t, uint32 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    int32 length = 0;
    int32 padding = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_INTERVAL);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 4);
    
    decode_uint32_be(ctx, value);
    
    decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
    return(KMIP_OK);
}

int
encode_name(struct kmip *ctx, const struct name *value)
{
    /* TODO (peter-hamilton) Check for value == NULL? */
    
    int result = 0;
    
    result = encode_int32_be(
        ctx, TAG_TYPE(KMIP_TAG_NAME, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_text_string(
        ctx,
        KMIP_TAG_NAME_VALUE,
        value->value);
    CHECK_RESULT(ctx, result);
    
    result = encode_enum(ctx, KMIP_TAG_NAME_TYPE, value->type);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = encode_int32_be(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
decode_name(struct kmip *ctx, struct name *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_NAME, KMIP_TYPE_STRUCTURE);
    
    decode_uint32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->value = ctx->malloc_func(ctx->state, sizeof(struct text_string));
    
    result = decode_text_string(ctx, KMIP_TAG_NAME_VALUE, value->value);
    CHECK_RESULT(ctx, result);
    
    result = decode_enum(ctx, KMIP_TAG_NAME_TYPE, (int32*)&value->type);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
encode_attribute_name(struct kmip *ctx, enum attribute_type value)
{
    int result = 0;
    enum tag t = KMIP_TAG_ATTRIBUTE_NAME;
    struct text_string attribute_name = {0};
    
    switch(value)
    {
        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        attribute_name.value = "Unique Identifier";
        attribute_name.size = 17;
        break;
        
        case KMIP_ATTR_NAME:
        attribute_name.value = "Name";
        attribute_name.size = 4;
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        attribute_name.value = "Object Type";
        attribute_name.size = 11;
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        attribute_name.value = "Cryptographic Algorithm";
        attribute_name.size = 23;
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        attribute_name.value = "Cryptographic Length";
        attribute_name.size = 20;
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        attribute_name.value = "Operation Policy Name";
        attribute_name.size = 21;
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        attribute_name.value = "Cryptographic Usage Mask";
        attribute_name.size = 24;
        break;
        
        case KMIP_ATTR_STATE:
        attribute_name.value = "State";
        attribute_name.size = 5;
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_ERROR_ATTR_UNSUPPORTED);
        break;
    };
    
    result = encode_text_string(ctx, t, &attribute_name);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
encode_attribute(struct kmip *ctx, const struct attribute *value)
{
    /* TODO (peter-hamilton) Check value == NULL? */
    /* TODO (peter-hamilton) Cehck value->value == NULL? */
    
    /* TODO (peter-hamilton) Add CryptographicParameters support? */
    
    int result = 0;
    
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_ATTRIBUTE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(value->index != KMIP_UNSET)
    {
        result = encode_integer(ctx, KMIP_TAG_ATTRIBUTE_INDEX, value->index);
        CHECK_RESULT(ctx, result);
    }
    
    result = encode_attribute_name(ctx, value->type);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    uint8 *tag_index = ctx->index;
    enum tag t = KMIP_TAG_ATTRIBUTE_VALUE;
    
    switch(value->type)
    {
        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        result = encode_text_string(
            ctx, t, 
            (struct text_string*)value->value);
        break;
        
        case KMIP_ATTR_NAME:
        /* TODO (peter-hamilton) This is messy. Clean it up? */
        result = encode_name(ctx, (struct name*)value->value);
        CHECK_RESULT(ctx, result);
        
        curr_index = ctx->index;
        ctx->index = tag_index;
        
        result = encode_int32_be(
            ctx,
            TAG_TYPE(KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE));
        
        ctx->index = curr_index;
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        result = encode_enum(ctx, t, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        result = encode_enum(ctx, t, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        result = encode_integer(ctx, t, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        result = encode_text_string(
            ctx, t, 
            (struct text_string*)value->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        result = encode_integer(ctx, t, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_STATE:
        result = encode_enum(ctx, t, *(int32 *)value->value);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_ERROR_ATTR_UNSUPPORTED);
        break;
    };
    CHECK_RESULT(ctx, result);
    
    curr_index = ctx->index;
    ctx->index = length_index;
    
    result = encode_int32_be(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_template_attribute(struct kmip *ctx, 
                          const struct template_attribute *value)
{
    int result = 0;
    
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_TEMPLATE_ATTRIBUTE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    for(size_t i = 0; i < value->name_count; i++)
    {
        result = encode_name(ctx, &value->names[i]);
        CHECK_RESULT(ctx, result);
    }
    
    for(size_t i = 0; i <value->attribute_count; i++)
    {
        result = encode_attribute(ctx, &value->attributes[i]);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = encode_int32_be(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_protocol_version(struct kmip *ctx, 
                        const struct protocol_version *value)
{
    CHECK_BUFFER_FULL(ctx, 40);
    
    encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_PROTOCOL_VERSION, KMIP_TYPE_STRUCTURE));
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    encode_integer(ctx, KMIP_TAG_PROTOCOL_VERSION_MAJOR, value->major);
    encode_integer(ctx, KMIP_TAG_PROTOCOL_VERSION_MINOR, value->minor);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_cryptographic_parameters(struct kmip *ctx, 
                                const struct cryptographic_parameters *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(value->block_cipher_mode != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_BLOCK_CIPHER_MODE,
            value->block_cipher_mode);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->padding_method != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_PADDING_METHOD,
            value->padding_method);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->hashing_algorithm != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_HASHING_ALGORITHM,
            value->hashing_algorithm);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->key_role_type != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_KEY_ROLE_TYPE,
            value->key_role_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_2)
    {
        if(value->digital_signature_algorithm != 0)
        {
            result = encode_enum(
                ctx,
                KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM,
                value->digital_signature_algorithm);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->cryptographic_algorithm != 0)
        {
            result = encode_enum(
                ctx,
                KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
                value->cryptographic_algorithm);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->random_iv != KMIP_UNSET)
        {
            result = encode_bool(
                ctx,
                KMIP_TAG_RANDOM_IV,
                value->random_iv);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->iv_length != KMIP_UNSET)
        {
            result = encode_integer(
                ctx,
                KMIP_TAG_IV_LENGTH,
                value->iv_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->tag_length != KMIP_UNSET)
        {
            result = encode_integer(
                ctx,
                KMIP_TAG_TAG_LENGTH,
                value->tag_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->fixed_field_length != KMIP_UNSET)
        {
            result = encode_integer(
                ctx,
                KMIP_TAG_FIXED_FIELD_LENGTH,
                value->fixed_field_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->invocation_field_length != KMIP_UNSET)
        {
            result = encode_integer(
                ctx,
                KMIP_TAG_INVOCATION_FIELD_LENGTH,
                value->invocation_field_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->counter_length != KMIP_UNSET)
        {
            result = encode_integer(
                ctx,
                KMIP_TAG_COUNTER_LENGTH,
                value->counter_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->initial_counter_value != KMIP_UNSET)
        {
            result = encode_integer(
                ctx,
                KMIP_TAG_INITIAL_COUNTER_VALUE,
                value->initial_counter_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(value->salt_length != KMIP_UNSET)
        {
            result = encode_integer(
                ctx,
                KMIP_TAG_SALT_LENGTH,
                value->salt_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->mask_generator != 0)
        {
            result = encode_enum(
                ctx,
                KMIP_TAG_MASK_GENERATOR,
                value->mask_generator);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->mask_generator_hashing_algorithm != 0)
        {
            result = encode_enum(
                ctx,
                KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM,
                value->mask_generator_hashing_algorithm);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->p_source != NULL)
        {
            result = encode_byte_string(
                ctx,
                KMIP_TAG_P_SOURCE,
                value->p_source);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->trailer_field != KMIP_UNSET)
        {
            result = encode_integer(
                ctx,
                KMIP_TAG_TRAILER_FIELD,
                value->trailer_field);
            CHECK_RESULT(ctx, result);
        }
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_encryption_key_information(struct kmip *ctx, 
                                  const struct encryption_key_information *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_ENCRYPTION_KEY_INFORMATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_text_string(
        ctx, KMIP_TAG_UNIQUE_IDENTIFIER, 
        value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(value->cryptographic_parameters != 0)
    {
        result = encode_cryptographic_parameters(
            ctx, 
            value->cryptographic_parameters);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_mac_signature_key_information(struct kmip *ctx, 
                                     const struct mac_signature_key_information *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_text_string(
        ctx, KMIP_TAG_UNIQUE_IDENTIFIER, 
        value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(value->cryptographic_parameters != 0)
    {
        result = encode_cryptographic_parameters(
            ctx, 
            value->cryptographic_parameters);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_key_wrapping_data(struct kmip *ctx, 
                         const struct key_wrapping_data *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_KEY_WRAPPING_DATA, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_WRAPPING_METHOD, value->wrapping_method);
    CHECK_RESULT(ctx, result);
    
    if(value->encryption_key_info != NULL)
    {
        result = encode_encryption_key_information(
            ctx, 
            value->encryption_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->mac_signature_key_info != NULL)
    {
        result = encode_mac_signature_key_information(
            ctx, 
            value->mac_signature_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->mac_signature != NULL)
    {
        result = encode_byte_string(
            ctx, KMIP_TAG_MAC_SIGNATURE, 
            value->mac_signature);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->iv_counter_nonce != NULL)
    {
        result = encode_byte_string(
            ctx, KMIP_TAG_IV_COUNTER_NONCE, 
            value->iv_counter_nonce);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_1)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_ENCODING_OPTION,
            value->encoding_option);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_transparent_symmetric_key(struct kmip *ctx,
                                 const struct transparent_symmetric_key *value)
{
    int result = 0;
    
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_KEY_MATERIAL, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_byte_string(
        ctx,
        KMIP_TAG_KEY,
        value->key);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_key_material(struct kmip *ctx, enum key_format_type format, const void *value)
{
    int result = 0;
    
    switch(format)
    {
        case KMIP_KEYFORMAT_RAW:
        case KMIP_KEYFORMAT_OPAQUE:
        case KMIP_KEYFORMAT_PKCS1:
        case KMIP_KEYFORMAT_PKCS8:
        case KMIP_KEYFORMAT_X509:
        case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
        result = encode_byte_string(
            ctx,
            KMIP_TAG_KEY_MATERIAL,
            (struct byte_string*)value);
        CHECK_RESULT(ctx, result);
        return(KMIP_OK);
        break;
        
        default:
        break;
    };
    
    switch(format)
    {
        case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
        result = encode_transparent_symmetric_key(
            ctx,
            (struct transparent_symmetric_key*)value);
        CHECK_RESULT(ctx, result);
        break;
        
        /* TODO (peter-hamilton) The rest require BigInteger support. */
        
        case KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    
    return(KMIP_OK);
}

int
encode_key_value(struct kmip *ctx, enum key_format_type format,
                 const struct key_value *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_KEY_VALUE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_key_material(ctx, format, value->key_material);
    CHECK_RESULT(ctx, result);
    
    for(size_t i = 0; i < value->attribute_count; i++)
    {
        result = encode_attribute(ctx, &value->attributes[i]);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_key_block(struct kmip *ctx, const struct key_block *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_KEY_BLOCK, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_KEY_FORMAT_TYPE, value->key_format_type);
    CHECK_RESULT(ctx, result);
    
    if(value->key_compression_type != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_KEY_COMPRESSION_TYPE,
            value->key_compression_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->key_wrapping_data != NULL)
    {
        result = encode_byte_string(
            ctx,
            KMIP_TAG_KEY_VALUE,
            (struct byte_string*)value->key_value);
    }
    else
    {
        result = encode_key_value(
            ctx,
            value->key_format_type,
            (struct key_value*)value->key_value);
    }
    CHECK_RESULT(ctx, result);
    
    if(value->cryptographic_algorithm != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
            value->cryptographic_algorithm);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->cryptographic_length != KMIP_UNSET)
    {
        result = encode_integer(
            ctx,
            KMIP_TAG_CRYPTOGRAPHIC_LENGTH,
            value->cryptographic_length);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->key_wrapping_data != NULL)
    {
        result = encode_key_wrapping_data(ctx, value->key_wrapping_data);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_symmetric_key(struct kmip *ctx, const struct symmetric_key *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_SYMMETRIC_KEY, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_public_key(struct kmip *ctx, const struct public_key *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_PUBLIC_KEY, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_private_key(struct kmip *ctx, const struct private_key *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_PRIVATE_KEY, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_key_wrapping_specification(struct kmip *ctx,
                                  const struct key_wrapping_specification *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_KEY_WRAPPING_SPECIFICATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_WRAPPING_METHOD, value->wrapping_method);
    CHECK_RESULT(ctx, result);
    
    if(value->encryption_key_info != NULL)
    {
        result = encode_encryption_key_information(
            ctx,
            value->encryption_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->mac_signature_key_info != NULL)
    {
        result = encode_mac_signature_key_information(
            ctx,
            value->mac_signature_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    for(size_t i = 0; i < value->attribute_name_count; i++)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_ATTRIBUTE_NAME, 
            &value->attribute_names[i]);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_1)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_ENCODING_OPTION,
            value->encoding_option);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_create_request_payload(struct kmip *ctx, 
                              const struct create_request_payload *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    CHECK_RESULT(ctx, result);
    
    result = encode_template_attribute(ctx, value->template_attribute);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}


int
encode_create_response_payload(struct kmip *ctx, 
                               const struct create_response_payload *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    CHECK_RESULT(ctx, result);
    
    result = encode_text_string(
        ctx, KMIP_TAG_UNIQUE_IDENTIFIER,
        value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(value->template_attribute != NULL)
    {
        result = encode_template_attribute(ctx, value->template_attribute);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_get_request_payload(struct kmip *ctx,
                           const struct get_request_payload *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(value->unique_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_UNIQUE_IDENTIFIER,
            value->unique_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->key_format_type != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_KEY_FORMAT_TYPE,
            value->key_format_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(value->key_wrap_type != 0)
        {
            result = encode_enum(
                ctx,
                KMIP_TAG_KEY_WRAP_TYPE,
                value->key_wrap_type);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(value->key_compression_type != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_KEY_COMPRESSION_TYPE,
            value->key_compression_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->key_wrapping_spec != NULL)
    {
        result = encode_key_wrapping_specification(
            ctx,
            value->key_wrapping_spec);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_get_response_payload(struct kmip *ctx,
                            const struct get_response_payload *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    CHECK_RESULT(ctx, result);
    
    result = encode_text_string(
        ctx, KMIP_TAG_UNIQUE_IDENTIFIER,
        value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    switch(value->object_type)
    {
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
        result = encode_symmetric_key(
            ctx,
            (const struct symmetric_key*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_OBJTYPE_PUBLIC_KEY:
        result = encode_public_key(
            ctx,
            (const struct public_key*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_OBJTYPE_PRIVATE_KEY:
        result = encode_private_key(
            ctx,
            (const struct private_key*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_destroy_request_payload(struct kmip *ctx, 
                               const struct destroy_request_payload *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(value->unique_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_UNIQUE_IDENTIFIER,
            value->unique_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_destroy_response_payload(struct kmip *ctx, 
                                const struct destroy_response_payload *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_text_string(
        ctx, KMIP_TAG_UNIQUE_IDENTIFIER,
        value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_nonce(struct kmip *ctx, const struct nonce *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_NONCE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_byte_string(
        ctx,
        KMIP_TAG_NONCE_ID,
        value->nonce_id);
    CHECK_RESULT(ctx, result);
    
    result = encode_byte_string(
        ctx,
        KMIP_TAG_NONCE_VALUE,
        value->nonce_value);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_username_password_credential(
struct kmip *ctx, 
const struct username_password_credential *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_CREDENTIAL_VALUE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_text_string(
        ctx, KMIP_TAG_USERNAME,
        value->username);
    CHECK_RESULT(ctx, result);
    
    if(value->password != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_PASSWORD,
            value->password);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_device_credential(struct kmip *ctx,
                         const struct device_credential *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_CREDENTIAL_VALUE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(value->device_serial_number != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_DEVICE_SERIAL_NUMBER,
            value->device_serial_number);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->password != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_PASSWORD,
            value->password);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->device_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_DEVICE_IDENTIFIER,
            value->device_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->network_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_NETWORK_IDENTIFIER,
            value->network_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->machine_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_MACHINE_IDENTIFIER,
            value->machine_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->media_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_MEDIA_IDENTIFIER,
            value->media_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_attestation_credential(struct kmip *ctx,
                              const struct attestation_credential *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_CREDENTIAL_VALUE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_nonce(ctx, value->nonce);
    CHECK_RESULT(ctx, result);
    
    result = encode_enum(
        ctx,
        KMIP_TAG_ATTESTATION_TYPE,
        value->attestation_type);
    CHECK_RESULT(ctx, result);
    
    if(value->attestation_measurement != NULL)
    {
        result = encode_byte_string(
            ctx, KMIP_TAG_ATTESTATION_MEASUREMENT,
            value->attestation_measurement);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->attestation_assertion != NULL)
    {
        result = encode_byte_string(
            ctx, KMIP_TAG_ATTESTATION_ASSERTION,
            value->attestation_assertion);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_credential_value(struct kmip *ctx, 
                        enum credential_type type, 
                        void *value)
{
    int result = 0;
    
    switch(type)
    {
        case KMIP_CRED_USERNAME_AND_PASSWORD:
        result = encode_username_password_credential(
            ctx, 
            (struct username_password_credential*)value);
        break;
        
        case KMIP_CRED_DEVICE:
        result = encode_device_credential(
            ctx,
            (struct device_credential*)value);
        break;
        
        case KMIP_CRED_ATTESTATION:
        result = encode_attestation_credential(
            ctx,
            (struct attestation_credential*)value);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    }
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
encode_credential(struct kmip *ctx, const struct credential *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_CREDENTIAL, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_CREDENTIAL_TYPE, value->credential_type);
    CHECK_RESULT(ctx, result);
    
    result = encode_credential_value(
        ctx,
        value->credential_type,
        value->credential_value);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_authentication(struct kmip *ctx, const struct authentication *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_AUTHENTICATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_credential(ctx, value->credential);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_request_header(struct kmip *ctx, const struct request_header *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_REQUEST_HEADER, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_protocol_version(ctx, value->protocol_version);
    CHECK_RESULT(ctx, result);
    
    if(value->maximum_response_size != 0)
    {
        result = encode_integer(
            ctx,
            KMIP_TAG_MAXIMUM_RESPONSE_SIZE,
            value->maximum_response_size);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(value->client_correlation_value != NULL)
        {
            result = encode_text_string(
                ctx,
                KMIP_TAG_CLIENT_CORRELATION_VALUE,
                value->client_correlation_value);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->server_correlation_value != NULL)
        {
            result = encode_text_string(
                ctx,
                KMIP_TAG_SERVER_CORRELATION_VALUE,
                value->server_correlation_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(value->asynchronous_indicator != KMIP_UNSET)
    {
        result = encode_bool(
            ctx,
            KMIP_TAG_ASYNCHRONOUS_INDICATOR,
            value->asynchronous_indicator);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_2)
    {
        if(value->attestation_capable_indicator != KMIP_UNSET)
        {
            result = encode_bool(
                ctx,
                KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR,
                value->attestation_capable_indicator);
            CHECK_RESULT(ctx, result);
        }
        
        for(size_t i = 0; i < value->attestation_type_count; i++)
        {
            result = encode_enum(
                ctx,
                KMIP_TAG_ATTESTATION_TYPE,
                value->attestation_types[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(value->authentication != NULL)
    {
        result = encode_authentication(ctx, value->authentication);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->batch_error_continuation_option != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION,
            value->batch_error_continuation_option);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->batch_order_option != KMIP_UNSET)
    {
        result = encode_bool(
            ctx,
            KMIP_TAG_BATCH_ORDER_OPTION,
            value->batch_order_option);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->time_stamp != 0)
    {
        result = encode_date_time(ctx, KMIP_TAG_TIME_STAMP, value->time_stamp);
        CHECK_RESULT(ctx, result);
    }
    
    result = encode_integer(ctx, KMIP_TAG_BATCH_COUNT, value->batch_count);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_response_header(struct kmip *ctx, const struct response_header *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_RESPONSE_HEADER, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_protocol_version(ctx, value->protocol_version);
    CHECK_RESULT(ctx, result);
    
    result = encode_date_time(ctx, KMIP_TAG_TIME_STAMP, value->time_stamp);
    CHECK_RESULT(ctx, result);
    
    if(ctx->version >= KMIP_1_2)
    {
        if(value->nonce != NULL)
        {
            result = encode_nonce(ctx, value->nonce);
            CHECK_RESULT(ctx, result);
        }
        
        for(size_t i = 0; i < value->attestation_type_count; i++)
        {
            result = encode_enum(
                ctx,
                KMIP_TAG_ATTESTATION_TYPE,
                value->attestation_types[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(value->client_correlation_value != NULL)
        {
            result = encode_text_string(
                ctx,
                KMIP_TAG_CLIENT_CORRELATION_VALUE,
                value->client_correlation_value);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->server_correlation_value != NULL)
        {
            result = encode_text_string(
                ctx,
                KMIP_TAG_SERVER_CORRELATION_VALUE,
                value->server_correlation_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    result = encode_integer(ctx, KMIP_TAG_BATCH_COUNT, value->batch_count);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_request_batch_item(struct kmip *ctx,
                          const struct request_batch_item *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_BATCH_ITEM, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_OPERATION, value->operation);
    CHECK_RESULT(ctx, result);
    
    if(value->unique_batch_item_id != NULL)
    {
        result = encode_byte_string(
            ctx,
            KMIP_TAG_UNIQUE_BATCH_ITEM_ID,
            value->unique_batch_item_id);
        CHECK_RESULT(ctx, result);
    }
    
    switch(value->operation)
    {
        case KMIP_OP_CREATE:
        result = encode_create_request_payload(
            ctx, 
            (struct create_request_payload*)value->request_payload);
        break;
        
        case KMIP_OP_GET:
        result = encode_get_request_payload(
            ctx, 
            (struct get_request_payload*)value->request_payload);
        break;
        
        case KMIP_OP_DESTROY:
        result = encode_destroy_request_payload(
            ctx,
            (struct destroy_request_payload*)value->request_payload);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_response_batch_item(struct kmip *ctx,
                           const struct response_batch_item *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_BATCH_ITEM, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_OPERATION, value->operation);
    CHECK_RESULT(ctx, result);
    
    if(value->unique_batch_item_id != NULL)
    {
        result = encode_byte_string(
            ctx,
            KMIP_TAG_UNIQUE_BATCH_ITEM_ID,
            value->unique_batch_item_id);
        CHECK_RESULT(ctx, result);
    }
    
    result = encode_enum(ctx, KMIP_TAG_RESULT_STATUS, value->result_status);
    CHECK_RESULT(ctx, result);
    
    if(value->result_reason != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_RESULT_REASON,
            value->result_reason);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->result_message != NULL)
    {
        result = encode_text_string(
            ctx,
            KMIP_TAG_RESULT_MESSAGE,
            value->result_message);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->asynchronous_correlation_value != NULL)
    {
        result = encode_byte_string(
            ctx,
            KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE,
            value->asynchronous_correlation_value);
        CHECK_RESULT(ctx, result);
    }
    
    switch(value->operation)
    {
        case KMIP_OP_CREATE:
        result = encode_create_response_payload(
            ctx,
            (struct create_response_payload*)value->response_payload);
        break;
        
        case KMIP_OP_GET:
        result = encode_get_response_payload(
            ctx, 
            (struct get_response_payload*)value->response_payload);
        break;
        
        case KMIP_OP_DESTROY:
        result = encode_destroy_response_payload(
            ctx,
            (struct destroy_response_payload*)value->response_payload);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_request_message(struct kmip *ctx, const struct request_message *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_REQUEST_MESSAGE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_request_header(ctx, value->request_header);
    CHECK_RESULT(ctx, result);
    
    for(size_t i = 0; i < value->batch_count; i++)
    {
        result = encode_request_batch_item(ctx, &value->batch_items[i]);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_response_message(struct kmip *ctx, const struct response_message *value)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_RESPONSE_MESSAGE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_response_header(ctx, value->response_header);
    CHECK_RESULT(ctx, result);
    
    for(size_t i = 0; i < value->batch_count; i++)
    {
        result = encode_response_batch_item(ctx, &value->batch_items[i]);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

#endif /* KMIP_H */
