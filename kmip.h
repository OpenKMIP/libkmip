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
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_INTEGER));
    encode_int32_be(ctx, 4);
    encode_int32_be(ctx, value);
    encode_int32_be(ctx, 0);
    
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
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_ENUMERATION));
    encode_int32_be(ctx, 4);
    encode_int32_be(ctx, value);
    encode_int32_be(ctx, 0);
    
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
encode_text_string(struct kmip *ctx, enum tag t, const char *value, 
                   uint32 length)
{
    uint8 padding = (8 - (length % 8)) % 8;
    CHECK_BUFFER_FULL(ctx, 8 + length + padding);
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_TEXT_STRING));
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
encode_byte_string(struct kmip *ctx, enum tag t, const uint8 *value, uint32 length)
{
    uint8 padding = (8 - (length % 8)) % 8;
    CHECK_BUFFER_FULL(ctx, 8 + length + padding);
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_BYTE_STRING));
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
    
    encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_DATE_TIME));
    encode_int32_be(ctx, 8);
    encode_int64_be(ctx, value);
    
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
encode_name(struct kmip *ctx, struct name *n)
{
    /* TODO (peter-hamilton) Check for n == NULL? */
    
    int result = 0;
    
    result = encode_int32_be(
        ctx, TAG_TYPE(KMIP_TAG_NAME, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_text_string(ctx, KMIP_TAG_NAME_VALUE, n->value, n->size);
    CHECK_RESULT(ctx, result);
    result = encode_enum(ctx, KMIP_TAG_NAME_TYPE, n->type);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = encode_int32_be(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_attribute_name(struct kmip *ctx, enum attribute_type type)
{
    int result = 0;
    enum tag t = KMIP_TAG_ATTRIBUTE_NAME;
    
    switch(type)
    {
        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        result = encode_text_string(ctx, t, "Unique Identifier", 17);
        break;
        
        case KMIP_ATTR_NAME:
        result = encode_text_string(ctx, t, "Name", 4);
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        result = encode_text_string(ctx, t, "Object Type", 11);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        result = encode_text_string(ctx, t, "Cryptographic Algorithm", 23);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        result = encode_text_string(ctx, t, "Cryptographic Length", 20);
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        result = encode_text_string(ctx, t, "Operation Policy Name", 21);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        result = encode_text_string(ctx, t, "Cryptographic Usage Mask", 24);
        break;
        
        case KMIP_ATTR_STATE:
        result = encode_text_string(ctx, t, "State", 5);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_ERROR_ATTR_UNSUPPORTED);
        break;
    };
    
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
encode_attribute(struct kmip *ctx, struct attribute *attr)
{
    /* TODO (peter-hamilton) Check attr == NULL? */
    /* TODO (peter-hamilton) Cehck attr->value == NULL? */
    
    /* TODO (peter-hamilton) Add CryptographicParameters support? */
    
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_ATTRIBUTE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(attr->index != KMIP_UNSET)
    {
        result = encode_integer(ctx, KMIP_TAG_ATTRIBUTE_INDEX, attr->index);
        CHECK_RESULT(ctx, result);
    }
    
    result = encode_attribute_name(ctx, attr->type);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    uint8 *tag_index = ctx->index;
    enum tag t = KMIP_TAG_ATTRIBUTE_VALUE;
    
    switch(attr->type)
    {
        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        result = encode_text_string(
            ctx, t, 
            ((struct text_string*)attr->value)->value,
            ((struct text_string*)attr->value)->size);
        break;
        
        case KMIP_ATTR_NAME:
        /* TODO (peter-hamilton) This is messy. Clean it up? */
        result = encode_name(ctx, (struct name*)attr->value);
        CHECK_RESULT(ctx, result);
        curr_index = ctx->index;
        ctx->index = tag_index;
        result = encode_int32_be(
            ctx,
            TAG_TYPE(KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE));
        ctx->index = curr_index;
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        result = encode_enum(ctx, t, *(int32 *)attr->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        result = encode_enum(ctx, t, *(int32 *)attr->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        result = encode_integer(ctx, t, *(int32 *)attr->value);
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        result = encode_text_string(
            ctx, t, 
            ((struct text_string*)attr->value)->value,
            ((struct text_string*)attr->value)->size);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        result = encode_integer(ctx, t, *(int32 *)attr->value);
        break;
        
        case KMIP_ATTR_STATE:
        result = encode_enum(ctx, t, *(int32 *)attr->value);
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
encode_template_attribute(struct kmip *ctx, struct template_attribute *ta)
{
    int result = 0;
    
    result = encode_int32_be(
        ctx, TAG_TYPE(KMIP_TAG_TEMPLATE_ATTRIBUTE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    for(size_t i = 0; i < ta->name_count; i++)
    {
        result = encode_name(ctx, &ta->names[i]);
        CHECK_RESULT(ctx, result);
    }
    
    for(size_t i = 0; i <ta->attribute_count; i++)
    {
        result = encode_attribute(ctx, &ta->attributes[i]);
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
                        const struct protocol_version *pv)
{
    CHECK_BUFFER_FULL(ctx, 40);
    
    encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_PROTOCOL_VERSION, KMIP_TYPE_STRUCTURE));
    
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

int
encode_cryptographic_parameters(struct kmip *ctx, 
                                const struct cryptographic_parameters *cp)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(cp->block_cipher_mode != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_BLOCK_CIPHER_MODE,
            cp->block_cipher_mode);
        CHECK_RESULT(ctx, result);
    }
    
    if(cp->padding_method != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_PADDING_METHOD,
            cp->padding_method);
        CHECK_RESULT(ctx, result);
    }
    
    if(cp->hashing_algorithm != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_HASHING_ALGORITHM,
            cp->hashing_algorithm);
        CHECK_RESULT(ctx, result);
    }
    
    if(cp->key_role_type != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_KEY_ROLE_TYPE,
            cp->key_role_type);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_encryption_key_information(struct kmip *ctx, 
                                  const struct encryption_key_information *eki)
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
        eki->unique_identifier->value,
        eki->unique_identifier->size);
    CHECK_RESULT(ctx, result);
    
    if(eki->cryptographic_parameters != 0)
    {
        result = encode_cryptographic_parameters(
            ctx, 
            eki->cryptographic_parameters);
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
                                     const struct mac_signature_key_information *mski)
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
        mski->unique_identifier->value,
        mski->unique_identifier->size);
    CHECK_RESULT(ctx, result);
    
    if(mski->cryptographic_parameters != 0)
    {
        result = encode_cryptographic_parameters(
            ctx, 
            mski->cryptographic_parameters);
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
                         const struct key_wrapping_data *kwd)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_KEY_WRAPPING_DATA, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_WRAPPING_METHOD, kwd->wrapping_method);
    CHECK_RESULT(ctx, result);
    
    if(kwd->encryption_key_info != NULL)
    {
        result = encode_encryption_key_information(
            ctx, 
            kwd->encryption_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(kwd->mac_signature_key_info != NULL)
    {
        result = encode_mac_signature_key_information(
            ctx, 
            kwd->mac_signature_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(kwd->mac_signature != NULL)
    {
        result = encode_byte_string(
            ctx, KMIP_TAG_MAC_SIGNATURE, 
            kwd->mac_signature->value,
            kwd->mac_signature->size);
        CHECK_RESULT(ctx, result);
    }
    
    if(kwd->iv_counter_nonce != NULL)
    {
        result = encode_byte_string(
            ctx, KMIP_TAG_IV_COUNTER_NONCE, 
            kwd->iv_counter_nonce->value,
            kwd->iv_counter_nonce->size);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_1)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_ENCODING_OPTION,
            kwd->encoding_option);
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
                                 const struct transparent_symmetric_key *tsk)
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
        tsk->key->value,
        tsk->key->size);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_key_material(struct kmip *ctx, enum key_format_type format, const void *km)
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
            ((struct byte_string*)km)->value,
            ((struct byte_string*)km)->size);
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
            (struct transparent_symmetric_key*)km);
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
                 const struct key_value *kv)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_KEY_VALUE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_key_material(ctx, format, kv->key_material);
    CHECK_RESULT(ctx, result);
    
    for(size_t i = 0; i < kv->attribute_count; i++)
    {
        struct attribute attr = kv->attributes[i];
        result = encode_attribute(ctx, &attr);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_key_block(struct kmip *ctx, const struct key_block *kb)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_KEY_BLOCK, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_KEY_FORMAT_TYPE, kb->key_format_type);
    CHECK_RESULT(ctx, result);
    
    if(kb->key_compression_type != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_KEY_COMPRESSION_TYPE,
            kb->key_compression_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(kb->key_wrapping_data != NULL)
    {
        result = encode_byte_string(
            ctx,
            KMIP_TAG_KEY_VALUE,
            ((struct byte_string*)kb->key_value)->value,
            ((struct byte_string*)kb->key_value)->size);
    }
    else
    {
        result = encode_key_value(
            ctx,
            kb->key_format_type,
            (struct key_value*)kb->key_value);
    }
    CHECK_RESULT(ctx, result);
    
    if(kb->cryptographic_algorithm != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
            kb->cryptographic_algorithm);
        CHECK_RESULT(ctx, result);
    }
    
    if(kb->cryptographic_length != KMIP_UNSET)
    {
        result = encode_integer(
            ctx,
            KMIP_TAG_CRYPTOGRAPHIC_LENGTH,
            kb->cryptographic_length);
        CHECK_RESULT(ctx, result);
    }
    
    if(kb->key_wrapping_data != NULL)
    {
        result = encode_key_wrapping_data(ctx, kb->key_wrapping_data);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_symmetric_key(struct kmip *ctx, const struct symmetric_key *sk)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_SYMMETRIC_KEY, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_key_block(ctx, sk->key_block);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_public_key(struct kmip *ctx, const struct public_key *pk)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_PUBLIC_KEY, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_key_block(ctx, pk->key_block);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_private_key(struct kmip *ctx, const struct private_key *pk)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_PRIVATE_KEY, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_key_block(ctx, pk->key_block);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_key_wrapping_specification(struct kmip *ctx,
                                  const struct key_wrapping_specification *kws)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_KEY_WRAPPING_SPECIFICATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_WRAPPING_METHOD, kws->wrapping_method);
    CHECK_RESULT(ctx, result);
    
    if(kws->encryption_key_info != NULL)
    {
        result = encode_encryption_key_information(
            ctx,
            kws->encryption_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(kws->mac_signature_key_info != NULL)
    {
        result = encode_mac_signature_key_information(
            ctx,
            kws->mac_signature_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    for(size_t i = 0; i < kws->attribute_name_count; i++)
    {
        struct text_string name = kws->attribute_names[i];
        result = encode_text_string(
            ctx, KMIP_TAG_ATTRIBUTE_NAME, 
            name.value,
            name.size);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_1)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_ENCODING_OPTION,
            kws->encoding_option);
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
        value->unique_identifier->value,
        value->unique_identifier->size);
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
                           const struct get_request_payload *grp)
{
    int result = 0;
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(grp->unique_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_UNIQUE_IDENTIFIER,
            grp->unique_identifier->value,
            grp->unique_identifier->size);
        CHECK_RESULT(ctx, result);
    }
    
    if(grp->key_format_type != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_KEY_FORMAT_TYPE,
            grp->key_format_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(grp->key_compression_type != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_KEY_COMPRESSION_TYPE,
            grp->key_compression_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(grp->key_wrapping_spec != NULL)
    {
        result = encode_key_wrapping_specification(
            ctx,
            grp->key_wrapping_spec);
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
        value->unique_identifier->value,
        value->unique_identifier->size);
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
            value->unique_identifier->value,
            value->unique_identifier->size);
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
        value->unique_identifier->value,
        value->unique_identifier->size);
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
        value->nonce_id->value,
        value->nonce_id->size);
    CHECK_RESULT(ctx, result);
    
    result = encode_byte_string(
        ctx,
        KMIP_TAG_NONCE_VALUE,
        value->nonce_value->value,
        value->nonce_value->size);
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
const struct username_password_credential *upc)
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
        upc->username->value,
        upc->username->size);
    CHECK_RESULT(ctx, result);
    
    if(upc->password != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_PASSWORD,
            upc->password->value,
            upc->password->size);
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
            value->device_serial_number->value,
            value->device_serial_number->size);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->password != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_PASSWORD,
            value->password->value,
            value->password->size);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->device_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_DEVICE_IDENTIFIER,
            value->device_identifier->value,
            value->device_identifier->size);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->network_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_NETWORK_IDENTIFIER,
            value->network_identifier->value,
            value->network_identifier->size);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->machine_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_MACHINE_IDENTIFIER,
            value->machine_identifier->value,
            value->machine_identifier->size);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->media_identifier != NULL)
    {
        result = encode_text_string(
            ctx, KMIP_TAG_MEDIA_IDENTIFIER,
            value->media_identifier->value,
            value->media_identifier->size);
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
            value->attestation_measurement->value,
            value->attestation_measurement->size);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->attestation_assertion != NULL)
    {
        result = encode_byte_string(
            ctx, KMIP_TAG_ATTESTATION_ASSERTION,
            value->attestation_assertion->value,
            value->attestation_assertion->size);
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
                        void *credential_value)
{
    int result = 0;
    
    switch(type)
    {
        case KMIP_CRED_USERNAME_AND_PASSWORD:
        result = encode_username_password_credential(
            ctx, 
            (struct username_password_credential*)credential_value);
        break;
        
        case KMIP_CRED_DEVICE:
        result = encode_device_credential(
            ctx,
            (struct device_credential*)credential_value);
        break;
        
        case KMIP_CRED_ATTESTATION:
        result = encode_attestation_credential(
            ctx,
            (struct attestation_credential*)credential_value);
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
encode_credential(struct kmip *ctx, const struct credential *c)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_CREDENTIAL, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_CREDENTIAL_TYPE, c->credential_type);
    CHECK_RESULT(ctx, result);
    
    result = encode_credential_value(
        ctx,
        c->credential_type,
        c->credential_value);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_authentication(struct kmip *ctx, const struct authentication *a)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_AUTHENTICATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_credential(ctx, a->credential);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_request_header(struct kmip *ctx, const struct request_header *rh)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_REQUEST_HEADER, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_protocol_version(ctx, rh->protocol_version);
    CHECK_RESULT(ctx, result);
    
    if(rh->maximum_response_size != 0)
    {
        result = encode_integer(
            ctx,
            KMIP_TAG_MAXIMUM_RESPONSE_SIZE,
            rh->maximum_response_size);
        CHECK_RESULT(ctx, result);
    }
    
    if(rh->asynchronous_indicator != KMIP_UNSET)
    {
        result = encode_bool(
            ctx,
            KMIP_TAG_ASYNCHRONOUS_INDICATOR,
            rh->asynchronous_indicator);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_2)
    {
        if(rh->attestation_capable_indicator != KMIP_UNSET)
        {
            result = encode_bool(
                ctx,
                KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR,
                rh->attestation_capable_indicator);
            CHECK_RESULT(ctx, result);
        }
        
        for(size_t i = 0; i < rh->attestation_type_count; i++)
        {
            result = encode_enum(
                ctx,
                KMIP_TAG_ATTESTATION_TYPE,
                rh->attestation_types[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(rh->authentication != NULL)
    {
        result = encode_authentication(ctx, rh->authentication);
        CHECK_RESULT(ctx, result);
    }
    
    if(rh->batch_error_continuation_option != 0)
    {
        result = encode_enum(
            ctx,
            KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION,
            rh->batch_error_continuation_option);
        CHECK_RESULT(ctx, result);
    }
    
    if(rh->batch_order_option != KMIP_UNSET)
    {
        result = encode_bool(
            ctx,
            KMIP_TAG_BATCH_ORDER_OPTION,
            rh->batch_order_option);
        CHECK_RESULT(ctx, result);
    }
    
    if(rh->time_stamp != 0)
    {
        result = encode_date_time(ctx, KMIP_TAG_TIME_STAMP, rh->time_stamp);
        CHECK_RESULT(ctx, result);
    }
    
    result = encode_integer(ctx, KMIP_TAG_BATCH_COUNT, rh->batch_count);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_response_header(struct kmip *ctx, const struct response_header *rh)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_RESPONSE_HEADER, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_protocol_version(ctx, rh->protocol_version);
    CHECK_RESULT(ctx, result);
    
    result = encode_date_time(ctx, KMIP_TAG_TIME_STAMP, rh->time_stamp);
    CHECK_RESULT(ctx, result);
    
    result = encode_integer(ctx, KMIP_TAG_BATCH_COUNT, rh->batch_count);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    encode_int32_be(ctx, curr_index - value_index);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
encode_request_batch_item(struct kmip *ctx,
                          const struct request_batch_item *rbi)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_BATCH_ITEM, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_enum(ctx, KMIP_TAG_OPERATION, rbi->operation);
    CHECK_RESULT(ctx, result);
    
    if(rbi->unique_batch_item_id != NULL)
    {
        result = encode_byte_string(
            ctx,
            KMIP_TAG_UNIQUE_BATCH_ITEM_ID,
            rbi->unique_batch_item_id->value,
            rbi->unique_batch_item_id->size);
        CHECK_RESULT(ctx, result);
    }
    
    switch(rbi->operation)
    {
        case KMIP_OP_CREATE:
        result = encode_create_request_payload(
            ctx, 
            (struct create_request_payload*)rbi->request_payload);
        break;
        
        case KMIP_OP_GET:
        result = encode_get_request_payload(
            ctx, 
            (struct get_request_payload*)rbi->request_payload);
        break;
        
        case KMIP_OP_DESTROY:
        result = encode_destroy_request_payload(
            ctx,
            (struct destroy_request_payload*)rbi->request_payload);
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
            value->unique_batch_item_id->value,
            value->unique_batch_item_id->size);
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
            value->result_message->value,
            value->result_message->size);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->asynchronous_correlation_value != NULL)
    {
        result = encode_byte_string(
            ctx,
            KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE,
            value->asynchronous_correlation_value->value,
            value->asynchronous_correlation_value->size);
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
encode_request_message(struct kmip *ctx, const struct request_message *rm)
{
    int result = 0;
    result = encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_REQUEST_MESSAGE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = encode_request_header(ctx, rm->request_header);
    CHECK_RESULT(ctx, result);
    
    for(size_t i = 0; i < rm->batch_count; i++)
    {
        result = encode_request_batch_item(ctx, &rm->batch_items[i]);
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
