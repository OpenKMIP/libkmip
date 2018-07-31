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

#include <stdlib.h>
#include "memset.h"
#include <string.h>
#include "types.h"
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

#define CHECK_ENUM(A, B, C)                                \
do                                                         \
{                                                          \
    int result = check_enum_value((A)->version, (B), (C)); \
    if(result != KMIP_OK)                                  \
    {                                                      \
        set_enum_error_message((A), (B), (C), result);     \
        kmip_push_error_frame((A), __func__, __LINE__);    \
        return(result);                                    \
    }                                                      \
} while(0)

#define CHECK_NEW_MEMORY(A, B, C, D)                    \
do                                                      \
{                                                       \
    if((B) == NULL)                                     \
    {                                                   \
        set_alloc_error_message((A), (C), (D));         \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_MEMORY_ALLOC_FAILED);               \
    }                                                   \
} while(0)

#define CALCULATE_PADDING(A) ((8 - ((A) % 8)) % 8)

void *
kmip_calloc(void *state, size_t num, size_t size)
{
    (void)state;
    return(calloc(num, size));
}

void *
kmip_realloc(void *state, void *ptr, size_t size)
{
    (void)state;
    return(realloc(ptr, size));
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
    
    if(ctx->error_message != NULL)
    {
        ctx->free_func(ctx->state, ctx->error_message);
        ctx->error_message = NULL;
    }
}

void
kmip_init(struct kmip *ctx, uint8 *buffer, size_t buffer_size, 
          enum kmip_version v)
{
    ctx->buffer = buffer;
    ctx->index = ctx->buffer;
    ctx->size = buffer_size;
    ctx->version = v;
    
    if(ctx->calloc_func == NULL)
        ctx->calloc_func = &kmip_calloc;
    if(ctx->realloc_func == NULL)
        ctx->realloc_func = &kmip_realloc;
    if(ctx->memset_func == NULL)
        ctx->memset_func = &kmip_memset;
    if(ctx->free_func == NULL)
        ctx->free_func = &kmip_free;
    
    ctx->error_message_size = 200;
    ctx->error_message = NULL;
    
    kmip_clear_errors(ctx);
}

void
kmip_init_error_message(struct kmip *ctx)
{
    if(ctx->error_message == NULL)
    {
        ctx->error_message = ctx->calloc_func(
            ctx->state,
            ctx->error_message_size,
            sizeof(char));
    }
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
    /* TODO (peter-hamilton) Add own_buffer if buffer == NULL? */
    ctx->buffer = buffer;
    ctx->index = ctx->buffer;
    ctx->size = buffer_size;
}

void
kmip_destroy(struct kmip *ctx)
{
    kmip_reset(ctx);
    
    ctx->calloc_func = NULL;
    ctx->realloc_func = NULL;
    ctx->memset_func = NULL;
    ctx->free_func = NULL;
    ctx->state = NULL;
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

void
set_enum_error_message(struct kmip *ctx, enum tag t, int value, int result)
{
    switch(result)
    {
        /* TODO (ph) Update error message for KMIP version 2.0+ */
        case KMIP_INVALID_FOR_VERSION:
        kmip_init_error_message(ctx);
        snprintf(
            ctx->error_message,
            ctx->error_message_size,
            "KMIP 1.%d does not support %s enumeration value (%d)",
            ctx->version,
            attribute_names[get_enum_string_index(t)],
            value);
        break;
        
        default: /* KMIP_ENUM_MISMATCH */
        kmip_init_error_message(ctx);
        snprintf(
            ctx->error_message,
            ctx->error_message_size,
            "Invalid %s enumeration value (%d)",
            attribute_names[get_enum_string_index(t)],
            value);
        break;
    };
}

void
set_alloc_error_message(struct kmip *ctx, size_t size, const char *type)
{
    kmip_init_error_message(ctx);
    snprintf(
        ctx->error_message,
        ctx->error_message_size,
        "Could not allocate %zd bytes for a %s",
        size,
        type);
}

void
set_error_message(struct kmip *ctx, const char *message)
{
    kmip_init_error_message(ctx);
    snprintf(ctx->error_message, ctx->error_message_size, "%s", message);
}

int
is_tag_next(const struct kmip *ctx, enum tag t)
{
    uint8 *index = ctx->index;
    
    if((ctx->size - (index - ctx->buffer)) < 3)
    {
        return(KMIP_FALSE);
    }
    
    uint32 tag = 0;
    
    tag |= ((int32)*index++ << 16);
    tag |= ((int32)*index++ << 8);
    tag |= ((int32)*index++ << 0);
    
    if(tag != t)
    {
        return(KMIP_FALSE);
    }
    
    return(KMIP_TRUE);
}

int
is_tag_type_next(const struct kmip *ctx, enum tag t, enum type s)
{
    uint8 *index = ctx->index;
    
    if((ctx->size - (index - ctx->buffer)) < 4)
    {
        return(KMIP_FALSE);
    }
    
    uint32 tag_type = 0;
    
    tag_type |= ((int32)*index++ << 24);
    tag_type |= ((int32)*index++ << 16);
    tag_type |= ((int32)*index++ << 8);
    tag_type |= ((int32)*index++ << 0);
    
    if(tag_type != TAG_TYPE(t, s))
    {
        return(KMIP_FALSE);
    }
    
    return(KMIP_TRUE);
}

int
get_num_items_next(struct kmip *ctx, enum tag t)
{
    int count = 0;
    
    uint8 *index = ctx->index;
    uint32 length = 0;
    
    while((ctx->size - (ctx->index - ctx->buffer)) > 8)
    {
        if(is_tag_next(ctx, t))
        {
            ctx->index += 4;
            
            length = 0;
            length |= ((int32)*ctx->index++ << 24);
            length |= ((int32)*ctx->index++ << 16);
            length |= ((int32)*ctx->index++ << 8);
            length |= ((int32)*ctx->index++ << 0);
            length += CALCULATE_PADDING(length);
            
            if((ctx->size - (ctx->index - ctx->buffer)) >= length)
            {
                ctx->index += length;
                count++;
            }
            else
            {
                break;
            }
        }
        else
        {
            break;
        }
    }
    
    ctx->index = index;
    return(count);
}

/*
Initialization Functions
*/

void
init_attribute(struct attribute *value)
{
    value->type = 0;
    value->index = KMIP_UNSET;
    value->value = NULL;
}

void
init_cryptographic_parameters(struct cryptographic_parameters *value)
{
    value->block_cipher_mode = 0;
    value->padding_method = 0;
    value->hashing_algorithm = 0;
    value->key_role_type = 0;
    
    value->digital_signature_algorithm = 0;
    value->cryptographic_algorithm = 0;
    value->random_iv = KMIP_UNSET;
    value->iv_length = KMIP_UNSET;
    value->tag_length = KMIP_UNSET;
    value->fixed_field_length = KMIP_UNSET;
    value->invocation_field_length = KMIP_UNSET;
    value->counter_length = KMIP_UNSET;
    value->initial_counter_value = KMIP_UNSET;
    
    value->salt_length = KMIP_UNSET;
    value->mask_generator = 0;
    value->mask_generator_hashing_algorithm = 0;
    value->p_source = NULL;
    value->trailer_field = KMIP_UNSET;
}

void
init_key_block(struct key_block *value)
{
    value->key_format_type = 0;
    value->key_compression_type = 0;
    value->key_value = NULL;
    value->key_value_type = 0;
    value->cryptographic_algorithm = 0;
    value->cryptographic_length = KMIP_UNSET;
    value->key_wrapping_data = NULL;
}

void
init_response_header(struct response_header *value)
{
    value->protocol_version = NULL;
    value->time_stamp = 0;
    value->batch_count = KMIP_UNSET;
    
    value->nonce = NULL;
    value->attestation_types = NULL;
    value->attestation_type_count = 0;
    
    value->client_correlation_value = NULL;
    value->server_correlation_value = NULL;
}

/*
Freeing Functions
*/

void
free_text_string(struct kmip *ctx, struct text_string *value)
{
    if(value != NULL)
    {
        if(value->value != NULL)
        {
            ctx->memset_func(value->value, 0, value->size);
            ctx->free_func(ctx->state, value->value);
            
            value->value = NULL;
        }
        
        value->size = 0;
    }
    
    return;
}

void
free_byte_string(struct kmip *ctx, struct byte_string *value)
{
    if(value != NULL)
    {
        if(value->value != NULL)
        {
            ctx->memset_func(value->value, 0, value->size);
            ctx->free_func(ctx->state, value->value);
            
            value->value = NULL;
        }
        
        value->size = 0;
    }
    
    return;
}

void
free_name(struct kmip *ctx, struct name *value)
{
    if(value != NULL)
    {
        if(value->value != NULL)
        {
            free_text_string(ctx, value->value);
            ctx->free_func(ctx->state, value->value);
            
            value->value = NULL;
        }
        
        value->type = 0;
    }
    
    return;
}

void
free_attribute(struct kmip *ctx, struct attribute *value)
{
    if(value != NULL)
    {
        if(value->value != NULL)
        {
            switch(value->type)
            {
                case KMIP_ATTR_UNIQUE_IDENTIFIER:
                free_text_string(ctx, value->value);
                break;
                
                case KMIP_ATTR_NAME:
                free_name(ctx, value->value);
                break;
                
                case KMIP_ATTR_OBJECT_TYPE:
                *(int32*)value->value = 0;
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
                *(int32*)value->value = 0;
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
                *(int32*)value->value = KMIP_UNSET;
                break;
                
                case KMIP_ATTR_OPERATION_POLICY_NAME:
                free_text_string(ctx, value->value);
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
                *(int32*)value->value = KMIP_UNSET;
                break;
                
                case KMIP_ATTR_STATE:
                *(int32*)value->value = 0;
                break;
                
                default:
                /* NOTE (ph) Hitting this case means that we don't know what the */
                /*      actual type, size, or value of value->value is. We can   */
                /*      still free it but we cannot securely zero the memory. We */
                /*      also do not know how to free any possible substructures  */
                /*      pointed to within value->value.                          */
                /*                                                               */
                /*      Avoid hitting this case at all costs.                    */
                break;
            };
            
            ctx->free_func(ctx->state, value->value);
            value->value = NULL;
        }
        
        value->type = 0;
        value->index = KMIP_UNSET;
    }
    
    return;
}

void
free_template_attribute(struct kmip *ctx, struct template_attribute *value)
{
    if(value != NULL)
    {
        if(value->names != NULL)
        {
            for(size_t i = 0; i < value->name_count; i++)
            {
                free_name(ctx, &value->names[i]);
            }
            ctx->free_func(ctx->state, value->names);
            
            value->names = NULL;
        }
        
        value->name_count = 0;
        
        if(value->attributes != NULL)
        {
            for(size_t i = 0; i < value->attribute_count; i++)
            {
                free_attribute(ctx, &value->attributes[i]);
            }
            ctx->free_func(ctx->state, value->attributes);
            
            value->attributes = NULL;
        }
        
        value->attribute_count = 0;
    }
    
    return;
}

void
free_transparent_symmetric_key(struct kmip *ctx, 
                               struct transparent_symmetric_key *value)
{
    if(value != NULL)
    {
        if(value->key != NULL)
        {
            free_byte_string(ctx, value->key);
            
            ctx->free_func(ctx->state, value->key);
            value->key = NULL;
        }
    }
    
    return;
}

void
free_key_material(struct kmip *ctx,
                  enum key_format_type format,
                  void **value)
{
    if(value != NULL)
    {
        if(*value != NULL)
        {
            switch(format)
            {
                case KMIP_KEYFORMAT_RAW:
                case KMIP_KEYFORMAT_OPAQUE:
                case KMIP_KEYFORMAT_PKCS1:
                case KMIP_KEYFORMAT_PKCS8:
                case KMIP_KEYFORMAT_X509:
                case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
                free_byte_string(ctx, *value);
                break;
                
                case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
                free_transparent_symmetric_key(ctx, *value);
                break;
                
                default:
                /* NOTE (ph) Hitting this case means that we don't know   */
                /*      what the actual type, size, or value of value is. */
                /*      We can still free it but we cannot securely zero  */
                /*      the memory. We also do not know how to free any   */
                /*      possible substructures pointed to within value.   */
                /*                                                        */
                /*      Avoid hitting this case at all costs.             */
                break;
            };
            
            ctx->free_func(ctx->state, *value);
            *value = NULL;
        }
    }
    
    return;
}

void
free_key_value(struct kmip *ctx,
               enum key_format_type format,
               struct key_value *value)
{
    if(value != NULL)
    {
        if(value->key_material != NULL)
        {
            free_key_material(ctx, format, &value->key_material);
            value->key_material = NULL;
        }
        
        if(value->attributes != NULL)
        {
            for(size_t i = 0; i < value->attribute_count; i++)
            {
                free_attribute(ctx, &value->attributes[i]);
            }
            ctx->free_func(ctx->state, value->attributes);
            
            value->attributes = NULL;
        }
        
        value->attribute_count = 0;
    }
    
    return;
}

void
free_cryptographic_parameters(struct kmip *ctx,
                              struct cryptographic_parameters *value)
{
    if(value != NULL)
    {
        if(value->p_source != NULL)
        {
            free_byte_string(ctx, value->p_source);
            
            ctx->free_func(ctx->state, value->p_source);
            value->p_source = NULL;
        }
        
        init_cryptographic_parameters(value);
    }
    
    return;
}

void
free_encryption_key_information(struct kmip *ctx,
                                struct encryption_key_information *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            free_text_string(ctx, value->unique_identifier);
            
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        
        if(value->cryptographic_parameters != NULL)
        {
            free_cryptographic_parameters(ctx, value->cryptographic_parameters);
            
            ctx->free_func(ctx->state, value->cryptographic_parameters);
            value->cryptographic_parameters = NULL;
        }
    }
    
    return;
}

void
free_mac_signature_key_information(struct kmip *ctx,
                                   struct mac_signature_key_information *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            free_text_string(ctx, value->unique_identifier);
            
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        
        if(value->cryptographic_parameters != NULL)
        {
            free_cryptographic_parameters(ctx, value->cryptographic_parameters);
            
            ctx->free_func(ctx->state, value->cryptographic_parameters);
            value->cryptographic_parameters = NULL;
        }
    }
    
    return;
}

void
free_key_wrapping_data(struct kmip *ctx,
                       struct key_wrapping_data *value)
{
    if(value != NULL)
    {
        if(value->encryption_key_info != NULL)
        {
            free_encryption_key_information(ctx, value->encryption_key_info);
            
            ctx->free_func(ctx->state, value->encryption_key_info);
            value->encryption_key_info = NULL;
        }
        
        if(value->mac_signature_key_info != NULL)
        {
            free_mac_signature_key_information(ctx, value->mac_signature_key_info);
            
            ctx->free_func(ctx->state, value->mac_signature_key_info);
            value->mac_signature_key_info = NULL;
        }
        
        if(value->mac_signature != NULL)
        {
            free_byte_string(ctx, value->mac_signature);
            
            ctx->free_func(ctx->state, value->mac_signature);
            value->mac_signature = NULL;
        }
        
        if(value->iv_counter_nonce != NULL)
        {
            free_byte_string(ctx, value->iv_counter_nonce);
            
            ctx->free_func(ctx->state, value->iv_counter_nonce);
            value->iv_counter_nonce = NULL;
        }
        
        value->wrapping_method = 0;
        value->encoding_option = 0;
    }
    
    return;
}

void
free_key_block(struct kmip *ctx, struct key_block *value)
{
    if(value != NULL)
    {
        if(value->key_value != NULL)
        {
            if(value->key_value_type == KMIP_TYPE_BYTE_STRING)
            {
                free_byte_string(ctx, value->key_value);
                ctx->free_func(ctx->state, value->key_value);
            }
            else
            {
                free_key_value(ctx, value->key_format_type, value->key_value);
                ctx->free_func(ctx->state, value->key_value);
            }
            value->key_value = NULL;
        }
        
        if(value->key_wrapping_data != NULL)
        {
            free_key_wrapping_data(ctx, value->key_wrapping_data);
            ctx->free_func(ctx->state, value->key_wrapping_data);
            value->key_wrapping_data = NULL;
        }
        
        init_key_block(value);
    }
    
    return;
}

void
free_symmetric_key(struct kmip *ctx, struct symmetric_key *value)
{
    if(value != NULL)
    {
        if(value->key_block != NULL)
        {
            free_key_block(ctx, value->key_block);
            ctx->free_func(ctx->state, value->key_block);
            value->key_block = NULL;
        }
    }
    
    return;
}

void
free_public_key(struct kmip *ctx, struct public_key *value)
{
    if(value != NULL)
    {
        if(value->key_block != NULL)
        {
            free_key_block(ctx, value->key_block);
            ctx->free_func(ctx->state, value->key_block);
            value->key_block = NULL;
        }
    }
    
    return;
}

void
free_private_key(struct kmip *ctx, struct private_key *value)
{
    if(value != NULL)
    {
        if(value->key_block != NULL)
        {
            free_key_block(ctx, value->key_block);
            ctx->free_func(ctx->state, value->key_block);
            value->key_block = NULL;
        }
    }
    
    return;
}

void
free_create_response_payload(struct kmip *ctx,
                             struct create_response_payload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        
        if(value->template_attribute != NULL)
        {
            free_template_attribute(ctx, value->template_attribute);
            ctx->free_func(ctx->state, value->template_attribute);
            value->template_attribute = NULL;
        }
        
        value->object_type = 0;
    }
    
    return;
}

void
free_get_response_payload(struct kmip *ctx,
                          struct get_response_payload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        
        if(value->object != NULL)
        {
            switch(value->object_type)
            {
                case KMIP_OBJTYPE_SYMMETRIC_KEY:
                free_symmetric_key(ctx, (struct symmetric_key *)value->object);
                break;
                
                case KMIP_OBJTYPE_PUBLIC_KEY:
                free_public_key(ctx, (struct public_key *)value->object);
                break;
                
                case KMIP_OBJTYPE_PRIVATE_KEY:
                free_private_key(ctx, (struct private_key *)value->object);
                break;
                
                default:
                /* NOTE (ph) Hitting this case means that we don't know */
                /*      what the actual type, size, or value of         */
                /*      value->object is. We can still free it but we   */
                /*      cannot securely zero the memory. We also do not */
                /*      know how to free any possible substructures     */
                /*      pointed to within value->object.                */
                /*                                                      */
                /*      Avoid hitting this case at all costs.           */
                break;
            };
            
            ctx->free_func(ctx->state, value->object);
            value->object = NULL;
        }
        
        value->object_type = 0;
    }
    
    return;
}

void
free_destroy_response_payload(struct kmip *ctx,
                              struct destroy_response_payload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
    }
    
    return;
}

void
free_response_batch_item(struct kmip *ctx, struct response_batch_item *value)
{
    if(value != NULL)
    {
        if(value->unique_batch_item_id != NULL)
        {
            free_byte_string(ctx, value->unique_batch_item_id);
            ctx->free_func(ctx->state, value->unique_batch_item_id);
            value->unique_batch_item_id = NULL;
        }
        
        if(value->result_message != NULL)
        {
            free_text_string(ctx, value->result_message);
            ctx->free_func(ctx->state, value->result_message);
            value->result_message = NULL;
        }
        
        if(value->asynchronous_correlation_value != NULL)
        {
            free_byte_string(ctx, value->asynchronous_correlation_value);
            ctx->free_func(ctx->state, value->asynchronous_correlation_value);
            value->asynchronous_correlation_value = NULL;
        }
        
        if(value->response_payload != NULL)
        {
            switch(value->operation)
            {
                case KMIP_OP_CREATE:
                free_create_response_payload(
                    ctx,
                    (struct create_response_payload *)value->response_payload);
                break;
                
                case KMIP_OP_GET:
                free_get_response_payload(
                    ctx, 
                    (struct get_response_payload *)value->response_payload);
                break;
                
                case KMIP_OP_DESTROY:
                free_destroy_response_payload(
                    ctx,
                    (struct destroy_response_payload *)value->response_payload);
                break;
                
                default:
                /* NOTE (ph) Hitting this case means that we don't know    */
                /*      what the actual type, size, or value of            */
                /*      value->response_payload is. We can still free it   */
                /*      but we cannot securely zero the memory. We also    */
                /*      do not know how to free any possible substructures */
                /*      pointed to within value->object.                   */
                /*                                                         */
                /*      Avoid hitting this case at all costs.              */
                break;
            };
            
            ctx->free_func(ctx->state, value->response_payload);
            value->response_payload = NULL;
        }
        
        value->operation = 0;
        value->result_status = 0;
        value->result_reason = 0;
    }
    
    return;
}

void
free_nonce(struct kmip *ctx, struct nonce *value)
{
    if(value != NULL)
    {
        if(value->nonce_id != NULL)
        {
            free_byte_string(ctx, value->nonce_id);
            ctx->free_func(ctx->state, value->nonce_id);
            value->nonce_id = NULL;
        }
        
        if(value->nonce_value != NULL)
        {
            free_byte_string(ctx, value->nonce_value);
            ctx->free_func(ctx->state, value->nonce_value);
            value->nonce_value = NULL;
        }
    }
    
    return;
}

void
free_username_password_credential(struct kmip *ctx,
                                  struct username_password_credential *value)
{
    if(value != NULL)
    {
        if(value->username != NULL)
        {
            free_text_string(ctx, value->username);
            ctx->free_func(ctx->state, value->username);
            value->username = NULL;
        }
        
        if(value->password != NULL)
        {
            free_text_string(ctx, value->password);
            ctx->free_func(ctx->state, value->password);
            value->password = NULL;
        }
    }
    
    return;
}

void
free_device_credential(struct kmip *ctx, struct device_credential *value)
{
    if(value != NULL)
    {
        if(value->device_serial_number != NULL)
        {
            free_text_string(ctx, value->device_serial_number);
            ctx->free_func(ctx->state, value->device_serial_number);
            value->device_serial_number = NULL;
        }
        
        if(value->password != NULL)
        {
            free_text_string(ctx, value->password);
            ctx->free_func(ctx->state, value->password);
            value->password = NULL;
        }
        
        if(value->device_identifier != NULL)
        {
            free_text_string(ctx, value->device_identifier);
            ctx->free_func(ctx->state, value->device_identifier);
            value->device_identifier = NULL;
        }
        
        if(value->network_identifier != NULL)
        {
            free_text_string(ctx, value->network_identifier);
            ctx->free_func(ctx->state, value->network_identifier);
            value->network_identifier = NULL;
        }
        
        if(value->machine_identifier != NULL)
        {
            free_text_string(ctx, value->machine_identifier);
            ctx->free_func(ctx->state, value->machine_identifier);
            value->machine_identifier = NULL;
        }
        
        if(value->media_identifier != NULL)
        {
            free_text_string(ctx, value->media_identifier);
            ctx->free_func(ctx->state, value->media_identifier);
            value->media_identifier = NULL;
        }
    }
    
    return;
}

void
free_attestation_credential(struct kmip *ctx, struct attestation_credential *value)
{
    if(value != NULL)
    {
        if(value->nonce != NULL)
        {
            free_nonce(ctx, value->nonce);
            ctx->free_func(ctx->state, value->nonce);
            value->nonce = NULL;
        }
        
        if(value->attestation_measurement != NULL)
        {
            free_byte_string(ctx, value->attestation_measurement);
            ctx->free_func(ctx->state, value->attestation_measurement);
            value->attestation_measurement = NULL;
        }
        
        if(value->attestation_assertion != NULL)
        {
            free_byte_string(ctx, value->attestation_assertion);
            ctx->free_func(ctx->state, value->attestation_assertion);
            value->attestation_assertion = NULL;
        }
        
        value->attestation_type = 0;
    }
    
    return;
}

void
free_credential_value(struct kmip *ctx,
                      enum credential_type type,
                      void **value)
{
    if(value != NULL)
    {
        if(*value != NULL)
        {
            switch(type)
            {
                case KMIP_CRED_USERNAME_AND_PASSWORD:
                free_username_password_credential(
                    ctx,
                    (struct username_password_credential *)*value);
                break;
                
                case KMIP_CRED_DEVICE:
                free_device_credential(
                    ctx,
                    (struct device_credential *)*value);
                break;
                
                case KMIP_CRED_ATTESTATION:
                free_attestation_credential(
                    ctx,
                    (struct attestation_credential *)*value);
                break;
                
                default:
                /* NOTE (ph) Hitting this case means that we don't know   */
                /*      what the actual type, size, or value of value is. */
                /*      We can still free it but we cannot securely zero  */
                /*      the memory. We also do not know how to free any   */
                /*      possible substructures pointed to within value.   */
                /*                                                        */
                /*      Avoid hitting this case at all costs.             */
                break;
            };
        
            ctx->free_func(ctx->state, *value);
            *value = NULL;
        }    
    }
    
    return;
}

void
free_credential(struct kmip *ctx, struct credential *value)
{
    if(value != NULL)
    {
        if(value->credential_value != NULL)
        {
            free_credential_value(
                ctx,
                value->credential_type,
                &value->credential_value);
            value->credential_value = NULL;
        }
        
        value->credential_type = 0;
    }
    
    return;
}

void
free_authentication(struct kmip *ctx, struct authentication *value)
{
    if(value != NULL)
    {
        if(value->credential != NULL)
        {
            free_credential(ctx, value->credential);
            ctx->free_func(ctx->state, value->credential);
            value->credential = NULL;
        }
    }
    
    return;
}

void
free_response_header(struct kmip *ctx, struct response_header *value)
{
    if(value != NULL)
    {
        if(value->protocol_version != NULL)
        {
            ctx->memset_func(
                value->protocol_version,
                0,
                sizeof(struct protocol_version));
            ctx->free_func(ctx->state, value->protocol_version);
            value->protocol_version = NULL;
        }
        
        if(value->nonce != NULL)
        {
            free_nonce(ctx, value->nonce);
            ctx->free_func(ctx->state, value->nonce);
            value->nonce = NULL;
        }
        
        if(value->attestation_types != NULL)
        {
            ctx->memset_func(
                value->attestation_types,
                0,
                value->attestation_type_count * sizeof(enum attestation_type));
            ctx->free_func(ctx->state, value->attestation_types);
            value->attestation_types = NULL;
        }
        
        value->attestation_type_count = 0;
        
        if(value->client_correlation_value != NULL)
        {
            free_text_string(ctx, value->client_correlation_value);
            ctx->free_func(ctx->state, value->client_correlation_value);
            value->client_correlation_value = NULL;
        }
        
        if(value->server_correlation_value != NULL)
        {
            free_text_string(ctx, value->server_correlation_value);
            ctx->free_func(ctx->state, value->server_correlation_value);
            value->server_correlation_value = NULL;
        }
        
        init_response_header(value);
    }
    
    return;
}

void
free_response_message(struct kmip *ctx, struct response_message *value)
{
    if(value != NULL)
    {
        if(value->response_header != NULL)
        {
            free_response_header(ctx, value->response_header);
            ctx->free_func(ctx->state, value->response_header);
            value->response_header = NULL;
        }
        
        if(value->batch_items != NULL)
        {
            for(size_t i = 0; i < value->batch_count; i++)
            {
                free_response_batch_item(ctx, &value->batch_items[i]);
            }
            ctx->free_func(ctx, value->batch_items);
            value->batch_items = NULL;
        }
        
        value->batch_count = 0;
    }
    
    return;
}

/*
Comparison Functions
*/

int
compare_text_string(const struct text_string *a, 
                    const struct text_string *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->size != b->size)
        {
            return(KMIP_FALSE);
        }
        
        if(a->value != b->value)
        {
            if((a->value == NULL) || (b->value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->size; i++)
            {
                if(a->value[i] != b->value[i])
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_byte_string(const struct byte_string *a, 
                    const struct byte_string *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->size != b->size)
        {
            return(KMIP_FALSE);
        }
        
        if(a->value != b->value)
        {
            if((a->value == NULL) || (b->value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->size; i++)
            {
                if(a->value[i] != b->value[i])
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_name(const struct name *a, const struct name *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->type != b->type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->value != b->value)
        {
            if((a->value == NULL) || (b->value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->value, b->value) != KMIP_TRUE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_attribute(const struct attribute *a, 
                  const struct attribute *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->type != b->type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->index != b->index)
        {
            return(KMIP_FALSE);
        }
        
        if(a->value != b->value)
        {
            if((a->value == NULL) || (b->value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            switch(a->type)
            {
                case KMIP_ATTR_UNIQUE_IDENTIFIER:
                return(compare_text_string((struct text_string *)a->value, 
                                           (struct text_string *)b->value));
                break;
                
                case KMIP_ATTR_NAME:
                return(compare_name((struct name *)a->value,
                                    (struct name *)b->value));
                break;
                
                case KMIP_ATTR_OBJECT_TYPE:
                
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
                if(*(int32*)a->value != *(int32*)b->value)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
                if(*(int32*)a->value != *(int32*)b->value)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_ATTR_OPERATION_POLICY_NAME:
                return(compare_text_string((struct text_string *)a->value,
                                           (struct text_string *)b->value));
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
                if(*(int32*)a->value != *(int32*)b->value)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_ATTR_STATE:
                if(*(int32*)a->value != *(int32*)b->value)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                default:
                /* NOTE (ph) Unsupported types can't be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_template_attribute(const struct template_attribute *a,
                           const struct template_attribute *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->name_count != b->name_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->attribute_count != b->attribute_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->names != b->names)
        {
            if((a->names == NULL) || (b->names == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->name_count; i++)
            {
                if(compare_name(&a->names[i], &b->names[i]) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
        
        if(a->attributes != b->attributes)
        {
            if((a->attributes == NULL) || (b->attributes == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->attribute_count; i++)
            {
                if(compare_attribute(
                    &a->attributes[i], 
                    &b->attributes[i]) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_protocol_version(const struct protocol_version *a,
                         const struct protocol_version *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->major != b->major)
        {
            return(KMIP_FALSE);
        }
        
        if(a->minor != b->minor)
        {
            return(KMIP_FALSE);
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_transparent_symmetric_key(const struct transparent_symmetric_key *a,
                                  const struct transparent_symmetric_key *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key != b->key)
        {
            if((a->key == NULL) || (b->key == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_byte_string(a->key, b->key) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_key_material(enum key_format_type format,
                     void **a,
                     void **b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(*a != *b)
        {
            if((*a == NULL) || (*b == NULL))
            {
                return(KMIP_FALSE);
            }
            
            switch(format)
            {
                case KMIP_KEYFORMAT_RAW:
                case KMIP_KEYFORMAT_OPAQUE:
                case KMIP_KEYFORMAT_PKCS1:
                case KMIP_KEYFORMAT_PKCS8:
                case KMIP_KEYFORMAT_X509:
                case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
                if(compare_byte_string(*a, *b) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
                if(compare_transparent_symmetric_key(*a, *b) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                default:
                /* NOTE (ph) Unsupported types cannot be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_key_value(enum key_format_type format,
                  const struct key_value *a,
                  const struct key_value *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_material != b->key_material)
        {
            if((a->key_material == NULL) || (b->key_material == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_key_material(format,
                                    (void**)&a->key_material,
                                    (void**)&b->key_material) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->attributes != b->attributes)
        {
            if((a->attributes == NULL) || (b->attributes == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->attribute_count; i++)
            {
                if(compare_attribute(
                    &a->attributes[i], 
                    &b->attributes[i]) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_cryptographic_parameters(const struct cryptographic_parameters *a,
                                 const struct cryptographic_parameters *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->block_cipher_mode != b->block_cipher_mode)
        {
            return(KMIP_FALSE);
        }
        
        if(a->padding_method != b->padding_method)
        {
            return(KMIP_FALSE);
        }
        
        if(a->hashing_algorithm != b->hashing_algorithm)
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_role_type != b->key_role_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->digital_signature_algorithm != b->digital_signature_algorithm)
        {
            return(KMIP_FALSE);
        }
        
        if(a->cryptographic_algorithm != b->cryptographic_algorithm)
        {
            return(KMIP_FALSE);
        }
        
        if(a->random_iv != b->random_iv)
        {
            return(KMIP_FALSE);
        }
        
        if(a->iv_length != b->iv_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->tag_length != b->tag_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->fixed_field_length != b->fixed_field_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->invocation_field_length != b->invocation_field_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->counter_length != b->counter_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->initial_counter_value != b->initial_counter_value)
        {
            return(KMIP_FALSE);
        }
        
        if(a->salt_length != b->salt_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->mask_generator != b->mask_generator)
        {
            return(KMIP_FALSE);
        }
        
        if(a->mask_generator_hashing_algorithm != 
           b->mask_generator_hashing_algorithm)
        {
            return(KMIP_FALSE);
        }
        
        if(a->trailer_field != b->trailer_field)
        {
            return(KMIP_FALSE);
        }
        
        if(a->p_source != b->p_source)
        {
            if((a->p_source == NULL) || (b->p_source == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_byte_string(a->p_source, b->p_source) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_encryption_key_information(const struct encryption_key_information *a,
                                   const struct encryption_key_information *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->unique_identifier,
                                   b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->cryptographic_parameters != b->cryptographic_parameters)
        {
            if((a->cryptographic_parameters == NULL) ||
               (b->cryptographic_parameters == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_cryptographic_parameters(
                a->cryptographic_parameters, 
                b->cryptographic_parameters) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_mac_signature_key_information(const struct mac_signature_key_information *a,
                                      const struct mac_signature_key_information *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->unique_identifier,
                                   b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->cryptographic_parameters != b->cryptographic_parameters)
        {
            if((a->cryptographic_parameters == NULL) ||
               (b->cryptographic_parameters == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_cryptographic_parameters(
                a->cryptographic_parameters, 
                b->cryptographic_parameters) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_key_wrapping_data(const struct key_wrapping_data *a,
                          const struct key_wrapping_data *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->wrapping_method != b->wrapping_method)
        {
            return(KMIP_FALSE);
        }
        
        if(a->encoding_option != b->encoding_option)
        {
            return(KMIP_FALSE);
        }
        
        if(a->mac_signature != b->mac_signature)
        {
            if((a->mac_signature == NULL) || (b->mac_signature == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_byte_string(a->mac_signature,
                                   b->mac_signature) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->iv_counter_nonce != b->iv_counter_nonce)
        {
            if((a->iv_counter_nonce == NULL) || (b->iv_counter_nonce == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_byte_string(a->iv_counter_nonce,
                                   b->iv_counter_nonce) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->encryption_key_info != b->encryption_key_info)
        {
            if((a->encryption_key_info == NULL) || (b->encryption_key_info == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_encryption_key_information(
                a->encryption_key_info,
                b->encryption_key_info) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->mac_signature_key_info != b->mac_signature_key_info)
        {
            if((a->mac_signature_key_info == NULL) || 
               (b->mac_signature_key_info == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_mac_signature_key_information(
                a->mac_signature_key_info,
                b->mac_signature_key_info) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_key_block(const struct key_block *a, const struct key_block *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_format_type != b->key_format_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_compression_type != b->key_compression_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->cryptographic_algorithm != b->cryptographic_algorithm)
        {
            return(KMIP_FALSE);
        }
        
        if(a->cryptographic_length != b->cryptographic_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_value_type != b->key_value_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_value != b->key_value)
        {
            if((a->key_value == NULL) || (b->key_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(a->key_value_type == KMIP_TYPE_BYTE_STRING)
            {
                if(compare_byte_string(
                    (struct byte_string *)a->key_value,
                    (struct byte_string *)b->key_value) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
            else
            {
                if(compare_key_value(a->key_format_type,
                                     (struct key_value *)a->key_value,
                                     (struct key_value *)b->key_value) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
        
        if(a->key_wrapping_data != b->key_wrapping_data)
        {
            if((a->key_wrapping_data == NULL) || (b->key_wrapping_data == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_key_wrapping_data(
                a->key_wrapping_data, 
                b->key_wrapping_data) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_symmetric_key(const struct symmetric_key *a,
                      const struct symmetric_key *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_block != b->key_block)
        {
            if((a->key_block == NULL) || (b->key_block == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_key_block(a->key_block, b->key_block) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_public_key(const struct public_key *a, const struct public_key *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_block != b->key_block)
        {
            if((a->key_block == NULL) || (b->key_block == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_key_block(a->key_block, b->key_block) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_private_key(const struct private_key *a, const struct private_key *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_block != b->key_block)
        {
            if((a->key_block == NULL) || (b->key_block == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_key_block(a->key_block, b->key_block) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_create_response_payload(const struct create_response_payload *a,
                                const struct create_response_payload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->object_type != b->object_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->unique_identifier,
                                   b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->template_attribute != b->template_attribute)
        {
            if((a->template_attribute == NULL) || (b->template_attribute == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_template_attribute(a->template_attribute,
                                          b->template_attribute) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_get_response_payload(const struct get_response_payload *a,
                             const struct get_response_payload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->object_type != b->object_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->unique_identifier,
                                   b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->object != b->object)
        {
            switch(a->object_type)
            {
                case KMIP_OBJTYPE_SYMMETRIC_KEY:
                if(compare_symmetric_key(
                    (struct symmetric_key *)a->object,
                    (struct symmetric_key *)b->object) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OBJTYPE_PUBLIC_KEY:
                if(compare_public_key(
                    (struct public_key *)a->object,
                    (struct public_key *)b->object) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OBJTYPE_PRIVATE_KEY:
                if(compare_private_key(
                    (struct private_key *)a->object,
                    (struct private_key *)b->object) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                default:
                /* NOTE (ph) Unsupported types cannot be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_destroy_response_payload(const struct destroy_response_payload *a,
                                 const struct destroy_response_payload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->unique_identifier,
                                   b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_response_batch_item(const struct response_batch_item *a,
                            const struct response_batch_item *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->operation != b->operation)
        {
            return(KMIP_FALSE);
        }
        
        if(a->result_status != b->result_status)
        {
            return(KMIP_FALSE);
        }
        
        if(a->result_reason != b->result_reason)
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_batch_item_id != b->unique_batch_item_id)
        {
            if((a->unique_batch_item_id == NULL) || 
               (b->unique_batch_item_id == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_byte_string(a->unique_batch_item_id, 
                                   b->unique_batch_item_id) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->result_message != b->result_message)
        {
            if((a->result_message == NULL) || (b->result_message == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->result_message,
                                   b->result_message) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->asynchronous_correlation_value !=
           b->asynchronous_correlation_value)
        {
            if((a->asynchronous_correlation_value == NULL) ||
               (b->asynchronous_correlation_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_byte_string(
                a->asynchronous_correlation_value,
                b->asynchronous_correlation_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->response_payload != b->response_payload)
        {
            if((a->response_payload == NULL) || (b->response_payload == NULL))
            {
                return(KMIP_FALSE);
            }
            
            switch(a->operation)
            {
                case KMIP_OP_CREATE:
                if(compare_create_response_payload(
                    (struct create_response_payload *)a->response_payload,
                    (struct create_response_payload *)b->response_payload) == 
                   KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OP_GET:
                if(compare_get_response_payload(
                    (struct get_response_payload *)a->response_payload,
                    (struct get_response_payload *)b->response_payload) == 
                   KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OP_DESTROY:
                if(compare_destroy_response_payload(
                    (struct destroy_response_payload *)a->response_payload,
                    (struct destroy_response_payload *)b->response_payload) == 
                   KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                default:
                /* NOTE (ph) Unsupported payloads cannot be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_nonce(const struct nonce *a, const struct nonce *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->nonce_id != b->nonce_id)
        {
            if((a->nonce_id == NULL) || (b->nonce_id == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_byte_string(a->nonce_id, b->nonce_id) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->nonce_value != b->nonce_value)
        {
            if((a->nonce_value == NULL) || (b->nonce_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_byte_string(a->nonce_value, b->nonce_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_username_password_credential(const struct username_password_credential *a,
                                     const struct username_password_credential *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->username != b->username)
        {
            if((a->username == NULL) || (b->username == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->username, b->username) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->password != b->password)
        {
            if((a->password == NULL) || (b->password == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->password, b->password) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_device_credential(const struct device_credential *a,
                          const struct device_credential *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->device_serial_number != b->device_serial_number)
        {
            if((a->device_serial_number == NULL) || (b->device_serial_number == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->device_serial_number,
                                   b->device_serial_number) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->password != b->password)
        {
            if((a->password == NULL) || (b->password == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->password,
                                   b->password) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->device_identifier != b->device_identifier)
        {
            if((a->device_identifier == NULL) || (b->device_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->device_identifier,
                                   b->device_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->network_identifier != b->network_identifier)
        {
            if((a->network_identifier == NULL) || (b->network_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->network_identifier,
                                   b->network_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->machine_identifier != b->machine_identifier)
        {
            if((a->machine_identifier == NULL) || (b->machine_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->machine_identifier,
                                   b->machine_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->media_identifier != b->media_identifier)
        {
            if((a->media_identifier == NULL) || (b->media_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->media_identifier,
                                   b->media_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_attestation_credential(const struct attestation_credential *a,
                               const struct attestation_credential *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->attestation_type != b->attestation_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->nonce != b->nonce)
        {
            if((a->nonce == NULL) || (b->nonce == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_nonce(a->nonce, b->nonce) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->attestation_measurement != b->attestation_measurement)
        {
            if((a->attestation_measurement == NULL) || 
               (b->attestation_measurement == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_byte_string(a->attestation_measurement,
                                   b->attestation_measurement) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->attestation_assertion != b->attestation_assertion)
        {
            if((a->attestation_assertion == NULL) || 
               (b->attestation_assertion == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_byte_string(a->attestation_assertion,
                                   b->attestation_assertion) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_credential_value(enum credential_type type,
                         void **a,
                         void **b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(*a != *b)
        {
            if((*a == NULL) || (*b == NULL))
            {
                return(KMIP_FALSE);
            }
            
            switch(type)
            {
                case KMIP_CRED_USERNAME_AND_PASSWORD:
                if(compare_username_password_credential(*a, *b) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_CRED_DEVICE:
                if(compare_device_credential(*a, *b) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_CRED_ATTESTATION:
                if(compare_attestation_credential(*a, *b) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                default:
                /* NOTE (ph) Unsupported types cannot be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_credential(const struct credential *a, const struct credential *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->credential_type != b->credential_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->credential_value != b->credential_value)
        {
            if((a->credential_value == NULL) || (b->credential_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_credential_value(
                a->credential_type,
                (void**)&a->credential_value,
                (void**)&b->credential_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_authentication(const struct authentication *a,
                       const struct authentication *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->credential != b->credential)
        {
            if((a->credential == NULL) || (b->credential == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_credential(a->credential, b->credential) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_response_header(const struct response_header *a,
                        const struct response_header *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->time_stamp != b->time_stamp)
        {
            return(KMIP_FALSE);
        }
        
        if(a->batch_count != b->batch_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->attestation_type_count != b->attestation_type_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->protocol_version != b->protocol_version)
        {
            if((a->protocol_version == NULL) || (b->protocol_version == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_protocol_version(a->protocol_version,
                                        b->protocol_version) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->nonce != b->nonce)
        {
            if((a->nonce == NULL) || (b->nonce == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_nonce(a->nonce, b->nonce) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->attestation_types != b->attestation_types)
        {
            if((a->attestation_types == NULL) || (b->attestation_types == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->attestation_type_count; i++)
            {
                if(a->attestation_types[i] != b->attestation_types[i])
                {
                    return(KMIP_FALSE);
                }
            }
        }
        
        if(a->client_correlation_value != b->client_correlation_value)
        {
            if((a->client_correlation_value == NULL) || 
               (b->client_correlation_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->client_correlation_value,
                                   b->client_correlation_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->server_correlation_value != b->server_correlation_value)
        {
            if((a->server_correlation_value == NULL) ||
               (b->server_correlation_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_text_string(a->server_correlation_value,
                                   b->server_correlation_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
compare_response_message(const struct response_message *a,
                         const struct response_message *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->batch_count != b->batch_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->response_header != b->response_header)
        {
            if((a->response_header == NULL) || (b->response_header == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(compare_response_header(a->response_header,
                                       b->response_header) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->batch_items != b->batch_items)
        {
            if((a->batch_items == NULL) || (b->batch_items == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->batch_count; i++)
            {
                if(compare_response_batch_item(&a->batch_items[i], 
                                               &b->batch_items[i]) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

/*
Encoding Functions
*/

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
encode_text_string(struct kmip *ctx, enum tag t,
                   const struct text_string *value)
{
    /* TODO (ph) What if value is NULL? */
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
encode_name(struct kmip *ctx, const struct name *value)
{
    /* TODO (peter-hamilton) Check for value == NULL? */
    
    int result = 0;
    
    result = encode_int32_be(
        ctx, 
        TAG_TYPE(KMIP_TAG_NAME, KMIP_TYPE_STRUCTURE));
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
    
    result = encode_attribute_name(ctx, value->type);
    CHECK_RESULT(ctx, result);
    
    if(value->index != KMIP_UNSET)
    {
        result = encode_integer(ctx, KMIP_TAG_ATTRIBUTE_INDEX, value->index);
        CHECK_RESULT(ctx, result);
    }
    
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
        /* TODO (ph) This is messy. Clean it up? */
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
encode_mac_signature_key_information(
struct kmip *ctx, 
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
encode_transparent_symmetric_key(
struct kmip *ctx,
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
encode_key_material(struct kmip *ctx,
                    enum key_format_type format,
                    const void *value)
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

/*
Decoding Functions
*/

int
decode_int8_be(struct kmip *ctx, void *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int8));
    
    int8 *i = (int8*)value;
    
    *i = 0;
    *i = *ctx->index++;
    
    return(KMIP_OK);
}

int
decode_int32_be(struct kmip *ctx, void *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int32));
    
    int32 *i = (int32*)value;
    
    *i = 0;
    *i |= ((int32)*ctx->index++ << 24);
    *i |= ((int32)*ctx->index++ << 16);
    *i |= ((int32)*ctx->index++ << 8);
    *i |= ((int32)*ctx->index++ << 0);
    
    return(KMIP_OK);
}

int
decode_int64_be(struct kmip *ctx, void *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int64));
    
    int64 *i = (int64*)value;
    
    *i = 0;
    *i |= ((int64)*ctx->index++ << 56);
    *i |= ((int64)*ctx->index++ << 48);
    *i |= ((int64)*ctx->index++ << 40);
    *i |= ((int64)*ctx->index++ << 32);
    *i |= ((int64)*ctx->index++ << 24);
    *i |= ((int64)*ctx->index++ << 16);
    *i |= ((int64)*ctx->index++ << 8);
    *i |= ((int64)*ctx->index++ << 0);
    
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
decode_enum(struct kmip *ctx, enum tag t, void *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    int32 length = 0;
    int32 *v = (int32*)value;
    int32 padding = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_ENUMERATION);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 4);
    
    decode_int32_be(ctx, v);
    
    decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
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
    
    value->value = ctx->calloc_func(ctx->state, 1, length);
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
    
    value->value = ctx->calloc_func(ctx->state, 1, length);
    value->size = length;
    
    uint8 *index = value->value;
    
    for(int32 i = 0; i < length; i++)
    {
        decode_int8_be(ctx, index++);
    }
    for(int32 i = 0; i < padding; i++)
    {
        decode_int8_be(ctx, &spacer);
        CHECK_PADDING(ctx, spacer);
    }
    
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
    
    decode_int64_be(ctx, value);
    
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
    
    decode_int32_be(ctx, value);
    
    decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
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
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->value = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct text_string));
    
    result = decode_text_string(ctx, KMIP_TAG_NAME_VALUE, value->value);
    CHECK_RESULT(ctx, result);
    
    result = decode_enum(ctx, KMIP_TAG_NAME_TYPE, (int32*)&value->type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_NAME_TYPE, value->type);
    
    return(KMIP_OK);
}

int
decode_attribute_name(struct kmip *ctx, enum attribute_type *value)
{
    int result = 0;
    enum tag t = KMIP_TAG_ATTRIBUTE_NAME;
    struct text_string n = {0};
    
    result = decode_text_string(ctx, t, &n);
    CHECK_RESULT(ctx, result);
    
    if((n.size == 17) && (strncmp(n.value, "Unique Identifier", 17) == 0))
    {
        *value = KMIP_ATTR_UNIQUE_IDENTIFIER;
    }
    else if((n.size == 4) && (strncmp(n.value, "Name", 4) == 0))
    {
        *value = KMIP_ATTR_NAME;
    }
    else if((n.size == 11) && (strncmp(n.value, "Object Type", 11) == 0))
    {
        *value = KMIP_ATTR_OBJECT_TYPE;
    }
    else if((n.size == 23) && 
            (strncmp(n.value, "Cryptographic Algorithm", 23) == 0))
    {
        *value = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    }
    else if((n.size == 20) && (strncmp(n.value, "Cryptographic Length", 20) == 0))
    {
        *value = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    }
    else if((n.size == 21) && 
            (strncmp(n.value, "Operation Policy Name", 21) == 0))
    {
        *value = KMIP_ATTR_OPERATION_POLICY_NAME;
    }
    else if((n.size == 24) && 
            (strncmp(n.value, "Cryptographic Usage Mask", 24) == 0))
    {
        *value = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
    }
    else if((n.size == 5) && (strncmp(n.value, "State", 5) == 0))
    {
        *value = KMIP_ATTR_STATE;
    }
    /* TODO (peter-hamilton) Add all remaining attributes here. */
    else
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        free_text_string(ctx, &n);
        return(KMIP_ERROR_ATTR_UNSUPPORTED);
    }
    
    free_text_string(ctx, &n);
    return(KMIP_OK);
}

int
decode_attribute(struct kmip *ctx, struct attribute *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    init_attribute(value);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_ATTRIBUTE, KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = decode_attribute_name(ctx, &value->type);
    CHECK_RESULT(ctx, result);
    
    if(is_tag_next(ctx, KMIP_TAG_ATTRIBUTE_INDEX))
    {
        result = decode_integer(
            ctx,
            KMIP_TAG_ATTRIBUTE_INDEX,
            &value->index);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    uint8 *tag_index = ctx->index;
    enum tag t = KMIP_TAG_ATTRIBUTE_VALUE;
    
    switch(value->type)
    {
        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        value->value = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct text_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->value,
            sizeof(struct text_string),
            "UniqueIdentifier text string");
        result = decode_text_string(
            ctx,
            t,
            (struct text_string*)value->value);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_ATTR_NAME:
        /* TODO (ph) Like encoding, this is messy. Better solution? */
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(struct name));
        CHECK_NEW_MEMORY(
            ctx,
            value->value,
            sizeof(struct name),
            "Name structure");
        
        if(is_tag_type_next(
            ctx,
            KMIP_TAG_ATTRIBUTE_VALUE,
            KMIP_TYPE_STRUCTURE))
        {
            /* NOTE (ph) Decoding name structures will fail if the name tag */
            /* is not present in the encoding. Temporarily swap the tags, */
            /* decode the name structure, and then swap the tags back to */
            /* preserve the encoding. The tag/type check above guarantees */
            /* space exists for this to succeed. */
            encode_int32_be(
                ctx, 
                TAG_TYPE(KMIP_TAG_NAME, KMIP_TYPE_STRUCTURE));
            ctx->index = tag_index;
            
            result = decode_name(ctx, (struct name*)value->value);
            
            curr_index = ctx->index;
            ctx->index = tag_index;
            
            encode_int32_be(
                ctx,
                TAG_TYPE(KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE));
            ctx->index = curr_index;
        }
        else
        {
            result = KMIP_TAG_MISMATCH;
        }
        
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(
            ctx,
            value->value,
            sizeof(int32),
            "ObjectType enumeration");
        result = decode_enum(ctx, t, (int32 *)value->value);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_OBJECT_TYPE, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(
            ctx,
            value->value,
            sizeof(int32),
            "CryptographicAlgorithm enumeration");
        result = decode_enum(ctx, t, (int32 *)value->value);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(
            ctx,
            KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
            *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(
            ctx,
            value->value,
            sizeof(int32),
            "CryptographicLength integer");
        result = decode_integer(ctx, t, (int32 *)value->value);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        value->value = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct text_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->value,
            sizeof(struct text_string),
            "OperationPolicyName text string");
        result = decode_text_string(
            ctx,
            t,
            (struct text_string*)value->value);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(
            ctx,
            value->value,
            sizeof(int32),
            "CryptographicUsageMask integer");
        result = decode_integer(ctx, t, (int32 *)value->value);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_ATTR_STATE:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(
            ctx,
            value->value,
            sizeof(int32),
            "State enumeration");
        result = decode_enum(ctx, t, (int32 *)value->value);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_STATE, *(int32 *)value->value);
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
decode_template_attribute(struct kmip *ctx, 
                          struct template_attribute *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_TEMPLATE_ATTRIBUTE,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->name_count = get_num_items_next(ctx, KMIP_TAG_NAME);
    if(value->name_count > 0)
    {
        value->names = ctx->calloc_func(
            ctx->state,
            value->name_count,
            sizeof(struct name));
        CHECK_NEW_MEMORY(
            ctx,
            value->names,
            value->name_count * sizeof(struct name),
            "sequence of Name structures");
        
        for(size_t i = 0; i < value->name_count; i++)
        {
            result = decode_name(ctx, &value->names[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    value->attribute_count = get_num_items_next(ctx, KMIP_TAG_ATTRIBUTE);
    if(value->attribute_count > 0)
    {
        value->attributes = ctx->calloc_func(
            ctx->state,
            value->attribute_count,
            sizeof(struct attribute));
        CHECK_NEW_MEMORY(
            ctx,
            value->attributes,
            value->attribute_count * sizeof(struct attribute),
            "sequence of Attribute structures");
        
        for(size_t i = 0; i < value->attribute_count; i++)
        {
            result = decode_attribute(ctx, &value->attributes[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    return(KMIP_OK);
}

int
decode_protocol_version(struct kmip *ctx, 
                        struct protocol_version *value)
{
    CHECK_BUFFER_FULL(ctx, 40);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_PROTOCOL_VERSION,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_LENGTH(ctx, length, 32);
    
    result = decode_integer(
        ctx,
        KMIP_TAG_PROTOCOL_VERSION_MAJOR,
        &value->major);
    CHECK_RESULT(ctx, result);
    
    result = decode_integer(
        ctx,
        KMIP_TAG_PROTOCOL_VERSION_MINOR,
        &value->minor);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
decode_transparent_symmetric_key(struct kmip *ctx,
                                 struct transparent_symmetric_key *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_KEY_MATERIAL,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->key = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct byte_string));
    CHECK_NEW_MEMORY(
        ctx,
        value->key,
        sizeof(struct byte_string),
        "Key byte string");
    
    result = decode_byte_string(ctx, KMIP_TAG_KEY, value->key);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
decode_key_material(struct kmip *ctx,
                    enum key_format_type format,
                    void **value)
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
        *value = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct byte_string));
        CHECK_NEW_MEMORY(
            ctx,
            *value,
            sizeof(struct byte_string),
            "KeyMaterial byte string");
        result = decode_byte_string(
            ctx,
            KMIP_TAG_KEY_MATERIAL,
            (struct byte_string*)*value);
        CHECK_RESULT(ctx, result);
        return(KMIP_OK);
        break;
        
        default:
        break;
    };
    
    switch(format)
    {
        case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
        *value = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct transparent_symmetric_key));
        CHECK_NEW_MEMORY(
            ctx,
            *value,
            sizeof(struct transparent_symmetric_key),
            "TransparentSymmetricKey structure");
        result = decode_transparent_symmetric_key(
            ctx,
            (struct transparent_symmetric_key*)*value);
        CHECK_RESULT(ctx, result);
        break;
        
        /* TODO (peter-hamilton) The rest require BigInteger support. */
        
        case KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY:
        case KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY:
        case KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY:
        case KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY:
        case KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY:
        case KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY:
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    
    return(KMIP_OK);
}

int
decode_key_value(struct kmip *ctx,
                 enum key_format_type format,
                 struct key_value *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_KEY_VALUE,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = decode_key_material(ctx, format, &value->key_material);
    CHECK_RESULT(ctx, result);
    
    value->attribute_count = get_num_items_next(ctx, KMIP_TAG_ATTRIBUTE);
    if(value->attribute_count > 0)
    {
        value->attributes = ctx->calloc_func(
            ctx->state,
            value->attribute_count,
            sizeof(struct attribute));
        CHECK_NEW_MEMORY(
            ctx,
            value->attributes,
            value->attribute_count * sizeof(struct attribute),
            "sequence of Attribute structures");
        
        for(size_t i = 0; i < value->attribute_count; i++)
        {
            result = decode_attribute(ctx, &value->attributes[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    return(KMIP_OK);
}

int
decode_cryptographic_parameters(struct kmip *ctx, 
                                struct cryptographic_parameters *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    init_cryptographic_parameters(value);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    if(is_tag_next(ctx, KMIP_TAG_BLOCK_CIPHER_MODE))
    {
        result = decode_enum(
            ctx,
            KMIP_TAG_BLOCK_CIPHER_MODE,
            &value->block_cipher_mode);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_BLOCK_CIPHER_MODE, value->block_cipher_mode);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_PADDING_METHOD))
    {
        result = decode_enum(
            ctx,
            KMIP_TAG_PADDING_METHOD,
            &value->padding_method);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_PADDING_METHOD, value->padding_method);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_HASHING_ALGORITHM))
    {
        result = decode_enum(
            ctx,
            KMIP_TAG_HASHING_ALGORITHM,
            &value->hashing_algorithm);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_HASHING_ALGORITHM, value->hashing_algorithm);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_KEY_ROLE_TYPE))
    {
        result = decode_enum(
            ctx,
            KMIP_TAG_KEY_ROLE_TYPE,
            &value->key_role_type);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_KEY_ROLE_TYPE, value->key_role_type);
    }
    
    if(ctx->version >= KMIP_1_2)
    {
        if(is_tag_next(ctx, KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM))
        {
            result = decode_enum(
                ctx,
                KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM,
                &value->digital_signature_algorithm);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(
                ctx,
                KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM,
                value->digital_signature_algorithm);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM))
        {
            result = decode_enum(
                ctx,
                KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
                &value->cryptographic_algorithm);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(
                ctx,
                KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
                value->cryptographic_algorithm);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_RANDOM_IV))
        {
            result = decode_bool(
                ctx,
                KMIP_TAG_RANDOM_IV,
                &value->random_iv);
            CHECK_RESULT(ctx, result);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_IV_LENGTH))
        {
            result = decode_integer(
                ctx,
                KMIP_TAG_IV_LENGTH,
                &value->iv_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_TAG_LENGTH))
        {
            result = decode_integer(
                ctx,
                KMIP_TAG_TAG_LENGTH,
                &value->tag_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_FIXED_FIELD_LENGTH))
        {
            result = decode_integer(
                ctx,
                KMIP_TAG_FIXED_FIELD_LENGTH,
                &value->fixed_field_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_INVOCATION_FIELD_LENGTH))
        {
            result = decode_integer(
                ctx,
                KMIP_TAG_INVOCATION_FIELD_LENGTH,
                &value->invocation_field_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_COUNTER_LENGTH))
        {
            result = decode_integer(
                ctx,
                KMIP_TAG_COUNTER_LENGTH,
                &value->counter_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_INITIAL_COUNTER_VALUE))
        {
            result = decode_integer(
                ctx,
                KMIP_TAG_INITIAL_COUNTER_VALUE,
                &value->initial_counter_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(is_tag_next(ctx, KMIP_TAG_SALT_LENGTH))
        {
            result = decode_integer(
                ctx,
                KMIP_TAG_SALT_LENGTH,
                &value->salt_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_MASK_GENERATOR))
        {
            result = decode_enum(
                ctx,
                KMIP_TAG_MASK_GENERATOR,
                &value->mask_generator);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(ctx, KMIP_TAG_MASK_GENERATOR, value->mask_generator);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM))
        {
            result = decode_enum(
                ctx,
                KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM,
                &value->mask_generator_hashing_algorithm);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(
                ctx,
                KMIP_TAG_HASHING_ALGORITHM,
                value->mask_generator_hashing_algorithm);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_P_SOURCE))
        {
            value->p_source = ctx->calloc_func(
                ctx->state,
                1,
                sizeof(struct byte_string));
            CHECK_NEW_MEMORY(
                ctx,
                value->p_source,
                sizeof(struct byte_string),
                "P Source byte string");
            
            result = decode_byte_string(
                ctx,
                KMIP_TAG_P_SOURCE,
                value->p_source);
            CHECK_RESULT(ctx, result);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_TRAILER_FIELD))
        {
            result = decode_integer(
                ctx,
                KMIP_TAG_TRAILER_FIELD,
                &value->trailer_field);
            CHECK_RESULT(ctx, result);
        }
    }
    
    return(KMIP_OK);
}

int
decode_encryption_key_information(struct kmip *ctx, 
                                  struct encryption_key_information *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_ENCRYPTION_KEY_INFORMATION,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->unique_identifier = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct text_string));
    CHECK_NEW_MEMORY(
        ctx,
        value->unique_identifier,
        sizeof(struct text_string),
        "UniqueIdentifier text string");
    
    result = decode_text_string(
        ctx,
        KMIP_TAG_UNIQUE_IDENTIFIER,
        value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(is_tag_next(ctx, KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS))
    {
        value->cryptographic_parameters = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct cryptographic_parameters));
        CHECK_NEW_MEMORY(
            ctx,
            value->cryptographic_parameters,
            sizeof(struct cryptographic_parameters),
            "CryptographicParameters structure");
        
        result = decode_cryptographic_parameters(
            ctx,
            value->cryptographic_parameters);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
decode_mac_signature_key_information(struct kmip *ctx, 
                                     struct mac_signature_key_information *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->unique_identifier = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct text_string));
    CHECK_NEW_MEMORY(
        ctx,
        value->unique_identifier,
        sizeof(struct text_string),
        "UniqueIdentifier text string");
    
    result = decode_text_string(
        ctx,
        KMIP_TAG_UNIQUE_IDENTIFIER,
        value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(is_tag_next(ctx, KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS))
    {
        value->cryptographic_parameters = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct cryptographic_parameters));
        CHECK_NEW_MEMORY(
            ctx,
            value->cryptographic_parameters,
            sizeof(struct cryptographic_parameters),
            "CryptographicParameters structure");
        
        result = decode_cryptographic_parameters(
            ctx,
            value->cryptographic_parameters);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}


int
decode_key_wrapping_data(struct kmip *ctx, 
                         struct key_wrapping_data *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_KEY_WRAPPING_DATA,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = decode_enum(ctx, KMIP_TAG_WRAPPING_METHOD, &value->wrapping_method);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_WRAPPING_METHOD, value->wrapping_method);
    
    if(is_tag_next(ctx, KMIP_TAG_ENCRYPTION_KEY_INFORMATION))
    {
        value->encryption_key_info = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct encryption_key_information));
        CHECK_NEW_MEMORY(
            ctx,
            value->encryption_key_info,
            sizeof(struct encryption_key_information),
            "EncryptionKeyInformation structure");
        
        result = decode_encryption_key_information(
            ctx,
            value->encryption_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION))
    {
        value->mac_signature_key_info = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct mac_signature_key_information));
        CHECK_NEW_MEMORY(
            ctx,
            value->mac_signature_key_info,
            sizeof(struct mac_signature_key_information),
            "MAC/SignatureKeyInformation structure");
        
        result = decode_mac_signature_key_information(
            ctx,
            value->mac_signature_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_MAC_SIGNATURE))
    {
        value->mac_signature = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct byte_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->mac_signature,
            sizeof(struct byte_string),
            "MAC/Signature byte string");
        
        result = decode_byte_string(
            ctx,
            KMIP_TAG_MAC_SIGNATURE,
            value->mac_signature);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_IV_COUNTER_NONCE))
    {
        value->iv_counter_nonce = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct byte_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->iv_counter_nonce,
            sizeof(struct byte_string),
            "IV/Counter/Nonce byte string");
        
        result = decode_byte_string(
            ctx,
            KMIP_TAG_IV_COUNTER_NONCE,
            value->iv_counter_nonce);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_1)
    {
        if(is_tag_next(ctx, KMIP_TAG_ENCODING_OPTION))
        {
            result = decode_enum(
                ctx,
                KMIP_TAG_ENCODING_OPTION,
                &value->encoding_option);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(ctx, KMIP_TAG_ENCODING_OPTION, value->encoding_option);
        }
    }
    
    return(KMIP_OK);
}

int
decode_key_block(struct kmip *ctx, struct key_block *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_KEY_BLOCK,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = decode_enum(ctx, KMIP_TAG_KEY_FORMAT_TYPE, &value->key_format_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_KEY_FORMAT_TYPE, value->key_format_type);
    
    if(is_tag_next(ctx, KMIP_TAG_KEY_COMPRESSION_TYPE))
    {
        result = decode_enum(
            ctx,
            KMIP_TAG_KEY_COMPRESSION_TYPE,
            &value->key_compression_type);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_KEY_COMPRESSION_TYPE, value->key_compression_type);
    }
    
    if(is_tag_type_next(ctx, KMIP_TAG_KEY_VALUE, KMIP_TYPE_BYTE_STRING))
    {
        value->key_value_type = KMIP_TYPE_BYTE_STRING;
        value->key_value = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct byte_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->key_value,
            sizeof(struct byte_string),
            "KeyValue byte string");
        
        result = decode_byte_string(
            ctx,
            KMIP_TAG_KEY_VALUE,
            (struct byte_string *)value->key_value);
    }
    else
    {
        value->key_value_type = KMIP_TYPE_STRUCTURE;
        value->key_value = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct key_value));
        CHECK_NEW_MEMORY(
            ctx,
            value->key_value,
            sizeof(struct key_value),
            "KeyValue structure");
        
        result = decode_key_value(
            ctx,
            value->key_format_type,
            (struct key_value *)value->key_value);
    }
    CHECK_RESULT(ctx, result);
    
    if(is_tag_next(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM))
    {
        result = decode_enum(
            ctx,
            KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
            &value->cryptographic_algorithm);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(
            ctx,
            KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
            value->cryptographic_algorithm);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_CRYPTOGRAPHIC_LENGTH))
    {
        result = decode_integer(
            ctx,
            KMIP_TAG_CRYPTOGRAPHIC_LENGTH,
            &value->cryptographic_length);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_KEY_WRAPPING_DATA))
    {
        value->key_wrapping_data = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct key_wrapping_data));
        CHECK_NEW_MEMORY(
            ctx,
            value->key_wrapping_data,
            sizeof(struct key_wrapping_data),
            "KeyWrappingData structure");
        
        result = decode_key_wrapping_data(ctx, value->key_wrapping_data);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
decode_symmetric_key(struct kmip *ctx, struct symmetric_key *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_SYMMETRIC_KEY,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->key_block = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct key_block));
    CHECK_NEW_MEMORY(
        ctx,
        value->key_block,
        sizeof(struct key_block),
        "KeyBlock structure");
    
    result = decode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
decode_public_key(struct kmip *ctx, struct public_key *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_PUBLIC_KEY,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->key_block = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct key_block));
    CHECK_NEW_MEMORY(
        ctx,
        value->key_block,
        sizeof(struct key_block),
        "KeyBlock structure");
    
    result = decode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
decode_private_key(struct kmip *ctx, struct private_key *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_PRIVATE_KEY,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->key_block = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct key_block));
    CHECK_NEW_MEMORY(
        ctx,
        value->key_block,
        sizeof(struct key_block),
        "KeyBlock structure");
    
    result = decode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
decode_create_response_payload(struct kmip *ctx, 
                               struct create_response_payload *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_RESPONSE_PAYLOAD,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = decode_enum(ctx, KMIP_TAG_OBJECT_TYPE, &value->object_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    
    value->unique_identifier = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct text_string));
    CHECK_NEW_MEMORY(
        ctx,
        value->unique_identifier,
        sizeof(struct text_string),
        "UniqueIdentifier text string");
    
    result = decode_text_string(
        ctx,
        KMIP_TAG_UNIQUE_IDENTIFIER,
        value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(is_tag_next(ctx, KMIP_TAG_TEMPLATE_ATTRIBUTE))
    {
        value->template_attribute = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct template_attribute));
        CHECK_NEW_MEMORY(
            ctx,
            value->template_attribute,
            sizeof(struct template_attribute),
            "TemplateAttribute structure");
        
        result = decode_template_attribute(ctx, value->template_attribute);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
decode_get_response_payload(struct kmip *ctx,
                            struct get_response_payload *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_RESPONSE_PAYLOAD,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = decode_enum(ctx, KMIP_TAG_OBJECT_TYPE, &value->object_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    
    value->unique_identifier = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct text_string));
    CHECK_NEW_MEMORY(
        ctx,
        value->unique_identifier,
        sizeof(struct text_string),
        "UniqueIdentifier text string");
    
    result = decode_text_string(
        ctx,
        KMIP_TAG_UNIQUE_IDENTIFIER,
        value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    switch(value->object_type)
    {
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
        value->object = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct symmetric_key));
        CHECK_NEW_MEMORY(
            ctx,
            value->object,
            sizeof(struct symmetric_key),
            "SymmetricKey structure");
        result = decode_symmetric_key(
            ctx,
            (struct symmetric_key*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_OBJTYPE_PUBLIC_KEY:
        value->object = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct public_key));
        CHECK_NEW_MEMORY(
            ctx,
            value->object,
            sizeof(struct public_key),
            "PublicKey structure");
        result = decode_public_key(
            ctx,
            (struct public_key*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_OBJTYPE_PRIVATE_KEY:
        value->object = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct private_key));
        CHECK_NEW_MEMORY(
            ctx,
            value->object,
            sizeof(struct private_key),
            "PrivateKey structure");
        result = decode_private_key(
            ctx,
            (struct private_key*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    
    return(KMIP_OK);
}

int
decode_destroy_response_payload(struct kmip *ctx, 
                                struct destroy_response_payload *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_RESPONSE_PAYLOAD,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->unique_identifier = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct text_string));
    CHECK_NEW_MEMORY(
        ctx,
        value->unique_identifier,
        sizeof(struct text_string),
        "UniqueIdentifier text string");
    
    result = decode_text_string(
        ctx,
        KMIP_TAG_UNIQUE_IDENTIFIER,
        value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
decode_response_batch_item(struct kmip *ctx,
                           struct response_batch_item *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_BATCH_ITEM,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = decode_enum(ctx, KMIP_TAG_OPERATION, &value->operation);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_OPERATION, value->operation);
    
    if(is_tag_next(ctx, KMIP_TAG_UNIQUE_BATCH_ITEM_ID))
    {
        value->unique_batch_item_id = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct byte_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->unique_batch_item_id,
            sizeof(struct byte_string),
            "UniqueBatchItemID byte string");
        
        result = decode_byte_string(
            ctx,
            KMIP_TAG_UNIQUE_BATCH_ITEM_ID,
            value->unique_batch_item_id);
        CHECK_RESULT(ctx, result);
    }
    
    result = decode_enum(ctx, KMIP_TAG_RESULT_STATUS, &value->result_status);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_RESULT_STATUS, value->result_status);
    
    if(is_tag_next(ctx, KMIP_TAG_RESULT_REASON))
    {
        result = decode_enum(
            ctx,
            KMIP_TAG_RESULT_REASON,
            &value->result_reason);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_RESULT_MESSAGE))
    {
        value->result_message = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct text_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->result_message,
            sizeof(struct text_string),
            "ResultMessage text string");
        
        result = decode_text_string(
            ctx,
            KMIP_TAG_RESULT_MESSAGE,
            value->result_message);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE))
    {
        value->asynchronous_correlation_value = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct byte_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->asynchronous_correlation_value,
            sizeof(struct byte_string),
            "AsynchronousCorrelationValue byte string");
        
        result = decode_byte_string(
            ctx,
            KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE,
            value->asynchronous_correlation_value);
        CHECK_RESULT(ctx, result);
    }
    
    switch(value->operation)
    {
        /*
        case KMIP_OP_CREATE:
        result = encode_create_response_payload(
            ctx,
            (struct create_response_payload*)value->response_payload);
        break;
        */
        
        case KMIP_OP_GET:
        value->response_payload = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct get_response_payload));
        CHECK_NEW_MEMORY(
            ctx,
            value->response_payload,
            sizeof(struct get_response_payload),
            "GetResponsePayload structure");
        
        result = decode_get_response_payload(
            ctx,
            (struct get_response_payload *)value->response_payload);
        break;
        
        /*
        case KMIP_OP_DESTROY:
        result = encode_destroy_response_payload(
            ctx,
            (struct destroy_response_payload*)value->response_payload);
        break;
        */
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
decode_nonce(struct kmip *ctx, struct nonce *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_NONCE,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->nonce_id = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct byte_string));
    CHECK_NEW_MEMORY(
        ctx,
        value->nonce_id,
        sizeof(struct byte_string),
        "NonceID byte string");
    
    result = decode_byte_string(
        ctx,
        KMIP_TAG_NONCE_ID,
        value->nonce_id);
    CHECK_RESULT(ctx, result);
    
    value->nonce_value = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct byte_string));
    CHECK_NEW_MEMORY(
        ctx,
        value->nonce_value,
        sizeof(struct byte_string),
        "NonceValue byte string");
    
    result = decode_byte_string(
        ctx,
        KMIP_TAG_NONCE_VALUE,
        value->nonce_value);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
decode_username_password_credential(struct kmip *ctx,
                                    struct username_password_credential *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_CREDENTIAL_VALUE,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->username = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct text_string));
    CHECK_NEW_MEMORY(
        ctx,
        value->username,
        sizeof(struct text_string),
        "Username text string");
    
    result = decode_text_string(
        ctx,
        KMIP_TAG_USERNAME,
        value->username);
    CHECK_RESULT(ctx, result);
    
    if(is_tag_next(ctx, KMIP_TAG_PASSWORD))
    {
        value->password = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct text_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->password,
            sizeof(struct text_string),
            "Password text string");
        
        result = decode_text_string(
            ctx,
            KMIP_TAG_PASSWORD,
            value->password);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
decode_device_credential(struct kmip *ctx,
                         struct device_credential *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_CREDENTIAL_VALUE,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    if(is_tag_next(ctx, KMIP_TAG_DEVICE_SERIAL_NUMBER))
    {
        value->device_serial_number = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct text_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->device_serial_number,
            sizeof(struct text_string),
            "DeviceSerialNumber text string");
        
        result = decode_text_string(
            ctx,
            KMIP_TAG_DEVICE_SERIAL_NUMBER,
            value->device_serial_number);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_PASSWORD))
    {
        value->password = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct text_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->password,
            sizeof(struct text_string),
            "Password text string");
        
        result = decode_text_string(
            ctx,
            KMIP_TAG_PASSWORD,
            value->password);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_DEVICE_IDENTIFIER))
    {
        value->device_identifier = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct text_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->device_identifier,
            sizeof(struct text_string),
            "DeviceIdentifier text string");
        
        result = decode_text_string(
            ctx,
            KMIP_TAG_DEVICE_IDENTIFIER,
            value->device_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_NETWORK_IDENTIFIER))
    {
        value->network_identifier = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct text_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->network_identifier,
            sizeof(struct text_string),
            "NetworkIdentifier text string");
        
        result = decode_text_string(
            ctx,
            KMIP_TAG_NETWORK_IDENTIFIER,
            value->network_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_MACHINE_IDENTIFIER))
    {
        value->machine_identifier = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct text_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->machine_identifier,
            sizeof(struct text_string),
            "MachineIdentifier text string");
        
        result = decode_text_string(
            ctx,
            KMIP_TAG_MACHINE_IDENTIFIER,
            value->machine_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_MEDIA_IDENTIFIER))
    {
        value->media_identifier = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct text_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->media_identifier,
            sizeof(struct text_string),
            "MediaIdentifier text string");
        
        result = decode_text_string(
            ctx,
            KMIP_TAG_MEDIA_IDENTIFIER,
            value->media_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
decode_attestation_credential(struct kmip *ctx,
                              struct attestation_credential *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_CREDENTIAL_VALUE,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->nonce = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct nonce));
    CHECK_NEW_MEMORY(
        ctx,
        value->nonce,
        sizeof(struct nonce),
        "Nonce structure");
    
    result = decode_nonce(ctx, value->nonce);
    CHECK_RESULT(ctx, result);
    
    result = decode_enum(
        ctx,
        KMIP_TAG_ATTESTATION_TYPE,
        &value->attestation_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_ATTESTATION_TYPE, value->attestation_type);
    
    if(is_tag_next(ctx, KMIP_TAG_ATTESTATION_MEASUREMENT))
    {
        value->attestation_measurement = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct byte_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->attestation_measurement,
            sizeof(struct byte_string),
            "AttestationMeasurement byte string");
        
        result = decode_byte_string(
            ctx,
            KMIP_TAG_ATTESTATION_MEASUREMENT,
            value->attestation_measurement);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_ATTESTATION_ASSERTION))
    {
        value->attestation_assertion = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct byte_string));
        CHECK_NEW_MEMORY(
            ctx,
            value->attestation_assertion,
            sizeof(struct byte_string),
            "AttestationAssertion byte string");
        
        result = decode_byte_string(
            ctx,
            KMIP_TAG_ATTESTATION_ASSERTION,
            value->attestation_assertion);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
decode_credential_value(struct kmip *ctx, 
                        enum credential_type type, 
                        void **value)
{
    int result = 0;
    
    switch(type)
    {
        case KMIP_CRED_USERNAME_AND_PASSWORD:
        *value = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct username_password_credential));
        CHECK_NEW_MEMORY(
            ctx,
            *value,
            sizeof(struct username_password_credential),
            "UsernamePasswordCredential structure");
        result = decode_username_password_credential(
            ctx, 
            (struct username_password_credential *)*value);
        break;
        
        case KMIP_CRED_DEVICE:
        *value = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct device_credential));
        CHECK_NEW_MEMORY(
            ctx,
            *value,
            sizeof(struct device_credential),
            "DeviceCredential structure");
        result = decode_device_credential(
            ctx,
            (struct device_credential *)*value);
        break;
        
        case KMIP_CRED_ATTESTATION:
        *value = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct attestation_credential));
        CHECK_NEW_MEMORY(
            ctx,
            *value,
            sizeof(struct attestation_credential),
            "AttestationCredential structure");
        result = decode_attestation_credential(
            ctx,
            (struct attestation_credential*)*value);
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
decode_credential(struct kmip *ctx, struct credential *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_CREDENTIAL,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = decode_enum(
        ctx,
        KMIP_TAG_CREDENTIAL_TYPE,
        &value->credential_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_CREDENTIAL_TYPE, value->credential_type);
    
    result = decode_credential_value(
        ctx,
        value->credential_type,
        &value->credential_value);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
decode_authentication(struct kmip *ctx, struct authentication *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_AUTHENTICATION,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->credential = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct credential));
    CHECK_NEW_MEMORY(
        ctx,
        value->credential,
        sizeof(struct credential),
        "Credential structure");
    
    result = decode_credential(ctx, value->credential);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

/*
int
decode_request_header(struct kmip *ctx, struct request_header *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_REQUEST_HEADER,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->protocol_version = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct protocol_version));
    CHECK_NEW_MEMORY(
        ctx,
        value->protocol_version,
        sizeof(struct protocol_version),
        "ProtocolVersion structure");
    
    result = decode_protocol_version(ctx, value->protocol_version);
    CHECK_RESULT(ctx, result);
    
    if(is_tag_next(ctx, KMIP_TAG_MAXIMUM_RESPONSE_SIZE))
    {
        result = decode_integer(
            ctx,
            KMIP_TAG_MAXIMUM_RESPONSE_SIZE,
            &value->maximum_response_size);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(is_tag_next(ctx, KMIP_TAG_CLIENT_CORRELATION_VALUE))
        {
            value->client_correlation_value = ctx->calloc_func(
                ctx->state,
                1,
                sizeof(struct text_string));
            CHECK_NEW_MEMORY(
                ctx,
                value->client_correlation_value,
                sizeof(struct text_string),
                "ClientCorrelationValue text string");
            
            result = decode_text_string(
                ctx,
                KMIP_TAG_CLIENT_CORRELATION_VALUE,
                value->client_correlation_value);
            CHECK_RESULT(ctx, result);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_SERVER_CORRELATION_VALUE))
        {
            value->server_correlation_value = ctx->calloc_func(
                ctx->state,
                1,
                sizeof(struct text_string));
            CHECK_NEW_MEMORY(
                ctx,
                value->server_correlation_value,
                sizeof(struct text_string),
                "ServerCorrelationValue text string");
            
            result = decode_text_string(
                ctx,
                KMIP_TAG_SERVER_CORRELATION_VALUE,
                value->server_correlation_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(is_tag_next(ctx, KMIP_TAG_ASYNCHRONOUS_INDICATOR))
    {
        result = decode_bool(
            ctx,
            KMIP_TAG_ASYNCHRONOUS_INDICATOR,
            &value->asynchronous_indicator);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_2)
    {
        if(is_tag_next(ctx, KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR))
        {
            result = decode_bool(
                ctx,
                KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR,
                &value->attestation_capable_indicator);
            CHECK_RESULT(ctx, result);
        }
        
        value->attestation_type_count = get_num_items_next(
            ctx, 
            KMIP_TAG_ATTESTATION_TYPE);
        if(value->attestation_type_count > 0)
        {
            value->attestation_types = ctx->calloc_func(
                ctx->state,
                value->attestation_type_count,
                sizeof(enum attestation_type));
            CHECK_NEW_MEMORY(
                ctx,
                value->attestation_types,
                value->attestation_type_count * sizeof(enum attestation_type),
                "sequence of AttestationType enumerations");
            
            for(size_t i = 0; i < value->attestation_type_count; i++)
            {
                result = decode_enum(
                    ctx,
                    KMIP_TAG_ATTESTATION_TYPE,
                    &value->attestation_types[i]);
                CHECK_RESULT(ctx, result);
                CHECK_ENUM(
                    ctx,
                    KMIP_TAG_ATTESTATION_TYPE,
                    value->attestation_types[i]);
            }
        }
    }
    
    if(is_tag_next(ctx, KMIP_TAG_AUTHENTICATION))
    {
        value->authentication = ctx->calloc_func(
            ctx->state,
            1,
            sizeof(struct authentication));
        CHECK_NEW_MEMORY(
            ctx,
            value->authentication,
            sizeof(struct authentication),
            "Authentication structure");
        
        result = decode_authentication(ctx, value->authentication);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION))
    {
        result = decode_enum(
            ctx,
            KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION,
            &value->batch_error_continuation_option);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(
            ctx,
            KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION,
            value->batch_error_continuation_option);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_BATCH_ORDER_OPTION))
    {
        result = decode_bool(
            ctx,
            KMIP_TAG_BATCH_ORDER_OPTION,
            &value->batch_order_option);
        CHECK_RESULT(ctx, result);
    }
    
    if(is_tag_next(ctx, KMIP_TAG_TIME_STAMP))
    {
        result = decode_date_time(
            ctx,
            KMIP_TAG_TIME_STAMP,
            &value->time_stamp);
        CHECK_RESULT(ctx, result);
    }
    
    result = decode_integer(ctx, KMIP_TAG_BATCH_COUNT, &value->batch_count);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}
*/

int
decode_response_header(struct kmip *ctx, struct response_header *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_RESPONSE_HEADER,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->protocol_version = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct protocol_version));
    CHECK_NEW_MEMORY(
        ctx,
        value->protocol_version,
        sizeof(struct protocol_version),
        "ProtocolVersion structure");
    
    result = decode_protocol_version(ctx, value->protocol_version);
    CHECK_RESULT(ctx, result);
    
    result = decode_date_time(ctx, KMIP_TAG_TIME_STAMP, &value->time_stamp);
    CHECK_RESULT(ctx, result);
    
    if(ctx->version >= KMIP_1_2)
    {
        if(is_tag_next(ctx, KMIP_TAG_NONCE))
        {
            value->nonce = ctx->calloc_func(
                ctx->state,
                1,
                sizeof(struct nonce));
            CHECK_NEW_MEMORY(
                ctx,
                value->nonce,
                sizeof(struct nonce),
                "Nonce structure");
            
            result = decode_nonce(ctx, value->nonce);
            CHECK_RESULT(ctx, result);
        }
        
        value->attestation_type_count = get_num_items_next(
            ctx, 
            KMIP_TAG_ATTESTATION_TYPE);
        if(value->attestation_type_count > 0)
        {
            value->attestation_types = ctx->calloc_func(
                ctx->state,
                value->attestation_type_count,
                sizeof(enum attestation_type));
            CHECK_NEW_MEMORY(
                ctx,
                value->attestation_types,
                value->attestation_type_count * sizeof(enum attestation_type),
                "sequence of AttestationType enumerations");
            
            for(size_t i = 0; i < value->attestation_type_count; i++)
            {
                result = decode_enum(
                    ctx,
                    KMIP_TAG_ATTESTATION_TYPE,
                    &value->attestation_types[i]);
                CHECK_RESULT(ctx, result);
                CHECK_ENUM(
                    ctx,
                    KMIP_TAG_ATTESTATION_TYPE,
                    value->attestation_types[i]);
            }
        }
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(is_tag_next(ctx, KMIP_TAG_CLIENT_CORRELATION_VALUE))
        {
            value->client_correlation_value = ctx->calloc_func(
                ctx->state,
                1,
                sizeof(struct text_string));
            CHECK_NEW_MEMORY(
                ctx,
                value->client_correlation_value,
                sizeof(struct text_string),
                "ClientCorrelationValue text string");
            
            result = decode_text_string(
                ctx,
                KMIP_TAG_CLIENT_CORRELATION_VALUE,
                value->client_correlation_value);
            CHECK_RESULT(ctx, result);
        }
        
        if(is_tag_next(ctx, KMIP_TAG_SERVER_CORRELATION_VALUE))
        {
            value->server_correlation_value = ctx->calloc_func(
                ctx->state,
                1,
                sizeof(struct text_string));
            CHECK_NEW_MEMORY(
                ctx,
                value->server_correlation_value,
                sizeof(struct text_string),
                "ServerCorrelationValue text string");
            
            result = decode_text_string(
                ctx,
                KMIP_TAG_SERVER_CORRELATION_VALUE,
                value->server_correlation_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    result = decode_integer(ctx, KMIP_TAG_BATCH_COUNT, &value->batch_count);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
decode_response_message(struct kmip *ctx, struct response_message *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(
        ctx,
        tag_type,
        KMIP_TAG_RESPONSE_MESSAGE,
        KMIP_TYPE_STRUCTURE);
    
    decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->response_header = ctx->calloc_func(
        ctx->state,
        1,
        sizeof(struct response_header));
    CHECK_NEW_MEMORY(
        ctx,
        value->response_header,
        sizeof(struct response_header),
        "ResponseHeader structure");
    
    result = decode_response_header(ctx, value->response_header);
    CHECK_RESULT(ctx, result);
    
    value->batch_count = get_num_items_next(ctx, KMIP_TAG_BATCH_ITEM);
    if(value->batch_count > 0)
    {
        value->batch_items = ctx->calloc_func(
            ctx->state,
            value->batch_count,
            sizeof(struct response_batch_item));
        CHECK_NEW_MEMORY(
            ctx,
            value->batch_items,
            value->batch_count * sizeof(struct response_batch_item),
            "sequence of ResponseBatchItem structures");
        
        for(size_t i = 0; i < value->batch_count; i++)
        {
            result = decode_response_batch_item(
                ctx,
                &value->batch_items[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    return(KMIP_OK);
}

#endif /* KMIP_H */
