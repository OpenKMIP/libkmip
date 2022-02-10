/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <openssl/ssl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kmip.h"
#include "kmip_memset.h"
#include "kmip_bio.h"

/*
OpenSSH BIO API
*/

int kmip_bio_create_symmetric_key(BIO *bio,
                                  TemplateAttribute *template_attribute,
                                  char **id, int *id_size)
{
    if(bio == NULL || template_attribute == NULL || id == NULL || id_size == NULL)
        return(KMIP_ARG_INVALID);
    
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_0);
    
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                      buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx.version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx.max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    CreateRequestPayload crp = {0};
    crp.object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
    crp.template_attribute = template_attribute;
    
    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_CREATE;
    rbi.request_payload = &crp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(&ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(&ctx);
        ctx.free_func(ctx.state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                   buffer_block_size);
        if(encoding == NULL)
        {
            kmip_destroy(&ctx);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            &ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(&ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx.buffer, ctx.index - ctx.buffer);
    if(sent != ctx.index - ctx.buffer)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx.calloc_func(ctx.state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    ctx.index += 4;
    int length = 0;
    
    kmip_decode_int32_be(&ctx, &length);
    kmip_rewind(&ctx);
    if(length > ctx.max_message_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(&ctx, NULL, 0);
    uint8 *extended = ctx.realloc_func(ctx.state, encoding, buffer_total_size + length);
    if(encoding != extended)
        encoding = extended;
    ctx.memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(&ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(decode_result);
    }

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;

    if(result != KMIP_STATUS_SUCCESS)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(result);
    }
    
    CreateResponsePayload *pld = (CreateResponsePayload *)resp_item.response_payload;
    TextString *unique_identifier = pld->unique_identifier;
    
    /* KMIP text strings are not null-terminated by default. Add an extra */
    /* character to the end of the UUID copy to make space for the null   */
    /* terminator.                                                        */
    char *result_id = ctx.calloc_func(
        ctx.state,
        1,
        unique_identifier->size + 1);
    *id_size = unique_identifier->size;
    for(int i = 0; i < *id_size; i++)
        result_id[i] = unique_identifier->value[i];
    *id = result_id;
    
    /* Clean up the response message, the encoding buffer, and the KMIP */
    /* context. */
    kmip_free_response_message(&ctx, &resp_m);
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(&ctx, NULL, 0);
    kmip_destroy(&ctx);
    
    return(result);
}

int kmip_bio_destroy_symmetric_key(BIO *bio, char *uuid, int uuid_size)
{
    if(bio == NULL || uuid == NULL || uuid_size <= 0)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_0);
    
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                      buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx.version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx.max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    TextString id = {0};
    id.value = uuid;
    id.size = uuid_size;
    
    DestroyRequestPayload drp = {0};
    drp.unique_identifier = &id;
    
    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_DESTROY;
    rbi.request_payload = &drp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(&ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(&ctx);
        ctx.free_func(ctx.state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                   buffer_block_size);
        if(encoding == NULL)
        {
            kmip_destroy(&ctx);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            &ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(&ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx.buffer, ctx.index - ctx.buffer);
    if(sent != ctx.index - ctx.buffer)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx.calloc_func(ctx.state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    ctx.index += 4;
    int length = 0;
    
    kmip_decode_int32_be(&ctx, &length);
    kmip_rewind(&ctx);
    if(length > ctx.max_message_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(&ctx, NULL, 0);
    uint8 *extended = ctx.realloc_func(ctx.state, encoding, buffer_total_size + length);
    if(extended == NULL)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    else
    {
        encoding = extended;
        extended = NULL;
    }
    
    ctx.memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation result status. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(&ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(decode_result);
    }

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;
    
    /* Clean up the response message, the encoding buffer, and the KMIP */
    /* context. */
    kmip_free_response_message(&ctx, &resp_m);
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(&ctx, NULL, 0);
    kmip_destroy(&ctx);
    
    return(result);
}

int kmip_bio_get_symmetric_key(BIO *bio,
                               char *id, int id_size,
                               char **key, int *key_size)
{
    if(bio == NULL || id == NULL || id_size <= 0 || key == NULL || key_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_0);
    
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                      buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx.version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx.max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    TextString uuid = {0};
    uuid.value = id;
    uuid.size = id_size;
    
    GetRequestPayload grp = {0};
    grp.unique_identifier = &uuid;
    
    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_GET;
    rbi.request_payload = &grp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(&ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(&ctx);
        ctx.free_func(ctx.state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                   buffer_block_size);
        if(encoding == NULL)
        {
            kmip_destroy(&ctx);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            &ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(&ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx.buffer, ctx.index - ctx.buffer);
    if(sent != ctx.index - ctx.buffer)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx.calloc_func(ctx.state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    ctx.index += 4;
    int length = 0;
    
    kmip_decode_int32_be(&ctx, &length);
    kmip_rewind(&ctx);
    if(length > ctx.max_message_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(&ctx, NULL, 0);
    uint8 *extended = ctx.realloc_func(ctx.state, encoding, buffer_total_size + length);
    if(encoding != extended)
    {
        encoding = extended;
    }
    ctx.memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation result status. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(&ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(decode_result);
    }
    
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;
    
    if(result != KMIP_STATUS_SUCCESS)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(result);
    }
    
    GetResponsePayload *pld = (GetResponsePayload *)resp_item.response_payload;
    
    if(pld->object_type != KMIP_OBJTYPE_SYMMETRIC_KEY)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(KMIP_OBJECT_MISMATCH);
    }
    
    SymmetricKey *symmetric_key = (SymmetricKey *)pld->object;
    KeyBlock *block = symmetric_key->key_block;
    if((block->key_format_type != KMIP_KEYFORMAT_RAW) || 
       (block->key_wrapping_data != NULL))
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(KMIP_OBJECT_MISMATCH);
    }
    
    KeyValue *block_value = block->key_value;
    ByteString *material = (ByteString *)block_value->key_material;
    
    char *result_key = ctx.calloc_func(ctx.state, 1, material->size);
    *key_size = material->size;
    for(int i = 0; i < *key_size; i++)
    {
        result_key[i] = material->value[i];
    }
    *key = result_key;
    
    /* Clean up the response message, the encoding buffer, and the KMIP */
    /* context. */
    kmip_free_response_message(&ctx, &resp_m);
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(&ctx, NULL, 0);
    kmip_destroy(&ctx);
    
    return(result);
}

LastResult last_result = {0};

void kmip_clear_last_result(void)
{
    last_result.operation     = 0;
    last_result.result_status = KMIP_STATUS_SUCCESS;
    last_result.result_reason = 0;
    last_result.result_message[0] = 0;
}

int kmip_set_last_result(ResponseBatchItem* value)
{
    if (value)
    {
        last_result.operation = value->operation;
        last_result.result_status = value->result_status;
        last_result.result_reason = value->result_reason;
        if (value->result_message)
            kmip_copy_textstring(last_result.result_message, value->result_message, sizeof(last_result.result_message));
        else
            last_result.result_message[0] = 0;
    }
    return 0;
}

const LastResult* kmip_get_last_result(void)
{
    return &last_result;
}

int kmip_last_reason(void)
{
    return last_result.result_reason;
}

const char* kmip_last_message(void)
{
    return last_result.result_message;
}

int kmip_bio_create_symmetric_key_with_context(KMIP *ctx, BIO *bio,
                                               TemplateAttribute *template_attribute,
                                               char **id, int *id_size)
{
    if(ctx == NULL || bio == NULL || template_attribute == NULL || id == NULL || id_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
        return(KMIP_MEMORY_ALLOC_FAILED);
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    CreateRequestPayload crp = {0};
    crp.object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
    crp.template_attribute = template_attribute;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_CREATE;
    rbi.request_payload = &crp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Add the context credential to the request message if it exists. */
    /* TODO (ph) Update this to add multiple credentials. */
    Authentication auth = {0};
    if(ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if(item != NULL)
        {
            auth.credential = (Credential *)item->data;
            rh.authentication = &auth;
        }
    }
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
        if(encoding == NULL)
        {
            kmip_set_buffer(ctx, NULL, 0);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx->buffer, ctx->index - ctx->buffer);
    if(sent != ctx->index - ctx->buffer)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
        return(KMIP_MEMORY_ALLOC_FAILED);
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    ctx->index += 4;
    int length = 0;
    
    kmip_decode_int32_be(ctx, &length);
    kmip_rewind(ctx);
    if(length > ctx->max_message_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(ctx, NULL, 0);
    uint8 *extended = ctx->realloc_func(ctx->state, encoding, buffer_total_size + length);
    if(encoding != extended)
    {
        encoding = extended;
    }
    ctx->memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    
    kmip_set_buffer(ctx, NULL, 0);
    
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(decode_result);
    }

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;

    kmip_set_last_result(&resp_item);

    if(result != KMIP_STATUS_SUCCESS)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        kmip_destroy(ctx);
        return(result);
    }
    
    if (result == KMIP_STATUS_SUCCESS)
    {
        CreateResponsePayload *pld = (CreateResponsePayload *)resp_item.response_payload;
        if (pld)
        {
            TextString *unique_identifier = pld->unique_identifier;

            char *result_id = ctx->calloc_func(ctx->state, 1, unique_identifier->size);
            *id_size = unique_identifier->size;
            for(int i = 0; i < *id_size; i++)
            {
                result_id[i] = unique_identifier->value[i];
            }
            *id = result_id;
        }
    }
    
    /* Clean up the response message and the encoding buffer. */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);
    
    return(result);
}

int kmip_bio_get_symmetric_key_with_context(KMIP *ctx, BIO *bio,
                                            char *uuid, int uuid_size,
                                            char **key, int *key_size)
{
    if(ctx == NULL || bio == NULL || uuid == NULL || uuid_size <= 0 || key == NULL || key_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx->calloc_func(
        ctx->state,
        buffer_blocks,
        buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    TextString id = {0};
    id.value = uuid;
    id.size = uuid_size;
    
    GetRequestPayload grp = {0};
    grp.unique_identifier = &id;
    
    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_GET;
    rbi.request_payload = &grp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Add the context credential to the request message if it exists. */
    /* TODO (ph) Update this to add multiple credentials. */
    Authentication auth = {0};
    if(ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if(item != NULL)
        {
            auth.credential = (Credential *)item->data;
            rh.authentication = &auth;
        }
    }
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx->calloc_func(
            ctx->state,
            buffer_blocks,
            buffer_block_size);
        if(encoding == NULL)
        {
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx->buffer, ctx->index - ctx->buffer);
    if(sent != ctx->index - ctx->buffer)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    ctx->index += 4;
    int length = 0;
    
    kmip_decode_int32_be(ctx, &length);
    kmip_rewind(ctx);
    if(length > ctx->max_message_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(ctx, NULL, 0);
    uint8 *extended = ctx->realloc_func(
        ctx->state,
        encoding,
        buffer_total_size + length);
    if(encoding != extended)
    {
        encoding = extended;
    }
    ctx->memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation result status. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(decode_result);
    }
    
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;
    
    kmip_set_last_result(&resp_item);
    
    if(result != KMIP_STATUS_SUCCESS)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return(result);
    }
    
    GetResponsePayload *pld = (GetResponsePayload *)resp_item.response_payload;
    
    if(pld->object_type != KMIP_OBJTYPE_SYMMETRIC_KEY)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_OBJECT_MISMATCH);
    }
    
    SymmetricKey *symmetric_key = (SymmetricKey *)pld->object;
    KeyBlock *block = symmetric_key->key_block;
    if((block->key_format_type != KMIP_KEYFORMAT_RAW) || 
       (block->key_wrapping_data != NULL))
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_OBJECT_MISMATCH);
    }
    
    KeyValue *block_value = block->key_value;
    ByteString *material = (ByteString *)block_value->key_material;
    
    char *result_key = ctx->calloc_func(ctx->state, 1, material->size);
    *key_size = material->size;
    for(int i = 0; i < *key_size; i++)
    {
        result_key[i] = material->value[i];
    }
    *key = result_key;
    
    /* Clean up the response message, the encoding buffer, and the KMIP */
    /* context. */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);
    
    return(result);
}

int kmip_bio_destroy_symmetric_key_with_context(KMIP *ctx, BIO *bio,
                                                char *uuid, int uuid_size)
{
    if(ctx == NULL || bio == NULL || uuid == NULL || uuid_size <= 0)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks,
                                       buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    TextString id = {0};
    id.value = uuid;
    id.size = uuid_size;
    
    DestroyRequestPayload drp = {0};
    drp.unique_identifier = &id;
    
    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_DESTROY;
    rbi.request_payload = &drp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Add the context credential to the request message if it exists. */
    /* TODO (ph) Update this to add multiple credentials. */
    Authentication auth = {0};
    if(ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if(item != NULL)
        {
            auth.credential = (Credential *)item->data;
            rh.authentication = &auth;
        }
    }
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx->calloc_func(ctx->state, buffer_blocks,
                                    buffer_block_size);
        if(encoding == NULL)
        {
            kmip_set_buffer(ctx, NULL, 0);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx->buffer, ctx->index - ctx->buffer);
    if(sent != ctx->index - ctx->buffer)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    ctx->index += 4;
    int length = 0;
    
    kmip_decode_int32_be(ctx, &length);
    kmip_rewind(ctx);
    if(length > ctx->max_message_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(ctx, NULL, 0);
    uint8 *extended = ctx->realloc_func(ctx->state, encoding,
                                        buffer_total_size + length);
    if(encoding != extended)
    {
        encoding = extended;
    }
    ctx->memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation result status. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    
    kmip_set_buffer(ctx, NULL, 0);
    
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(decode_result);
    }

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;
    
    /* Clean up the response message and the encoding buffer. */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);
    
    return(result);
}

int kmip_bio_send_request_encoding(KMIP *ctx, BIO *bio,
                                   char *request, int request_size,
                                   char **response, int *response_size)
{
    if(ctx == NULL || bio == NULL || request == NULL || request_size <= 0 || response == NULL || response_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Send the request message. */
    int sent = BIO_write(bio, request, request_size);
    if(sent != request_size)
    {
        return(KMIP_IO_FAILURE);
    }
    
    /* Read the response message. Dynamically resize the receiving buffer */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 8;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks,
                                       buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    ctx->index += 4;
    int length = 0;
    
    kmip_decode_int32_be(ctx, &length);
    kmip_rewind(ctx);
    if(length > ctx->max_message_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(ctx, NULL, 0);
    uint8 *extended = ctx->realloc_func(ctx->state, encoding,
                                        buffer_total_size + length);
    if(encoding != extended)
    {
        encoding = extended;
    }
    ctx->memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    *response_size = buffer_total_size;
    *response = (char *)encoding;
    
    kmip_set_buffer(ctx, NULL, 0);
    
    return(KMIP_OK);
}

int kmip_bio_query_with_context(KMIP *ctx, BIO *bio, enum query_function queries[], size_t query_count, QueryResponse* query_result)
{
    if (ctx == NULL || bio == NULL || queries == NULL || query_count == 0 || query_result == NULL)
    {
        return(KMIP_ARG_INVALID);
    }

    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;

    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(ctx, encoding, buffer_total_size);

    /* Build the request message. */


    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);

    RequestHeader rh = {0};
    kmip_init_request_header(&rh);

    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;

    LinkedList *funclist = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    for(size_t i = 0; i < query_count; i++)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        item->data = &queries[i];
        kmip_linked_list_enqueue(funclist, item);
    }
    Functions functions = {0};
    functions.function_list = funclist;

    QueryRequestPayload qrp = {0};
    qrp.functions = &functions;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_QUERY;
    rbi.request_payload = &qrp;

    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;

    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);

        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;

        encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
        if(encoding == NULL)
        {
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        kmip_set_buffer(ctx, encoding, buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }

    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(encode_result);
    }

    char *response = NULL;
    int response_size = 0;

    int result = kmip_bio_send_request_encoding(ctx, bio, (char *)encoding, ctx->index - ctx->buffer, &response, &response_size);
    if(result < 0)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        kmip_free_buffer(ctx, response, response_size);
        encoding = NULL;
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(result);
    }

    if (response)
    {
        FILE* out = fopen( "/tmp/kmip_query.dat", "w" );
        if (out)
        {
            fwrite( response, response_size, 1, out );
            fclose(out);
        }
        // kmip_print_buffer(response, response_size);
    }

    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, response, response_size);

    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, response, response_size);
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(decode_result);
    }

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, response, response_size);
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MALFORMED_RESPONSE);
    }

    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result_status = resp_item.result_status;

    kmip_set_last_result(&resp_item);

    if(result == KMIP_STATUS_SUCCESS)
    {
        kmip_copy_query_result(query_result, (QueryResponsePayload*) resp_item.response_payload);
    }

    /* Clean up the response message, the response buffer, and the KMIP */
    /* context.                                                         */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, response, response_size);
    response = NULL;

    return(result_status);
}

