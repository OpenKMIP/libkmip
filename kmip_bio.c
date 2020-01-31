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
    
    enum result_status result = KMIP_STATUS_OPERATION_FAILED;
    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    result = resp_item.result_status;

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
    
    enum result_status result = KMIP_STATUS_OPERATION_FAILED;
    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    result = resp_item.result_status;
    
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
    
    enum result_status result = KMIP_STATUS_OPERATION_FAILED;
    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    result = resp_item.result_status;
    
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
    
    enum result_status result = KMIP_STATUS_OPERATION_FAILED;
    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    result = resp_item.result_status;

    if(result != KMIP_STATUS_SUCCESS)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        kmip_destroy(ctx);
        return(result);
    }
    
    CreateResponsePayload *pld = (CreateResponsePayload *)resp_item.response_payload;
    TextString *unique_identifier = pld->unique_identifier;
    
    char *result_id = ctx->calloc_func(ctx->state, 1, unique_identifier->size);
    *id_size = unique_identifier->size;
    for(int i = 0; i < *id_size; i++)
    {
        result_id[i] = unique_identifier->value[i];
    }
    *id = result_id;
    
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
    
    enum result_status result = KMIP_STATUS_OPERATION_FAILED;
    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    result = resp_item.result_status;
    
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
    
    enum result_status result = KMIP_STATUS_OPERATION_FAILED;
    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    result = resp_item.result_status;
    
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
