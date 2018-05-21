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

#include <stdio.h>

#include "kmip.h"

static int
encode_protocol_version(struct kmip *ctx, const struct protocol_version *pv)
{
    int result;
    result = encode_integer(ctx, KMIP_TAG_PROTOCOL_VERSION_MAJOR, pv->major);
    result = encode_integer(ctx, KMIP_TAG_PROTOCOL_VERSION_MINOR, pv->minor);
    return(result * 0); 
}
/*
int
encode_integer(enum tag t, int32 value)
{
    return(0);
}
*/
int
main2(void)
{
    struct kmip ctx = {0};
    char buffer[256] = {0};
    ctx.buffer = buffer;
    ctx.size = sizeof(buffer);
    ctx.version = KMIP_1_0;
    
    struct protocol_version pv = {0};
    pv.major = 1;
    pv.minor = 0;
    
    int result = encode_protocol_version(&ctx, &pv);
    
    return(result * 0);
}

struct context
{
    uint8 *buffer;
    uint8 *index;
    size_t size;
};

/*
int
encode_int32_be(uint8 *buffer, int32 value)
{
    *buffer++ = value >> 24;
    *buffer++ = (value << 8) >> 24;
    *buffer++ = (value << 16) >> 24;
    *buffer++ = (value << 24) >> 24;
    
    return(0);
}
*/
int
encode_int32_be(struct context *ctx, int32 value)
{
    *ctx->index++ = (value << 0) >> 24;
    *ctx->index++ = (value << 8) >> 24;
    *ctx->index++ = (value << 16) >> 24;
    *ctx->index++ = (value << 24) >> 24;
    
    return(0);
}
/*
int
encode_int(uint8 *buffer, enum tag t, int32 value)
{
    encode_int32_be(buffer, (t << 8) | (uint8)KMIP_TYPE_INTEGER);
    buffer += 4;
    encode_int32_be(buffer, 4);
    buffer += 4;
    encode_int32_be(buffer, value);
    buffer += 4;
    encode_int32_be(buffer, 0);
    buffer += 4;
    
    return(0);
}
*/
int
encode_int(struct context *ctx, enum tag t, int32 value)
{
    encode_int32_be(ctx, (t << 8) | (uint8)KMIP_TYPE_INTEGER);
    encode_int32_be(ctx, 4);
    encode_int32_be(ctx, value);
    encode_int32_be(ctx, 0);
    
    return(0);
}

int
encode_pv(struct context *ctx, const struct protocol_version *pv)
{
    encode_int32_be(
        ctx, (KMIP_TAG_PROTOCOL_VERSION << 8) | (uint8)KMIP_TYPE_STRUCTURE);
    
    uint8 *length_index = ctx->index;
    encode_int32_be(ctx, 0);
    uint8 *data_index = ctx->index;
    
    encode_int(ctx, KMIP_TAG_PROTOCOL_VERSION_MAJOR, pv->major);
    encode_int(ctx, KMIP_TAG_PROTOCOL_VERSION_MINOR, pv->minor);
    
    uint8 *curr_index = ctx->index;
    int32 size = curr_index - data_index;
    ctx->index = length_index;
    encode_int32_be(ctx, size);
    ctx->index = curr_index;
    
    return(0);
}

int
main(void)
{
    uint8 buffer[40] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    /*
    uint8 *b = buffer;
    uint8 *a = buffer;
    */
    int32 value = 0xDEADBEEF;
    
    struct context ctx = {0};
    ctx.buffer = buffer;
    ctx.index = ctx.buffer;
    ctx.size = sizeof(buffer) / sizeof(buffer[0]);
    
    struct protocol_version pv = {0};
    pv.major = 1;
    pv.minor = 2;
    
    /*
    int error = encode_int(&ctx, KMIP_TAG_PROTOCOL_VERSION, value);
    */
    
    int error = encode_pv(&ctx, &pv);
    
    if(error == 0)
    {
        printf("No errors occurred during encoding.\n");
    }
    else
    {
        printf("Errors occurred during encoding.\n");
    }
    /*
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    printf("%p -> 0x%X\n", (void*)a, *a++);
    
    b = buffer; 
    
    printf("%p -> b[0]  -> 0x%X\n", (void*)&b[0], b[0]);
    printf("%p -> b[1]  -> 0x%X\n", (void*)&b[1], b[1]);
    printf("%p -> b[2]  -> 0x%X\n", (void*)&b[2], b[2]);
    printf("%p -> b[3]  -> 0x%X\n", (void*)&b[3], b[3]);
    printf("%p -> b[4]  -> 0x%X\n", (void*)&b[4], b[4]);
    printf("%p -> b[5]  -> 0x%X\n", (void*)&b[5], b[5]);
    printf("%p -> b[6]  -> 0x%X\n", (void*)&b[6], b[6]);
    printf("%p -> b[7]  -> 0x%X\n", (void*)&b[7], b[7]);
    printf("%p -> b[8]  -> 0x%X\n", (void*)&b[8], b[8]);
    printf("%p -> b[9]  -> 0x%X\n", (void*)&b[9], b[9]);
    printf("%p -> b[10] -> 0x%X\n", (void*)&b[10], b[10]);
    printf("%p -> b[11] -> 0x%X\n", (void*)&b[11], b[11]);
    printf("%p -> b[12] -> 0x%X\n", (void*)&b[12], b[12]);
    printf("%p -> b[13] -> 0x%X\n", (void*)&b[13], b[13]);
    printf("%p -> b[14] -> 0x%X\n", (void*)&b[14], b[14]);
    printf("%p -> b[15] -> 0x%X\n", (void*)&b[15], b[15]);
    */
}