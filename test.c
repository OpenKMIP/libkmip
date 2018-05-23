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

void
print_error_frames(struct kmip *ctx, const char *prefix)
{
    for(size_t i = 0; i < 20; i++)
    {
        struct error_frame *frame = &ctx->errors[i];
        if(frame->line != 0)
        {
            printf("%s%s(%d)\n", prefix, frame->function, frame->line);
        }
        else
        {
            break;
        }
    }
}

int
report_test_result(struct kmip *ctx, const uint8 *expected, const uint8 *observed,
                   int result, const char *function)
{
    if(result == KMIP_OK)
    {
        for(size_t i = 0; i < ctx->size; i++)
        {
            /* printf("%zu: %o - %o\n", i, expected[i], observed[i]); */
            if(expected[i] != observed[i])
            {
                printf("FAIL - %s\n", function);
                printf("- byte mismatch at: %zu (exp: %o, obs: %o)\n",
                       i, expected[i], observed[i]);
                return(1);
            }
        }
        
        printf("PASS - %s\n", function);
        return(0);
    }
    else
    {
        printf("FAIL - %s\n", function);
        if(result == KMIP_ERROR_BUFFER_FULL)
            printf("- context buffer is full\n");
        print_error_frames(ctx, "- ");
        return(1);
    }
}

int
test_encode_integer(void)
{
    uint8 expected[16] = {
        0x42, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[16] = {0};
    struct kmip ctx = {0};
    ctx.buffer = observed;
    ctx.index = observed;
    ctx.size = ARRAY_LENGTH(observed);
    
    int result = encode_integer(&ctx, KMIP_TAG_DEFAULT, 8);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_long(void)
{
    uint8 expected[16] = {
        0x42, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08,
        0x01, 0xB6, 0x9B, 0x4B, 0xA5, 0x74, 0x92, 0x00
    };
    
    uint8 observed[16] = {0};
    struct kmip ctx = {0};
    ctx.buffer = observed;
    ctx.index = observed;
    ctx.size = ARRAY_LENGTH(observed);
    
    int result = encode_long(&ctx, KMIP_TAG_DEFAULT, 123456789000000000);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_text_string(void)
{
    uint8 expected[24] = {
        0x42, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x0B,
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F,
        0x72, 0x6C, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[24] = {0};
    struct kmip ctx = {0};
    ctx.buffer = observed;
    ctx.index = observed;
    ctx.size = ARRAY_LENGTH(observed);
    
    int result = encode_text_string(&ctx, KMIP_TAG_DEFAULT, "Hello World", 11);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_byte_string(void)
{
    uint8 expected[16] = {
        0x42, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03,
        0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[16] = {0};
    struct kmip ctx = {0};
    ctx.buffer = observed;
    ctx.index = observed;
    ctx.size = ARRAY_LENGTH(observed);
    int8 str[3] = {0x01, 0x02, 0x03};
    
    int result = encode_byte_string(&ctx, KMIP_TAG_DEFAULT, str, 3);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_date_time(void)
{
    uint8 expected[16] = {
        0x42, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x47, 0xDA, 0x67, 0xF8
    };
    
    uint8 observed[16] = {0};
    struct kmip ctx = {0};
    ctx.buffer = observed;
    ctx.index = observed;
    ctx.size = ARRAY_LENGTH(observed);
    
    int result = encode_date_time(&ctx, KMIP_TAG_DEFAULT, 1205495800);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_interval(void)
{
    uint8 expected[16] = {
        0x42, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x0D, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[16] = {0};
    struct kmip ctx = {0};
    ctx.buffer = observed;
    ctx.index = observed;
    ctx.size = ARRAY_LENGTH(observed);
    
    int result = encode_interval(&ctx, KMIP_TAG_DEFAULT, 864000);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_protocol_version(void)
{
    uint8 expected[40] = {
        0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20,
        0x42, 0x00, 0x6A, 0x02, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x6B, 0x02, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[40] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    struct protocol_version pv = {0};
    pv.major = 1;
    pv.minor = 0;
    
    int result = encode_protocol_version(&ctx, &pv);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_buffer_full_and_resize(void)
{
    uint8 expected[40] = {
        0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20,
        0x42, 0x00, 0x6A, 0x02, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x6B, 0x02, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 too_small[30] = {0};
    uint8 large_enough[40] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, too_small, ARRAY_LENGTH(too_small), KMIP_1_0);
    
    struct protocol_version pv = {0};
    pv.major = 1;
    pv.minor = 0;
    
    int result = encode_protocol_version(&ctx, &pv);
    
    if(result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(&ctx);
        kmip_set_buffer(&ctx, large_enough, ARRAY_LENGTH(large_enough));
        
        result = encode_protocol_version(&ctx, &pv);
        return(report_test_result(&ctx, expected, large_enough, result, 
                                  __func__));
    }
    else
    {
        printf("FAIL - %s\n", __func__);
        printf("- expected buffer full");
        return(1);
    }
}

int
main(void)
{
    int num_tests = 8;
    int num_failures = 0;
    
    printf("Tests\n");
    printf("=====\n");
    
    num_failures += test_buffer_full_and_resize();
    num_failures += test_encode_integer();
    num_failures += test_encode_long();
    num_failures += test_encode_text_string();
    num_failures += test_encode_byte_string();
    num_failures += test_encode_date_time();
    num_failures += test_encode_interval();
    num_failures += test_encode_protocol_version();
    
    printf("\nSummary\n");
    printf("==============\n");
    printf("Total tests: %d\n", num_tests);
    printf("       PASS: %d\n", num_tests - num_failures);
    printf("    FAILURE: %d\n", num_failures);
}
