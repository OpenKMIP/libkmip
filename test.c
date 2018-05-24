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
            if(expected[i] != observed[i])
            {
                printf("FAIL - %s\n", function);
                printf("- byte mismatch at: %zu (exp: %o, obs: %o)\n",
                       i, expected[i], observed[i]);
                for(size_t j = 0; j < ctx->size; j++)
                {
                    printf("- %zu: %o - %o\n", j, expected[j], observed[j]);
                }
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
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
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
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
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
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
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
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
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
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
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
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    int result = encode_interval(&ctx, KMIP_TAG_DEFAULT, 864000);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_name(void)
{
    uint8 expected[48] = {
        0x42, 0x00, 0x53, 0x01, 0x00, 0x00, 0x00, 0x28,
        0x42, 0x00, 0x55, 0x07, 0x00, 0x00, 0x00, 0x09,
        0x54, 0x65, 0x6D, 0x70, 0x6C, 0x61, 0x74, 0x65,
        0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x54, 0x05, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[48] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    char *value = "Template1";
    struct name n = {0};
    n.value = value;
    n.size = 9;
    n.type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
    
    int result = encode_name(&ctx, &n);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_attribute_unique_identifier(void)
{
    uint8 expected[88] = {
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x50,
        0x42, 0x00, 0x0A, 0x07, 0x00, 0x00, 0x00, 0x11,
        0x55, 0x6E, 0x69, 0x71, 0x75, 0x65, 0x20, 0x49,
        0x64, 0x65, 0x6E, 0x74, 0x69, 0x66, 0x69, 0x65,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x0B, 0x07, 0x00, 0x00, 0x00, 0x24,
        0x34, 0x39, 0x61, 0x31, 0x63, 0x61, 0x38, 0x38,
        0x2D, 0x36, 0x62, 0x65, 0x61, 0x2D, 0x34, 0x66,
        0x62, 0x32, 0x2D, 0x62, 0x34, 0x35, 0x30, 0x2D,
        0x37, 0x65, 0x35, 0x38, 0x38, 0x30, 0x32, 0x63,
        0x33, 0x30, 0x33, 0x38, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[88] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    struct text_string uuid = {0};
    uuid.value = "49a1ca88-6bea-4fb2-b450-7e58802c3038";
    uuid.size = 36;
    struct attribute attr = {0};
    attr.type = KMIP_ATTR_UNIQUE_IDENTIFIER;
    attr.index = KMIP_UNSET;
    attr.value = &uuid;
    
    int result = encode_attribute(&ctx, &attr);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_attribute_name(void)
{
    uint8 expected[72] = {
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x40,
        0x42, 0x00, 0x0A, 0x07, 0x00, 0x00, 0x00, 0x04,
        0x4E, 0x61, 0x6D, 0x65, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x0B, 0x01, 0x00, 0x00, 0x00, 0x28,
        0x42, 0x00, 0x55, 0x07, 0x00, 0x00, 0x00, 0x09,
        0x54, 0x65, 0x6D, 0x70, 0x6C, 0x61, 0x74, 0x65,
        0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x54, 0x05, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[72] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    char *value = "Template1";
    struct name n = {0};
    n.value = value;
    n.size = 9;
    n.type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
    
    struct attribute attr = {0};
    attr.type = KMIP_ATTR_NAME;
    attr.index = KMIP_UNSET;
    attr.value = &n;
    
    int result = encode_attribute(&ctx, &attr);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_attribute_object_type(void)
{
    uint8 expected[48] = {
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x28,
        0x42, 0x00, 0x0A, 0x07, 0x00, 0x00, 0x00, 0x0B,
        0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x20, 0x54,
        0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x0B, 0x05, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[48] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    enum object_type t = KMIP_OBJTYPE_SYMMETRIC_KEY;
    struct attribute attr = {0};
    attr.type = KMIP_ATTR_OBJECT_TYPE;
    attr.index = KMIP_UNSET;
    attr.value = &t;
    
    int result = encode_attribute(&ctx, &attr);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_attribute_cryptographic_algorithm(void)
{
    uint8 expected[56] = {
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30,
        0x42, 0x00, 0x0A, 0x07, 0x00, 0x00, 0x00, 0x17,
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x67, 0x72,
        0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x41, 0x6C,
        0x67, 0x6F, 0x72, 0x69, 0x74, 0x68, 0x6D, 0x00,
        0x42, 0x00, 0x0B, 0x05, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[56] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    enum cryptographic_algorithm a = KMIP_CRYPTOALG_AES;
    struct attribute attr = {0};
    attr.type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    attr.index = KMIP_UNSET;
    attr.value = &a;
    
    int result = encode_attribute(&ctx, &attr);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_attribute_cryptographic_length(void)
{
    uint8 expected[56] = {
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30,
        0x42, 0x00, 0x0A, 0x07, 0x00, 0x00, 0x00, 0x14,
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x67, 0x72,
        0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x4C, 0x65,
        0x6E, 0x67, 0x74, 0x68, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x0B, 0x02, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[56] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    int32 length = 128;
    struct attribute attr = {0};
    attr.type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    attr.index = KMIP_UNSET;
    attr.value = &length;
    
    int result = encode_attribute(&ctx, &attr);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_attribute_operation_policy_name(void)
{
    uint8 expected[56] = {
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30,
        0x42, 0x00, 0x0A, 0x07, 0x00, 0x00, 0x00, 0x15,
        0x4F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
        0x6E, 0x20, 0x50, 0x6F, 0x6C, 0x69, 0x63, 0x79,
        0x20, 0x4E, 0x61, 0x6D, 0x65, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x0B, 0x07, 0x00, 0x00, 0x00, 0x07,
        0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x00
    };
    
    uint8 observed[56] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    struct text_string policy = {0};
    policy.value = "default";
    policy.size = 7;
    struct attribute attr = {0};
    attr.type = KMIP_ATTR_OPERATION_POLICY_NAME;
    attr.index = KMIP_UNSET;
    attr.value = &policy;
    
    int result = encode_attribute(&ctx, &attr);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_attribute_cryptographic_usage_mask(void)
{
    uint8 expected[56] = {
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30,
        0x42, 0x00, 0x0A, 0x07, 0x00, 0x00, 0x00, 0x18,
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x67, 0x72,
        0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x55, 0x73,
        0x61, 0x67, 0x65, 0x20, 0x4D, 0x61, 0x73, 0x6B,
        0x42, 0x00, 0x0B, 0x02, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[56] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
    struct attribute attr = {0};
    attr.type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
    attr.index = KMIP_UNSET;
    attr.value = &mask;
    
    int result = encode_attribute(&ctx, &attr);
    return(report_test_result(&ctx, expected, observed, result, __func__));
}

int
test_encode_attribute_state(void)
{
    uint8 expected[40] = {
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x20,
        0x42, 0x00, 0x0A, 0x07, 0x00, 0x00, 0x00, 0x05, 
        0x53, 0x74, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x0B, 0x05, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8 observed[40] = {0};
    struct kmip ctx = {0};
    kmip_init(&ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    enum state s = KMIP_STATE_PRE_ACTIVE;
    struct attribute attr = {0};
    attr.type = KMIP_ATTR_STATE;
    attr.index = KMIP_UNSET;
    attr.value = &s;
    
    int result = encode_attribute(&ctx, &attr);
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
    int num_tests = 17;
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
    num_failures += test_encode_name();
    num_failures += test_encode_attribute_unique_identifier();
    num_failures += test_encode_attribute_name();
    num_failures += test_encode_attribute_object_type();
    num_failures += test_encode_attribute_cryptographic_algorithm();
    num_failures += test_encode_attribute_cryptographic_length();
    num_failures += test_encode_attribute_operation_policy_name();
    num_failures += test_encode_attribute_cryptographic_usage_mask();
    num_failures += test_encode_attribute_state();
    num_failures += test_encode_protocol_version();
    
    printf("\nSummary\n");
    printf("==============\n");
    printf("Total tests: %d\n", num_tests);
    printf("       PASS: %d\n", num_tests - num_failures);
    printf("    FAILURE: %d\n", num_failures);
}
