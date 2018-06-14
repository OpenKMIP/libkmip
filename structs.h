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

#ifndef STRUCTS_H
#define STRUCTS_H

#include <stdint.h>

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

#define KMIP_UNSET -1

#define KMIP_OK                      0
#define KMIP_NOT_IMPLEMENTED        -1
#define KMIP_ERROR_BUFFER_FULL      -2
#define KMIP_ERROR_ATTR_UNSUPPORTED -3

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

struct template_attribute
{
    struct name *name;
    struct attribute *attributes;
    size_t attribute_count;
};

struct attribute
{
    enum attribute_type type;
    int32 index;
    void *value;
};

struct name
{
    char *value;
    size_t size;
    enum name_type type;
};

struct text_string
{
    char *value;
    size_t size;
};

struct byte_string
{
    uint8 *value;
    size_t size;
};

struct protocol_version
{
    int32 major;
    int32 minor;
};

struct cryptographic_parameters
{
    /* KMIP 1.0 */
    enum block_cipher_mode block_cipher_mode;
    enum padding_method padding_method;
    enum hashing_algorithm hashing_algorithm;
    enum key_role_type key_role_type;
};

struct encryption_key_information
{
    struct text_string *unique_identifier;
    struct cryptographic_parameters *cryptographic_parameters;
};

struct mac_signature_key_information
{
    struct text_string *unique_identifier;
    struct cryptographic_parameters *cryptographic_parameters;
};

struct key_wrapping_data
{
    /* KMIP 1.0 */
    enum wrapping_method wrapping_method;
    struct encryption_key_information *encryption_key_info;
    struct mac_signature_key_information *mac_signature_key_info;
    struct byte_string *mac_signature;
    struct byte_string *iv_counter_nonce;
    /* KMIP 1.1 */
    enum encoding_option encoding_option;
};

struct transparent_symmetric_key
{
    struct byte_string *key;
};

struct key_value
{
    void *key_material;
    struct attribute *attributes;
    size_t attribute_count;
};

struct key_block
{
    enum key_format_type key_format_type;
    enum key_compression_type key_compression_type;
    void *key_value;
    enum cryptographic_algorithm cryptographic_algorithm;
    int32 cryptographic_length;
    struct key_wrapping_data *key_wrapping_data;
};

struct symmetric_key
{
    struct key_block *key_block;
};

struct public_key
{
    struct key_block *key_block;
};

struct private_key
{
    struct key_block *key_block;
};

#endif /* ENUMS_H */
