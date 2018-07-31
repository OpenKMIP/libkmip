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
#include "types.h"

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
    
    char *error_message;
    size_t error_message_size;
    struct error_frame errors[20];
    struct error_frame *frame_index;
    
    void *(*calloc_func)(void *state, size_t num, size_t size);
    void *(*realloc_func)(void *state, void *ptr, size_t size);
    void (*free_func)(void *state, void *ptr);
    void *state;
    
    void *(*memset_func)(void *ptr, int value, size_t size);
};

struct template_attribute
{
    struct name *names;
    size_t name_count;
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
    struct text_string *value;
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
    /* KMIP 1.2 */
    enum digital_signature_algorithm digital_signature_algorithm;
    enum cryptographic_algorithm cryptographic_algorithm;
    bool32 random_iv;
    int32 iv_length;
    int32 tag_length;
    int32 fixed_field_length;
    int32 invocation_field_length;
    int32 counter_length;
    int32 initial_counter_value;
    /* KMIP 1.4 */
    int32 salt_length;
    enum mask_generator mask_generator;
    enum hashing_algorithm mask_generator_hashing_algorithm;
    struct byte_string *p_source;
    int32 trailer_field;
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
    enum type key_value_type;
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

struct key_wrapping_specification
{
    /* KMIP 1.0 */
    enum wrapping_method wrapping_method;
    struct encryption_key_information *encryption_key_info;
    struct mac_signature_key_information *mac_signature_key_info;
    struct text_string *attribute_names;
    size_t attribute_name_count;
    /* KMIP 1.1 */
    enum encoding_option encoding_option;
};

struct nonce
{
    struct byte_string *nonce_id;
    struct byte_string *nonce_value;
};

/* Operation Payloads */

struct create_request_payload
{
    enum object_type object_type;
    struct template_attribute *template_attribute;
};

struct create_response_payload
{
    enum object_type object_type;
    struct text_string *unique_identifier;
    struct template_attribute *template_attribute;
};

struct get_request_payload
{
    /* KMIP 1.0 */
    struct text_string *unique_identifier;
    enum key_format_type key_format_type;
    enum key_compression_type key_compression_type;
    struct key_wrapping_specification *key_wrapping_spec;
    /* KMIP 1.4 */
    enum key_wrap_type key_wrap_type;
};

struct get_response_payload
{
    enum object_type object_type;
    struct text_string *unique_identifier;
    void *object;
};

struct destroy_request_payload
{
    struct text_string *unique_identifier;
};

struct destroy_response_payload
{
    struct text_string *unique_identifier;
};

/* Authentication Structures */

struct credential
{
    enum credential_type credential_type;
    void *credential_value;
};

struct username_password_credential
{
    struct text_string *username;
    struct text_string *password;
};

struct device_credential
{
    struct text_string *device_serial_number;
    struct text_string *password;
    struct text_string *device_identifier;
    struct text_string *network_identifier;
    struct text_string *machine_identifier;
    struct text_string *media_identifier;
};

struct attestation_credential
{
    struct nonce *nonce;
    enum attestation_type attestation_type;
    struct byte_string *attestation_measurement;
    struct byte_string *attestation_assertion;
};

struct authentication
{
    /* NOTE (ph) KMIP 1.2+ supports multiple credentials here. */
    /* NOTE (ph) Polymorphism makes this tricky. Omitting for now. */
    /* TODO (ph) Credential structs are constant size, so no problem here. */
    struct credential *credential;
};

/* Message Structures */

struct request_header
{
    /* KMIP 1.0 */
    struct protocol_version *protocol_version;
    int32 maximum_response_size;
    bool32 asynchronous_indicator;
    struct authentication *authentication;
    enum batch_error_continuation_option batch_error_continuation_option;
    bool32 batch_order_option;
    uint64 time_stamp;
    int32 batch_count;
    /* KMIP 1.2 */
    bool32 attestation_capable_indicator;
    enum attestation_type *attestation_types;
    size_t attestation_type_count;
    /* KMIP 1.4 */
    struct text_string *client_correlation_value;
    struct text_string *server_correlation_value;
};

struct response_header
{
    /* KMIP 1.0 */
    struct protocol_version *protocol_version;
    uint64 time_stamp;
    int32 batch_count;
    /* KMIP 1.2 */
    struct nonce *nonce;
    enum attestation_type *attestation_types;
    size_t attestation_type_count;
    /* KMIP 1.4 */
    struct text_string *client_correlation_value;
    struct text_string *server_correlation_value;
};

struct request_batch_item
{
    enum operation operation;
    struct byte_string *unique_batch_item_id;
    void *request_payload;
    /* NOTE (peter-hamilton) Omitting the message extension field for now. */
};

struct response_batch_item
{
    enum operation operation;
    struct byte_string *unique_batch_item_id;
    enum result_status result_status;
    enum result_reason result_reason;
    struct text_string *result_message;
    struct byte_string *asynchronous_correlation_value;
    void *response_payload;
    /* NOTE (peter-hamilton) Omitting the message extension field for now. */
};

struct request_message
{
    struct request_header *request_header;
    struct request_batch_item *batch_items;
    size_t batch_count;
};

struct response_message
{
    struct response_header *response_header;
    struct response_batch_item *batch_items;
    size_t batch_count;
};

#endif /* ENUMS_H */
