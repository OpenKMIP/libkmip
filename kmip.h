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

#include "types.h"
#include "enums.h"
#include "structs.h"

/*
Macros
*/

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

/*
Miscellaneous Utilities
*/

size_t kmip_strnlen_s(const char *, size_t);

/*
Memory Handlers
*/

void *kmip_calloc(void *, size_t, size_t);
void *kmip_realloc(void *, void *, size_t);
void kmip_free(void *, void *);

/*
Enumeration Utilities
*/

int get_enum_string_index(enum tag);
int check_enum_value(enum kmip_version, enum tag, int);

/*
Context Utilities
*/

void kmip_clear_errors(struct kmip *);
void kmip_init(struct kmip *, uint8 *, size_t, enum kmip_version);
void kmip_init_error_message(struct kmip *);
void kmip_reset(struct kmip *);
void kmip_rewind(struct kmip *);
void kmip_set_buffer(struct kmip *, void *, size_t);
void kmip_destroy(struct kmip *);
void kmip_push_error_frame(struct kmip *, const char *, const int);
void set_enum_error_message(struct kmip *, enum tag, int, int);
void set_alloc_error_message(struct kmip *, size_t, const char *);
void set_error_message(struct kmip *, const char *);
int is_tag_next(const struct kmip *, enum tag);
int is_tag_type_next(const struct kmip *, enum tag, enum type);
int get_num_items_next(struct kmip *, enum tag);

/*
Initialization Functions
*/

void init_protocol_version(struct protocol_version *, enum kmip_version);
void init_attribute(struct attribute *);
void init_cryptographic_parameters(struct cryptographic_parameters *);
void init_key_block(struct key_block *);
void init_request_header(struct request_header *);
void init_response_header(struct response_header *);

/*
Printing Functions
*/

void print_buffer(void *, int);
void print_stack_trace(struct kmip *);
void print_error_string(int);
void print_batch_error_continuation_option(enum batch_error_continuation_option);
void print_operation_enum(enum operation);
void print_result_status_enum(enum result_status);
void print_result_reason_enum(enum result_reason);
void print_object_type_enum(enum object_type);
void print_key_format_type_enum(enum key_format_type);
void print_key_compression_type_enum(enum key_compression_type);
void print_cryptographic_algorithm_enum(enum cryptographic_algorithm);
void print_name_type_enum(enum name_type);
void print_attribute_type_enum(enum attribute_type);
void print_state_enum(enum state);
void print_block_cipher_mode_enum(enum block_cipher_mode);
void print_padding_method_enum(enum padding_method);
void print_hashing_algorithm_enum(enum hashing_algorithm);
void print_key_role_type_enum(enum key_role_type);
void print_digital_signature_algorithm_enum(enum digital_signature_algorithm);
void print_mask_generator_enum(enum mask_generator);
void print_wrapping_method_enum(enum wrapping_method);
void print_encoding_option_enum(enum encoding_option);
void print_key_wrap_type_enum(enum key_wrap_type);
void print_credential_type_enum(enum credential_type);
void print_cryptographic_usage_mask_enums(int, int32);
void print_integer(int32);
void print_bool(int32);
void print_text_string(int, const char *, struct text_string *);
void print_byte_string(int, const char *, struct byte_string *);
void print_protocol_version(int, struct protocol_version *);
void print_name(int, struct name *);
void print_nonce(int, struct nonce *);
void print_cryptographic_parameters(int, struct cryptographic_parameters *);
void print_encryption_key_information(int, struct encryption_key_information *);
void print_mac_signature_key_information(int, struct mac_signature_key_information *);
void print_key_wrapping_data(int, struct key_wrapping_data *);
void print_attribute_value(int, enum attribute_type, void *);
void print_attribute(int, struct attribute *);
void print_key_material(int, enum key_format_type, void *);
void print_key_value(int, enum type, enum key_format_type, void *);
void print_key_block(int, struct key_block *);
void print_symmetric_key(int, struct symmetric_key *);
void print_object(int, enum object_type, void *);
void print_key_wrapping_specification(int, struct key_wrapping_specification *);
void print_template_attribute(int, struct template_attribute *);
void print_create_request_payload(int, struct create_request_payload *);
void print_create_response_payload(int, struct create_response_payload *);
void print_get_request_payload(int, struct get_request_payload *);
void print_get_response_payload(int, struct get_response_payload *);
void print_destroy_request_payload(int, struct destroy_request_payload *);
void print_destroy_response_payload(int, struct destroy_response_payload *);
void print_request_payload(int, enum operation, void *);
void print_response_payload(int, enum operation, void *);
void print_username_password_credential(int, struct username_password_credential *);
void print_device_credential(int, struct device_credential *);
void print_attestation_credential(int, struct attestation_credential *);
void print_credential_value(int, enum credential_type, void *);
void print_credential(int, struct credential *);
void print_authentication(int, struct authentication *);
void print_request_batch_item(int, struct request_batch_item *);
void print_response_batch_item(int, struct response_batch_item *);
void print_request_header(int, struct request_header *);
void print_response_header(int, struct response_header *);
void print_request_message(struct request_message *);
void print_response_message(struct response_message *);

/*
Freeing Functions
*/

void free_buffer(struct kmip *, void *, size_t);
void free_text_string(struct kmip *, struct text_string *);
void free_byte_string(struct kmip *, struct byte_string *);
void free_name(struct kmip *, struct name *);
void free_attribute(struct kmip *, struct attribute *);
void free_template_attribute(struct kmip *, struct template_attribute *);
void free_transparent_symmetric_key(
struct kmip *,
struct transparent_symmetric_key *);
void free_key_material(struct kmip *, enum key_format_type, void **);
void free_key_value(struct kmip *, enum key_format_type, struct key_value *);
void free_cryptographic_parameters(
struct kmip *,
struct cryptographic_parameters *);
void free_encryption_key_information(
struct kmip *,
struct encryption_key_information *);
void free_mac_signature_key_information(
struct kmip *,
struct mac_signature_key_information *);
void free_key_wrapping_data(struct kmip *, struct key_wrapping_data *);
void free_key_block(struct kmip *, struct key_block *);
void free_symmetric_key(struct kmip *, struct symmetric_key *);
void free_public_key(struct kmip *, struct public_key *);
void free_private_key(struct kmip *, struct private_key *);
void free_key_wrapping_specification(
struct kmip *,
struct key_wrapping_specification *);
void free_create_request_payload(
struct kmip *,
struct create_request_payload *);
void free_create_response_payload(
struct kmip *,
struct create_response_payload *);
void free_get_request_payload(struct kmip *, struct get_request_payload *);
void free_get_response_payload(struct kmip *, struct get_response_payload *);
void free_destroy_request_payload(
struct kmip *,
struct destroy_request_payload *);
void free_destroy_response_payload(
struct kmip *,
struct destroy_response_payload *);
void free_request_batch_item(struct kmip *, struct request_batch_item *);
void free_response_batch_item(struct kmip *, struct response_batch_item *);
void free_nonce(struct kmip *, struct nonce *);
void free_username_password_credential(
struct kmip *,
struct username_password_credential *);
void free_device_credential(struct kmip *, struct device_credential *);
void free_attestation_credential(
struct kmip *,
struct attestation_credential *);
void free_credential_value(struct kmip *, enum credential_type, void **);
void free_credential(struct kmip *, struct credential *);
void free_authentication(struct kmip *, struct authentication *);
void free_request_header(struct kmip *, struct request_header *);
void free_response_header(struct kmip *, struct response_header *);
void free_request_message(struct kmip *, struct request_message *);
void free_response_message(struct kmip *, struct response_message *);

/*
Comparison Functions
*/

int compare_text_string(
const struct text_string *,
const struct text_string *);
int compare_byte_string(
const struct byte_string *, 
const struct byte_string *);
int compare_name(const struct name *, const struct name *);
int compare_attribute(const struct attribute *, const struct attribute *);
int compare_template_attribute(
const struct template_attribute *,
const struct template_attribute *);
int compare_protocol_version(
const struct protocol_version *,
const struct protocol_version *);
int compare_transparent_symmetric_key(
const struct transparent_symmetric_key *,
const struct transparent_symmetric_key *);
int compare_key_material(enum key_format_type, void **, void **);
int compare_key_value(
enum key_format_type,
const struct key_value *,
const struct key_value *);
int compare_cryptographic_parameters(
const struct cryptographic_parameters *,
const struct cryptographic_parameters *);
int compare_encryption_key_information(
const struct encryption_key_information *,
const struct encryption_key_information *);
int compare_mac_signature_key_information(const struct mac_signature_key_information *,
                                          const struct mac_signature_key_information *);
int compare_key_wrapping_data(
const struct key_wrapping_data *,
const struct key_wrapping_data *);
int compare_key_block(const struct key_block *, const struct key_block *);
int compare_symmetric_key(
const struct symmetric_key *, const struct symmetric_key *);
int compare_public_key(const struct public_key *, const struct public_key *);
int compare_private_key(
const struct private_key *,
const struct private_key *);
int compare_key_wrapping_specification(
const struct key_wrapping_specification *,
const struct key_wrapping_specification *);
int compare_create_request_payload(
const struct create_request_payload *,
const struct create_request_payload *);
int compare_create_response_payload(
const struct create_response_payload *,
const struct create_response_payload *);
int compare_get_request_payload(
const struct get_request_payload *,
const struct get_request_payload *);
int compare_get_response_payload(
const struct get_response_payload *,
const struct get_response_payload *);
int compare_destroy_request_payload(
const struct destroy_request_payload *,
const struct destroy_request_payload *);
int compare_destroy_response_payload(
const struct destroy_response_payload *,
const struct destroy_response_payload *);
int compare_request_batch_item(
const struct request_batch_item *,
const struct request_batch_item *);
int compare_response_batch_item(
const struct response_batch_item *,
const struct response_batch_item *);
int compare_nonce(const struct nonce *, const struct nonce *);
int compare_username_password_credential(
const struct username_password_credential *,
const struct username_password_credential *);
int compare_device_credential(
const struct device_credential *,
const struct device_credential *);
int compare_attestation_credential(
const struct attestation_credential *,
const struct attestation_credential *);
int compare_credential_value(enum credential_type, void **, void **);
int compare_credential(const struct credential *, const struct credential *);
int compare_authentication(
const struct authentication *,
const struct authentication *);
int compare_request_header(
const struct request_header *,
const struct request_header *);
int compare_response_header(
const struct response_header *,
const struct response_header *);
int compare_request_message(
const struct request_message *,
const struct request_message *);
int compare_response_message(
const struct response_message *,
const struct response_message *);

/*
Encoding Functions
*/

int encode_int8_be(struct kmip *, int8);
int encode_int32_be(struct kmip *, int32);
int encode_int64_be(struct kmip *, int64);
int encode_integer(struct kmip *, enum tag, int32);
int encode_long(struct kmip *, enum tag, int64);
int encode_enum(struct kmip *, enum tag, int32);
int encode_bool(struct kmip *, enum tag, bool32);
int encode_text_string(struct kmip *, enum tag, const struct text_string *);
int encode_byte_string(struct kmip *, enum tag, const struct byte_string *);
int encode_date_time(struct kmip *, enum tag, uint64);
int encode_interval(struct kmip *, enum tag, uint32);
int encode_name(struct kmip *, const struct name *);
int encode_attribute_name(struct kmip *, enum attribute_type);
int encode_attribute(struct kmip *, const struct attribute *);
int encode_template_attribute(
struct kmip *,
const struct template_attribute *);
int encode_protocol_version(struct kmip *, const struct protocol_version *);
int encode_cryptographic_parameters(
struct kmip *, 
const struct cryptographic_parameters *);
int encode_encryption_key_information(
struct kmip *, 
const struct encryption_key_information *);
int encode_mac_signature_key_information(
struct kmip *, 
const struct mac_signature_key_information *);
int encode_key_wrapping_data(
struct kmip *, 
const struct key_wrapping_data *);
int encode_transparent_symmetric_key(
struct kmip *,
const struct transparent_symmetric_key *);
int encode_key_material(struct kmip *, enum key_format_type, const void *);
int encode_key_value(
struct kmip *,
enum key_format_type,
const struct key_value *);
int encode_key_block(struct kmip *, const struct key_block *);
int encode_symmetric_key(struct kmip *, const struct symmetric_key *);
int encode_public_key(struct kmip *, const struct public_key *);
int encode_private_key(struct kmip *, const struct private_key *);
int encode_key_wrapping_specification(
struct kmip *,
const struct key_wrapping_specification *);
int encode_create_request_payload(
struct kmip *, 
const struct create_request_payload *);
int encode_create_response_payload(
struct kmip *, 
const struct create_response_payload *);
int encode_get_request_payload(
struct kmip *,
const struct get_request_payload *);
int encode_get_response_payload(
struct kmip *,
const struct get_response_payload *);
int encode_destroy_request_payload(
struct kmip *, 
const struct destroy_request_payload *);
int encode_destroy_response_payload(
struct kmip *, 
const struct destroy_response_payload *);
int encode_nonce(struct kmip *, const struct nonce *);
int encode_username_password_credential(
struct kmip *, 
const struct username_password_credential *);
int encode_device_credential(
struct kmip *,
const struct device_credential *);
int encode_attestation_credential(
struct kmip *,
const struct attestation_credential *);
int encode_credential_value(struct kmip *, enum credential_type, void *);
int encode_credential(struct kmip *, const struct credential *);
int encode_authentication(struct kmip *, const struct authentication *);
int encode_request_header(struct kmip *, const struct request_header *);
int encode_response_header(struct kmip *, const struct response_header *);
int encode_request_batch_item(
struct kmip *,
const struct request_batch_item *);
int encode_response_batch_item(
struct kmip *,
const struct response_batch_item *);
int encode_request_message(struct kmip *, const struct request_message *);
int encode_response_message(struct kmip *, const struct response_message *);

/*
Decoding Functions
*/

int decode_int8_be(struct kmip *, void *);
int decode_int32_be(struct kmip *, void *);
int decode_int64_be(struct kmip *, void *);
int decode_integer(struct kmip *, enum tag, int32 *);
int decode_long(struct kmip *, enum tag, int64 *);
int decode_enum(struct kmip *, enum tag, void *);
int decode_bool(struct kmip *, enum tag, bool32 *);
int decode_text_string(struct kmip *, enum tag, struct text_string *);
int decode_byte_string(struct kmip *, enum tag, struct byte_string *);
int decode_date_time(struct kmip *, enum tag, uint64 *);
int decode_interval(struct kmip *, enum tag, uint32 *);
int decode_name(struct kmip *, struct name *);
int decode_attribute_name(struct kmip *, enum attribute_type *);
int decode_attribute(struct kmip *, struct attribute *);
int decode_template_attribute(struct kmip *, struct template_attribute *);
int decode_protocol_version(struct kmip *, struct protocol_version *);
int decode_transparent_symmetric_key(
struct kmip *,
struct transparent_symmetric_key *);
int decode_key_material(struct kmip *, enum key_format_type, void **);
int decode_key_value(struct kmip *, enum key_format_type, struct key_value *);
int decode_cryptographic_parameters(
struct kmip *, 
struct cryptographic_parameters *);
int decode_encryption_key_information(
struct kmip *, 
struct encryption_key_information *);
int decode_mac_signature_key_information(
struct kmip *, 
struct mac_signature_key_information *);
int decode_key_wrapping_data(struct kmip *, struct key_wrapping_data *);
int decode_key_block(struct kmip *, struct key_block *);
int decode_symmetric_key(struct kmip *, struct symmetric_key *);
int decode_public_key(struct kmip *, struct public_key *);
int decode_private_key(struct kmip *, struct private_key *);
int decode_key_wrapping_specification(
struct kmip *,
struct key_wrapping_specification *);
int decode_create_request_payload(
struct kmip *, 
struct create_request_payload *);
int decode_create_response_payload(
struct kmip *, 
struct create_response_payload *);
int decode_get_request_payload(struct kmip *, struct get_request_payload *);
int decode_get_response_payload(struct kmip *, struct get_response_payload *);
int decode_destroy_request_payload(
struct kmip *,
struct destroy_request_payload *);
int decode_destroy_response_payload(
struct kmip *, 
struct destroy_response_payload *);
int decode_request_batch_item(struct kmip *, struct request_batch_item *);
int decode_response_batch_item(struct kmip *, struct response_batch_item *);
int decode_nonce(struct kmip *, struct nonce *);
int decode_username_password_credential(
struct kmip *,
struct username_password_credential *);
int decode_device_credential(struct kmip *, struct device_credential *);
int decode_attestation_credential(
struct kmip *,
struct attestation_credential *);
int decode_credential_value(struct kmip *, enum credential_type, void **);
int decode_credential(struct kmip *, struct credential *);
int decode_authentication(struct kmip *, struct authentication *);
int decode_request_header(struct kmip *, struct request_header *);
int decode_response_header(struct kmip *, struct response_header *);
int decode_request_message(struct kmip *, struct request_message *);
int decode_response_message(struct kmip *, struct response_message *);

#endif  /* KMIP_H */
