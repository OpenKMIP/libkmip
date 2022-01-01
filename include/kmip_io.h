/* Copyright (c) 2021 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIP_IO_H
#define KMIP_IO_H

#include <stdio.h>

#include "kmip.h"

/*
Printing Functions
*/

void kmip_print_buffer(FILE *, void *, int);
void kmip_print_stack_trace(FILE *, KMIP *);
void kmip_print_error_string(FILE *, int);
void kmip_print_batch_error_continuation_option(FILE *, enum batch_error_continuation_option);
void kmip_print_operation_enum(FILE *, enum operation);
void kmip_print_result_status_enum(FILE *, enum result_status);
void kmip_print_result_reason_enum(FILE *, enum result_reason);
void kmip_print_object_type_enum(FILE *, enum object_type);
void kmip_print_key_format_type_enum(FILE *, enum key_format_type);
void kmip_print_key_compression_type_enum(FILE *, enum key_compression_type);
void kmip_print_cryptographic_algorithm_enum(FILE *, enum cryptographic_algorithm);
void kmip_print_name_type_enum(FILE *, enum name_type);
void kmip_print_attribute_type_enum(FILE *, enum attribute_type);
void kmip_print_state_enum(FILE *, enum state);
void kmip_print_block_cipher_mode_enum(FILE *, enum block_cipher_mode);
void kmip_print_padding_method_enum(FILE *, enum padding_method);
void kmip_print_hashing_algorithm_enum(FILE *, enum hashing_algorithm);
void kmip_print_key_role_type_enum(FILE *, enum key_role_type);
void kmip_print_digital_signature_algorithm_enum(FILE *, enum digital_signature_algorithm);
void kmip_print_mask_generator_enum(FILE *, enum mask_generator);
void kmip_print_wrapping_method_enum(FILE *, enum wrapping_method);
void kmip_print_encoding_option_enum(FILE *, enum encoding_option);
void kmip_print_key_wrap_type_enum(FILE *, enum key_wrap_type);
void kmip_print_credential_type_enum(FILE *, enum credential_type);
void kmip_print_cryptographic_usage_mask_enums(FILE *, int, int32);
void kmip_print_integer(FILE *, int32);
void kmip_print_bool(FILE *, int32);
void kmip_print_text_string(FILE *, int, const char *, TextString *);
void kmip_print_byte_string(FILE *, int, const char *, ByteString *);
void kmip_print_date_time(FILE *, int64);
void kmip_print_protocol_version(FILE *, int, ProtocolVersion *);
void kmip_print_name(FILE *, int, Name *);
void kmip_print_nonce(FILE *, int, Nonce *);
void kmip_print_protection_storage_masks_enum(FILE *, int, int32);
void kmip_print_protection_storage_masks(FILE *, int, ProtectionStorageMasks *);
void kmip_print_application_specific_information(FILE *, int, ApplicationSpecificInformation *);
void kmip_print_cryptographic_parameters(FILE *, int, CryptographicParameters *);
void kmip_print_encryption_key_information(FILE *, int, EncryptionKeyInformation *);
void kmip_print_mac_signature_key_information(FILE *, int, MACSignatureKeyInformation *);
void kmip_print_key_wrapping_data(FILE *, int, KeyWrappingData *);
void kmip_print_attribute_value(FILE *, int, enum attribute_type, void *);
void kmip_print_attribute(FILE *, int, Attribute *);
void kmip_print_attributes(FILE *, int, Attributes *);
void kmip_print_key_material(FILE *, int, enum key_format_type, void *);
void kmip_print_key_value(FILE *, int, enum type, enum key_format_type, void *);
void kmip_print_key_block(FILE *, int, KeyBlock *);
void kmip_print_symmetric_key(FILE *, int, SymmetricKey *);
void kmip_print_object(FILE *, int, enum object_type, void *);
void kmip_print_key_wrapping_specification(FILE *, int, KeyWrappingSpecification *);
void kmip_print_template_attribute(FILE *, int, TemplateAttribute *);
void kmip_print_create_request_payload(FILE *, int, CreateRequestPayload *);
void kmip_print_create_response_payload(FILE *, int, CreateResponsePayload *);
void kmip_print_get_request_payload(FILE *, int, GetRequestPayload *);
void kmip_print_get_response_payload(FILE *, int, GetResponsePayload *);
void kmip_print_destroy_request_payload(FILE *, int, DestroyRequestPayload *);
void kmip_print_destroy_response_payload(FILE *, int, DestroyResponsePayload *);
void kmip_print_request_payload(FILE *, int, enum operation, void *);
void kmip_print_response_payload(FILE *, int, enum operation, void *);
void kmip_print_username_password_credential(FILE *, int, UsernamePasswordCredential *);
void kmip_print_device_credential(FILE *, int, DeviceCredential *);
void kmip_print_attestation_credential(FILE *, int, AttestationCredential *);
void kmip_print_credential_value(FILE *, int, enum credential_type, void *);
void kmip_print_credential(FILE *, int, Credential *);
void kmip_print_authentication(FILE *, int, Authentication *);
void kmip_print_request_batch_item(FILE *, int, RequestBatchItem *);
void kmip_print_response_batch_item(FILE *, int, ResponseBatchItem *);
void kmip_print_request_header(FILE *, int, RequestHeader *);
void kmip_print_response_header(FILE *, int, ResponseHeader *);
void kmip_print_request_message(FILE *, RequestMessage *);
void kmip_print_response_message(FILE *, ResponseMessage *);
void kmip_print_query_function_enum(FILE*, int, enum query_function);
void kmip_print_query_functions(FILE*, int, Functions*);
void kmip_print_operations(FILE*, int, Operations *);
void kmip_print_object_types(FILE*, int, ObjectTypes*);
void kmip_print_query_request_payload(FILE*, int, QueryRequestPayload *);
void kmip_print_query_response_payload(FILE*, int, QueryResponsePayload *);
void kmip_print_server_information(FILE*, int, ServerInformation*);
void kmip_print_locate_request_payload(FILE*, int, LocateRequestPayload *);
void kmip_print_locate_response_payload(FILE*, int, LocateResponsePayload *);
void kmip_print_unique_identifiers(FILE*, int indent, UniqueIdentifiers* value);

#endif  /* KMIP_IO_H */
