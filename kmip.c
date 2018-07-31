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

#include <openssl/ssl.h>
#include <stdio.h>

#include "kmip.h"

void
print_error_string(int value)
{
    switch(value)
    {
        case 0:
        printf("KMIP_OK");
        break;
        
        case -1:
        printf("KMIP_NOT_IMPLEMENTED");
        break;
        
        case -2:
        printf("KMIP_ERROR_BUFFER_FULL");
        break;
        
        case -3:
        printf("KMIP_ERROR_ATTR_UNSUPPORTED");
        break;
        
        case -4:
        printf("KMIP_TAG_MISMATCH");
        break;
        
        case -5:
        printf("KMIP_TYPE_MISMATCH");
        break;
        
        case -6:
        printf("KMIP_LENGTH_MISMATCH");
        break;
        
        case -7:
        printf("KMIP_PADDING_MISMATCH");
        break;
        
        case -8:
        printf("KMIP_BOOLEAN_MISMATCH");
        break;
        
        case -9:
        printf("KMIP_ENUM_MISMATCH");
        break;
        
        case -10:
        printf("KMIP_ENUM_UNSUPPORTED");
        break;
        
        case -11:
        printf("KMIP_INVALID_FOR_VERSION");
        break;
        
        case -12:
        printf("KMIP_MEMORY_ALLOC_FAILED");
        break;
        
        default:
        printf("Unknown");
        break;
    };
    
    return;
}

void
print_operation_enum(enum operation value)
{
    if(value == 0)
    {
        printf("-");
        return;
    }
    
    switch(value)
    {
        case KMIP_OP_CREATE:
        printf("Create");
        break;
        
        case KMIP_OP_GET:
        printf("Get");
        break;
        
        case KMIP_OP_DESTROY:
        printf("Destroy");
        break;
        
        default:
        printf("Unknown");
        break;
    };
}

void
print_result_status_enum(enum result_status value)
{
    switch(value)
    {
        case KMIP_STATUS_SUCCESS:
        printf("Success");
        break;
        
        case KMIP_STATUS_OPERATION_FAILED:
        printf("Operation Failed");
        break;
        
        case KMIP_STATUS_OPERATION_PENDING:
        printf("Operation Pending");
        break;
        
        case KMIP_STATUS_OPERATION_UNDONE:
        printf("Operation Undone");
        break;
        
        default:
        printf("Unknown");
        break;
    };
}

void
print_result_reason_enum(enum result_reason value)
{
    if(value == 0)
    {
        printf("-");
        return;
    }
    
    switch(value)
    {
        case KMIP_REASON_GENERAL_FAILURE:
        printf("General Failure");
        break;
        
        case KMIP_REASON_ITEM_NOT_FOUND:
        printf("Item Not Found");
        break;
        
        case KMIP_REASON_RESPONSE_TOO_LARGE:
        printf("Response Too Large");
        break;
        
        case KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL:
        printf("Authentication Not Successful");
        break;
        
        case KMIP_REASON_INVALID_MESSAGE:
        printf("Invalid Message");
        break;
        
        case KMIP_REASON_OPERATION_NOT_SUPPORTED:
        printf("Operation Not Supported");
        break;
        
        case KMIP_REASON_MISSING_DATA:
        printf("Missing Data");
        break;
        
        case KMIP_REASON_INVALID_FIELD:
        printf("Invalid Field");
        break;
        
        case KMIP_REASON_FEATURE_NOT_SUPPORTED:
        printf("Feature Not Supported");
        break;
        
        case KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER:
        printf("Operation Canceled By Requester");
        break;
        
        case KMIP_REASON_CRYPTOGRAPHIC_FAILURE:
        printf("Cryptographic Failure");
        break;
        
        case KMIP_REASON_ILLEGAL_OPERATION:
        printf("Illegal Operation");
        break;
        
        case KMIP_REASON_PERMISSION_DENIED:
        printf("Permission Denied");
        break;
        
        case KMIP_REASON_OBJECT_ARCHIVED:
        printf("Object Archived");
        break;
        
        case KMIP_REASON_INDEX_OUT_OF_BOUNDS:
        printf("Index Out Of Bounds");
        break;
        
        case KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED:
        printf("Application Namespace Not Supported");
        break;
        
        case KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED:
        printf("Key Format Type Not Supported");
        break;
        
        case KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED:
        printf("Key Compression Type Not Supported");
        break;
        
        case KMIP_REASON_ENCODING_OPTION_FAILURE:
        printf("Encoding Option Failure");
        break;
        
        case KMIP_REASON_KEY_VALUE_NOT_PRESENT:
        printf("Key Value Not Present");
        break;
        
        case KMIP_REASON_ATTESTATION_REQUIRED:
        printf("Attestation Required");
        break;
        
        case KMIP_REASON_ATTESTATION_FAILED:
        printf("Attestation Failed");
        break;
        
        case KMIP_REASON_SENSITIVE:
        printf("Sensitive");
        break;
        
        case KMIP_REASON_NOT_EXTRACTABLE:
        printf("Not Extractable");
        break;
        
        case KMIP_REASON_OBJECT_ALREADY_EXISTS:
        printf("Object Already Exists");
        break;
        
        default:
        printf("Unknown");
        break;
    };
}

void
print_object_type_enum(enum object_type value)
{
    if(value == 0)
    {
        printf("-");
        return;
    }
    
    switch(value)
    {
        case KMIP_OBJTYPE_CERTIFICATE:
        printf("Certificate");
        break;
        
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
        printf("Symmetric Key");
        break;
        
        case KMIP_OBJTYPE_PUBLIC_KEY:
        printf("Public Key");
        break;
        
        case KMIP_OBJTYPE_PRIVATE_KEY:
        printf("Private Key");
        break;
        
        case KMIP_OBJTYPE_SPLIT_KEY:
        printf("Split Key");
        break;
        
        case KMIP_OBJTYPE_TEMPLATE:
        printf("Template");
        break;
        
        case KMIP_OBJTYPE_SECRET_DATA:
        printf("Secret Data");
        break;
        
        case KMIP_OBJTYPE_OPAQUE_OBJECT:
        printf("Opaque Object");
        break;
        
        case KMIP_OBJTYPE_PGP_KEY:
        printf("PGP Key");
        break;
        
        default:
        printf("Unknown");
        break;
    };
}

void
print_key_format_type_enum(enum key_format_type value)
{
    if(value == 0)
    {
        printf("-");
        return;
    }
    
    switch(value)
    {
        case KMIP_KEYFORMAT_RAW:
        printf("Raw");
        break;
        
        case KMIP_KEYFORMAT_OPAQUE:
        printf("Opaque");
        break;
        
        case KMIP_KEYFORMAT_PKCS1:
        printf("PKCS1");
        break;
        
        case KMIP_KEYFORMAT_PKCS8:
        printf("PKCS8");
        break;
        
        case KMIP_KEYFORMAT_X509:
        printf("X509");
        break;
        
        case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
        printf("EC Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
        printf("Transparent Symmetric Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY:
        printf("Transparent DSA Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY:
        printf("Transparent DSA Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY:
        printf("Transparent RSA Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY:
        printf("Transparent RSA Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY:
        printf("Transparent DH Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY:
        printf("Transparent DH Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY:
        printf("Transparent ECDSA Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY:
        printf("Transparent ECDSA Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY:
        printf("Transparent ECDH Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY:
        printf("Transparent ECDH Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY:
        printf("Transparent ECMQV Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY:
        printf("Transparent ECMQV Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY:
        printf("Transparent EC Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY:
        printf("Transparent EC Public Key");
        break;
        
        case KMIP_KEYFORMAT_PKCS12:
        printf("PKCS12");
        break;
        
        default:
        printf("Unknown");
        break;
    };
}

void
print_key_compression_type_enum(enum key_compression_type value)
{
    if(value == 0)
    {
        printf("-");
        return;
    }
    
    switch(value)
    {
        case KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED:
        printf("EC Public Key Type Uncompressed");
        break;
        
        case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME:
        printf("EC Public Key Type X9.62 Compressed Prime");
        break;
        
        case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2:
        printf("EC Public Key Type X9.62 Compressed Char2");
        break;
        
        case KMIP_KEYCOMP_EC_PUB_X962_HYBRID:
        printf("EC Public Key Type X9.62 Hybrid");
        break;
        
        default:
        printf("Unknown");
        break;
    };
}

void
print_cryptographic_algorithm_enum(enum cryptographic_algorithm value)
{
    if(value == 0)
    {
        printf("-");
        return;
    }
    
    switch(value)
    {
        case KMIP_CRYPTOALG_DES:
        printf("DES");
        break;
        
        case KMIP_CRYPTOALG_TRIPLE_DES:
        printf("3DES");
        break;
        
        case KMIP_CRYPTOALG_AES:
        printf("AES");
        break;
        
        case KMIP_CRYPTOALG_RSA:
        printf("RSA");
        break;
        
        case KMIP_CRYPTOALG_DSA:
        printf("DSA");
        break;
        
        case KMIP_CRYPTOALG_ECDSA:
        printf("ECDSA");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA1:
        printf("SHA1");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA224:
        printf("SHA224");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA256:
        printf("SHA256");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA384:
        printf("SHA384");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA512:
        printf("SHA512");
        break;
        
        case KMIP_CRYPTOALG_HMAC_MD5:
        printf("MD5");
        break;
        
        case KMIP_CRYPTOALG_DH:
        printf("DH");
        break;
        
        case KMIP_CRYPTOALG_ECDH:
        printf("ECDH");
        break;
        
        case KMIP_CRYPTOALG_ECMQV:
        printf("ECMQV");
        break;
        
        case KMIP_CRYPTOALG_BLOWFISH:
        printf("Blowfish");
        break;
        
        case KMIP_CRYPTOALG_CAMELLIA:
        printf("Camellia");
        break;
        
        case KMIP_CRYPTOALG_CAST5:
        printf("CAST5");
        break;
        
        case KMIP_CRYPTOALG_IDEA:
        printf("IDEA");
        break;
        
        case KMIP_CRYPTOALG_MARS:
        printf("MARS");
        break;
        
        case KMIP_CRYPTOALG_RC2:
        printf("RC2");
        break;
        
        case KMIP_CRYPTOALG_RC4:
        printf("RC4");
        break;
        
        case KMIP_CRYPTOALG_RC5:
        printf("RC5");
        break;
        
        case KMIP_CRYPTOALG_SKIPJACK:
        printf("Skipjack");
        break;
        
        case KMIP_CRYPTOALG_TWOFISH:
        printf("Twofish");
        break;
        
        case KMIP_CRYPTOALG_EC:
        printf("EC");
        break;
        
        case KMIP_CRYPTOALG_ONE_TIME_PAD:
        printf("One Time Pad");
        break;
        
        case KMIP_CRYPTOALG_CHACHA20:
        printf("ChaCha20");
        break;
        
        case KMIP_CRYPTOALG_POLY1305:
        printf("Poly1305");
        break;
        
        case KMIP_CRYPTOALG_CHACHA20_POLY1305:
        printf("ChaCha20 Poly1305");
        break;
        
        case KMIP_CRYPTOALG_SHA3_224:
        printf("SHA3-224");
        break;
        
        case KMIP_CRYPTOALG_SHA3_256:
        printf("SHA3-256");
        break;
        
        case KMIP_CRYPTOALG_SHA3_384:
        printf("SHA3-384");
        break;
        
        case KMIP_CRYPTOALG_SHA3_512:
        printf("SHA3-512");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_224:
        printf("HMAC SHA3-224");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_256:
        printf("HMAC SHA3-256");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_384:
        printf("HMAC SHA3-384");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_512:
        printf("HMAC SHA3-512");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHAKE_128:
        printf("HMAC SHAKE-128");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHAKE_256:
        printf("HMAC SHAKE-256");
        break;
        
        default:
        printf("Unknown");
        break;
    };
}

void
print_text_string(int indent, const char *name, struct text_string *value)
{
    printf("%*s%s @ %p\n", indent, "", name, (void *)value);
    
    if(value != NULL)
    {
        printf("%*sValue: %s\n", indent + 2, "", value->value);
    }
    
    return;
}

void
print_byte_string(int indent, const char *name, struct byte_string *value)
{
    printf("%*s%s @ %p\n", indent, "", name, (void *)value);
    
    if(value != NULL)
    {
        printf("%*sValue:", indent + 2, "");
        for(size_t i = 0; i < value->size; i++)
        {
            if(i % 16 == 0)
            {
                printf("\n%*s0x", indent + 4, "");
            }
            printf("%02X", value->value[i]);
        }
        printf("\n");
    }
    
    return;
}

void
print_protocol_version(int indent, struct protocol_version *value)
{
    printf("%*sProtocol Version @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        printf("%*sMajor: %d\n", indent + 2, "", value->major);
        printf("%*sMinor: %d\n", indent + 2, "", value->minor);
    }
    
    return;
}

void
print_nonce(int indent, struct nonce *value)
{
    printf("%*sNonce @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        print_byte_string(indent + 2, "Nonce ID", value->nonce_id);
        print_byte_string(indent + 2, "Nonce Value", value->nonce_value);
    }
    
    return;
}

void
print_key_wrapping_data(int indent, struct key_wrapping_data *value)
{
    printf("%*sKey Wrapping Data @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
    }
    
    return;
}

void
print_attribute(int indent, struct attribute *value)
{
    printf("%*sAttribute @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
    }
    
    return;
}

void
print_key_material(int indent, enum key_format_type format, void *value)
{
    switch(format)
    {
        case KMIP_KEYFORMAT_RAW:
        case KMIP_KEYFORMAT_OPAQUE:
        case KMIP_KEYFORMAT_PKCS1:
        case KMIP_KEYFORMAT_PKCS8:
        case KMIP_KEYFORMAT_X509:
        case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
        print_byte_string(indent, "Key Material", (struct byte_string *)value);
        break;
        
        default:
        printf("%*sUnknown Key Material @ %p\n", indent, "", value);
        break;
    };
}

void
print_key_value(int indent, enum type type, enum key_format_type format, void *value)
{
    switch(type)
    {
        case KMIP_TYPE_BYTE_STRING:
        print_byte_string(indent, "Key Value", (struct byte_string *)value);
        break;
        
        case KMIP_TYPE_STRUCTURE:
        printf("%*sKey Value @ %p\n", indent, "", value);
        
        if(value != NULL)
        {
            struct key_value key_value = *(struct key_value *)value;
            print_key_material(indent + 2, format, key_value.key_material);
            printf("%*sAttributes: %zu\n", indent + 2, "", key_value.attribute_count);
            for(size_t i = 0; i < key_value.attribute_count; i++)
            {
                print_attribute(indent + 2, &key_value.attributes[i]);
            }
            /*
            struct key_value
            {
                void *key_material;
                struct attribute *attributes;
                size_t attribute_count;
            };
            */
        }
        break;
        
        default:
        printf("%*sUnknown Key Value @ %p\n", indent, "", value);
        break;
    };
}

void
print_key_block(int indent, struct key_block *value)
{
    printf("%*sKey Block @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        printf("%*sKey Format Type: ", indent + 2, "");
        print_key_format_type_enum(value->key_format_type);
        printf("\n");
        
        printf("%*sKey Compression Type: ", indent + 2, "");
        print_key_compression_type_enum(value->key_compression_type);
        printf("\n");
        
        print_key_value(indent + 2, value->key_value_type, value->key_format_type, value->key_value);
        
        printf("%*sCryptographic Algorithm: ", indent + 2, "");
        print_cryptographic_algorithm_enum(value->cryptographic_algorithm);
        printf("\n");
        
        printf("%*sCryptographic Length: %d\n", indent + 2, "", value->cryptographic_length);
        
        print_key_wrapping_data(indent + 2, value->key_wrapping_data);
    }
    
    return;
}

void
print_symmetric_key(int indent, struct symmetric_key *value)
{
    printf("%*sSymmetric Key @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        print_key_block(indent + 2, value->key_block);
    }
    
    return;
}

void
print_object(int indent, enum object_type type, void *value)
{
    switch(type)
    {
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
        print_symmetric_key(indent, (struct symmetric_key *)value);
        break;
        
        default:
        printf("%*sUnknown Object @ %p\n", indent, "", value);
        break;
    };
}

void
print_get_response_payload(int indent, struct get_response_payload *value)
{
    printf("%*sGet Response Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        printf("%*sObject Type: ", indent + 2, "");
        print_object_type_enum(value->object_type);
        printf("\n");
        
        print_text_string(indent + 2, "Unique Identifier", value->unique_identifier);
        print_object(indent + 2, value->object_type, value->object);
    }
    
    return;
}

void
print_response_payload(int indent, enum operation type, void *value)
{
    switch(type)
    {
        case KMIP_OP_GET:
        print_get_response_payload(indent, (struct get_response_payload *)value);
        break;
        
        default:
        printf("%*sUnknown Payload @ %p\n", indent, "", value);
        break;
    };
}

void
print_response_batch_item(int indent, struct response_batch_item *value)
{
    printf("%*sResponse Batch Item @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        printf("%*sOperation: ", indent + 2, "");
        print_operation_enum(value->operation);
        printf("\n");
        
        print_byte_string(indent + 2, "Unique Batch Item ID", value->unique_batch_item_id);
        
        printf("%*sResult Status: ", indent + 2, "");
        print_result_status_enum(value->result_status);
        printf("\n");
        
        printf("%*sResult Reason: ", indent + 2, "");
        print_result_reason_enum(value->result_reason);
        printf("\n");
        
        print_text_string(indent + 2, "Result Message", value->result_message);
        print_byte_string(indent + 2, "Asynchronous Correlation Value", value->asynchronous_correlation_value);
        
        print_response_payload(indent + 2, value->operation, value->response_payload);
    }
    
    return;
}

void
print_response_header(int indent, struct response_header *value)
{
    printf("%*sResponse Header @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        print_protocol_version(indent + 2, value->protocol_version);
        printf("%*sTime Stamp: %lu\n", indent + 2, "", value->time_stamp);
        printf("%*sBatch Count: %d\n", indent + 2, "", value->batch_count);
        print_nonce(indent + 2, value->nonce);
        printf("%*sAttestation Types: %zu\n", indent + 2, "", value->attestation_type_count);
        for(size_t i = 0; i < value->attestation_type_count; i++)
        {
            /* TODO (ph) Add enum value -> string functionality. */
            printf("%*sAttestation Type: %s\n", indent + 4, "", "???");
        }
        print_text_string(indent + 2, "Client Correlation Value", value->client_correlation_value);
        print_text_string(indent + 2, "Server Correlation Value", value->server_correlation_value);
    }
}

void
print_response_message(struct response_message *value)
{
    printf("Response Message @ %p\n", (void *)value);
    
    if(value != NULL)
    {
        print_response_header(2, value->response_header);
        printf("  Batch Items: %zu\n", value->batch_count);
        
        for(size_t i = 0; i < value->batch_count; i++)
        {
            print_response_batch_item(4, &value->batch_items[i]);
        }
    }
    
    return;
}

int
main(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());
    
    /* load certs and keys and coordinate cipher choices for TLS */
    int result = SSL_CTX_use_certificate_file(
        ctx,
        "/etc/pykmip/certs/slugs/client_certificate_john_doe.pem",
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client certificate failed.\n");
    }
    result = SSL_CTX_use_PrivateKey_file(
        ctx,
        "/etc/pykmip/certs/slugs/client_key_john_doe.pem",
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client key failed.\n");
    }
    result = SSL_CTX_load_verify_locations(
        ctx, 
        "/etc/pykmip/certs/slugs/root_certificate.pem",
        NULL);
    if(result != 1)
    {
        printf("Loading the CA file failed.\n");
    }
    
    BIO *bio = NULL;
    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, "127.0.0.1");
    BIO_set_conn_port(bio, "5696");
    BIO_do_connect(bio);
    
    /* Get a SymmetricKey with ID: 1*/
    /*
    uint8 request[120] = {
    0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x70,
    0x42, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00, 0x38,
    0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20,
    0x42, 0x00, 0x6A, 0x02, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x6B, 0x02, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x0F, 0x01, 0x00, 0x00, 0x00, 0x48,
    0x42, 0x00, 0x5C, 0x05, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x79, 0x01, 0x00, 0x00, 0x00, 0x30,
    0x42, 0x00, 0x94, 0x07, 0x00, 0x00, 0x00, 0x01,
    0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    */
    
    uint8 observed[1024] = {0};
    struct kmip kmip_ctx = {0};
    kmip_init(&kmip_ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    struct protocol_version pv = {0};
    pv.major = 1;
    pv.minor = 0;
    
    struct request_header rh = {0};
    rh.protocol_version = &pv;
    rh.asynchronous_indicator = KMIP_UNSET;
    rh.batch_order_option = KMIP_UNSET;
    rh.batch_count = 1;
    
    struct text_string uuid = {0};
    uuid.value = "1";
    uuid.size = 1;
    
    struct get_request_payload grp = {0};
    grp.unique_identifier = &uuid;
    
    struct request_batch_item rbi = {0};
    rbi.operation = KMIP_OP_GET;
    rbi.request_payload = &grp;
    
    struct request_message rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    int encode_result = encode_request_message(&kmip_ctx, &rm);
    if(encode_result != KMIP_OK)
    {
        printf("Encoding failure detected. Aborting request.");
        return(encode_result);
    }
    
    uint8 response[300] = {0};
    
    /*
    BIO_write(bio, request, 120);
    int recv = BIO_read(bio, response, 300);
    */
    
    BIO_write(bio, kmip_ctx.buffer, kmip_ctx.index - kmip_ctx.buffer);
    int recv = BIO_read(bio, response, 300);
    
    printf("Received bytes: %d\n\n", recv);
    
    kmip_reset(&kmip_ctx);
    kmip_set_buffer(&kmip_ctx, response, recv);
    
    struct response_message resp_m = {0};
    
    int decode_result = decode_response_message(&kmip_ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        printf("Decoding failure detected. Error: %d\n", decode_result);
        printf("- error code: %d\n", decode_result);
        printf("- error name: ");
        print_error_string(decode_result);
        printf("\n");
        
        /* NOTE (ph) The following was taken from test.c */
        printf("Stack trace:\n");
        for(size_t i = 0; i < 20; i++)
        {
            struct error_frame *frame = &kmip_ctx.errors[i];
            if(frame->line != 0)
            {
                printf("- %s%s @ line: %d\n", "", frame->function, frame->line);
            }
            else
            {
                break;
            }
        }
        return(decode_result);
    }
    else
    {
        printf("Decoding succeeded!\n\n");
    }
    
    print_response_message(&resp_m);
    
    free_response_message(&kmip_ctx, &resp_m);
    kmip_destroy(&kmip_ctx);
    
    return(0);
}