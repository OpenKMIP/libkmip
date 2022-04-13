/* Copyright (c) 2021 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kmip_io.h"

/*
Printing Functions
*/

void
kmip_print_buffer(FILE *f, void *buffer, int size)
{
    if(buffer == NULL)
    {
        return;
    }
    
    uint8 *index = (uint8 *)buffer;
    for(int i = 0; i < size; i++)
    {
        if(i % 16 == 0)
        {
            fprintf(f, "\n0x");
        }
        fprintf(f, "%02X", index[i]);
    }
}

void
kmip_print_stack_trace(FILE *f, KMIP *ctx)
{
    if(ctx == NULL)
    {
        return;
    }
    
    ErrorFrame *index = ctx->frame_index;
    do
    {
        fprintf(f, "- %s @ line: %d\n", index->function, index->line);
    } while(index-- != ctx->errors);
}

void
kmip_print_error_string(FILE *f, int value)
{
    /* TODO (ph) Move this to a static string array. */
    switch(value)
    {
        case 0:
        {
            fprintf(f, "KMIP_OK");
        } break;
        
        case -1:
        {
            fprintf(f, "KMIP_NOT_IMPLEMENTED");
        } break;
        
        case -2:
        {
            fprintf(f, "KMIP_ERROR_BUFFER_FULL");
        } break;
        
        case -3:
        {
            fprintf(f, "KMIP_ERROR_ATTR_UNSUPPORTED");
        } break;
        
        case -4:
        {
            fprintf(f, "KMIP_TAG_MISMATCH");
        } break;
        
        case -5:
        {
            fprintf(f, "KMIP_TYPE_MISMATCH");
        } break;
        
        case -6:
        {
            fprintf(f, "KMIP_LENGTH_MISMATCH");
        } break;
        
        case -7:
        {
            fprintf(f, "KMIP_PADDING_MISMATCH");
        } break;
        
        case -8:
        {
            fprintf(f, "KMIP_BOOLEAN_MISMATCH");
        } break;
        
        case -9:
        {
            fprintf(f, "KMIP_ENUM_MISMATCH");
        } break;
        
        case -10:
        {
            fprintf(f, "KMIP_ENUM_UNSUPPORTED");
        } break;
        
        case -11:
        {
            fprintf(f, "KMIP_INVALID_FOR_VERSION");
        } break;
        
        case -12:
        {
            fprintf(f, "KMIP_MEMORY_ALLOC_FAILED");
        } break;

        case -13:
        {
            fprintf(f, "KMIP_IO_FAILURE");
        } break;

        case -14:
        {
            fprintf(f, "KMIP_EXCEED_MAX_MESSAGE_SIZE");
        } break;

        case -15:
        {
            fprintf(f, "KMIP_MALFORMED_RESPONSE");
        } break;

        case -16:
        {
            fprintf(f, "KMIP_OBJECT_MISMATCH");
        } break;

        case -17:
        {
            fprintf(f, "KMIP_ARG_INVALID");
        } break;

        case -18:
        {
            fprintf(f, "KMIP_ERROR_BUFFER_UNDERFULL");
        } break;

        default:
        {
            fprintf(f, "Unrecognized Error Code");
        } break;
    };
    
    return;
}

void
kmip_print_attestation_type_enum(FILE *f, enum attestation_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_ATTEST_TPM_QUOTE:
        fprintf(f, "TPM Quote");
        break;
        
        case KMIP_ATTEST_TCG_INTEGRITY_REPORT:
        fprintf(f, "TCG Integrity Report");
        break;
        
        case KMIP_ATTEST_SAML_ASSERTION:
        fprintf(f, "SAML Assertion");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_batch_error_continuation_option(FILE *f, enum batch_error_continuation_option value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_BATCH_CONTINUE:
        fprintf(f, "Continue");
        break;
        
        case KMIP_BATCH_STOP:
        fprintf(f, "Stop");
        break;
        
        case KMIP_BATCH_UNDO:
        fprintf(f, "Undo");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_operation_enum(FILE *f, enum operation value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_OP_CREATE:
        fprintf(f, "Create");
        break;

        case KMIP_OP_CREATE_KEY_PAIR:
        fprintf(f, "Create Key Pair");
        break;

        case KMIP_OP_REGISTER:
        fprintf(f, "Register");
        break;

        case KMIP_OP_REKEY:
        fprintf(f, "Rekey");
        break;

        case KMIP_OP_DERIVE_KEY:
        fprintf(f, "Derive Key");
        break;

        case KMIP_OP_CERTIFY:
        fprintf(f, "Certify");
        break;

        case KMIP_OP_RECERTIFY:
        fprintf(f, "Recertify");
        break;

        case KMIP_OP_LOCATE:
        fprintf(f, "Locate");
        break;

        case KMIP_OP_CHECK:
        fprintf(f, "Check");
        break;

        case KMIP_OP_GET:
        fprintf(f, "Get");
        break;

        case KMIP_OP_GET_ATTRIBUTES:
        fprintf(f, "Get Attributes");
        break;

        case KMIP_OP_GET_ATTRIBUTE_LIST:
        fprintf(f, "Get Attribute List");
        break;

        case KMIP_OP_ADD_ATTRIBUTE:
        fprintf(f, "Add Attribute");
        break;

        case KMIP_OP_MODIFY_ATTRIBUTE:
        fprintf(f, "Modify Attribute");
        break;

        case KMIP_OP_DELETE_ATTRIBUTE:
        fprintf(f, "Delete Attribute");
        break;

        case KMIP_OP_OBTAIN_LEASE:
        fprintf(f, "Obtain Lease");
        break;

        case KMIP_OP_GET_USAGE_ALLOCATION:
        fprintf(f, "Get Usage Allocation");
        break;

        case KMIP_OP_ACTIVATE:
        fprintf(f, "Activate");
        break;

        case KMIP_OP_REVOKE:
        fprintf(f, "Revoke");
        break;

        case KMIP_OP_DESTROY:
        fprintf(f, "Destroy");
        break;

        case KMIP_OP_ARCHIVE:
        fprintf(f, "Archive");
        break;

        case KMIP_OP_RECOVER:
        fprintf(f, "Recover");
        break;

        case KMIP_OP_VALIDATE:
        fprintf(f, "Validate");
        break;

        case KMIP_OP_QUERY:
        printf("Query");
        break;

        case KMIP_OP_CANCEL:
        fprintf(f, "Cancel");
        break;

        case KMIP_OP_POLL:
        fprintf(f, "Poll");
        break;

        case KMIP_OP_NOTIFY:
        fprintf(f, "Notify");
        break;

        case KMIP_OP_PUT:
        fprintf(f, "Put");
        break;

        // # KMIP 1.1
        case KMIP_OP_REKEY_KEY_PAIR:
        fprintf(f, "Rekey Key Pair");
        break;

        case KMIP_OP_DISCOVER_VERSIONS:
        fprintf(f, "Discover Versions");
        break;

        //# KMIP 1.2
        case KMIP_OP_ENCRYPT:
        fprintf(f, "Encrypt");
        break;

        case KMIP_OP_DECRYPT:
        fprintf(f, "Decrypt");
        break;

        case KMIP_OP_SIGN:
        fprintf(f, "Sign");
        break;

        case KMIP_OP_SIGNATURE_VERIFY:
        fprintf(f, "Signature Verify");
        break;

        case KMIP_OP_MAC:
        fprintf(f, "MAC");
        break;

        case KMIP_OP_MAC_VERIFY:
        fprintf(f, "MAC Verify");
        break;

        case KMIP_OP_RNG_RETRIEVE:
        fprintf(f, "RNG Retrieve");
        break;

        case KMIP_OP_RNG_SEED:
        fprintf(f, "RNG Seed");
        break;

        case KMIP_OP_HASH:
        fprintf(f, "Hash");
        break;

        case KMIP_OP_CREATE_SPLIT_KEY:
        fprintf(f, "Create Split Key");
        break;

        case KMIP_OP_JOIN_SPLIT_KEY:
        fprintf(f, "Split Key");
        break;

        // # KMIP 1.4
        case KMIP_OP_IMPORT:
        fprintf(f, "Import");
        break;

        case KMIP_OP_EXPORT:
        fprintf(f, "Export");
        break;

        // # KMIP 2.0
        case KMIP_OP_LOG:
        fprintf(f, "Log");
        break;

        case KMIP_OP_LOGIN:
        fprintf(f, "Login");
        break;

        case KMIP_OP_LOGOUT:
        fprintf(f, "Logout");
        break;

        case KMIP_OP_DELEGATED_LOGIN:
        fprintf(f, "Delegated Login");
        break;

        case KMIP_OP_ADJUST_ATTRIBUTE:
        fprintf(f, "Adjust Attribute");
        break;

        case KMIP_OP_SET_ATTRIBUTE:
        fprintf(f, "Set Attribute");
        break;

        case KMIP_OP_SET_ENDPOINT_ROLE:
        fprintf(f, "Set Endpoint Role");
        break;

        case KMIP_OP_PKCS_11:
        fprintf(f, "PKCS11");
        break;

        case KMIP_OP_INTEROP:
        fprintf(f, "Interop");
        break;

        case KMIP_OP_REPROVISION:
        fprintf(f, "Reprovision");
        break;

        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_result_status_enum(FILE *f, enum result_status value)
{
    switch(value)
    {
        case KMIP_STATUS_SUCCESS:
        fprintf(f, "Success");
        break;
        
        case KMIP_STATUS_OPERATION_FAILED:
        fprintf(f, "Operation Failed");
        break;
        
        case KMIP_STATUS_OPERATION_PENDING:
        fprintf(f, "Operation Pending");
        break;
        
        case KMIP_STATUS_OPERATION_UNDONE:
        fprintf(f, "Operation Undone");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_result_reason_enum(FILE *f, enum result_reason value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_REASON_GENERAL_FAILURE:
        fprintf(f, "General Failure");
        break;
        
        case KMIP_REASON_ITEM_NOT_FOUND:
        fprintf(f, "Item Not Found");
        break;
        
        case KMIP_REASON_RESPONSE_TOO_LARGE:
        fprintf(f, "Response Too Large");
        break;
        
        case KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL:
        fprintf(f, "Authentication Not Successful");
        break;
        
        case KMIP_REASON_INVALID_MESSAGE:
        fprintf(f, "Invalid Message");
        break;
        
        case KMIP_REASON_OPERATION_NOT_SUPPORTED:
        fprintf(f, "Operation Not Supported");
        break;
        
        case KMIP_REASON_MISSING_DATA:
        fprintf(f, "Missing Data");
        break;
        
        case KMIP_REASON_INVALID_FIELD:
        fprintf(f, "Invalid Field");
        break;
        
        case KMIP_REASON_FEATURE_NOT_SUPPORTED:
        fprintf(f, "Feature Not Supported");
        break;
        
        case KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER:
        fprintf(f, "Operation Canceled By Requester");
        break;
        
        case KMIP_REASON_CRYPTOGRAPHIC_FAILURE:
        fprintf(f, "Cryptographic Failure");
        break;
        
        case KMIP_REASON_ILLEGAL_OPERATION:
        fprintf(f, "Illegal Operation");
        break;
        
        case KMIP_REASON_PERMISSION_DENIED:
        fprintf(f, "Permission Denied");
        break;
        
        case KMIP_REASON_OBJECT_ARCHIVED:
        fprintf(f, "Object Archived");
        break;
        
        case KMIP_REASON_INDEX_OUT_OF_BOUNDS:
        fprintf(f, "Index Out Of Bounds");
        break;
        
        case KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED:
        fprintf(f, "Application Namespace Not Supported");
        break;
        
        case KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED:
        fprintf(f, "Key Format Type Not Supported");
        break;
        
        case KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED:
        fprintf(f, "Key Compression Type Not Supported");
        break;
        
        case KMIP_REASON_ENCODING_OPTION_FAILURE:
        fprintf(f, "Encoding Option Failure");
        break;
        
        case KMIP_REASON_KEY_VALUE_NOT_PRESENT:
        fprintf(f, "Key Value Not Present");
        break;
        
        case KMIP_REASON_ATTESTATION_REQUIRED:
        fprintf(f, "Attestation Required");
        break;
        
        case KMIP_REASON_ATTESTATION_FAILED:
        fprintf(f, "Attestation Failed");
        break;
        
        case KMIP_REASON_SENSITIVE:
        fprintf(f, "Sensitive");
        break;
        
        case KMIP_REASON_NOT_EXTRACTABLE:
        fprintf(f, "Not Extractable");
        break;
        
        case KMIP_REASON_OBJECT_ALREADY_EXISTS:
        fprintf(f, "Object Already Exists");
        break;
        
        case KMIP_REASON_INVALID_TICKET:
        fprintf(f, "Invalid Ticket");
        break;

        case KMIP_REASON_USAGE_LIMIT_EXCEEDED:
        fprintf(f, "Usage Limit Exceeded");
        break;

        case KMIP_REASON_NUMERIC_RANGE:
        fprintf(f, "Numeric Range");
        break;

        case KMIP_REASON_INVALID_DATA_TYPE:
        fprintf(f, "Invalid Data Type");
        break;

        case KMIP_REASON_READ_ONLY_ATTRIBUTE:
        fprintf(f, "Read Only Attribute");
        break;

        case KMIP_REASON_MULTI_VALUED_ATTRIBUTE:
        fprintf(f, "Multi Valued Attribute");
        break;

        case KMIP_REASON_UNSUPPORTED_ATTRIBUTE:
        fprintf(f, "Unsupported Attribute");
        break;

        case KMIP_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND:
        fprintf(f, "Attribute Instance Not Found");
        break;

        case KMIP_REASON_ATTRIBUTE_NOT_FOUND:
        fprintf(f, "Attribute Not Found");
        break;

        case KMIP_REASON_ATTRIBUTE_READ_ONLY:
        fprintf(f, "Attribute Read Only");
        break;

        case KMIP_REASON_ATTRIBUTE_SINGLE_VALUED:
        fprintf(f, "Attribute Single Valued");
        break;

        case KMIP_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS:
        fprintf(f, "Bad Cryptographic Parameters");
        break;

        case KMIP_REASON_BAD_PASSWORD:
        fprintf(f, "Bad Password");
        break;

        case KMIP_REASON_CODEC_ERROR:
        fprintf(f, "Codec Error");
        break;

        case KMIP_REASON_ILLEGAL_OBJECT_TYPE:
        fprintf(f, "Illegal Object Type");
        break;

        case KMIP_REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK:
        fprintf(f, "Incompatible Cryptographic Usage Mask");
        break;

        case KMIP_REASON_INTERNAL_SERVER_ERROR:
        fprintf(f, "Internal Server Error");
        break;

        case KMIP_REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE:
        fprintf(f, "Invalid Asynchronous Correlation Value");
        break;

        case KMIP_REASON_INVALID_ATTRIBUTE:
        fprintf(f, "Invalid Attribute");
        break;

        case KMIP_REASON_INVALID_ATTRIBUTE_VALUE:
        fprintf(f, "Invalid Attribute Value");
        break;

        case KMIP_REASON_INVALID_CORRELATION_VALUE:
        fprintf(f, "Invalid Correlation Value");
        break;

        case KMIP_REASON_INVALID_CSR:
        fprintf(f, "Invalid CSR");
        break;

        case KMIP_REASON_INVALID_OBJECT_TYPE:
        fprintf(f, "Invalid Object Type");
        break;

        case KMIP_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED:
        fprintf(f, "Key Wrap Type Not Supported");
        break;

        case KMIP_REASON_MISSING_INITIALIZATION_VECTOR:
        fprintf(f, "Missing Initialization Vector");
        break;

        case KMIP_REASON_NON_UNIQUE_NAME_ATTRIBUTE:
        fprintf(f, "Non Unique Name Attribute");
        break;

        case KMIP_REASON_OBJECT_DESTROYED:
        fprintf(f, "Object Destroyed");
        break;

        case KMIP_REASON_OBJECT_NOT_FOUND:
        fprintf(f, "Object Not Found");
        break;

        case KMIP_REASON_NOT_AUTHORISED:
        fprintf(f, "Not Authorised");
        break;

        case KMIP_REASON_SERVER_LIMIT_EXCEEDED:
        fprintf(f, "Server Limit Exceeded");
        break;

        case KMIP_REASON_UNKNOWN_ENUMERATION:
        fprintf(f, "Unknown Enumeration");
        break;

        case KMIP_REASON_UNKNOWN_MESSAGE_EXTENSION:
        fprintf(f, "Unknown Message Extension");
        break;

        case KMIP_REASON_UNKNOWN_TAG:
        fprintf(f, "Unknown Tag");
        break;

        case KMIP_REASON_UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS:
        fprintf(f, "Unsupported Cryptographic Parameters");
        break;

        case KMIP_REASON_UNSUPPORTED_PROTOCOL_VERSION:
        fprintf(f, "Unsupported Protocol Version");
        break;

        case KMIP_REASON_WRAPPING_OBJECT_ARCHIVED:
        fprintf(f, "Wrapping Object Archived");
        break;

        case KMIP_REASON_WRAPPING_OBJECT_DESTROYED:
        fprintf(f, "Wrapping Object Destroyed");
        break;

        case KMIP_REASON_WRAPPING_OBJECT_NOT_FOUND:
        fprintf(f, "Wrapping Object Not Found");
        break;

        case KMIP_REASON_WRONG_KEY_LIFECYCLE_STATE:
        fprintf(f, "Wrong Key Lifecycle State");
        break;

        case KMIP_REASON_PROTECTION_STORAGE_UNAVAILABLE:
        fprintf(f, "Protection Storage Unavailable");
        break;

        case KMIP_REASON_PKCS11_CODEC_ERROR:
        fprintf(f, "PKCS#11 Codec Error");
        break;

        case KMIP_REASON_PKCS11_INVALID_FUNCTION:
        fprintf(f, "PKCS#11 Invalid Function");
        break;

        case KMIP_REASON_PKCS11_INVALID_INTERFACE:
        fprintf(f, "PKCS#11 Invalid Interface");
        break;

        case KMIP_REASON_PRIVATE_PROTECTION_STORAGE_UNAVAILABLE:
        fprintf(f, "Private Protection Storage Unavailable");
        break;

        case KMIP_REASON_PUBLIC_PROTECTION_STORAGE_UNAVAILABLE:
        fprintf(f, "Public Protection Storage Unavailable");
        break;

        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_object_type_enum(FILE *f, enum object_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_OBJTYPE_CERTIFICATE:
        fprintf(f, "Certificate");
        break;
        
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
        fprintf(f, "Symmetric Key");
        break;
        
        case KMIP_OBJTYPE_PUBLIC_KEY:
        fprintf(f, "Public Key");
        break;
        
        case KMIP_OBJTYPE_PRIVATE_KEY:
        fprintf(f, "Private Key");
        break;
        
        case KMIP_OBJTYPE_SPLIT_KEY:
        fprintf(f, "Split Key");
        break;
        
        case KMIP_OBJTYPE_TEMPLATE:
        fprintf(f, "Template");
        break;
        
        case KMIP_OBJTYPE_SECRET_DATA:
        fprintf(f, "Secret Data");
        break;
        
        case KMIP_OBJTYPE_OPAQUE_OBJECT:
        fprintf(f, "Opaque Object");
        break;
        
        case KMIP_OBJTYPE_PGP_KEY:
        fprintf(f, "PGP Key");
        break;

        case KMIP_OBJTYPE_CERTIFICATE_REQUEST:
        fprintf(f, "Certificate Request");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_key_format_type_enum(FILE *f, enum key_format_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_KEYFORMAT_RAW:
        fprintf(f, "Raw");
        break;
        
        case KMIP_KEYFORMAT_OPAQUE:
        fprintf(f, "Opaque");
        break;
        
        case KMIP_KEYFORMAT_PKCS1:
        fprintf(f, "PKCS1");
        break;
        
        case KMIP_KEYFORMAT_PKCS8:
        fprintf(f, "PKCS8");
        break;
        
        case KMIP_KEYFORMAT_X509:
        fprintf(f, "X509");
        break;
        
        case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
        fprintf(f, "EC Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
        fprintf(f, "Transparent Symmetric Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY:
        fprintf(f, "Transparent DSA Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY:
        fprintf(f, "Transparent DSA Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY:
        fprintf(f, "Transparent RSA Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY:
        fprintf(f, "Transparent RSA Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY:
        fprintf(f, "Transparent DH Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY:
        fprintf(f, "Transparent DH Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY:
        fprintf(f, "Transparent ECDSA Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY:
        fprintf(f, "Transparent ECDSA Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY:
        fprintf(f, "Transparent ECDH Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY:
        fprintf(f, "Transparent ECDH Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY:
        fprintf(f, "Transparent ECMQV Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY:
        fprintf(f, "Transparent ECMQV Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY:
        fprintf(f, "Transparent EC Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY:
        fprintf(f, "Transparent EC Public Key");
        break;
        
        case KMIP_KEYFORMAT_PKCS12:
        fprintf(f, "PKCS#12");
        break;
        
        case KMIP_KEYFORMAT_PKCS10:
        fprintf(f, "PKCS#10");
        break;

        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_key_compression_type_enum(FILE *f, enum key_compression_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED:
        fprintf(f, "EC Public Key Type Uncompressed");
        break;
        
        case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME:
        fprintf(f, "EC Public Key Type X9.62 Compressed Prime");
        break;
        
        case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2:
        fprintf(f, "EC Public Key Type X9.62 Compressed Char2");
        break;
        
        case KMIP_KEYCOMP_EC_PUB_X962_HYBRID:
        fprintf(f, "EC Public Key Type X9.62 Hybrid");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_cryptographic_algorithm_enum(FILE *f, enum cryptographic_algorithm value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_CRYPTOALG_DES:
        fprintf(f, "DES");
        break;
        
        case KMIP_CRYPTOALG_TRIPLE_DES:
        fprintf(f, "3DES");
        break;
        
        case KMIP_CRYPTOALG_AES:
        fprintf(f, "AES");
        break;
        
        case KMIP_CRYPTOALG_RSA:
        fprintf(f, "RSA");
        break;
        
        case KMIP_CRYPTOALG_DSA:
        fprintf(f, "DSA");
        break;
        
        case KMIP_CRYPTOALG_ECDSA:
        fprintf(f, "ECDSA");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA1:
        fprintf(f, "SHA1");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA224:
        fprintf(f, "SHA224");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA256:
        fprintf(f, "SHA256");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA384:
        fprintf(f, "SHA384");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA512:
        fprintf(f, "SHA512");
        break;
        
        case KMIP_CRYPTOALG_HMAC_MD5:
        fprintf(f, "MD5");
        break;
        
        case KMIP_CRYPTOALG_DH:
        fprintf(f, "DH");
        break;
        
        case KMIP_CRYPTOALG_ECDH:
        fprintf(f, "ECDH");
        break;
        
        case KMIP_CRYPTOALG_ECMQV:
        fprintf(f, "ECMQV");
        break;
        
        case KMIP_CRYPTOALG_BLOWFISH:
        fprintf(f, "Blowfish");
        break;
        
        case KMIP_CRYPTOALG_CAMELLIA:
        fprintf(f, "Camellia");
        break;
        
        case KMIP_CRYPTOALG_CAST5:
        fprintf(f, "CAST5");
        break;
        
        case KMIP_CRYPTOALG_IDEA:
        fprintf(f, "IDEA");
        break;
        
        case KMIP_CRYPTOALG_MARS:
        fprintf(f, "MARS");
        break;
        
        case KMIP_CRYPTOALG_RC2:
        fprintf(f, "RC2");
        break;
        
        case KMIP_CRYPTOALG_RC4:
        fprintf(f, "RC4");
        break;
        
        case KMIP_CRYPTOALG_RC5:
        fprintf(f, "RC5");
        break;
        
        case KMIP_CRYPTOALG_SKIPJACK:
        fprintf(f, "Skipjack");
        break;
        
        case KMIP_CRYPTOALG_TWOFISH:
        fprintf(f, "Twofish");
        break;
        
        case KMIP_CRYPTOALG_EC:
        fprintf(f, "EC");
        break;
        
        case KMIP_CRYPTOALG_ONE_TIME_PAD:
        fprintf(f, "One Time Pad");
        break;
        
        case KMIP_CRYPTOALG_CHACHA20:
        fprintf(f, "ChaCha20");
        break;
        
        case KMIP_CRYPTOALG_POLY1305:
        fprintf(f, "Poly1305");
        break;
        
        case KMIP_CRYPTOALG_CHACHA20_POLY1305:
        fprintf(f, "ChaCha20 Poly1305");
        break;
        
        case KMIP_CRYPTOALG_SHA3_224:
        fprintf(f, "SHA3-224");
        break;
        
        case KMIP_CRYPTOALG_SHA3_256:
        fprintf(f, "SHA3-256");
        break;
        
        case KMIP_CRYPTOALG_SHA3_384:
        fprintf(f, "SHA3-384");
        break;
        
        case KMIP_CRYPTOALG_SHA3_512:
        fprintf(f, "SHA3-512");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_224:
        fprintf(f, "HMAC SHA3-224");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_256:
        fprintf(f, "HMAC SHA3-256");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_384:
        fprintf(f, "HMAC SHA3-384");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_512:
        fprintf(f, "HMAC SHA3-512");
        break;
        
        case KMIP_CRYPTOALG_SHAKE_128:
        fprintf(f, "SHAKE-128");
        break;
        
        case KMIP_CRYPTOALG_SHAKE_256:
        fprintf(f, "SHAKE-256");
        break;
        
        case KMIP_CRYPTOALG_ARIA:
        fprintf(f, "ARIA");
        break;

        case KMIP_CRYPTOALG_SEED:
        fprintf(f, "SEED");
        break;

        case KMIP_CRYPTOALG_SM2:
        fprintf(f, "SM2");
        break;

        case KMIP_CRYPTOALG_SM3:
        fprintf(f, "SM3");
        break;

        case KMIP_CRYPTOALG_SM4:
        fprintf(f, "SM4");
        break;

        case KMIP_CRYPTOALG_GOST_R_34_10_2012:
        fprintf(f, "GOST R 34.10-2012");
        break;

        case KMIP_CRYPTOALG_GOST_R_34_11_2012:
        fprintf(f, "GOST R 34.11-2012");
        break;

        case KMIP_CRYPTOALG_GOST_R_34_13_2015:
        fprintf(f, "GOST R 34.13-2015");
        break;

        case KMIP_CRYPTOALG_GOST_28147_89:
        fprintf(f, "GOST 28147-89");
        break;

        case KMIP_CRYPTOALG_XMSS:
        fprintf(f, "XMSS");
        break;

        case KMIP_CRYPTOALG_SPHINCS_256:
        fprintf(f, "SPHINCS-256");
        break;

        case KMIP_CRYPTOALG_MCELIECE:
        fprintf(f, "McEliece");
        break;

        case KMIP_CRYPTOALG_MCELIECE_6960119:
        fprintf(f, "McEliece 6960119");
        break;

        case KMIP_CRYPTOALG_MCELIECE_8192128:
        fprintf(f, "McEliece 8192128");
        break;

        case KMIP_CRYPTOALG_ED25519:
        fprintf(f, "Ed25519");
        break;

        case KMIP_CRYPTOALG_ED448:
        fprintf(f, "Ed448");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_name_type_enum(FILE *f, enum name_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_NAME_UNINTERPRETED_TEXT_STRING:
        fprintf(f, "Uninterpreted Text String");
        break;
        
        case KMIP_NAME_URI:
        fprintf(f, "URI");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_attribute_type_enum(FILE *f, enum attribute_type value)
{
    if((int)value == KMIP_UNSET)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION:
        {
            fprintf(f, "Application Specific Information");
        }
        break;

        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        fprintf(f, "Unique Identifier");
        break;
        
        case KMIP_ATTR_NAME:
        fprintf(f, "Name");
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        fprintf(f, "Object Type");
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        fprintf(f, "Cryptographic Algorithm");
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        fprintf(f, "Cryptographic Length");
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        fprintf(f, "Operation Policy Name");
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        fprintf(f, "Cryptographic Usage Mask");
        break;
        
        case KMIP_ATTR_STATE:
        fprintf(f, "State");
        break;

        case KMIP_ATTR_OBJECT_GROUP:
        {
            fprintf(f, "Object Group");
        }
        break;

        case KMIP_ATTR_CONTACT_INFORMATION:
        {
            fprintf(f, "Contact Information");
        }
        break;

        case KMIP_ATTR_ACTIVATION_DATE:
        {
            fprintf(f, "Activation Date");
        } break;

        case KMIP_ATTR_DEACTIVATION_DATE:
        {
            fprintf(f, "Deactivation Date");
        } break;

        case KMIP_ATTR_PROCESS_START_DATE:
        {
            fprintf(f, "Process Start Date");
        } break;

        case KMIP_ATTR_PROTECT_STOP_DATE:
        {
            fprintf(f, "Protect Stop Date");
        } break;

        case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
        {
            fprintf(f, "Cryptographic Parameters");
        } break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_state_enum(FILE *f, enum state value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_STATE_PRE_ACTIVE:
        fprintf(f, "Pre-Active");
        break;
        
        case KMIP_STATE_ACTIVE:
        fprintf(f, "Active");
        break;
        
        case KMIP_STATE_DEACTIVATED:
        fprintf(f, "Deactivated");
        break;
        
        case KMIP_STATE_COMPROMISED:
        fprintf(f, "Compromised");
        break;
        
        case KMIP_STATE_DESTROYED:
        fprintf(f, "Destroyed");
        break;
        
        case KMIP_STATE_DESTROYED_COMPROMISED:
        fprintf(f, "Destroyed Compromised");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_block_cipher_mode_enum(FILE *f, enum block_cipher_mode value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_BLOCK_CBC:
        fprintf(f, "CBC");
        break;
        
        case KMIP_BLOCK_ECB:
        fprintf(f, "ECB");
        break;
        
        case KMIP_BLOCK_PCBC:
        fprintf(f, "PCBC");
        break;
        
        case KMIP_BLOCK_CFB:
        fprintf(f, "CFB");
        break;
        
        case KMIP_BLOCK_OFB:
        fprintf(f, "OFB");
        break;
        
        case KMIP_BLOCK_CTR:
        fprintf(f, "CTR");
        break;
        
        case KMIP_BLOCK_CMAC:
        fprintf(f, "CMAC");
        break;
        
        case KMIP_BLOCK_CCM:
        fprintf(f, "CCM");
        break;
        
        case KMIP_BLOCK_GCM:
        fprintf(f, "GCM");
        break;
        
        case KMIP_BLOCK_CBC_MAC:
        fprintf(f, "CBC-MAC");
        break;
        
        case KMIP_BLOCK_XTS:
        fprintf(f, "XTS");
        break;
        
        case KMIP_BLOCK_AES_KEY_WRAP_PADDING:
        fprintf(f, "AESKeyWrapPadding");
        break;
        
        case KMIP_BLOCK_NIST_KEY_WRAP:
        fprintf(f, "NISTKeyWrap");
        break;
        
        case KMIP_BLOCK_X9102_AESKW:
        fprintf(f, "X9.102 AESKW");
        break;
        
        case KMIP_BLOCK_X9102_TDKW:
        fprintf(f, "X9.102 TDKW");
        break;
        
        case KMIP_BLOCK_X9102_AKW1:
        fprintf(f, "X9.102 AKW1");
        break;
        
        case KMIP_BLOCK_X9102_AKW2:
        fprintf(f, "X9.102 AKW2");
        break;
        
        case KMIP_BLOCK_AEAD:
        fprintf(f, "AEAD");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_padding_method_enum(FILE *f, enum padding_method value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_PAD_NONE:
        fprintf(f, "None");
        break;
        
        case KMIP_PAD_OAEP:
        fprintf(f, "OAEP");
        break;
        
        case KMIP_PAD_PKCS5:
        fprintf(f, "PKCS5");
        break;
        
        case KMIP_PAD_SSL3:
        fprintf(f, "SSL3");
        break;
        
        case KMIP_PAD_ZEROS:
        fprintf(f, "Zeros");
        break;
        
        case KMIP_PAD_ANSI_X923:
        fprintf(f, "ANSI X9.23");
        break;
        
        case KMIP_PAD_ISO_10126:
        fprintf(f, "ISO 10126");
        break;
        
        case KMIP_PAD_PKCS1v15:
        fprintf(f, "PKCS1 v1.5");
        break;
        
        case KMIP_PAD_X931:
        fprintf(f, "X9.31");
        break;
        
        case KMIP_PAD_PSS:
        fprintf(f, "PSS");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_hashing_algorithm_enum(FILE *f, enum hashing_algorithm value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_HASH_MD2:
        fprintf(f, "MD2");
        break;
        
        case KMIP_HASH_MD4:
        fprintf(f, "MD4");
        break;
        
        case KMIP_HASH_MD5:
        fprintf(f, "MD5");
        break;
        
        case KMIP_HASH_SHA1:
        fprintf(f, "SHA-1");
        break;
        
        case KMIP_HASH_SHA224:
        fprintf(f, "SHA-224");
        break;
        
        case KMIP_HASH_SHA256:
        fprintf(f, "SHA-256");
        break;
        
        case KMIP_HASH_SHA384:
        fprintf(f, "SHA-384");
        break;
        
        case KMIP_HASH_SHA512:
        fprintf(f, "SHA-512");
        break;
        
        case KMIP_HASH_RIPEMD160:
        fprintf(f, "RIPEMD-160");
        break;
        
        case KMIP_HASH_TIGER:
        fprintf(f, "Tiger");
        break;
        
        case KMIP_HASH_WHIRLPOOL:
        fprintf(f, "Whirlpool");
        break;
        
        case KMIP_HASH_SHA512_224:
        fprintf(f, "SHA-512/224");
        break;
        
        case KMIP_HASH_SHA512_256:
        fprintf(f, "SHA-512/256");
        break;
        
        case KMIP_HASH_SHA3_224:
        fprintf(f, "SHA-3-224");
        break;
        
        case KMIP_HASH_SHA3_256:
        fprintf(f, "SHA-3-256");
        break;
        
        case KMIP_HASH_SHA3_384:
        fprintf(f, "SHA-3-384");
        break;
        
        case KMIP_HASH_SHA3_512:
        fprintf(f, "SHA-3-512");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_key_role_type_enum(FILE *f, enum key_role_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_ROLE_BDK:
        fprintf(f, "BDK");
        break;
        
        case KMIP_ROLE_CVK:
        fprintf(f, "CVK");
        break;
        
        case KMIP_ROLE_DEK:
        fprintf(f, "DEK");
        break;
        
        case KMIP_ROLE_MKAC:
        fprintf(f, "MKAC");
        break;
        
        case KMIP_ROLE_MKSMC:
        fprintf(f, "MKSMC");
        break;
        
        case KMIP_ROLE_MKSMI:
        fprintf(f, "MKSMI");
        break;
        
        case KMIP_ROLE_MKDAC:
        fprintf(f, "MKDAC");
        break;
        
        case KMIP_ROLE_MKDN:
        fprintf(f, "MKDN");
        break;
        
        case KMIP_ROLE_MKCP:
        fprintf(f, "MKCP");
        break;
        
        case KMIP_ROLE_MKOTH:
        fprintf(f, "MKOTH");
        break;
        
        case KMIP_ROLE_KEK:
        fprintf(f, "KEK");
        break;
        
        case KMIP_ROLE_MAC16609:
        fprintf(f, "MAC16609");
        break;
        
        case KMIP_ROLE_MAC97971:
        fprintf(f, "MAC97971");
        break;
        
        case KMIP_ROLE_MAC97972:
        fprintf(f, "MAC97972");
        break;
        
        case KMIP_ROLE_MAC97973:
        fprintf(f, "MAC97973");
        break;
        
        case KMIP_ROLE_MAC97974:
        fprintf(f, "MAC97974");
        break;
        
        case KMIP_ROLE_MAC97975:
        fprintf(f, "MAC97975");
        break;
        
        case KMIP_ROLE_ZPK:
        fprintf(f, "ZPK");
        break;
        
        case KMIP_ROLE_PVKIBM:
        fprintf(f, "PVKIBM");
        break;
        
        case KMIP_ROLE_PVKPVV:
        fprintf(f, "PVKPVV");
        break;
        
        case KMIP_ROLE_PVKOTH:
        fprintf(f, "PVKOTH");
        break;
        
        case KMIP_ROLE_DUKPT:
        fprintf(f, "DUKPT");
        break;
        
        case KMIP_ROLE_IV:
        fprintf(f, "IV");
        break;
        
        case KMIP_ROLE_TRKBK:
        fprintf(f, "TRKBK");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_digital_signature_algorithm_enum(FILE *f, enum digital_signature_algorithm value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_DIGITAL_MD2_WITH_RSA:
        fprintf(f, "MD2 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_MD5_WITH_RSA:
        fprintf(f, "MD5 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_SHA1_WITH_RSA:
        fprintf(f, "SHA-1 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_SHA224_WITH_RSA:
        fprintf(f, "SHA-224 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_SHA256_WITH_RSA:
        fprintf(f, "SHA-256 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_SHA384_WITH_RSA:
        fprintf(f, "SHA-384 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_SHA512_WITH_RSA:
        fprintf(f, "SHA-512 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_RSASSA_PSS:
        fprintf(f, "RSASSA-PSS (PKCS#1 v2.1)");
        break;
        
        case KMIP_DIGITAL_DSA_WITH_SHA1:
        fprintf(f, "DSA with SHA-1");
        break;
        
        case KMIP_DIGITAL_DSA_WITH_SHA224:
        fprintf(f, "DSA with SHA224");
        break;
        
        case KMIP_DIGITAL_DSA_WITH_SHA256:
        fprintf(f, "DSA with SHA256");
        break;
        
        case KMIP_DIGITAL_ECDSA_WITH_SHA1:
        fprintf(f, "ECDSA with SHA-1");
        break;
        
        case KMIP_DIGITAL_ECDSA_WITH_SHA224:
        fprintf(f, "ECDSA with SHA224");
        break;
        
        case KMIP_DIGITAL_ECDSA_WITH_SHA256:
        fprintf(f, "ECDSA with SHA256");
        break;
        
        case KMIP_DIGITAL_ECDSA_WITH_SHA384:
        fprintf(f, "ECDSA with SHA384");
        break;
        
        case KMIP_DIGITAL_ECDSA_WITH_SHA512:
        fprintf(f, "ECDSA with SHA512");
        break;
        
        case KMIP_DIGITAL_SHA3_256_WITH_RSA:
        fprintf(f, "SHA3-256 with RSA Encryption");
        break;
        
        case KMIP_DIGITAL_SHA3_384_WITH_RSA:
        fprintf(f, "SHA3-384 with RSA Encryption");
        break;
        
        case KMIP_DIGITAL_SHA3_512_WITH_RSA:
        fprintf(f, "SHA3-512 with RSA Encryption");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_mask_generator_enum(FILE *f, enum mask_generator value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_MASKGEN_MGF1:
        fprintf(f, "MGF1");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_wrapping_method_enum(FILE *f, enum wrapping_method value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_WRAP_ENCRYPT:
        fprintf(f, "Encrypt");
        break;
        
        case KMIP_WRAP_MAC_SIGN:
        fprintf(f, "MAC/sign");
        break;
        
        case KMIP_WRAP_ENCRYPT_MAC_SIGN:
        fprintf(f, "Encrypt then MAC/sign");
        break;
        
        case KMIP_WRAP_MAC_SIGN_ENCRYPT:
        fprintf(f, "MAC/sign then encrypt");
        break;
        
        case KMIP_WRAP_TR31:
        fprintf(f, "TR-31");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_encoding_option_enum(FILE *f, enum encoding_option value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_ENCODE_NO_ENCODING:
        fprintf(f, "No Encoding");
        break;
        
        case KMIP_ENCODE_TTLV_ENCODING:
        fprintf(f, "TTLV Encoding");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_key_wrap_type_enum(FILE *f, enum key_wrap_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_WRAPTYPE_NOT_WRAPPED:
        fprintf(f, "Not Wrapped");
        break;
        
        case KMIP_WRAPTYPE_AS_REGISTERED:
        fprintf(f, "As Registered");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_credential_type_enum(FILE *f, enum credential_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_CRED_USERNAME_AND_PASSWORD:
        fprintf(f, "Username and Password");
        break;
        
        case KMIP_CRED_DEVICE:
        fprintf(f, "Device");
        break;
        
        case KMIP_CRED_ATTESTATION:
        fprintf(f, "Attestation");
        break;

        case KMIP_CRED_ONE_TIME_PASSWORD:
        fprintf(f, "One Time Password");
        break;

        case KMIP_CRED_HASHED_PASSWORD:
        fprintf(f, "Hashed Password");
        break;

        case KMIP_CRED_TICKET:
        fprintf(f, "Ticket");
        break;

        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_cryptographic_usage_mask_enums(FILE *f, int indent, int32 value)
{
    fprintf(f, "\n");
    
    if((value & KMIP_CRYPTOMASK_SIGN) == KMIP_CRYPTOMASK_SIGN)
    {
        fprintf(f, "%*sSign\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_VERIFY) == KMIP_CRYPTOMASK_VERIFY)
    {
        fprintf(f, "%*sVerify\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_ENCRYPT) == KMIP_CRYPTOMASK_ENCRYPT)
    {
        fprintf(f, "%*sEncrypt\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_DECRYPT) == KMIP_CRYPTOMASK_DECRYPT)
    {
        fprintf(f, "%*sDecrypt\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_WRAP_KEY) == KMIP_CRYPTOMASK_WRAP_KEY)
    {
        fprintf(f, "%*sWrap Key\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_UNWRAP_KEY) == KMIP_CRYPTOMASK_UNWRAP_KEY)
    {
        fprintf(f, "%*sUnwrap Key\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_EXPORT) == KMIP_CRYPTOMASK_EXPORT)
    {
        fprintf(f, "%*sExport\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_MAC_GENERATE) == KMIP_CRYPTOMASK_MAC_GENERATE)
    {
        fprintf(f, "%*sMAC Generate\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_MAC_VERIFY) == KMIP_CRYPTOMASK_MAC_VERIFY)
    {
        fprintf(f, "%*sMAC Verify\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_DERIVE_KEY) == KMIP_CRYPTOMASK_DERIVE_KEY)
    {
        fprintf(f, "%*sDerive Key\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_CONTENT_COMMITMENT) == KMIP_CRYPTOMASK_CONTENT_COMMITMENT)
    {
        fprintf(f, "%*sContent Commitment\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_KEY_AGREEMENT) == KMIP_CRYPTOMASK_KEY_AGREEMENT)
    {
        fprintf(f, "%*sKey Agreement\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_CERTIFICATE_SIGN) == KMIP_CRYPTOMASK_CERTIFICATE_SIGN)
    {
        fprintf(f, "%*sCertificate Sign\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_CRL_SIGN) == KMIP_CRYPTOMASK_CRL_SIGN)
    {
        fprintf(f, "%*sCRL Sign\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM) == KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM)
    {
        fprintf(f, "%*sGenerate Cryptogram\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM) == KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM)
    {
        fprintf(f, "%*sValidate Cryptogram\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT) == KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT)
    {
        fprintf(f, "%*sTranslate Encrypt\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_TRANSLATE_DECRYPT) == KMIP_CRYPTOMASK_TRANSLATE_DECRYPT)
    {
        fprintf(f, "%*sTranslate Decrypt\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_TRANSLATE_WRAP) == KMIP_CRYPTOMASK_TRANSLATE_WRAP)
    {
        fprintf(f, "%*sTranslate Wrap\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_TRANSLATE_UNWRAP) == KMIP_CRYPTOMASK_TRANSLATE_UNWRAP)
    {
        fprintf(f, "%*sTranslate Unwrap\n", indent, "");
    }

    if((value & KMIP_CRYPTOMASK_AUTHENTICATE) == KMIP_CRYPTOMASK_AUTHENTICATE)
    {
        fprintf(f, "%*sAuthenticate\n", indent, "");
    }

    if((value & KMIP_CRYPTOMASK_UNRESTRICTED) == KMIP_CRYPTOMASK_UNRESTRICTED)
    {
        fprintf(f, "%*sUnrestricted\n", indent, "");
    }

    if((value & KMIP_CRYPTOMASK_FPE_ENCRYPT) == KMIP_CRYPTOMASK_FPE_ENCRYPT)
    {
        fprintf(f, "%*sFPE Encrypt\n", indent, "");
    }

    if((value & KMIP_CRYPTOMASK_FPE_DECRYPT) == KMIP_CRYPTOMASK_FPE_DECRYPT)
    {
        fprintf(f, "%*sFPE Decrypt\n", indent, "");
    }
}

void
kmip_print_protection_storage_mask_enum(FILE *f, int indent, int32 value)
{
    fprintf(f, "\n");

    if((value & KMIP_PROTECT_SOFTWARE) == KMIP_PROTECT_SOFTWARE)
    {
        fprintf(f, "%*sSoftware\n", indent, "");
    }

    if((value & KMIP_PROTECT_HARDWARE) == KMIP_PROTECT_HARDWARE)
    {
        fprintf(f, "%*sHardware\n", indent, "");
    }

    if((value & KMIP_PROTECT_ON_PROCESSOR) == KMIP_PROTECT_ON_PROCESSOR)
    {
        fprintf(f, "%*sOn Processor\n", indent, "");
    }

    if((value & KMIP_PROTECT_ON_SYSTEM) == KMIP_PROTECT_ON_SYSTEM)
    {
        fprintf(f, "%*sOn System\n", indent, "");
    }

    if((value & KMIP_PROTECT_OFF_SYSTEM) == KMIP_PROTECT_OFF_SYSTEM)
    {
        fprintf(f, "%*sOff System\n", indent, "");
    }

    if((value & KMIP_PROTECT_HYPERVISOR) == KMIP_PROTECT_HYPERVISOR)
    {
        fprintf(f, "%*sHypervisor\n", indent, "");
    }

    if((value & KMIP_PROTECT_OPERATING_SYSTEM) == KMIP_PROTECT_OPERATING_SYSTEM)
    {
        fprintf(f, "%*sOperating System\n", indent, "");
    }

    if((value & KMIP_PROTECT_CONTAINER) == KMIP_PROTECT_CONTAINER)
    {
        fprintf(f, "%*sContainer\n", indent, "");
    }

    if((value & KMIP_PROTECT_ON_PREMISES) == KMIP_PROTECT_ON_PREMISES)
    {
        fprintf(f, "%*sOn Premises\n", indent, "");
    }

    if((value & KMIP_PROTECT_OFF_PREMISES) == KMIP_PROTECT_OFF_PREMISES)
    {
        fprintf(f, "%*sOff Premises\n", indent, "");
    }

    if((value & KMIP_PROTECT_SELF_MANAGED) == KMIP_PROTECT_SELF_MANAGED)
    {
        fprintf(f, "%*sSelf Managed\n", indent, "");
    }

    if((value & KMIP_PROTECT_OUTSOURCED) == KMIP_PROTECT_OUTSOURCED)
    {
        fprintf(f, "%*sOutsourced\n", indent, "");
    }

    if((value & KMIP_PROTECT_VALIDATED) == KMIP_PROTECT_VALIDATED)
    {
        fprintf(f, "%*sValidated\n", indent, "");
    }

    if((value & KMIP_PROTECT_SAME_JURISDICTION) == KMIP_PROTECT_SAME_JURISDICTION)
    {
        fprintf(f, "%*sSame Jurisdiction\n", indent, "");
    }
}

void
kmip_print_protection_storage_masks(FILE *f, int indent, ProtectionStorageMasks *value)
{
    fprintf(f, "%*sProtection Storage Masks @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->masks != NULL)
    {
        fprintf(f, "%*sMasks: %zu\n", indent + 2, "", value->masks->size);
        LinkedListItem *curr = value->masks->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sMask: %zu", indent + 4, "", count);
            int32 mask = *(int32 *)curr->data;
            kmip_print_protection_storage_mask_enum(f, indent + 6, mask);

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_print_integer(FILE *f, int32 value)
{
    switch(value)
    {
        case KMIP_UNSET:
        fprintf(f, "-");
        break;
        
        default:
        fprintf(f, "%d", value);
        break;
    };
}

void
kmip_print_bool(FILE *f, int32 value)
{
    switch(value)
    {
        case KMIP_TRUE:
        fprintf(f, "True");
        break;
        
        case KMIP_FALSE:
        fprintf(f, "False");
        break;
        
        default:
        fprintf(f, "-");
        break;
    };
}

void
kmip_print_text_string(FILE *f, int indent, const char *name, TextString *value)
{
    fprintf(f, "%*s%s @ %p\n", indent, "", name, (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sValue: %.*s\n", indent + 2, "", (int)value->size, value->value);
    }
    
    return;
}

void
kmip_print_byte_string(FILE *f, int indent, const char *name, ByteString *value)
{
    fprintf(f, "%*s%s @ %p\n", indent, "", name, (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sValue:", indent + 2, "");
        for(size_t i = 0; i < value->size; i++)
        {
            if(i % 16 == 0)
            {
                fprintf(f, "\n%*s0x", indent + 4, "");
            }
            fprintf(f, "%02X", value->value[i]);
        }
        fprintf(f, "\n");
    }
    
    return;
}

void
kmip_print_date_time(FILE *f, int64 value)
{
    if(value <= KMIP_UNSET)
    {
        fprintf(f, "-");
    }
    else
    {
        /* NOTE: This cast is only problematic if the current year is 2038+
        *  AND time_t is equivalent to an int32 data type. If these conditions
        *  are true, the cast will overflow and the time value will appear to
        *  be set in 1901+.
        *
        *  No system should be using 32-bit time in 2038. If this impacts you,
        *  upgrade your system.
        */
        time_t t = (time_t)value;

        /* NOTE: The data pointed to by utc_time may change if gmtime is
        *  called again before utc_time is used.
        */
        struct tm *utc_time = gmtime(&t);
        fprintf(f, "%s", asctime(utc_time));
    }
    return;
}

void
kmip_print_protocol_version(FILE *f, int indent, ProtocolVersion *value)
{
    fprintf(f, "%*sProtocol Version @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sMajor: %d\n", indent + 2, "", value->major);
        fprintf(f, "%*sMinor: %d\n", indent + 2, "", value->minor);
    }
    
    return;
}

void
kmip_print_name(FILE *f, int indent, Name *value)
{
    fprintf(f, "%*sName @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Name Value", value->value);
        
        fprintf(f, "%*sName Type: ", indent + 2, "");
        kmip_print_name_type_enum(f, value->type);
        fprintf(f, "\n");
    }
}

void
kmip_print_nonce(FILE *f, int indent, Nonce *value)
{
    fprintf(f, "%*sNonce @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_byte_string(f, indent + 2, "Nonce ID", value->nonce_id);
        kmip_print_byte_string(f, indent + 2, "Nonce Value", value->nonce_value);
    }
    
    return;
}

void
kmip_print_application_specific_information(FILE *f, int indent, ApplicationSpecificInformation *value)
{
    fprintf(f, "%*sApplication Specific Information @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Application Namespace", value->application_namespace);
        kmip_print_text_string(f, indent + 2, "Application Data", value->application_data);
    }
}

void
kmip_print_cryptographic_parameters(FILE *f, int indent, CryptographicParameters *value)
{
    fprintf(f, "%*sCryptographic Parameters @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sBlock Cipher Mode: ", indent + 2, "");
        kmip_print_block_cipher_mode_enum(f, value->block_cipher_mode);
        fprintf(f, "\n");
        
        fprintf(f, "%*sPadding Method: ", indent + 2, "");
        kmip_print_padding_method_enum(f, value->padding_method);
        fprintf(f, "\n");
        
        fprintf(f, "%*sHashing Algorithm: ", indent + 2, "");
        kmip_print_hashing_algorithm_enum(f, value->hashing_algorithm);
        fprintf(f, "\n");
        
        fprintf(f, "%*sKey Role Type: ", indent + 2, "");
        kmip_print_key_role_type_enum(f, value->key_role_type);
        fprintf(f, "\n");
        
        fprintf(f, "%*sDigital Signature Algorithm: ", indent + 2, "");
        kmip_print_digital_signature_algorithm_enum(f, value->digital_signature_algorithm);
        fprintf(f, "\n");
        
        fprintf(f, "%*sCryptographic Algorithm: ", indent + 2, "");
        kmip_print_cryptographic_algorithm_enum(f, value->cryptographic_algorithm);
        fprintf(f, "\n");
        
        fprintf(f, "%*sRandom IV: ", indent + 2, "");
        kmip_print_bool(f, value->random_iv);
        fprintf(f, "\n");
        
        fprintf(f, "%*sIV Length: ", indent + 2, "");
        kmip_print_integer(f, value->iv_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sTag Length: ", indent + 2, "");
        kmip_print_integer(f, value->tag_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sFixed Field Length: ", indent + 2, "");
        kmip_print_integer(f, value->fixed_field_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sInvocation Field Length: ", indent + 2, "");
        kmip_print_integer(f, value->invocation_field_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sCounter Length: ", indent + 2, "");
        kmip_print_integer(f, value->counter_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sInitial Counter Value: ", indent + 2, "");
        kmip_print_integer(f, value->initial_counter_value);
        fprintf(f, "\n");
        
        fprintf(f, "%*sSalt Length: ", indent + 2, "");
        kmip_print_integer(f, value->salt_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sMask Generator: ", indent + 2, "");
        kmip_print_mask_generator_enum(f, value->mask_generator);
        fprintf(f, "\n");
        
        fprintf(f, "%*sMask Generator Hashing Algorithm: ", indent + 2, "");
        kmip_print_hashing_algorithm_enum(f, value->mask_generator_hashing_algorithm);
        fprintf(f, "\n");
        
        kmip_print_byte_string(f, indent + 2, "P Source", value->p_source);
        
        fprintf(f, "%*sTrailer Field: ", indent + 2, "");
        kmip_print_integer(f, value->trailer_field);
        fprintf(f, "\n");
    }
}

void
kmip_print_encryption_key_information(FILE *f, int indent, EncryptionKeyInformation *value)
{
    fprintf(f, "%*sEncryption Key Information @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        
        kmip_print_cryptographic_parameters(f, indent + 2, value->cryptographic_parameters);
    }
}

void
kmip_print_mac_signature_key_information(FILE *f, int indent, MACSignatureKeyInformation *value)
{
    fprintf(f, "%*sMAC/Signature Key Information @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        
        kmip_print_cryptographic_parameters(f, indent + 2, value->cryptographic_parameters);
    }
}

void
kmip_print_key_wrapping_data(FILE *f, int indent, KeyWrappingData *value)
{
    fprintf(f, "%*sKey Wrapping Data @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sWrapping Method: ", indent + 2, "");
        kmip_print_wrapping_method_enum(f, value->wrapping_method);
        fprintf(f, "\n");
        
        kmip_print_encryption_key_information(f, indent + 2, value->encryption_key_info);
        
        kmip_print_mac_signature_key_information(f, indent + 2, value->mac_signature_key_info);
        
        kmip_print_byte_string(f, indent + 2, "MAC/Signature", value->mac_signature);
        
        kmip_print_byte_string(f, indent + 2, "IV/Counter/Nonce", value->iv_counter_nonce);
        
        fprintf(f, "%*sEncoding Option: ", indent + 2, "");
        kmip_print_encoding_option_enum(f, value->encoding_option);
        fprintf(f, "\n");
    }
    
    return;
}

void
kmip_print_attribute_value(FILE *f, int indent, enum attribute_type type, void *value)
{
    fprintf(f, "%*sAttribute Value: ", indent, "");
    
    switch(type)
    {
        case KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION:
        {
            fprintf(f, "\n");
            kmip_print_application_specific_information(f, indent + 2, value);
        }
        break;

        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        fprintf(f, "\n");
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value);
        break;
        
        case KMIP_ATTR_NAME:
        fprintf(f, "\n");
        kmip_print_name(f, indent + 2, value);
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        kmip_print_object_type_enum(f, *(enum object_type *)value);
        fprintf(f, "\n");
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        kmip_print_cryptographic_algorithm_enum(f, *(enum cryptographic_algorithm *)value);
        fprintf(f, "\n");
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        fprintf(f, "%d\n", *(int32 *)value);
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        fprintf(f, "\n");
        kmip_print_text_string(f, indent + 2, "Operation Policy Name", value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        kmip_print_cryptographic_usage_mask_enums(f, indent + 2, *(int32 *)value);
        break;
        
        case KMIP_ATTR_STATE:
        kmip_print_state_enum(f, *(enum state *)value);
        fprintf(f, "\n");
        break;

        case KMIP_ATTR_OBJECT_GROUP:
        {
            fprintf(f, "\n");
            kmip_print_text_string(f, indent + 2, "Object Group", value);
        }
        break;

        case KMIP_ATTR_CONTACT_INFORMATION:
        {
            fprintf(f, "\n");
            kmip_print_text_string(f, indent + 2, "Contact Information", value);
        }
        break;

        case KMIP_ATTR_ACTIVATION_DATE:
        case KMIP_ATTR_DEACTIVATION_DATE:
        case KMIP_ATTR_PROCESS_START_DATE:
        case KMIP_ATTR_PROTECT_STOP_DATE:
        {
            fprintf(f, "\n");
            kmip_print_date_time(f, *(int64 *)value);
        } break;

        case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
        {
            fprintf(f, "\n");
            kmip_print_cryptographic_parameters(f, indent + 2, value);
        } break;

        default:
        fprintf(f, "Unknown\n");
        break;
    };
}

void
kmip_print_attribute(FILE *f, int indent, Attribute *value)
{
    fprintf(f, "%*sAttribute @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sAttribute Name: ", indent + 2, "");
        kmip_print_attribute_type_enum(f, value->type);
        fprintf(f, "\n");
        
        fprintf(f, "%*sAttribute Index: ", indent + 2, "");
        kmip_print_integer(f, value->index);
        fprintf(f, "\n");
        
        kmip_print_attribute_value(f, indent + 2, value->type, value->value);
    }
    
    return;
}

void
kmip_print_key_material(FILE *f, int indent, enum key_format_type format, void *value)
{
    switch(format)
    {
        case KMIP_KEYFORMAT_RAW:
        case KMIP_KEYFORMAT_OPAQUE:
        case KMIP_KEYFORMAT_PKCS1:
        case KMIP_KEYFORMAT_PKCS8:
        case KMIP_KEYFORMAT_X509:
        case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
        kmip_print_byte_string(f, indent, "Key Material", (ByteString *)value);
        break;
        
        default:
        fprintf(f, "%*sUnknown Key Material @ %p\n", indent, "", value);
        break;
    };
}

void
kmip_print_key_value(FILE *f, int indent, enum type type, enum key_format_type format, void *value)
{
    switch(type)
    {
        case KMIP_TYPE_BYTE_STRING:
        kmip_print_byte_string(f, indent, "Key Value", (ByteString *)value);
        break;
        
        case KMIP_TYPE_STRUCTURE:
        fprintf(f, "%*sKey Value @ %p\n", indent, "", value);
        
        if(value != NULL)
        {
            KeyValue key_value = *(KeyValue *)value;
            kmip_print_key_material(f, indent + 2, format, key_value.key_material);
            fprintf(f, "%*sAttributes: %zu\n", indent + 2, "", key_value.attribute_count);
            for(size_t i = 0; i < key_value.attribute_count; i++)
            {
                kmip_print_attribute(f, indent + 2, &key_value.attributes[i]);
            }
        }
        break;
        
        default:
        fprintf(f, "%*sUnknown Key Value @ %p\n", indent, "", value);
        break;
    };
}

void
kmip_print_key_block(FILE *f, int indent, KeyBlock *value)
{
    fprintf(f, "%*sKey Block @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sKey Format Type: ", indent + 2, "");
        kmip_print_key_format_type_enum(f, value->key_format_type);
        fprintf(f, "\n");
        
        fprintf(f, "%*sKey Compression Type: ", indent + 2, "");
        kmip_print_key_compression_type_enum(f, value->key_compression_type);
        fprintf(f, "\n");
        
        kmip_print_key_value(f, indent + 2, value->key_value_type, value->key_format_type, value->key_value);
        
        fprintf(f, "%*sCryptographic Algorithm: ", indent + 2, "");
        kmip_print_cryptographic_algorithm_enum(f, value->cryptographic_algorithm);
        fprintf(f, "\n");
        
        fprintf(f, "%*sCryptographic Length: %d\n", indent + 2, "", value->cryptographic_length);
        
        kmip_print_key_wrapping_data(f, indent + 2, value->key_wrapping_data);
    }
    
    return;
}

void
kmip_print_symmetric_key(FILE *f, int indent, SymmetricKey *value)
{
    fprintf(f, "%*sSymmetric Key @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_key_block(f, indent + 2, value->key_block);
    }
    
    return;
}

void
kmip_print_object(FILE *f, int indent, enum object_type type, void *value)
{
    switch(type)
    {
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
        kmip_print_symmetric_key(f, indent, (SymmetricKey *)value);
        break;
        
        default:
        fprintf(f, "%*sUnknown Object @ %p\n", indent, "", value);
        break;
    };
}

void
kmip_print_key_wrapping_specification(FILE *f, int indent, KeyWrappingSpecification *value)
{
    fprintf(f, "%*sKey Wrapping Specification @ %p\n", indent, "", (void *)value);
}

void
kmip_print_attributes(FILE *f, int indent, Attributes *value)
{
    fprintf(f, "%*sAttributes @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->attribute_list != NULL)
    {
        fprintf(f, "%*sAttributes: %zu\n", indent + 2, "", value->attribute_list->size);
        LinkedListItem *curr = value->attribute_list->head;
        while(curr != NULL)
        {
            Attribute *attribute = (Attribute *)curr->data;
            kmip_print_attribute(f, indent + 4, attribute);

            curr = curr->next;
        }
    }
}

void
kmip_print_template_attribute(FILE *f, int indent, TemplateAttribute *value)
{
    fprintf(f, "%*sTemplate Attribute @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sNames: %zu\n", indent + 2, "", value->name_count);
        for(size_t i = 0; i < value->name_count; i++)
        {
            kmip_print_name(f, indent + 4, &value->names[i]);
        }
        
        fprintf(f, "%*sAttributes: %zu\n", indent + 2, "", value->attribute_count);
        for(size_t i = 0; i< value->attribute_count; i++)
        {
            kmip_print_attribute(f, indent + 4, &value->attributes[i]);
        }
    }
}

void
kmip_print_create_request_payload(FILE *f, int indent, CreateRequestPayload *value)
{
    fprintf(f, "%*sCreate Request Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sObject Type: ", indent + 2, "");
        kmip_print_object_type_enum(f, value->object_type);
        fprintf(f, "\n");
        
        kmip_print_template_attribute(f, indent + 2, value->template_attribute);
        kmip_print_attributes(f, indent + 2, value->attributes);
        kmip_print_protection_storage_masks(f, indent + 2, value->protection_storage_masks);
    }
}

void
kmip_print_create_response_payload(FILE *f, int indent, CreateResponsePayload *value)
{
    fprintf(f, "%*sCreate Response Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sObject Type: ", indent + 2, "");
        kmip_print_object_type_enum(f, value->object_type);
        fprintf(f, "\n");
        
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        kmip_print_template_attribute(f, indent + 2, value->template_attribute);
    }
}

void
kmip_print_get_request_payload(FILE *f, int indent, GetRequestPayload *value)
{
    fprintf(f, "%*sGet Request Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        
        fprintf(f, "%*sKey Format Type: ", indent + 2, "");
        kmip_print_key_format_type_enum(f, value->key_format_type);
        fprintf(f, "\n");
        
        fprintf(f, "%*sKey Wrap Type: ", indent + 2, "");
        kmip_print_key_wrap_type_enum(f, value->key_wrap_type);
        fprintf(f, "\n");
        
        fprintf(f, "%*sKey Compression Type: ", indent + 2, "");
        kmip_print_key_compression_type_enum(f, value->key_compression_type);
        fprintf(f, "\n");
        
        kmip_print_key_wrapping_specification(f, indent + 2, value->key_wrapping_spec);
    }
}

void
kmip_print_get_response_payload(FILE *f, int indent, GetResponsePayload *value)
{
    fprintf(f, "%*sGet Response Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sObject Type: ", indent + 2, "");
        kmip_print_object_type_enum(f, value->object_type);
        fprintf(f, "\n");
        
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        kmip_print_object(f, indent + 2, value->object_type, value->object);
    }
    
    return;
}

void
kmip_print_destroy_request_payload(FILE *f, int indent, DestroyRequestPayload *value)
{
    fprintf(f, "%*sDestroy Request Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
    }
}

void
kmip_print_destroy_response_payload(FILE *f, int indent, DestroyResponsePayload *value)
{
    fprintf(f, "%*sDestroy Response Payload @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
    }
}

void
kmip_print_request_payload(FILE *f, int indent, enum operation type, void *value)
{
    switch(type)
    {
        case KMIP_OP_CREATE:
        kmip_print_create_request_payload(f, indent, value);
        break;
        
        case KMIP_OP_GET:
        kmip_print_get_request_payload(f, indent, (GetRequestPayload *)value);
        break;
        
        case KMIP_OP_DESTROY:
        kmip_print_destroy_request_payload(f, indent, value);
        break;
        
        case KMIP_OP_QUERY:
        kmip_print_query_request_payload(f, indent, value);
        break;

        case KMIP_OP_LOCATE:
        kmip_print_locate_request_payload(f, indent, value);
        break;

        default:
        fprintf(f, "%*sUnknown Payload @ %p\n", indent, "", value);
        break;
    };
}

void
kmip_print_response_payload(FILE *f, int indent, enum operation type, void *value)
{
    switch(type)
    {
        case KMIP_OP_CREATE:
        kmip_print_create_response_payload(f, indent, value);
        break;
        
        case KMIP_OP_GET:
        kmip_print_get_response_payload(f, indent, (GetResponsePayload *)value);
        break;
        
        case KMIP_OP_DESTROY:
        kmip_print_destroy_response_payload(f, indent, value);
        break;
        
        case KMIP_OP_QUERY:
        kmip_print_query_response_payload(f, indent, value);
        break;

        case KMIP_OP_LOCATE:
        kmip_print_locate_response_payload(f, indent, value);
        break;

        default:
        fprintf(f, "%*sUnknown Payload @ %p\n", indent, "", value);
        break;
    };
}

void
kmip_print_username_password_credential(FILE *f, int indent, UsernamePasswordCredential *value)
{
    fprintf(f, "%*sUsername/Password Credential @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Username", value->username);
        kmip_print_text_string(f, indent + 2, "Password", value->password);
    }
}

void
kmip_print_device_credential(FILE *f, int indent, DeviceCredential *value)
{
    fprintf(f, "%*sDevice Credential @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Device Serial Number", value->device_serial_number);
        kmip_print_text_string(f, indent + 2, "Password", value->password);
        kmip_print_text_string(f, indent + 2, "Device Identifier", value->device_identifier);
        kmip_print_text_string(f, indent + 2, "Network Identifier", value->network_identifier);
        kmip_print_text_string(f, indent + 2, "Machine Identifier", value->machine_identifier);
        kmip_print_text_string(f, indent + 2, "Media Identifier", value->media_identifier);
    }
}

void
kmip_print_attestation_credential(FILE *f, int indent, AttestationCredential *value)
{
    fprintf(f, "%*sAttestation Credential @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_nonce(f, indent + 2, value->nonce);
        fprintf(f, "%*sAttestation Type: ", indent + 2, "");
        kmip_print_attestation_type_enum(f, value->attestation_type);
        fprintf(f, "\n");
        kmip_print_byte_string(f, indent + 2, "Attestation Measurement", value->attestation_measurement);
        kmip_print_byte_string(f, indent + 2, "Attestation Assertion", value->attestation_assertion);
    }
}

void
kmip_print_credential_value(FILE *f, int indent, enum credential_type type, void *value)
{
    fprintf(f, "%*sCredential Value @ %p\n", indent, "", value);
    
    if(value != NULL)
    {
        switch(type)
        {
            case KMIP_CRED_USERNAME_AND_PASSWORD:
            kmip_print_username_password_credential(f, indent + 2, value);
            break;
            
            case KMIP_CRED_DEVICE:
            kmip_print_device_credential(f, indent + 2, value);
            break;
            
            case KMIP_CRED_ATTESTATION:
            kmip_print_attestation_credential(f, indent + 2, value);
            break;
            
            default:
            fprintf(f, "%*sUnknown Credential @ %p\n", indent + 2, "", value);
            break;
        };
    }
}

void
kmip_print_credential(FILE *f, int indent, Credential *value)
{
    fprintf(f, "%*sCredential @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sCredential Type: ", indent + 2, "");
        kmip_print_credential_type_enum(f, value->credential_type);
        fprintf(f, "\n");
        
        kmip_print_credential_value(f, indent + 2, value->credential_type, value->credential_value);
    }
}

void
kmip_print_authentication(FILE *f, int indent, Authentication *value)
{
    fprintf(f, "%*sAuthentication @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_credential(f, indent + 2, value->credential);
    }
}

void
kmip_print_request_batch_item(FILE *f, int indent, RequestBatchItem *value)
{
    fprintf(f, "%*sRequest Batch Item @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sOperation: ", indent + 2, "");
        kmip_print_operation_enum(f, value->operation);
        fprintf(f, "\n");

        fprintf(f, "%*sEphemeral: ", indent + 2, "");
        kmip_print_bool(f, value->ephemeral);
        fprintf(f, "\n");

        kmip_print_byte_string(f, indent + 2, "Unique Batch Item ID", value->unique_batch_item_id);
        kmip_print_request_payload(f, indent + 2, value->operation, value->request_payload);
    }
}

void
kmip_print_response_batch_item(FILE *f, int indent, ResponseBatchItem *value)
{
    fprintf(f, "%*sResponse Batch Item @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sOperation: ", indent + 2, "");
        kmip_print_operation_enum(f, value->operation);
        fprintf(f, "\n");
        
        kmip_print_byte_string(f, indent + 2, "Unique Batch Item ID", value->unique_batch_item_id);
        
        fprintf(f, "%*sResult Status: ", indent + 2, "");
        kmip_print_result_status_enum(f, value->result_status);
        fprintf(f, "\n");
        
        fprintf(f, "%*sResult Reason: ", indent + 2, "");
        kmip_print_result_reason_enum(f, value->result_reason);
        fprintf(f, "\n");
        
        kmip_print_text_string(f, indent + 2, "Result Message", value->result_message);
        kmip_print_byte_string(f, indent + 2, "Asynchronous Correlation Value", value->asynchronous_correlation_value);
        
        kmip_print_response_payload(f, indent + 2, value->operation, value->response_payload);
    }
    
    return;
}

void
kmip_print_request_header(FILE *f, int indent, RequestHeader *value)
{
    fprintf(f, "%*sRequest Header @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_protocol_version(f, indent + 2, value->protocol_version);

        fprintf(f, "%*sMaximum Response Size: ", indent + 2, "");
        kmip_print_integer(f, value->maximum_response_size);
        fprintf(f, "\n");

        kmip_print_text_string(f, indent + 2, "Client Correlation Value", value->client_correlation_value);
        kmip_print_text_string(f, indent + 2, "Server Correlation Value", value->server_correlation_value);
        fprintf(f, "%*sAsynchronous Indicator: ", indent + 2, "");
        kmip_print_bool(f, value->asynchronous_indicator);
        fprintf(f, "\n");
        fprintf(f, "%*sAttestation Capable Indicator: ", indent + 2, "");
        kmip_print_bool(f, value->attestation_capable_indicator);
        fprintf(f, "\n");
        fprintf(f, "%*sAttestation Types: %zu\n", indent + 2, "", value->attestation_type_count);
        for(size_t i = 0; i < value->attestation_type_count; i++)
        {
            /* TODO (ph) Add enum value -> string functionality. */
            fprintf(f, "%*sAttestation Type: %s\n", indent + 4, "", "???");
        }
        kmip_print_authentication(f, indent + 2, value->authentication);
        fprintf(f, "%*sBatch Error Continuation Option: ", indent + 2, "");
        kmip_print_batch_error_continuation_option(f, value->batch_error_continuation_option);
        fprintf(f, "\n");
        fprintf(f, "%*sBatch Order Option: ", indent + 2, "");
        kmip_print_bool(f, value->batch_order_option);
        fprintf(f, "\n");
        fprintf(f, "%*sTime Stamp: ", indent + 2, "");
        kmip_print_date_time(f, value->time_stamp);
        fprintf(f, "\n");
        fprintf(f, "%*sBatch Count: %d\n", indent + 2, "", value->batch_count);
    }
}

void
kmip_print_response_header(FILE *f, int indent, ResponseHeader *value)
{
    fprintf(f, "%*sResponse Header @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_protocol_version(f, indent + 2, value->protocol_version);
        fprintf(f, "%*sTime Stamp: ", indent + 2, "");
        kmip_print_date_time(f, value->time_stamp);
        fprintf(f, "\n");
        kmip_print_nonce(f, indent + 2, value->nonce);

        kmip_print_byte_string(f, indent + 2, "Server Hashed Password", value->server_hashed_password);

        fprintf(f, "%*sAttestation Types: %zu\n", indent + 2, "", value->attestation_type_count);
        for(size_t i = 0; i < value->attestation_type_count; i++)
        {
            /* TODO (ph) Add enum value -> string functionality. */
            fprintf(f, "%*sAttestation Type: %s\n", indent + 4, "", "???");
        }
        kmip_print_text_string(f, indent + 2, "Client Correlation Value", value->client_correlation_value);
        kmip_print_text_string(f, indent + 2, "Server Correlation Value", value->server_correlation_value);
        fprintf(f, "%*sBatch Count: %d\n", indent + 2, "", value->batch_count);
    }
}

void
kmip_print_request_message(FILE *f, RequestMessage *value)
{
    fprintf(f, "Request Message @ %p\n", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_request_header(f, 2, value->request_header);
        fprintf(f, "%*sBatch Items: %zu\n", 2, "", value->batch_count);
        
        for(size_t i = 0; i < value->batch_count; i++)
        {
            kmip_print_request_batch_item(f, 4, &value->batch_items[i]);
        }
    }
    
    return;
}

void
kmip_print_response_message(FILE *f, ResponseMessage *value)
{
    fprintf(f, "Response Message @ %p\n", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_response_header(f, 2, value->response_header);
        fprintf(f, "  Batch Items: %zu\n", value->batch_count);
        
        for(size_t i = 0; i < value->batch_count; i++)
        {
            kmip_print_response_batch_item(f, 4, &value->batch_items[i]);
        }
    }
    
    return;
}

void
kmip_print_query_function_enum(FILE* f, int indent, enum query_function value)
{
    if(value == 0)
    {
        fprintf(f, "%*s-", indent, "");
        return;
    }

    switch(value)
    {
        /* KMIP 1.0 */
        case KMIP_QUERY_OPERATIONS:
            fprintf(f, "%*sOperations", indent, "");
            break;
        case KMIP_QUERY_OBJECTS:
            fprintf(f, "%*sObjects", indent, "");
            break;
        case KMIP_QUERY_SERVER_INFORMATION:
            fprintf(f, "%*sServer Information", indent, "");
            break;
        case KMIP_QUERY_APPLICATION_NAMESPACES:
            fprintf(f, "%*sApplication namespaces", indent, "");
            break;
        /* KMIP 1.1 */
        case KMIP_QUERY_EXTENSION_LIST:
            fprintf(f, "%*sExtension list", indent, "");
            break;
        case KMIP_QUERY_EXTENSION_MAP:
            fprintf(f, "%*sExtension Map", indent, "");
            break;
        /* KMIP 1.2 */
        case KMIP_QUERY_ATTESTATION_TYPES:
            fprintf(f, "%*sAttestation Types", indent, "");
            break;
        /* KMIP 1.3 */
        case KMIP_QUERY_RNGS:
            fprintf(f, "%*sRNGS", indent, "");
            break;
        case KMIP_QUERY_VALIDATIONS:
            fprintf(f, "%*sValidations", indent, "");
            break;
        case KMIP_QUERY_PROFILES:
            fprintf(f, "%*sProfiles", indent, "");
            break;
        case KMIP_QUERY_CAPABILITIES:
            fprintf(f, "%*sCapabilities", indent, "");
            break;
        case KMIP_QUERY_CLIENT_REGISTRATION_METHODS:
            fprintf(f, "%*sRegistration Methods", indent, "");
            break;
        /* KMIP 2.0 */
        case KMIP_QUERY_DEFAULTS_INFORMATION:
            fprintf(f, "%*sDefaults Information", indent, "");
            break;
        case KMIP_QUERY_STORAGE_PROTECTION_MASKS:
            fprintf(f, "%*sStorage Protection Masks", indent, "");
            break;

        default:
        fprintf(f, "%*sUnknown", indent, "");
        break;
    };
}

void
kmip_print_query_functions(FILE* f, int indent, Functions* value)
{
    fprintf(f, "%*sQuery Functions @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->function_list != NULL)
    {
        fprintf(f, "%*sFunctions: %zu\n", indent + 2, "", value->function_list->size);
        LinkedListItem *curr = value->function_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sFunction: %zu: ", indent + 4, "", count);
            int32 func = *(int32 *)curr->data;
            kmip_print_query_function_enum(f, indent + 6, func);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}


void
kmip_print_operations(FILE* f, int indent, Operations *value)
{
    fprintf(f, "%*sOperations @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->operation_list != NULL)
    {
        fprintf(f, "%*sOperations: %zu\n", indent + 2, "", value->operation_list->size);
        LinkedListItem *curr = value->operation_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sOperation: %zu: ", indent + 4, "", count);
            int32 oper = *(int32 *)curr->data;
            kmip_print_operation_enum(f, oper);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_print_object_types(FILE* f, int indent, ObjectTypes* value)
{
    fprintf(f, "%*sObjects @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->object_list != NULL )
    {
        fprintf(f, "%*sObjects: %zu\n", indent + 2, "", value->object_list->size);
        LinkedListItem *curr = value->object_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sObject: %zu: ", indent + 4, "", count);
            int32 obj = *(int32 *)curr->data;
            kmip_print_object_type_enum(f, obj);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_print_attribute_names(FILE* f, int indent, AttributeNames* value)
{
    fprintf(f, "%*sAttribute Names @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->name_list != NULL)
    {
        fprintf(f, "%*sNames: %zu\n", indent + 2, "", value->name_list->size);
        LinkedListItem *curr = value->name_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sName: %zu: ", indent + 4, "", count);
            TextString* attrname = (TextString*)curr->data;
            kmip_print_text_string(f, indent + 2, "Attribute Name", attrname);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_print_get_attributes_request_payload(FILE* f, int indent, GetAttributesRequestPayload *value)
{
    fprintf(f,"%*sGet Attributes Request Payload @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        kmip_print_attribute_names(f, indent + 2, value->attribute_names);
    }
}

void
kmip_print_get_attributes_response_payload(FILE* f, int indent, GetAttributesResponsePayload *value)
{
    fprintf(f,"%*sGet Attributes Response Payload @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        kmip_print_attributes(f, indent + 2, value->attributes);
    }
}

void
kmip_print_alternative_endpoints(FILE* f, int indent, AltEndpoints* value)
{
    fprintf(f, "%*sAlt Endpointss @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->endpoint_list != NULL )
    {
        fprintf(f, "%*sAlt Endpoints: %zu\n", indent + 2, "", value->endpoint_list->size);
        LinkedListItem *curr = value->endpoint_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sEndpoint: %zu: ", indent + 4, "", count);
            TextString* endpoint = (TextString*)curr->data;
            kmip_print_text_string(f, indent + 2, "Endpoint", endpoint);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_print_server_information(FILE* f, int indent, ServerInformation* value)
{
    fprintf(f,"%*sServer Information @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(f,indent + 2, "Server Name", value->server_name);
        kmip_print_text_string(f,indent + 2, "Server Serial Number", value->server_serial_number);
        kmip_print_text_string(f,indent + 2, "Server Version", value->server_version);
        kmip_print_text_string(f,indent + 2, "Server Load", value->server_load);
        kmip_print_text_string(f,indent + 2, "Product Name", value->product_name);
        kmip_print_text_string(f,indent + 2, "Build Level", value->build_level);
        kmip_print_text_string(f,indent + 2, "Build Date", value->build_date);
        kmip_print_text_string(f,indent + 2, "Cluster info", value->cluster_info);

        kmip_print_alternative_endpoints(f,indent+2, value->alternative_failover_endpoints);
    }
}

void
kmip_print_query_response_payload(FILE* f, int indent, QueryResponsePayload *value)
{
    fprintf(f,"%*sQuery response @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_operations(f,indent, value->operations);
        kmip_print_object_types(f,indent, value->objects);
        kmip_print_text_string(f,indent, "Vendor ID", value->vendor_identification);
        kmip_print_server_information(f,indent, value->server_information);
    }
}

void
kmip_print_query_request_payload(FILE* f, int indent, QueryRequestPayload *value)
{
    fprintf(f,"%*sQuery request @ %p\n", indent, "", (void *)value);

    if(value != NULL)
        kmip_print_query_functions(f, indent, value->functions);
}

void
kmip_print_locate_request_payload(FILE* f, int indent, LocateRequestPayload * value)
{
    fprintf(f, "%*sLocate Request Payload @ %p\n", indent, "", (void *)value);
    if (value)
    {
        fprintf(f, "%*sMaximum items: ", indent + 2, "");
        kmip_print_integer(f, value->maximum_items);
        fprintf(f, "\n");

        fprintf(f, "%*sOffset items: ", indent + 2, "");
        kmip_print_integer(f, value->offset_items);
        fprintf(f, "\n");

        fprintf(f, "%*sStorage status: ", indent + 2, "");
        kmip_print_integer(f, value->storage_status_mask);
        fprintf(f, "\n");

        if(value->attributes)
            kmip_print_attributes(f, indent + 2, value->attributes);
    }
}

void
kmip_print_locate_response_payload(FILE* f, int indent, LocateResponsePayload *value)
{
    fprintf(f, "%*sLocated Items: ", indent + 2, "");
    kmip_print_integer(f, value->located_items);
    fprintf(f, "\n");

    kmip_print_unique_identifiers(f, indent, value->unique_ids);
}

void
kmip_print_unique_identifiers(FILE* f, int indent, UniqueIdentifiers* value)
{
    fprintf(f, "%*sUnique IDs @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        fprintf(f, "%*sUnique IDs: %zu\n", indent + 2, "", value->unique_identifier_list->size);
        LinkedListItem *curr = value->unique_identifier_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sUnique ID: %zu: ", indent + 4, "", count);
            kmip_print_text_string(f, indent + 2, "", curr->data);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}

