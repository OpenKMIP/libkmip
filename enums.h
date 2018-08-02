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

#ifndef ENUMS_H
#define ENUMS_H

#include "types.h"

enum attestation_type
{
    /* KMIP 1.2 */
    KMIP_ATTEST_TPM_QUOTE            = 0x01,
    KMIP_ATTEST_TCG_INTEGRITY_REPORT = 0x02,
    KMIP_ATTEST_SAML_ASSERTION       = 0x03
};

enum attribute_type
{
    /* KMIP 1.0 */
    KMIP_ATTR_UNIQUE_IDENTIFIER,
    KMIP_ATTR_NAME,
    KMIP_ATTR_OBJECT_TYPE,
    KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM,
    KMIP_ATTR_CRYPTOGRAPHIC_LENGTH,
    KMIP_ATTR_OPERATION_POLICY_NAME,
    KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK,
    KMIP_ATTR_STATE
};

enum batch_error_continuation_option
{
    /* KMIP 1.0 */
    KMIP_BATCH_CONTINUE = 0x01,
    KMIP_BATCH_STOP     = 0x02,
    KMIP_BATCH_UNDO     = 0x03
};

enum block_cipher_mode
{
    /* KMIP 1.0 */
    KMIP_BLOCK_CBC                  = 0x01,
    KMIP_BLOCK_ECB                  = 0x02,
    KMIP_BLOCK_PCBC                 = 0x03,
    KMIP_BLOCK_CFB                  = 0x04,
    KMIP_BLOCK_OFB                  = 0x05,
    KMIP_BLOCK_CTR                  = 0x06,
    KMIP_BLOCK_CMAC                 = 0x07,
    KMIP_BLOCK_CCM                  = 0x08,
    KMIP_BLOCK_GCM                  = 0x09,
    KMIP_BLOCK_CBC_MAC              = 0x0A,
    KMIP_BLOCK_XTS                  = 0x0B,
    KMIP_BLOCK_AES_KEY_WRAP_PADDING = 0x0C,
    KMIP_BLOCK_NIST_KEY_WRAP        = 0x0D,
    KMIP_BLOCK_X9102_AESKW          = 0x0E,
    KMIP_BLOCK_X9102_TDKW           = 0x0F,
    KMIP_BLOCK_X9102_AKW1           = 0x10,
    KMIP_BLOCK_X9102_AKW2           = 0x11,
    /* KMIP 1.4 */
    KMIP_BLOCK_AEAD                 = 0x12
};

enum credential_type
{
    /* KMIP 1.0 */
    KMIP_CRED_USERNAME_AND_PASSWORD = 0x01,
    /* KMIP 1.1 */
    KMIP_CRED_DEVICE                = 0x02,
    /* KMIP 1.2 */
    KMIP_CRED_ATTESTATION           = 0x03
};

enum cryptographic_algorithm
{
    /* KMIP 1.0 */
    KMIP_CRYPTOALG_DES               = 0x01,
    KMIP_CRYPTOALG_TRIPLE_DES        = 0x02,
    KMIP_CRYPTOALG_AES               = 0x03,
    KMIP_CRYPTOALG_RSA               = 0x04,
    KMIP_CRYPTOALG_DSA               = 0x05,
    KMIP_CRYPTOALG_ECDSA             = 0x06,
    KMIP_CRYPTOALG_HMAC_SHA1         = 0x07,
    KMIP_CRYPTOALG_HMAC_SHA224       = 0x08,
    KMIP_CRYPTOALG_HMAC_SHA256       = 0x09,
    KMIP_CRYPTOALG_HMAC_SHA384       = 0x0A,
    KMIP_CRYPTOALG_HMAC_SHA512       = 0x0B,
    KMIP_CRYPTOALG_HMAC_MD5          = 0x0C,
    KMIP_CRYPTOALG_DH                = 0x0D,
    KMIP_CRYPTOALG_ECDH              = 0x0E,
    KMIP_CRYPTOALG_ECMQV             = 0x0F,
    KMIP_CRYPTOALG_BLOWFISH          = 0x10,
    KMIP_CRYPTOALG_CAMELLIA          = 0x11,
    KMIP_CRYPTOALG_CAST5             = 0x12,
    KMIP_CRYPTOALG_IDEA              = 0x13,
    KMIP_CRYPTOALG_MARS              = 0x14,
    KMIP_CRYPTOALG_RC2               = 0x15,
    KMIP_CRYPTOALG_RC4               = 0x16,
    KMIP_CRYPTOALG_RC5               = 0x17,
    KMIP_CRYPTOALG_SKIPJACK          = 0x18,
    KMIP_CRYPTOALG_TWOFISH           = 0x19,
    /* KMIP 1.2 */
    KMIP_CRYPTOALG_EC                = 0x1A,
    /* KMIP 1.3 */
    KMIP_CRYPTOALG_ONE_TIME_PAD      = 0x1B,
    /* KMIP 1.4 */
    KMIP_CRYPTOALG_CHACHA20          = 0x1C,
    KMIP_CRYPTOALG_POLY1305          = 0x1D,
    KMIP_CRYPTOALG_CHACHA20_POLY1305 = 0x1E,
    KMIP_CRYPTOALG_SHA3_224          = 0x1F,
    KMIP_CRYPTOALG_SHA3_256          = 0x20,
    KMIP_CRYPTOALG_SHA3_384          = 0x21,
    KMIP_CRYPTOALG_SHA3_512          = 0x22,
    KMIP_CRYPTOALG_HMAC_SHA3_224     = 0x23,
    KMIP_CRYPTOALG_HMAC_SHA3_256     = 0x24,
    KMIP_CRYPTOALG_HMAC_SHA3_384     = 0x25,
    KMIP_CRYPTOALG_HMAC_SHA3_512     = 0x26,
    KMIP_CRYPTOALG_HMAC_SHAKE_128    = 0x27,
    KMIP_CRYPTOALG_HMAC_SHAKE_256    = 0x28
};

enum cryptographic_usage_mask
{
    /* KMIP 1.0 */
    KMIP_CRYPTOMASK_SIGN                = 0x00000001,
    KMIP_CRYPTOMASK_VERIFY              = 0x00000002,
    KMIP_CRYPTOMASK_ENCRYPT             = 0x00000004,
    KMIP_CRYPTOMASK_DECRYPT             = 0x00000008,
    KMIP_CRYPTOMASK_WRAP_KEY            = 0x00000010,
    KMIP_CRYPTOMASK_UNWRAP_KEY          = 0x00000020,
    KMIP_CRYPTOMASK_EXPORT              = 0x00000040,
    KMIP_CRYPTOMASK_MAC_GENERATE        = 0x00000080,
    KMIP_CRYPTOMASK_MAC_VERIFY          = 0x00000100,
    KMIP_CRYPTOMASK_DERIVE_KEY          = 0x00000200,
    KMIP_CRYPTOMASK_CONTENT_COMMITMENT  = 0x00000400,
    KMIP_CRYPTOMASK_KEY_AGREEMENT       = 0x00000800,
    KMIP_CRYPTOMASK_CERTIFICATE_SIGN    = 0x00001000,
    KMIP_CRYPTOMASK_CRL_SIGN            = 0x00002000,
    KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM = 0x00004000,
    KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM = 0x00008000,
    KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT   = 0x00010000,
    KMIP_CRYPTOMASK_TRANSLATE_DECRYPT   = 0x00020000,
    KMIP_CRYPTOMASK_TRANSLATE_WRAP      = 0x00040000,
    KMIP_CRYPTOMASK_TRANSLATE_UNWRAP    = 0x00080000
};

enum digital_signature_algorithm
{
    /* KMIP 1.1 */
    KMIP_DIGITAL_MD2_WITH_RSA      = 0x01,
    KMIP_DIGITAL_MD5_WITH_RSA      = 0x02,
    KMIP_DIGITAL_SHA1_WITH_RSA     = 0x03,
    KMIP_DIGITAL_SHA224_WITH_RSA   = 0x04,
    KMIP_DIGITAL_SHA256_WITH_RSA   = 0x05,
    KMIP_DIGITAL_SHA384_WITH_RSA   = 0x06,
    KMIP_DIGITAL_SHA512_WITH_RSA   = 0x07,
    KMIP_DIGITAL_RSASSA_PSS        = 0x08,
    KMIP_DIGITAL_DSA_WITH_SHA1     = 0x09,
    KMIP_DIGITAL_DSA_WITH_SHA224   = 0x0A,
    KMIP_DIGITAL_DSA_WITH_SHA256   = 0x0B,
    KMIP_DIGITAL_ECDSA_WITH_SHA1   = 0x0C,
    KMIP_DIGITAL_ECDSA_WITH_SHA224 = 0x0D,
    KMIP_DIGITAL_ECDSA_WITH_SHA256 = 0x0E,
    KMIP_DIGITAL_ECDSA_WITH_SHA384 = 0x0F,
    KMIP_DIGITAL_ECDSA_WITH_SHA512 = 0x10,
    /* KMIP 1.4 */
    KMIP_DIGITAL_SHA3_256_WITH_RSA = 0x11,
    KMIP_DIGITAL_SHA3_384_WITH_RSA = 0x12,
    KMIP_DIGITAL_SHA3_512_WITH_RSA = 0x13
};

enum encoding_option
{
    /* KMIP 1.1 */
    KMIP_ENCODE_NO_ENCODING   = 0x01,
    KMIP_ENCODE_TTLV_ENCODING = 0x02
};

enum hashing_algorithm
{
    /* KMIP 1.0 */
    KMIP_HASH_MD2        = 0x01,
    KMIP_HASH_MD4        = 0x02,
    KMIP_HASH_MD5        = 0x03,
    KMIP_HASH_SHA1       = 0x04,
    KMIP_HASH_SHA224     = 0x05,
    KMIP_HASH_SHA256     = 0x06,
    KMIP_HASH_SHA384     = 0x07,
    KMIP_HASH_SHA512     = 0x08,
    KMIP_HASH_RIPEMD160  = 0x09,
    KMIP_HASH_TIGER      = 0x0A,
    KMIP_HASH_WHIRLPOOL  = 0x0B,
    /* KMIP 1.2 */
    KMIP_HASH_SHA512_224 = 0x0C,
    KMIP_HASH_SHA512_256 = 0x0D,
    /* KMIP 1.4 */
    KMIP_HASH_SHA3_224   = 0x0E,
    KMIP_HASH_SHA3_256   = 0x0F,
    KMIP_HASH_SHA3_384   = 0x10,
    KMIP_HASH_SHA3_512   = 0x11
};

enum key_compression_type
{
    /* KMIP 1.0 */
    KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED          = 0x01,
    KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME = 0x02,
    KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2 = 0x03,
    KMIP_KEYCOMP_EC_PUB_X962_HYBRID           = 0x04
};

enum key_format_type
{
    /* KMIP 1.0 */
    KMIP_KEYFORMAT_RAW                     = 0x01,
    KMIP_KEYFORMAT_OPAQUE                  = 0x02,
    KMIP_KEYFORMAT_PKCS1                   = 0x03,
    KMIP_KEYFORMAT_PKCS8                   = 0x04,
    KMIP_KEYFORMAT_X509                    = 0x05,
    KMIP_KEYFORMAT_EC_PRIVATE_KEY          = 0x06,
    KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY     = 0x07,
    KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY   = 0x08,
    KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY    = 0x09,
    KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY   = 0x0A,
    KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY    = 0x0B,
    KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY    = 0x0C,
    KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY     = 0x0D,
    KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY = 0x0E, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY  = 0x0F, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY  = 0x10, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY   = 0x11, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY = 0x12, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY  = 0x13, /* Deprecated as of KMIP 1.3 */
    /* KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY    = 0x14,
    KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY     = 0x15,
    /* KMIP 1.4 */
    KMIP_KEYFORMAT_PKCS12                  = 0x16
};

enum key_role_type
{
    /* KMIP 1.0 */
    KMIP_ROLE_BDK      = 0x01,
    KMIP_ROLE_CVK      = 0x02,
    KMIP_ROLE_DEK      = 0x03,
    KMIP_ROLE_MKAC     = 0x04,
    KMIP_ROLE_MKSMC    = 0x05,
    KMIP_ROLE_MKSMI    = 0x06,
    KMIP_ROLE_MKDAC    = 0x07,
    KMIP_ROLE_MKDN     = 0x08,
    KMIP_ROLE_MKCP     = 0x09,
    KMIP_ROLE_MKOTH    = 0x0A,
    KMIP_ROLE_KEK      = 0x0B,
    KMIP_ROLE_MAC16609 = 0x0C,
    KMIP_ROLE_MAC97971 = 0x0D,
    KMIP_ROLE_MAC97972 = 0x0E,
    KMIP_ROLE_MAC97973 = 0x0F,
    KMIP_ROLE_MAC97974 = 0x10,
    KMIP_ROLE_MAC97975 = 0x11,
    KMIP_ROLE_ZPK      = 0x12,
    KMIP_ROLE_PVKIBM   = 0x13,
    KMIP_ROLE_PVKPVV   = 0x14,
    KMIP_ROLE_PVKOTH   = 0x15,
    /* KMIP 1.4 */
    KMIP_ROLE_DUKPT    = 0x16,
    KMIP_ROLE_IV       = 0x17,
    KMIP_ROLE_TRKBK    = 0x18
};

enum key_wrap_type
{
    /* KMIP 1.4 */
    KMIP_WRAPTYPE_NOT_WRAPPED   = 0x01,
    KMIP_WRAPTYPE_AS_REGISTERED = 0x02
};

enum kmip_version
{
    KMIP_1_0 = 0,
    KMIP_1_1 = 1,
    KMIP_1_2 = 2,
    KMIP_1_3 = 3,
    KMIP_1_4 = 4
};

enum mask_generator
{
    /* KMIP 1.4 */
    KMIP_MASKGEN_MGF1 = 0x01
};

enum name_type
{
    /* KMIP 1.0 */
    KMIP_NAME_UNINTERPRETED_TEXT_STRING = 0x01,
    KMIP_NAME_URI                       = 0x02
};

enum object_type
{
    /* KMIP 1.0 */
    KMIP_OBJTYPE_CERTIFICATE   = 0x01,
    KMIP_OBJTYPE_SYMMETRIC_KEY = 0x02,
    KMIP_OBJTYPE_PUBLIC_KEY    = 0x03,
    KMIP_OBJTYPE_PRIVATE_KEY   = 0x04,
    KMIP_OBJTYPE_SPLIT_KEY     = 0x05,
    KMIP_OBJTYPE_TEMPLATE      = 0x06, /* Deprecated as of KMIP 1.3 */
    KMIP_OBJTYPE_SECRET_DATA   = 0x07,
    KMIP_OBJTYPE_OPAQUE_OBJECT = 0x08,
    /* KMIP 1.2 */
    KMIP_OBJTYPE_PGP_KEY       = 0x09
};

enum operation
{
    /* KMIP 1.0 */
    KMIP_OP_CREATE  = 0x01,
    KMIP_OP_GET     = 0x0A,
    KMIP_OP_DESTROY = 0x14
};

enum padding_method
{
    /* KMIP 1.0 */
    KMIP_PAD_NONE      = 0x01,
    KMIP_PAD_OAEP      = 0x02,
    KMIP_PAD_PKCS5     = 0x03,
    KMIP_PAD_SSL3      = 0x04,
    KMIP_PAD_ZEROS     = 0x05,
    KMIP_PAD_ANSI_X923 = 0x06,
    KMIP_PAD_ISO_10126 = 0x07,
    KMIP_PAD_PKCS1v15  = 0x08,
    KMIP_PAD_X931      = 0x09,
    KMIP_PAD_PSS       = 0x0A
};

enum result_reason
{
    /* KMIP 1.0 */
    KMIP_REASON_GENERAL_FAILURE                     = 0x0100,
    KMIP_REASON_ITEM_NOT_FOUND                      = 0x0001,
    KMIP_REASON_RESPONSE_TOO_LARGE                  = 0x0002,
    KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL       = 0x0003,
    KMIP_REASON_INVALID_MESSAGE                     = 0x0004,
    KMIP_REASON_OPERATION_NOT_SUPPORTED             = 0x0005,
    KMIP_REASON_MISSING_DATA                        = 0x0006,
    KMIP_REASON_INVALID_FIELD                       = 0x0007,
    KMIP_REASON_FEATURE_NOT_SUPPORTED               = 0x0008,
    KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER     = 0x0009,
    KMIP_REASON_CRYPTOGRAPHIC_FAILURE               = 0x000A,
    KMIP_REASON_ILLEGAL_OPERATION                   = 0x000B,
    KMIP_REASON_PERMISSION_DENIED                   = 0x000C,
    KMIP_REASON_OBJECT_ARCHIVED                     = 0x000D,
    KMIP_REASON_INDEX_OUT_OF_BOUNDS                 = 0x000E,
    KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED = 0x000F,
    KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED       = 0x0010,
    KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED  = 0x0011,
    /* KMIP 1.1 */
    KMIP_REASON_ENCODING_OPTION_FAILURE             = 0x0012,
    /* KMIP 1.2 */
    KMIP_REASON_KEY_VALUE_NOT_PRESENT               = 0x0013,
    KMIP_REASON_ATTESTATION_REQUIRED                = 0x0014,
    KMIP_REASON_ATTESTATION_FAILED                  = 0x0015,
    /* KMIP 1.4 */
    KMIP_REASON_SENSITIVE                           = 0x0016,
    KMIP_REASON_NOT_EXTRACTABLE                     = 0x0017,
    KMIP_REASON_OBJECT_ALREADY_EXISTS               = 0x0018
};

enum result_status
{
    /* KMIP 1.0 */
    KMIP_STATUS_SUCCESS           = 0x00,
    KMIP_STATUS_OPERATION_FAILED  = 0x01,
    KMIP_STATUS_OPERATION_PENDING = 0x02,
    KMIP_STATUS_OPERATION_UNDONE  = 0x03
};

enum state
{
    /* KMIP 1.0 */
    KMIP_STATE_PRE_ACTIVE            = 0x01,
    KMIP_STATE_ACTIVE                = 0x02,
    KMIP_STATE_DEACTIVATED           = 0x03,
    KMIP_STATE_COMPROMISED           = 0x04,
    KMIP_STATE_DESTROYED             = 0x05,
    KMIP_STATE_DESTROYED_COMPROMISED = 0x06
};

enum tag
{
    KMIP_TAG_TAG                              = 0x000000,
    KMIP_TAG_TYPE                             = 0x000001,
    KMIP_TAG_DEFAULT                          = 0x420000,
    /* KMIP 1.0 */
    KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE   = 0x420006,
    KMIP_TAG_ASYNCHRONOUS_INDICATOR           = 0x420007,
    KMIP_TAG_ATTRIBUTE                        = 0x420008,
    KMIP_TAG_ATTRIBUTE_INDEX                  = 0x420009,
    KMIP_TAG_ATTRIBUTE_NAME                   = 0x42000A,
    KMIP_TAG_ATTRIBUTE_VALUE                  = 0x42000B,
    KMIP_TAG_AUTHENTICATION                   = 0x42000C,
    KMIP_TAG_BATCH_COUNT                      = 0x42000D,
    KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION  = 0x42000E,
    KMIP_TAG_BATCH_ITEM                       = 0x42000F,
    KMIP_TAG_BATCH_ORDER_OPTION               = 0x420010,
    KMIP_TAG_BLOCK_CIPHER_MODE                = 0x420011,
    KMIP_TAG_CREDENTIAL                       = 0x420023,
    KMIP_TAG_CREDENTIAL_TYPE                  = 0x420024,
    KMIP_TAG_CREDENTIAL_VALUE                 = 0x420025,
    KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM          = 0x420028,
    KMIP_TAG_CRYPTOGRAPHIC_LENGTH             = 0x42002A,
    KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS         = 0x42002B,
    KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK         = 0x42002C,
    KMIP_TAG_ENCRYPTION_KEY_INFORMATION       = 0x420036,
    KMIP_TAG_HASHING_ALGORITHM                = 0x420038,
    KMIP_TAG_IV_COUNTER_NONCE                 = 0x42003D,
    KMIP_TAG_KEY                              = 0x42003F,
    KMIP_TAG_KEY_BLOCK                        = 0x420040,
    KMIP_TAG_KEY_COMPRESSION_TYPE             = 0x420041,
    KMIP_TAG_KEY_FORMAT_TYPE                  = 0x420042,
    KMIP_TAG_KEY_MATERIAL                     = 0x420043,
    KMIP_TAG_KEY_VALUE                        = 0x420045,
    KMIP_TAG_KEY_WRAPPING_DATA                = 0x420046,
    KMIP_TAG_KEY_WRAPPING_SPECIFICATION       = 0x420047,
    KMIP_TAG_MAC_SIGNATURE                    = 0x42004D,
    KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION    = 0x42004E,
    KMIP_TAG_MAXIMUM_RESPONSE_SIZE            = 0x420050,
    KMIP_TAG_NAME                             = 0x420053,
    KMIP_TAG_NAME_TYPE                        = 0x420054,
    KMIP_TAG_NAME_VALUE                       = 0x420055,
    KMIP_TAG_OBJECT_TYPE                      = 0x420057,
    KMIP_TAG_OPERATION                        = 0x42005C,
    KMIP_TAG_PADDING_METHOD                   = 0x42005F,
    KMIP_TAG_PRIVATE_KEY                      = 0x420064,
    KMIP_TAG_PROTOCOL_VERSION                 = 0x420069,
    KMIP_TAG_PROTOCOL_VERSION_MAJOR           = 0x42006A,
    KMIP_TAG_PROTOCOL_VERSION_MINOR           = 0x42006B,
    KMIP_TAG_PUBLIC_KEY                       = 0x42006D,
    KMIP_TAG_REQUEST_HEADER                   = 0x420077,
    KMIP_TAG_REQUEST_MESSAGE                  = 0x420078,
    KMIP_TAG_REQUEST_PAYLOAD                  = 0x420079,
    KMIP_TAG_RESPONSE_HEADER                  = 0x42007A,
    KMIP_TAG_RESPONSE_MESSAGE                 = 0x42007B,
    KMIP_TAG_RESPONSE_PAYLOAD                 = 0x42007C,
    KMIP_TAG_RESULT_MESSAGE                   = 0x42007D,
    KMIP_TAG_RESULT_REASON                    = 0x42007E,
    KMIP_TAG_RESULT_STATUS                    = 0x42007F,
    KMIP_TAG_KEY_ROLE_TYPE                    = 0x420083,
    KMIP_TAG_STATE                            = 0x42008D,
    KMIP_TAG_SYMMETRIC_KEY                    = 0x42008F,
    KMIP_TAG_TEMPLATE_ATTRIBUTE               = 0x420091,
    KMIP_TAG_TIME_STAMP                       = 0x420092,
    KMIP_TAG_UNIQUE_BATCH_ITEM_ID             = 0x420093,
    KMIP_TAG_UNIQUE_IDENTIFIER                = 0x420094,
    KMIP_TAG_USERNAME                         = 0x420099,
    KMIP_TAG_WRAPPING_METHOD                  = 0x42009E,
    KMIP_TAG_PASSWORD                         = 0x4200A1,
    /* KMIP 1.1 */
    KMIP_TAG_DEVICE_IDENTIFIER                = 0x4200A2,
    KMIP_TAG_ENCODING_OPTION                  = 0x4200A3,
    KMIP_TAG_MACHINE_IDENTIFIER               = 0x4200A9,
    KMIP_TAG_MEDIA_IDENTIFIER                 = 0x4200AA,
    KMIP_TAG_NETWORK_IDENTIFIER               = 0x4200AB,
    KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM      = 0x4200AE,
    KMIP_TAG_DEVICE_SERIAL_NUMBER             = 0x4200B0,
    /* KMIP 1.2 */
    KMIP_TAG_RANDOM_IV                        = 0x4200C5,
    KMIP_TAG_ATTESTATION_TYPE                 = 0x4200C7,
    KMIP_TAG_NONCE                            = 0x4200C8,
    KMIP_TAG_NONCE_ID                         = 0x4200C9,
    KMIP_TAG_NONCE_VALUE                      = 0x4200CA,
    KMIP_TAG_ATTESTATION_MEASUREMENT          = 0x4200CB,
    KMIP_TAG_ATTESTATION_ASSERTION            = 0x4200CC,
    KMIP_TAG_IV_LENGTH                        = 0x4200CD,
    KMIP_TAG_TAG_LENGTH                       = 0x4200CE,
    KMIP_TAG_FIXED_FIELD_LENGTH               = 0x4200CF,
    KMIP_TAG_COUNTER_LENGTH                   = 0x4200D0,
    KMIP_TAG_INITIAL_COUNTER_VALUE            = 0x4200D1,
    KMIP_TAG_INVOCATION_FIELD_LENGTH          = 0x4200D2,
    KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR    = 0x4200D3,
    /* KMIP 1.4 */
    KMIP_TAG_KEY_WRAP_TYPE                    = 0x4200F8,
    KMIP_TAG_SALT_LENGTH                      = 0x420100,
    KMIP_TAG_MASK_GENERATOR                   = 0x420101,
    KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM = 0x420102,
    KMIP_TAG_P_SOURCE                         = 0x420103,
    KMIP_TAG_TRAILER_FIELD                    = 0x420104,
    KMIP_TAG_CLIENT_CORRELATION_VALUE         = 0x420105,
    KMIP_TAG_SERVER_CORRELATION_VALUE         = 0x420106
};

enum type
{
    /* KMIP 1.0 */
    KMIP_TYPE_STRUCTURE    = 0x01,
    KMIP_TYPE_INTEGER      = 0x02,
    KMIP_TYPE_LONG_INTEGER = 0x03,
    KMIP_TYPE_BIG_INTEGER  = 0x04,
    KMIP_TYPE_ENUMERATION  = 0x05,
    KMIP_TYPE_BOOLEAN      = 0x06,
    KMIP_TYPE_TEXT_STRING  = 0x07,
    KMIP_TYPE_BYTE_STRING  = 0x08,
    KMIP_TYPE_DATE_TIME    = 0x09,
    KMIP_TYPE_INTERVAL     = 0x0A
};

enum wrapping_method
{
    /* KMIP 1.0 */
    KMIP_WRAP_ENCRYPT          = 0x01,
    KMIP_WRAP_MAC_SIGN         = 0x02,
    KMIP_WRAP_ENCRYPT_MAC_SIGN = 0x03,
    KMIP_WRAP_MAC_SIGN_ENCRYPT = 0x04,
    KMIP_WRAP_TR31             = 0x05
};

static const char *attribute_names[25] = {
    "Attestation Type",
    "BatchErrorContinuation Option",
    "BlockCipher Mode",
    "Credential Type",
    "Cryptographic Algorithm",
    "Cryptographic Usage Mask",
    "DigitalSignature Algorithm",
    "Encoding Option",
    "Hashing Algorithm",
    "Key Compression Type",
    "Key Format Type",
    "Key Role Type",
    "Key Wrap Type",
    "Mask Generator",
    "Name Type",
    "Object Type",
    "Operation",
    "Padding Method",
    "Result Reason",
    "Result Status",
    "State",
    "Tag", /*?*/
    "Type", /*?*/
    "Wrapping Method",
    "Unknown" /* Catch all for unsupported enumerations */
};

int
get_enum_string_index(enum tag t)
{
    switch(t)
    {
        case KMIP_TAG_ATTESTATION_TYPE:
        return(0);
        break;
        
        case KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION:
        return(1);
        break;
        
        case KMIP_TAG_BLOCK_CIPHER_MODE:
        return(2);
        break;
        
        case KMIP_TAG_CREDENTIAL_TYPE:
        return(3);
        break;
        
        case KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
        return(4);
        break;
        
        case KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK:
        return(5);
        break;
        
        case KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM:
        return(6);
        break;
        
        case KMIP_TAG_ENCODING_OPTION:
        return(7);
        break;
        
        case KMIP_TAG_HASHING_ALGORITHM:
        return(8);
        break;
        
        case KMIP_TAG_KEY_COMPRESSION_TYPE:
        return(9);
        break;
        
        case KMIP_TAG_KEY_FORMAT_TYPE:
        return(10);
        break;
        
        case KMIP_TAG_KEY_ROLE_TYPE:
        return(11);
        break;
        
        case KMIP_TAG_KEY_WRAP_TYPE:
        return(12);
        break;
        
        case KMIP_TAG_MASK_GENERATOR:
        return(13);
        break;
        
        case KMIP_TAG_NAME_TYPE:
        return(14);
        break;
        
        case KMIP_TAG_OBJECT_TYPE:
        return(15);
        break;
        
        case KMIP_TAG_OPERATION:
        return(16);
        break;
        
        case KMIP_TAG_PADDING_METHOD:
        return(17);
        break;
        
        case KMIP_TAG_RESULT_REASON:
        return(18);
        break;
        
        case KMIP_TAG_RESULT_STATUS:
        return(19);
        break;
        
        case KMIP_TAG_STATE:
        return(20);
        break;
        
        case KMIP_TAG_TAG:
        return(21);
        break;
        
        case KMIP_TAG_TYPE:
        return(22);
        break;
        
        case KMIP_TAG_WRAPPING_METHOD:
        return(23);
        break;
        
        default:
        return(24);
        break;
    };
}

int
check_enum_value(enum kmip_version version, enum tag t, int value)
{
    switch(t)
    {
        case KMIP_TAG_ATTESTATION_TYPE:
        switch(value)
        {
            case KMIP_ATTEST_TPM_QUOTE:
            case KMIP_ATTEST_TCG_INTEGRITY_REPORT:
            case KMIP_ATTEST_SAML_ASSERTION:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION:
        switch(value)
        {
            case KMIP_BATCH_CONTINUE:
            case KMIP_BATCH_STOP:
            case KMIP_BATCH_UNDO:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_BLOCK_CIPHER_MODE:
        switch(value)
        {
            case KMIP_BLOCK_CBC:
            case KMIP_BLOCK_ECB:
            case KMIP_BLOCK_PCBC:
            case KMIP_BLOCK_CFB:
            case KMIP_BLOCK_OFB:
            case KMIP_BLOCK_CTR:
            case KMIP_BLOCK_CMAC:
            case KMIP_BLOCK_CCM:
            case KMIP_BLOCK_GCM:
            case KMIP_BLOCK_CBC_MAC:
            case KMIP_BLOCK_XTS:
            case KMIP_BLOCK_AES_KEY_WRAP_PADDING:
            case KMIP_BLOCK_NIST_KEY_WRAP:
            case KMIP_BLOCK_X9102_AESKW:
            case KMIP_BLOCK_X9102_TDKW:
            case KMIP_BLOCK_X9102_AKW1:
            case KMIP_BLOCK_X9102_AKW2:
            return(KMIP_OK);
            break;
            
            case KMIP_BLOCK_AEAD:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_CREDENTIAL_TYPE:
        switch(value)
        {
            case KMIP_CRED_USERNAME_AND_PASSWORD:
            return(KMIP_OK);
            break;
            
            case KMIP_CRED_DEVICE:
            if(version >= KMIP_1_1)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_CRED_ATTESTATION:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
        switch(value)
        {
            case KMIP_CRYPTOALG_DES:
            case KMIP_CRYPTOALG_TRIPLE_DES:
            case KMIP_CRYPTOALG_AES:
            case KMIP_CRYPTOALG_RSA:
            case KMIP_CRYPTOALG_DSA:
            case KMIP_CRYPTOALG_ECDSA:
            case KMIP_CRYPTOALG_HMAC_SHA1:
            case KMIP_CRYPTOALG_HMAC_SHA224:
            case KMIP_CRYPTOALG_HMAC_SHA256:
            case KMIP_CRYPTOALG_HMAC_SHA384:
            case KMIP_CRYPTOALG_HMAC_SHA512:
            case KMIP_CRYPTOALG_HMAC_MD5:
            case KMIP_CRYPTOALG_DH:
            case KMIP_CRYPTOALG_ECDH:
            case KMIP_CRYPTOALG_ECMQV:
            case KMIP_CRYPTOALG_BLOWFISH:
            case KMIP_CRYPTOALG_CAMELLIA:
            case KMIP_CRYPTOALG_CAST5:
            case KMIP_CRYPTOALG_IDEA:
            case KMIP_CRYPTOALG_MARS:
            case KMIP_CRYPTOALG_RC2:
            case KMIP_CRYPTOALG_RC4:
            case KMIP_CRYPTOALG_RC5:
            case KMIP_CRYPTOALG_SKIPJACK:
            case KMIP_CRYPTOALG_TWOFISH:
            return(KMIP_OK);
            break;
            
            case KMIP_CRYPTOALG_EC:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_CRYPTOALG_ONE_TIME_PAD:
            if(version >= KMIP_1_3)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_CRYPTOALG_CHACHA20:
            case KMIP_CRYPTOALG_POLY1305:
            case KMIP_CRYPTOALG_CHACHA20_POLY1305:
            case KMIP_CRYPTOALG_SHA3_224:
            case KMIP_CRYPTOALG_SHA3_256:
            case KMIP_CRYPTOALG_SHA3_384:
            case KMIP_CRYPTOALG_SHA3_512:
            case KMIP_CRYPTOALG_HMAC_SHA3_224:
            case KMIP_CRYPTOALG_HMAC_SHA3_256:
            case KMIP_CRYPTOALG_HMAC_SHA3_384:
            case KMIP_CRYPTOALG_HMAC_SHA3_512:
            case KMIP_CRYPTOALG_HMAC_SHAKE_128:
            case KMIP_CRYPTOALG_HMAC_SHAKE_256:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK:
        switch(value)
        {
            case KMIP_CRYPTOMASK_SIGN:
            case KMIP_CRYPTOMASK_VERIFY:
            case KMIP_CRYPTOMASK_ENCRYPT:
            case KMIP_CRYPTOMASK_DECRYPT:
            case KMIP_CRYPTOMASK_WRAP_KEY:
            case KMIP_CRYPTOMASK_UNWRAP_KEY:
            case KMIP_CRYPTOMASK_EXPORT:
            case KMIP_CRYPTOMASK_MAC_GENERATE:
            case KMIP_CRYPTOMASK_MAC_VERIFY:
            case KMIP_CRYPTOMASK_DERIVE_KEY:
            case KMIP_CRYPTOMASK_CONTENT_COMMITMENT:
            case KMIP_CRYPTOMASK_KEY_AGREEMENT:
            case KMIP_CRYPTOMASK_CERTIFICATE_SIGN:
            case KMIP_CRYPTOMASK_CRL_SIGN:
            case KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM:
            case KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM:
            case KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT:
            case KMIP_CRYPTOMASK_TRANSLATE_DECRYPT:
            case KMIP_CRYPTOMASK_TRANSLATE_WRAP:
            case KMIP_CRYPTOMASK_TRANSLATE_UNWRAP:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM:
        switch(value)
        {
            case KMIP_DIGITAL_MD2_WITH_RSA:
            case KMIP_DIGITAL_MD5_WITH_RSA:
            case KMIP_DIGITAL_SHA1_WITH_RSA:
            case KMIP_DIGITAL_SHA224_WITH_RSA:
            case KMIP_DIGITAL_SHA256_WITH_RSA:
            case KMIP_DIGITAL_SHA384_WITH_RSA:
            case KMIP_DIGITAL_SHA512_WITH_RSA:
            case KMIP_DIGITAL_RSASSA_PSS:
            case KMIP_DIGITAL_DSA_WITH_SHA1:
            case KMIP_DIGITAL_DSA_WITH_SHA224:
            case KMIP_DIGITAL_DSA_WITH_SHA256:
            case KMIP_DIGITAL_ECDSA_WITH_SHA1:
            case KMIP_DIGITAL_ECDSA_WITH_SHA224:
            case KMIP_DIGITAL_ECDSA_WITH_SHA256:
            case KMIP_DIGITAL_ECDSA_WITH_SHA384:
            case KMIP_DIGITAL_ECDSA_WITH_SHA512:
            if(version >= KMIP_1_1)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_DIGITAL_SHA3_256_WITH_RSA:
            case KMIP_DIGITAL_SHA3_384_WITH_RSA:
            case KMIP_DIGITAL_SHA3_512_WITH_RSA:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_ENCODING_OPTION:
        switch(value)
        {
            case KMIP_ENCODE_NO_ENCODING:
            case KMIP_ENCODE_TTLV_ENCODING:
            if(version >= KMIP_1_1)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_HASHING_ALGORITHM:
        switch(value)
        {
            case KMIP_HASH_MD2:
            case KMIP_HASH_MD4:
            case KMIP_HASH_MD5:
            case KMIP_HASH_SHA1:
            case KMIP_HASH_SHA224:
            case KMIP_HASH_SHA256:
            case KMIP_HASH_SHA384:
            case KMIP_HASH_SHA512:
            case KMIP_HASH_RIPEMD160:
            case KMIP_HASH_TIGER:
            case KMIP_HASH_WHIRLPOOL:
            return(KMIP_OK);
            break;
            
            case KMIP_HASH_SHA512_224:
            case KMIP_HASH_SHA512_256:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_HASH_SHA3_224:
            case KMIP_HASH_SHA3_256:
            case KMIP_HASH_SHA3_384:
            case KMIP_HASH_SHA3_512:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_KEY_COMPRESSION_TYPE:
        switch(value)
        {
            case KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED:
            case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME:
            case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2:
            case KMIP_KEYCOMP_EC_PUB_X962_HYBRID:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_KEY_FORMAT_TYPE:
        switch(value)
        {
            case KMIP_KEYFORMAT_RAW:
            case KMIP_KEYFORMAT_OPAQUE:
            case KMIP_KEYFORMAT_PKCS1:
            case KMIP_KEYFORMAT_PKCS8:
            case KMIP_KEYFORMAT_X509:
            case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
            case KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY:
            case KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY:
            case KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY:
            return(KMIP_OK);
            break;
            
            /* The following set is deprecated as of KMIP 1.3 */
            case KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY:
            case KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY:
            case KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY:
            /* TODO (peter-hamilton) What should happen if version >= 1.3? */
            return(KMIP_OK);
            break;
            
            case KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY:
            if(version >= KMIP_1_3)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_KEYFORMAT_PKCS12:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_KEY_ROLE_TYPE:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_ROLE_BDK:
            case KMIP_ROLE_CVK:
            case KMIP_ROLE_DEK:
            case KMIP_ROLE_MKAC:
            case KMIP_ROLE_MKSMC:
            case KMIP_ROLE_MKSMI:
            case KMIP_ROLE_MKDAC:
            case KMIP_ROLE_MKDN:
            case KMIP_ROLE_MKCP:
            case KMIP_ROLE_MKOTH:
            case KMIP_ROLE_KEK:
            case KMIP_ROLE_MAC16609:
            case KMIP_ROLE_MAC97971:
            case KMIP_ROLE_MAC97972:
            case KMIP_ROLE_MAC97973:
            case KMIP_ROLE_MAC97974:
            case KMIP_ROLE_MAC97975:
            case KMIP_ROLE_ZPK:
            case KMIP_ROLE_PVKIBM:
            case KMIP_ROLE_PVKPVV:
            case KMIP_ROLE_PVKOTH:
            return(KMIP_OK);
            break;
            
            /* KMIP 1.4 */
            case KMIP_ROLE_DUKPT:
            case KMIP_ROLE_IV:
            case KMIP_ROLE_TRKBK:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_KEY_WRAP_TYPE:
        switch(value)
        {
            /* KMIP 1.4 */
            case KMIP_WRAPTYPE_NOT_WRAPPED:
            case KMIP_WRAPTYPE_AS_REGISTERED:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_MASK_GENERATOR:
        switch(value)
        {
            /* KMIP 1.4 */
            case KMIP_MASKGEN_MGF1:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_NAME_TYPE:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_NAME_UNINTERPRETED_TEXT_STRING:
            case KMIP_NAME_URI:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_OBJECT_TYPE:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_OBJTYPE_CERTIFICATE:
            case KMIP_OBJTYPE_SYMMETRIC_KEY:
            case KMIP_OBJTYPE_PUBLIC_KEY:
            case KMIP_OBJTYPE_PRIVATE_KEY:
            case KMIP_OBJTYPE_SPLIT_KEY:
            case KMIP_OBJTYPE_SECRET_DATA:
            case KMIP_OBJTYPE_OPAQUE_OBJECT:
            return(KMIP_OK);
            break;
            
            /* The following set is deprecated as of KMIP 1.3 */
            case KMIP_OBJTYPE_TEMPLATE:
            /* TODO (peter-hamilton) What should happen if version >= 1.3? */
            return(KMIP_OK);
            break;
            
            /* KMIP 1.2 */
            case KMIP_OBJTYPE_PGP_KEY:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_OPERATION:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_OP_CREATE:
            case KMIP_OP_GET:
            case KMIP_OP_DESTROY:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_PADDING_METHOD:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_PAD_NONE:
            case KMIP_PAD_OAEP:
            case KMIP_PAD_PKCS5:
            case KMIP_PAD_SSL3:
            case KMIP_PAD_ZEROS:
            case KMIP_PAD_ANSI_X923:
            case KMIP_PAD_ISO_10126:
            case KMIP_PAD_PKCS1v15:
            case KMIP_PAD_X931:
            case KMIP_PAD_PSS:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_RESULT_REASON:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_REASON_GENERAL_FAILURE:
            case KMIP_REASON_ITEM_NOT_FOUND:
            case KMIP_REASON_RESPONSE_TOO_LARGE:
            case KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL:
            case KMIP_REASON_INVALID_MESSAGE:
            case KMIP_REASON_OPERATION_NOT_SUPPORTED:
            case KMIP_REASON_MISSING_DATA:
            case KMIP_REASON_INVALID_FIELD:
            case KMIP_REASON_FEATURE_NOT_SUPPORTED:
            case KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER:
            case KMIP_REASON_CRYPTOGRAPHIC_FAILURE:
            case KMIP_REASON_ILLEGAL_OPERATION:
            case KMIP_REASON_PERMISSION_DENIED:
            case KMIP_REASON_OBJECT_ARCHIVED:
            case KMIP_REASON_INDEX_OUT_OF_BOUNDS:
            case KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED:
            case KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED:
            case KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED:
            return(KMIP_OK);
            break;
            
            /* KMIP 1.1 */
            case KMIP_REASON_ENCODING_OPTION_FAILURE:
            if(version >= KMIP_1_1)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            /* KMIP 1.2 */
            case KMIP_REASON_KEY_VALUE_NOT_PRESENT:
            case KMIP_REASON_ATTESTATION_REQUIRED:
            case KMIP_REASON_ATTESTATION_FAILED:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            /* KMIP 1.4 */
            case KMIP_REASON_SENSITIVE:
            case KMIP_REASON_NOT_EXTRACTABLE:
            case KMIP_REASON_OBJECT_ALREADY_EXISTS:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_RESULT_STATUS:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_STATUS_SUCCESS:
            case KMIP_STATUS_OPERATION_FAILED:
            case KMIP_STATUS_OPERATION_PENDING:
            case KMIP_STATUS_OPERATION_UNDONE:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_STATE:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_STATE_PRE_ACTIVE:
            case KMIP_STATE_ACTIVE:
            case KMIP_STATE_DEACTIVATED:
            case KMIP_STATE_COMPROMISED:
            case KMIP_STATE_DESTROYED:
            case KMIP_STATE_DESTROYED_COMPROMISED:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_TAG:
        /* TODO (peter-hamilton) Fill this in. */
        return(KMIP_OK);
        break;
        
        case KMIP_TAG_TYPE:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_TYPE_STRUCTURE:
            case KMIP_TYPE_INTEGER:
            case KMIP_TYPE_LONG_INTEGER:
            case KMIP_TYPE_BIG_INTEGER:
            case KMIP_TYPE_ENUMERATION:
            case KMIP_TYPE_BOOLEAN:
            case KMIP_TYPE_TEXT_STRING:
            case KMIP_TYPE_BYTE_STRING:
            case KMIP_TYPE_DATE_TIME:
            case KMIP_TYPE_INTERVAL:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_WRAPPING_METHOD:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_WRAP_ENCRYPT:
            case KMIP_WRAP_MAC_SIGN:
            case KMIP_WRAP_ENCRYPT_MAC_SIGN:
            case KMIP_WRAP_MAC_SIGN_ENCRYPT:
            case KMIP_WRAP_TR31:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        default:
        return(KMIP_ENUM_UNSUPPORTED);
        break;
    };
}

#endif /* ENUMS_H */
