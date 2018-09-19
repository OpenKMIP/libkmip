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

#include <stddef.h>
#include <stdint.h>

/*
Types and Constants
*/

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

#define KMIP_TRUE (1)
#define KMIP_FALSE (0)

#define KMIP_UNSET (-1)

#define KMIP_OK                      (0)
#define KMIP_NOT_IMPLEMENTED         (-1)
#define KMIP_ERROR_BUFFER_FULL       (-2)
#define KMIP_ERROR_ATTR_UNSUPPORTED  (-3)
#define KMIP_TAG_MISMATCH            (-4)
#define KMIP_TYPE_MISMATCH           (-5)
#define KMIP_LENGTH_MISMATCH         (-6)
#define KMIP_PADDING_MISMATCH        (-7)
#define KMIP_BOOLEAN_MISMATCH        (-8)
#define KMIP_ENUM_MISMATCH           (-9)
#define KMIP_ENUM_UNSUPPORTED        (-10)
#define KMIP_INVALID_FOR_VERSION     (-11)
#define KMIP_MEMORY_ALLOC_FAILED     (-12)
#define KMIP_IO_FAILURE              (-13)
#define KMIP_EXCEED_MAX_MESSAGE_SIZE (-14)
#define KMIP_MALFORMED_RESPONSE      (-15)
#define KMIP_OBJECT_MISMATCH         (-16)

/*
Enumerations
*/

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

/*
Structures
*/

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
    
    int max_message_size;
    struct linked_list *credential_list;
    
    char *error_message;
    size_t error_message_size;
    struct error_frame errors[20];
    size_t error_frame_count;
    struct error_frame *frame_index;
    
    void *(*calloc_func)(void *state, size_t num, size_t size);
    void *(*realloc_func)(void *state, void *ptr, size_t size);
    void (*free_func)(void *state, void *ptr);
    void *state;
    
    void *(*memset_func)(void *ptr, int value, size_t size);
};

struct linked_list_item
{
    struct linked_list_item *next;
    struct linked_list_item *prev;
    
    void *data;
};

struct linked_list
{
    struct linked_list_item *head;
    size_t size;
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
    /* NOTE (ph) Omitting the message extension field for now. */
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
    /* NOTE (ph) Omitting the message extension field for now. */
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
struct linked_list_item *linked_list_pop(struct linked_list *);
void linked_list_push(struct linked_list *, struct linked_list_item *);

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
int kmip_add_credential(struct kmip *, struct credential *);
void kmip_remove_credentials(struct kmip *);
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
