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

enum cryptographic_algorithm
{
    /* KMIP 1.0 */
    KMIP_CRYPTOALG_DES         = 0x01,
    KMIP_CRYPTOALG_TRIPLE_DES  = 0x02,
    KMIP_CRYPTOALG_AES         = 0x03,
    KMIP_CRYPTOALG_RSA         = 0x04,
    KMIP_CRYPTOALG_DSA         = 0x05,
    KMIP_CRYPTOALG_ECDSA       = 0x06,
    KMIP_CRYPTOALG_HMAC_SHA1   = 0x07,
    KMIP_CRYPTOALG_HMAC_SHA224 = 0x08,
    KMIP_CRYPTOALG_HMAC_SHA256 = 0x09,
    KMIP_CRYPTOALG_HMAC_SHA384 = 0x0A,
    KMIP_CRYPTOALG_HMAC_SHA512 = 0x0B,
    KMIP_CRYPTOALG_HMAC_MD5    = 0x0C,
    KMIP_CRYPTOALG_DH          = 0x0D,
    KMIP_CRYPTOALG_ECDH        = 0x0E,
    KMIP_CRYPTOALG_ECMQV       = 0x0F,
    KMIP_CRYPTOALG_BLOWFISH    = 0x10,
    KMIP_CRYPTOALG_CAMELLIA    = 0x11,
    KMIP_CRYPTOALG_CAST5       = 0x12,
    KMIP_CRYPTOALG_IDEA        = 0x13,
    KMIP_CRYPTOALG_MARS        = 0x14,
    KMIP_CRYPTOALG_RC2         = 0x15,
    KMIP_CRYPTOALG_RC4         = 0x16,
    KMIP_CRYPTOALG_RC5         = 0x17,
    KMIP_CRYPTOALG_SKIPJACK    = 0x18,
    KMIP_CRYPTOALG_TWOFISH     = 0x19
};

enum cryptographic_usage_mask
{
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

enum kmip_version
{
    KMIP_1_0,
    KMIP_1_1,
    KMIP_1_2,
    KMIP_1_3,
    KMIP_1_4
};

enum name_type
{
    KMIP_NAME_UNINTERPRETED_TEXT_STRING = 0x01,
    KMIP_NAME_URI                       = 0x02
};

enum object_type
{
    KMIP_OBJTYPE_CERTIFICATE   = 0x01,
    KMIP_OBJTYPE_SYMMETRIC_KEY = 0x02,
    KMIP_OBJTYPE_PUBLIC_KEY    = 0x03,
    KMIP_OBJTYPE_PRIVATE_KEY   = 0x04,
    KMIP_OBJTYPE_SPLIT_KEY     = 0x05,
    KMIP_OBJTYPE_TEMPLATE      = 0x06,
    KMIP_OBJTYPE_SECRET_DATA   = 0x07,
    KMIP_OBJTYPE_OPAQUE_OBJECT = 0x08
};

enum operation
{
    KMIP_OP_CREATE  = 0x01,
    KMIP_OP_GET     = 0x0A,
    KMIP_OP_DESTROY = 0x14
};

enum state
{
    KMIP_STATE_PRE_ACTIVE            = 0x01,
    KMIP_STATE_ACTIVE                = 0x02,
    KMIP_STATE_DEACTIVATED           = 0x03,
    KMIP_STATE_COMPROMISED           = 0x04,
    KMIP_STATE_DESTROYED             = 0x05,
    KMIP_STATE_DESTROYED_COMPROMISED = 0x06
};

enum tag
{
    KMIP_TAG_DEFAULT                = 0x420000,
    /* KMIP 1.0 */
    KMIP_TAG_ATTRIBUTE              = 0x420008,
    KMIP_TAG_ATTRIBUTE_INDEX        = 0x420009,
    KMIP_TAG_ATTRIBUTE_NAME         = 0x42000A,
    KMIP_TAG_ATTRIBUTE_VALUE        = 0x42000B,
    KMIP_TAG_NAME                   = 0x420053,
    KMIP_TAG_NAME_TYPE              = 0x420054,
    KMIP_TAG_NAME_VALUE             = 0x420055,
    KMIP_TAG_PROTOCOL_VERSION       = 0x420069,
    KMIP_TAG_PROTOCOL_VERSION_MAJOR = 0x42006A,
    KMIP_TAG_PROTOCOL_VERSION_MINOR = 0x42006B,
};

enum type
{
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

#endif /* ENUMS_H */
