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

enum kmip_version
{
    KMIP_1_0 = 10,
    KMIP_1_1 = 11,
    KMIP_1_2 = 12,
    KMIP_1_3 = 13,
    KMIP_1_4 = 14
};

enum tag
{
    KMIP_TAG_DEFAULT                = 0x420000,
    /* KMIP 1.0 */
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
