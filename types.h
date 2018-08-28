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

#ifndef KMIP_TYPES_H
#define KMIP_TYPES_H

#include <stddef.h>
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

#endif /* KMIP_TYPES_H */