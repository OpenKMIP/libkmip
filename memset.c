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

#include "memset.h"

/*
#if defined __STDC_LIB_EXT1__

#define __STDC_WANT_LIB_EXT1__
#include <string.h>

void *
kmip_memset(void *ptr, int value, size_t size)
{
    if(ptr == NULL)
    {
        return(ptr);
    }
    
    memset_s(ptr, size, value, size);
    
    return(ptr);
}

#else
*/

void *
kmip_base_memset(void *ptr, int value, size_t size)
{
    if(ptr != NULL)
    {
        unsigned char *index = (unsigned char*)ptr;
        for(size_t i = 0; i < size; i++)
        {
            *index++ = (unsigned char)value;
        }
    }
    
    return(ptr);
}

static void *
(* volatile kmip_indirect_memset)(void *, int, size_t) = kmip_base_memset;

void *
kmip_memset(void *ptr, int value, size_t size)
{
    if(ptr != NULL)
    {
        kmip_indirect_memset(ptr, value, size);
    }
    
    return(ptr);
}

/*
#endif
*/