/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "kmip.h"
#include "kmip_memset.h"
#include "kmip_bio.h"
#include "kmip_query.h"

/*
Query Utilities
*/



void
kmip_print_query_function_enum(int indent, enum query_function value)
{
    if(value == 0)
    {
        printf("-");
        return;
    }

    switch(value)
    {
        /* KMIP 1.0 */
        case KMIP_QUERY_OPERATIONS:
            printf("Operations");
            break;
        case KMIP_QUERY_OBJECTS:
            printf("Objects");
            break;
        case KMIP_QUERY_SERVER_INFORMATION:
            printf("Server Information");
            break;
        case KMIP_QUERY_APPLICATION_NAMESPACES:
            printf("Application namespaces");
            break;
        /* KMIP 1.1 */
        case KMIP_QUERY_EXTENSION_LIST:
            printf("Extension list");
            break;
        case KMIP_QUERY_EXTENSION_MAP:
            printf("Extension Map");
            break;
        /* KMIP 1.2 */
        case KMIP_QUERY_ATTESTATION_TYPES:
            printf("Attestation Types");
            break;
        /* KMIP 1.3 */
        case KMIP_QUERY_RNGS:
            printf("RNGS");
            break;
        case KMIP_QUERY_VALIDATIONS:
            printf("Validations");
            break;
        case KMIP_QUERY_PROFILES:
            printf("Profiles");
            break;
        case KMIP_QUERY_CAPABILITIES:
            printf("Capabilities");
            break;
        case KMIP_QUERY_CLIENT_REGISTRATION_METHODS:
            printf("Registration Methods");
            break;
        /* KMIP 2.0 */
        case KMIP_QUERY_DEFAULTS_INFORMATION:
            printf("Defaults Information");
            break;
        case KMIP_QUERY_STORAGE_PROTECTION_MASKS:
            printf("Storage Protection Masks");
            break;

        default:
        printf("Unknown");
        break;
    };
}

void
kmip_print_query_functions(int indent, QueryRequestPayload* value)
{
    printf("%*sQuery Functions @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        printf("%*sFunctions: %zu\n", indent + 2, "", value->functions->size);
        LinkedListItem *curr = value->functions->head;
        size_t count = 1;
        while(curr != NULL)
        {
            printf("%*sFunction: %zu: ", indent + 4, "", count);
            int32 func = *(int32 *)curr->data;
            kmip_print_query_function_enum(indent + 6, func);
            printf("\n");

            curr = curr->next;
            count++;
        }
    }
}

/*
void
kmip_free_query_functions(KMIP *ctx, QueryRequestPayload* value)
{
    if(value != NULL)
    {
        if(value->functions != NULL)
        {
            LinkedListItem *curr = kmip_linked_list_pop(value->functions);
            while(curr != NULL)
            {
                ctx->free_func(ctx->state, curr->data);
                curr->data = NULL;
                ctx->free_func(ctx->state, curr);
                curr = kmip_linked_list_pop(value->functions);
            }
            ctx->free_func(ctx->state, value->functions);
            value->functions = NULL;
        }
    }

    return;
}
*/

int
kmip_compare_query_functions(const QueryRequestPayload* a, const QueryRequestPayload* b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if((a->functions != b->functions ))
        {
            if((a->functions == NULL) || (b->functions == NULL))
            {
                return(KMIP_FALSE);
            }

            if((a->functions->size != b->functions->size))
            {
                return(KMIP_FALSE);
            }

            LinkedListItem *a_item = a->functions->head;
            LinkedListItem *b_item = b->functions->head;
            while((a_item != NULL) || (b_item != NULL))
            {
                if(a_item != b_item)
                {
                    if(!a_item || !b_item)
                        break;

                    int32 a_data = *(int32 *)a_item->data;
                    int32 b_data = *(int32 *)b_item->data;
                    if(a_data != b_data)
                    {
                        return(KMIP_FALSE);
                    }
                }

                a_item = a_item->next;
                b_item = b_item->next;
            }

            if(a_item != b_item)
            {
                return(KMIP_FALSE);
            }
        }
    }

    return(KMIP_TRUE);
}

int
kmip_encode_query_functions(KMIP *ctx, const QueryRequestPayload* value)
{
    CHECK_ENCODE_ARGS(ctx, value);

    int result = 0;

    if(value->functions != NULL)
    {
        LinkedListItem *curr = value->functions->head;
        while(curr != NULL)
        {
            result = kmip_encode_enum(ctx, KMIP_TAG_QUERY_FUNCTION, *(int32 *)curr->data);
            CHECK_RESULT(ctx, result);

            curr = curr->next;
        }
    }

    return(KMIP_OK);
}

int
kmip_decode_query_functions(KMIP *ctx, QueryRequestPayload* value)
{
    CHECK_DECODE_ARGS(ctx, value);
    CHECK_BUFFER_FULL(ctx, 8);

    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;

    result = kmip_decode_int32_be(ctx, &tag_type);
    CHECK_RESULT(ctx, result);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_QUERY_FUNCTION, KMIP_TYPE_STRUCTURE);

    result = kmip_decode_int32_be(ctx, &length);
    CHECK_RESULT(ctx, result);
    CHECK_BUFFER_FULL(ctx, length);

    value->functions = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    CHECK_NEW_MEMORY(ctx, value->functions, sizeof(LinkedList), "LinkedList");

    uint32 tag = kmip_peek_tag(ctx);
    while(tag == KMIP_TAG_QUERY_FUNCTION)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        CHECK_NEW_MEMORY(ctx, item, sizeof(LinkedListItem), "LinkedListItem");
        kmip_linked_list_enqueue(value->functions, item);

        item->data = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, item->data, sizeof(int32), "Query Function");

        result = kmip_decode_enum(ctx, KMIP_TAG_QUERY_FUNCTION, (int32 *)item->data);
        CHECK_RESULT(ctx, result);

        tag = kmip_peek_tag(ctx);
    }

    return(KMIP_OK);
}

/*

Response Payload

Item                          REQUIRED                Description

 Operation                     No, MAY be repeated     Specifies an Operation that is supported by the server.
 Object Type                   No, MAY be repeated     Specifies a Managed Object Type that is supported by the server.
 Vendor Identification         No                      SHALL be returned if Query Server Information is requested. The Vendor Identification SHALL be a text string that uniquely identifies the vendor.
 Server Information            No                      Contains vendor-specific information possibly be of interest to the client.
 Application Namespace         No, MAY be repeated     Specifies an Application Namespace supported by the server.
 Extension Information         No, MAY be repeated     SHALL be returned if Query Extension List or Query Extension Map is requested and supported by the server.
 Attestation Type              No, MAY be repeated     Specifies an Attestation Type that is supported by the server.
 RNG Parameters                No, MAY be repeated     Specifies the RNG that is supported by the server.
 Profile Information           No, MAY be repeated     Specifies the Profiles that are supported by the server.
 Validation Information        No, MAY be repeated     Specifies the validations that are supported by the server.
 Capability Information        No, MAY be repeated     Specifies the capabilities that are supported by the server.
 Client Registration Method    No, MAY be repeated     Specifies a Client Registration Method that is supported by the server.
 Defaults Information          No                      Specifies the defaults that the server will use if the client omits them.
 Protection Storage Masks      Yes                     Specifies the list of Protection Storage Mask values supported by the server. A server MAY elect to provide an empty list in the Response if it is unable or unwilling to provide this information.

*/


/*

7.19 Operations

A list of Operations.

Object                        Encoding                REQUIRED
Operations                    Structure

Operation                     Enumeration             No, May be repeated.

*/

/*

4.36 Object Type

The Object Type of a Managed Object (e.g., public key, private key, symmetric key, etc.) SHALL be set by the server when the object is created or registered and then SHALL NOT be changed or deleted before the object is destroyed.

Item                          Encoding
Object Type                   Enumeration
*/

/*

Vendor identification        Text String

*/

/*


7.31 Server Information

The Server Information  base object is a structure that contains a set of OPTIONAL fields that describe server information. Where a server supports returning information in a vendor-specific field for which there is an equivalent field within the structure, the server SHALL provide the standardized version of the field.

Object                        Encoding                REQUIRED
Server Information            Structure
Server name                   Text String             No
Server serial number          Text String             No
Server version                Text String             No
Server load                   Text String             No
Product name                  Text String             No
Build level                   Text String             No
Build date                    Text String             No
Cluster info                  Text String             No
Alternative failover endpoints Text String, MAY be repeated No
Vendor-Specific               Any, MAY be repeated    No


*/


/*
application namespaces

this is a list of text strings

*/
/*

7.9 Extension Information

An Extension Information object is a structure describing Objects with Item Tag values in the Extensions range. The Extension Name is a Text String that is used to name the Object. The Extension Tag is the Item Tag Value of the Object. The Extension Type is the Item Type Value of the Object.

Object                        Encoding                REQUIRED
Extension Information         Structure
Extension Name                Text String             Yes
Extension Tag                 Integer                 No
Extension Type                Enumeration (Item Type) No
Extension Enumeration         Integer                 No
Extension Attribute           Boolean                 No
Extension Parent Structure Tag Integer                 No
Extension Description         Text String             No

*/


/*
attestation type

a list of enumerations

*/

/*
7.30 RNG Parameters

The RNG Parameters base object is a structure that contains a mandatory RNG Algorithm and a set of OPTIONAL fields that describe a Random Number Generator. Specific fields pertain only to certain types of RNGs.

The RNG Algorithm SHALL be specified and if the algorithm implemented is unknown or the implementation does not want to provide the specific details of the RNG Algorithm then the Unspecified enumeration SHALL be used.

If the cryptographic building blocks used within the RNG are known they MAY be specified in combination of the remaining fields within the RNG Parameters structure.

Object                        Encoding                REQUIRED
RNG Parameters                Structure
RNG Algorithm                 Enumeration             Yes
Cryptographic Algorithm       Enumeration             No
Cryptographic Length          Integer                 No
Hashing Algorithm             Enumeration             No
DRBG Algorithm                Enumeration             No
Recommended Curve             Enumeration             No
FIPS186 Variation             Enumeration             No
Prediction Resistance         Boolean                 No

*/

/*


7.25 Profile Information

The Profile Information structure contains details of the supported profiles. Specific fields MAY pertain only to certain types of profiles.

Item                          Encoding                REQUIRED
Profile Information           Structure
Profile Name                  Enumeration             Yes
Profile Version               Structure               No
Server URI                    Text String             No
Server Port                   Integer                 No


*/

/*

7.35 Validation Information

The Validation Information base object is a structure that contains details of a formal validation. Specific fields MAY pertain only to certain types of validations.

Object                        Encoding                REQUIRED
Validation Information        Structure
Validation Authority Type     Enumeration             Yes
Validation Authority Country  Text String             No
Validation Authority URI      Text String             No
Validation Version Major      Integer                 Yes
Validation Version Minor      Integer                 No
Validation Type               Enumeration             Yes
Validation Level              Integer                 Yes
Validation Certificate IdentifierText String          No
Validation Certificate URI    Text String             No
Validation Vendor URI         Text String             No
Validation Profile            Text String, MAY be repeated No

*/


/*
7.3 Capability Information

The Capability Information base object is a structure that contains details of the supported capabilities.

Object                        Encoding               REQUIRED

Capability Information        Structure
Streaming Capability          Boolean                 No
Asynchronous Capability       Boolean                 No
Attestation Capability        Boolean                 No
Batch Undo Capability         Boolean                 No
Batch Continue Capability     Boolean                 No
Unwrap Mode                   Enumeration             No
Destroy Action                Enumeration             No
Shredding Algorithm           Enumeration             No
RNG Mode                      Enumeration             No
Quantum Safe Capability       Boolean                 No

*/

/*
client registration methods
enumeration of supported client registration methods

*/

/*
7.7 Defaults Information

The Defaults Information is a structure used in Query responses for values that servers will use if clients omit them from factory operations requests.

Object                        Encoding                    REQUIRED
Defaults Information          Structure

Object Defaults               Structure, may be repeated  Yes

*/


/*

7.27 Protection Storage Masks

The Protection Storage Masks operations data object is a structure that contains an ordered collection of

Protection Storage Mask selections acceptable to the client.

from pykmip, its a list of integers

*/


void kmip_print_query_request_payload(int indent, QueryRequestPayload *value)
{
    kmip_print_query_functions(indent, value);
}

void
kmip_free_query_request_payload(KMIP *ctx, QueryRequestPayload *value)
{
    if(ctx == NULL || value == NULL)
    {
        return;
    }

    LinkedListItem *item = kmip_linked_list_pop(value->functions);
    while(item != NULL)
    {
        ctx->memset_func(item, 0, sizeof(LinkedListItem));
        ctx->free_func(ctx->state, item);

        item = kmip_linked_list_pop(value->functions);
    }

    ctx->free_func(ctx->state, value->functions);
    value->functions = NULL;

    return;
}
int kmip_compare_query_request_payload(const QueryRequestPayload *a, const QueryRequestPayload *b)
{
    return(KMIP_NOT_IMPLEMENTED);
}
int kmip_decode_query_request_payload(KMIP *ctx, QueryRequestPayload *value)
{
    return(KMIP_NOT_IMPLEMENTED);
}

int
kmip_encode_query_request_payload(KMIP *ctx, const QueryRequestPayload *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);

    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;

    if(value->functions != NULL)
    {
        result = kmip_encode_query_functions(ctx, value);
        CHECK_RESULT(ctx, result);
    }

    uint8 *curr_index = ctx->index;
    ctx->index = length_index;

    kmip_encode_int32_be(ctx, curr_index - value_index);

    ctx->index = curr_index;

    return(KMIP_OK);
}


int
kmip_decode_operations(KMIP *ctx, Operations *value)
{
    int result = 0;

    value->operation_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    CHECK_NEW_MEMORY(ctx, value->operation_list, sizeof(LinkedList), "LinkedList");

    uint32 tag = kmip_peek_tag(ctx);
    while(tag == KMIP_TAG_OPERATION)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        CHECK_NEW_MEMORY(ctx, item, sizeof(LinkedListItem), "LinkedListItem");
        kmip_linked_list_enqueue(value->operation_list, item);

        item->data = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, item->data, sizeof(int32), "Operation");


        result = kmip_decode_enum(ctx, KMIP_TAG_OPERATION, (int32 *)item->data);
        CHECK_RESULT(ctx, result);

        tag = kmip_peek_tag(ctx);
    }

    return(KMIP_OK);
}

void
kmip_print_operation_enum_2(enum all_operations value)
{
    #define PRINT(x)  case (x): printf(#x); break;

    switch (value)
    {
        PRINT(KMIP_OP_CREATE_);
        PRINT(KMIP_OP_CREATE_KEY_PAIR);
        PRINT(KMIP_OP_REGISTER);
        PRINT(KMIP_OP_REKEY);
        PRINT(KMIP_OP_DERIVE_KEY);
        PRINT(KMIP_OP_CERTIFY);
        PRINT(KMIP_OP_RECERTIFY);
        PRINT(KMIP_OP_LOCATE);
        PRINT(KMIP_OP_CHECK);
        PRINT(KMIP_OP_GET_);
        PRINT(KMIP_OP_GET_ATTRIBUTES);
        PRINT(KMIP_OP_GET_ATTRIBUTE_LIST);
        PRINT(KMIP_OP_ADD_ATTRIBUTE);
        PRINT(KMIP_OP_MODIFY_ATTRIBUTE);
        PRINT(KMIP_OP_DELETE_ATTRIBUTE);
        PRINT(KMIP_OP_OBTAIN_LEASE);
        PRINT(KMIP_OP_GET_USAGE_ALLOCATION);
        PRINT(KMIP_OP_ACTIVATE);
        PRINT(KMIP_OP_REVOKE);
        PRINT(KMIP_OP_DESTROY_);
        PRINT(KMIP_OP_ARCHIVE);
        PRINT(KMIP_OP_RECOVER);
        PRINT(KMIP_OP_VALIDATE);
        PRINT(KMIP_OP_QUERY_);
        PRINT(KMIP_OP_CANCEL);
        PRINT(KMIP_OP_POLL);
        PRINT(KMIP_OP_NOTIFY);
        PRINT(KMIP_OP_PUT);
        // # KMIP 1.1
        PRINT(KMIP_OP_REKEY_KEY_PAIR);
        PRINT(KMIP_OP_DISCOVER_VERSIONS);
        //# KMIP 1.2
        PRINT(KMIP_OP_ENCRYPT);
        PRINT(KMIP_OP_DECRYPT);
        PRINT(KMIP_OP_SIGN);
        PRINT(KMIP_OP_SIGNATURE_VERIFY);
        PRINT(KMIP_OP_MAC);
        PRINT(KMIP_OP_MAC_VERIFY);
        PRINT(KMIP_OP_RNG_RETRIEVE);
        PRINT(KMIP_OP_RNG_SEED);
        PRINT(KMIP_OP_HASH);
        PRINT(KMIP_OP_CREATE_SPLIT_KEY);
        PRINT(KMIP_OP_JOIN_SPLIT_KEY);
        // # KMIP 1.4
        PRINT(KMIP_OP_IMPORT);
        PRINT(KMIP_OP_EXPORT);
        // # KMIP 2.0
        PRINT(KMIP_OP_LOG);
        PRINT(KMIP_OP_LOGIN);
        PRINT(KMIP_OP_LOGOUT);
        PRINT(KMIP_OP_DELEGATED_LOGIN);
        PRINT(KMIP_OP_ADJUST_ATTRIBUTE);
        PRINT(KMIP_OP_SET_ATTRIBUTE);
        PRINT(KMIP_OP_SET_ENDPOINT_ROLE);
        PRINT(KMIP_OP_PKCS_11);
        PRINT(KMIP_OP_INTEROP);
        PRINT(KMIP_OP_REPROVISION);

        default:
            printf("Unknown");
            break;
    }
}

void
kmip_free_operations(KMIP *ctx, Operations *value)
{

    if(value != NULL)
    {
        if(value->operation_list != NULL)
        {
            LinkedListItem *curr = kmip_linked_list_pop(value->operation_list);
            while(curr != NULL)
            {
                ctx->free_func(ctx->state, curr->data);
                curr->data = NULL;
                ctx->free_func(ctx->state, curr);
                curr = kmip_linked_list_pop(value->operation_list);
            }
            ctx->free_func(ctx->state, value->operation_list);
            value->operation_list = NULL;
        }
    }

    return;
}

void
kmip_print_operations(int indent, Operations *value)
{
    printf("%*sOperations @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        printf("%*sOperations: %zu\n", indent + 2, "", value->operation_list->size);
        LinkedListItem *curr = value->operation_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            printf("%*sOperation: %zu: ", indent + 4, "", count);
            int32 oper = *(int32 *)curr->data;
            kmip_print_operation_enum_2(oper);
            printf("\n");

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_copy_operations(int ops[], size_t* ops_size, Operations *value, int max_ops)
{
    if(value != NULL)
    {
        *ops_size = value->operation_list->size;

        LinkedListItem *curr = value->operation_list->head;
        size_t idx = 0;
        while(curr != NULL && idx < max_ops )
        {
            ops[idx] = *(int32 *)curr->data;
            curr = curr->next;
            idx++;
        }
    }
}

void
kmip_copy_objects(int objs[], size_t* objs_size, ObjectTypes *value, int max_objs)
{
    if(value != NULL)
    {
        *objs_size = value->object_list->size;

        LinkedListItem *curr = value->object_list->head;
        size_t idx = 0;
        while(curr != NULL && idx < max_objs )
        {
            objs[idx] = *(int32 *)curr->data;
            curr = curr->next;
            idx++;
        }
    }
}

void
kmip_print_object_types(int indent, ObjectTypes* value)
{
    printf("%*sObjects @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        printf("%*sObjects: %zu\n", indent + 2, "", value->object_list->size);
        LinkedListItem *curr = value->object_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            printf("%*sObject: %zu: ", indent + 4, "", count);
            int32 obj = *(int32 *)curr->data;
            kmip_print_object_type_enum(obj);
            printf("\n");

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_free_objects(KMIP *ctx, ObjectTypes* value)
{
    if(value != NULL)
    {
        if(value->object_list != NULL)
        {
            LinkedListItem *curr = kmip_linked_list_pop(value->object_list);
            while(curr != NULL)
            {
                ctx->free_func(ctx->state, curr->data);
                curr->data = NULL;
                ctx->free_func(ctx->state, curr);
                curr = kmip_linked_list_pop(value->object_list);
            }
            ctx->free_func(ctx->state, value->object_list);
            value->object_list = NULL;
        }
    }

    return;
}

int
kmip_decode_object_types(KMIP *ctx, ObjectTypes *value)
{
    int result = 0;

    value->object_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    CHECK_NEW_MEMORY(ctx, value->object_list, sizeof(LinkedList), "LinkedList");

    uint32 tag = kmip_peek_tag(ctx);
    while(tag == KMIP_TAG_OBJECT_TYPE)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        CHECK_NEW_MEMORY(ctx, item, sizeof(LinkedListItem), "LinkedListItem");
        kmip_linked_list_enqueue(value->object_list, item);

        item->data = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, item->data, sizeof(int32), "Object");

        result = kmip_decode_enum(ctx, KMIP_TAG_OBJECT_TYPE, (int32 *)item->data);
        CHECK_RESULT(ctx, result);

        tag = kmip_peek_tag(ctx);
    }

    return(KMIP_OK);
}


void
kmip_free_server_information(KMIP* ctx, ServerInformation* value)
{
    kmip_free_text_string(ctx, value->server_name);
    kmip_free_text_string(ctx, value->server_serial_number);
    kmip_free_text_string(ctx, value->server_version);
    kmip_free_text_string(ctx, value->server_load);
    kmip_free_text_string(ctx, value->product_name);
    kmip_free_text_string(ctx, value->build_level);
    kmip_free_text_string(ctx, value->build_date);
    kmip_free_text_string(ctx, value->cluster_info);
}

int
kmip_decode_server_information(KMIP *ctx, ServerInformation *value)
{
    CHECK_BUFFER_FULL(ctx, 8);

    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;

    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_SERVER_INFORMATION, KMIP_TYPE_STRUCTURE);

    kmip_decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);

    if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_NAME))
    {
        value->server_name = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->server_name, sizeof(TextString), "ServerName text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_SERVER_NAME, value->server_name);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_SERIAL_NUMBER))
    {
        value->server_serial_number = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->server_serial_number, sizeof(TextString), "ServerSerialNumber text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_SERVER_SERIAL_NUMBER, value->server_serial_number);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_VERSION))
    {
        value->server_version = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->server_version, sizeof(TextString), "ServerVersion text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_SERVER_VERSION, value->server_version);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_LOAD))
    {
        value->server_load = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->server_load, sizeof(TextString), "ServerLoad text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_SERVER_LOAD, value->server_load);
        CHECK_RESULT(ctx, result);
    }


    if(kmip_is_tag_next(ctx, KMIP_TAG_PRODUCT_NAME))
    {
        value->product_name = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->product_name, sizeof(TextString), "ProductName text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_PRODUCT_NAME, value->product_name);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_BUILD_LEVEL))
    {
        value->build_level = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->build_level, sizeof(TextString), "BuildLevel text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_BUILD_LEVEL, value->build_level);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_BUILD_DATE))
    {
        value->build_date = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->build_date, sizeof(TextString), "BuildDate text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_BUILD_DATE, value->build_date);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_CLUSTER_INFO))
    {
        value->cluster_info = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->cluster_info, sizeof(TextString), "ClusterInfo text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_CLUSTER_INFO, value->cluster_info);
        CHECK_RESULT(ctx, result);
    }

    return(KMIP_OK);
}

void
kmip_print_server_information(int indent, ServerInformation* value)
{
    printf("%*sServer Information @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(indent + 2, "Server Name", value->server_name);
        kmip_print_text_string(indent + 2, "Server Serial Number", value->server_serial_number);
        kmip_print_text_string(indent + 2, "Server Version", value->server_version);
        kmip_print_text_string(indent + 2, "Server Load", value->server_load);
        kmip_print_text_string(indent + 2, "Product Name", value->product_name);
        kmip_print_text_string(indent + 2, "Build Llevel", value->build_level);
        kmip_print_text_string(indent + 2, "Build Date", value->build_date);
        kmip_print_text_string(indent + 2, "Cluster info", value->cluster_info);
    }
}


void kmip_print_query_response_payload(int indent, QueryResponsePayload *value)
{
    kmip_print_operations(indent, value->operations);
    kmip_print_object_types(indent, value->objects);
    kmip_print_text_string(indent, "Vendor ID", value->vendor_identification);
    kmip_print_server_information(indent, value->server_information);
}

void kmip_free_query_response_payload(KMIP *ctx, QueryResponsePayload *value)
{
    if (value->operations)
    {
        kmip_free_operations(ctx, value->operations);
        ctx->free_func(ctx->state, value->operations);
        value->operations = NULL;
    }
    if (value->objects)
    {
        kmip_free_objects(ctx, value->objects);
        ctx->free_func(ctx->state, value->objects);
        value->objects = NULL;
    }

    if (value->vendor_identification)
    {
        kmip_free_text_string(ctx, value->vendor_identification);
        ctx->free_func(ctx->state, value->vendor_identification);
        value->vendor_identification = NULL;
    }

    if (value->server_information)
    {
        kmip_free_server_information(ctx, value->server_information);
        ctx->free_func(ctx->state, value->server_information);
        value->server_information = NULL;
    }
}

int kmip_compare_query_response_payload(const QueryResponsePayload *a, const QueryResponsePayload *b)
{
    return(KMIP_NOT_IMPLEMENTED);
}

int kmip_decode_query_response_payload(KMIP *ctx, QueryResponsePayload *value)
{
    int result = 0;

    int32 tag_type = 0;
    uint32 length = 0;

    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE);

    kmip_decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);

    if(kmip_is_tag_next(ctx, KMIP_TAG_OPERATION))
    {
        value->operations = ctx->calloc_func(ctx->state, 1, sizeof(Operations));
        CHECK_NEW_MEMORY(ctx, value->operations, sizeof(Operations), "Operations");
        result = kmip_decode_operations(ctx, value->operations);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_OBJECT_TYPE))
    {
        value->objects = ctx->calloc_func(ctx->state, 1, sizeof(ObjectTypes));
        CHECK_NEW_MEMORY(ctx, value->objects, sizeof(ObjectTypes), "Object_Types");
        result = kmip_decode_object_types(ctx, value->objects);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_VENDOR_IDENTIFICATION))
    {
        value->vendor_identification = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->vendor_identification, sizeof(TextString), "Vendor Identifier text string");
        result = kmip_decode_text_string(ctx, KMIP_TAG_VENDOR_IDENTIFICATION, (TextString*)value->vendor_identification);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_INFORMATION))
    {
        value->server_information = ctx->calloc_func(ctx->state, 1, sizeof(ServerInformation));
        CHECK_NEW_MEMORY(ctx, value->server_information, sizeof(ServerInformation), "Server Information");
        result = kmip_decode_server_information(ctx, value->server_information);
        CHECK_RESULT(ctx, result);
    }

    return(KMIP_OK);
}

int
kmip_encode_query_response_payload(KMIP *ctx, const QueryResponsePayload *value)
{
    return(KMIP_NOT_IMPLEMENTED);
}

void
kmip_copy_query_result(QueryResponse* query_result, QueryResponsePayload *pld)
{
    if(pld != NULL)
    {
        kmip_copy_operations(query_result->operations, &query_result->operations_size, pld->operations, MAX_QUERY_OPS);
        kmip_copy_objects(query_result->objects, &query_result->objects_size, pld->objects, MAX_QUERY_OBJS);

        if(pld->vendor_identification)
        {
            kmip_copy_textstring(query_result->vendor_identification, pld->vendor_identification, sizeof(query_result->vendor_identification)-1);
        }

        if(pld->server_information)
        {
            ServerInformation* srv = pld->server_information;
            query_result->server_information_valid = 1;
            kmip_copy_textstring(query_result->server_name, srv->server_name, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->server_serial_number, srv->server_serial_number, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->server_version, srv->server_version, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->server_load, srv->server_load, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->product_name, srv->product_name, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->build_level, srv->build_level, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->build_date, srv->build_date, MAX_QUERY_LEN-1);
        }
    }
}

