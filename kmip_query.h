/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <openssl/ssl.h>      // for BIO


enum all_operations
{
    // # KMIP 1.0
    KMIP_OP_CREATE_               = 0x01,
    KMIP_OP_CREATE_KEY_PAIR      = 0x02,
    KMIP_OP_REGISTER             = 0x03,
    KMIP_OP_REKEY                = 0x04,
    KMIP_OP_DERIVE_KEY           = 0x05,
    KMIP_OP_CERTIFY              = 0x06,
    KMIP_OP_RECERTIFY            = 0x07,
    KMIP_OP_LOCATE_              = 0x08,
    KMIP_OP_CHECK                = 0x09,
    KMIP_OP_GET_                  = 0x0A,
    KMIP_OP_GET_ATTRIBUTES       = 0x0B,
    KMIP_OP_GET_ATTRIBUTE_LIST   = 0x0C,
    KMIP_OP_ADD_ATTRIBUTE        = 0x0D,
    KMIP_OP_MODIFY_ATTRIBUTE     = 0x0E,
    KMIP_OP_DELETE_ATTRIBUTE     = 0x0F,
    KMIP_OP_OBTAIN_LEASE         = 0x10,
    KMIP_OP_GET_USAGE_ALLOCATION = 0x11,
    KMIP_OP_ACTIVATE             = 0x12,
    KMIP_OP_REVOKE               = 0x13,
    KMIP_OP_DESTROY_              = 0x14,
    KMIP_OP_ARCHIVE              = 0x15,
    KMIP_OP_RECOVER              = 0x16,
    KMIP_OP_VALIDATE             = 0x17,
    KMIP_OP_QUERY_                = 0x18,
    KMIP_OP_CANCEL               = 0x19,
    KMIP_OP_POLL                 = 0x1A,
    KMIP_OP_NOTIFY               = 0x1B,
    KMIP_OP_PUT                  = 0x1C,
    // # KMIP 1.1
    KMIP_OP_REKEY_KEY_PAIR       = 0x1D,
    KMIP_OP_DISCOVER_VERSIONS    = 0x1E,
    //# KMIP 1.2
    KMIP_OP_ENCRYPT              = 0x1F,
    KMIP_OP_DECRYPT              = 0x20,
    KMIP_OP_SIGN                 = 0x21,
    KMIP_OP_SIGNATURE_VERIFY     = 0x22,
    KMIP_OP_MAC                  = 0x23,
    KMIP_OP_MAC_VERIFY           = 0x24,
    KMIP_OP_RNG_RETRIEVE         = 0x25,
    KMIP_OP_RNG_SEED             = 0x26,
    KMIP_OP_HASH                 = 0x27,
    KMIP_OP_CREATE_SPLIT_KEY     = 0x28,
    KMIP_OP_JOIN_SPLIT_KEY       = 0x29,
    // # KMIP 1.4
    KMIP_OP_IMPORT               = 0x2A,
    KMIP_OP_EXPORT               = 0x2B,
    // # KMIP 2.0
    KMIP_OP_LOG                  = 0x2C,
    KMIP_OP_LOGIN                = 0x2D,
    KMIP_OP_LOGOUT               = 0x2E,
    KMIP_OP_DELEGATED_LOGIN      = 0x2F,
    KMIP_OP_ADJUST_ATTRIBUTE     = 0x30,
    KMIP_OP_SET_ATTRIBUTE        = 0x31,
    KMIP_OP_SET_ENDPOINT_ROLE    = 0x32,
    KMIP_OP_PKCS_11              = 0x33,
    KMIP_OP_INTEROP              = 0x34,
    KMIP_OP_REPROVISION          = 0x35,
};

typedef struct operations
{
    LinkedList *operation_list;
} Operations;

typedef struct object_types
{
    LinkedList *object_list;
} ObjectTypes;

typedef struct server_information
{
    TextString* server_name;
    TextString* server_serial_number;
    TextString* server_version;
    TextString* server_load;
    TextString* product_name;
    TextString* build_level;
    TextString* build_date;
    TextString* cluster_info;
 // LinkedList* alternative_failover_endpoints;   MAY be repeated
 // Vendor-Specific               Any, MAY be repeated
} ServerInformation;


/*
typedef struct application_namespaces
{
    LinkedList *app_namespace_list;
} ApplicationNamespaces;
*/

typedef struct query_request_payload
{
    LinkedList *functions;
} QueryRequestPayload;

typedef struct query_response_payload
{
    Operations*             operations;              // Specifies an Operation that is supported by the server.
    ObjectTypes*            objects;                 // Specifies a Managed Object Type that is supported by the server.
    TextString*             vendor_identification;   // SHALL be returned if Query Server Information is requested. The Vendor Identification SHALL be a text string that uniquely identifies the vendor.
    ServerInformation*      server_information;      // Contains vendor-specific information possibly be of interest to the client.
 // ApplicationNamespaces*  application_namespaces;  // Specifies an Application Namespace supported by the server.
 // Extension Information         No, MAY be repeated  // SHALL be returned if Query Extension List or Query Extension Map is requested and supported by the server.
 // Attestation Type              No, MAY be repeated  // Specifies an Attestation Type that is supported by the server.
 // RNG Parameters                No, MAY be repeated  // Specifies the RNG that is supported by the server.
 // Profile Information           No, MAY be repeated  // Specifies the Profiles that are supported by the server.
 // Validation Information        No, MAY be repeated  // Specifies the validations that are supported by the server.
 // Capability Information        No, MAY be repeated  // Specifies the capabilities that are supported by the server.
 // Client Registration Method    No, MAY be repeated  // Specifies a Client Registration Method that is supported by the server.
 // Defaults Information          No                   // Specifies the defaults that the server will use if the client omits them.
 // Protection Storage Masks      Yes                  // Specifies the list of Protection Storage Mask values supported by the server. A server MAY elect to provide an empty list in the Response if it is unable or unwilling to provide this information.
} QueryResponsePayload;


#define MAX_QUERY_LEN    128
#define MAX_QUERY_OPS   0x40
#define MAX_QUERY_OBJS  0x20

typedef struct query_response
{
    size_t           operations_size;
    int              operations[MAX_QUERY_OPS];
    size_t           objects_size;
    int              objects[MAX_QUERY_OBJS];
    char             vendor_identification[MAX_QUERY_LEN];
    bool32           server_information_valid;
    char             server_name[MAX_QUERY_LEN];
    char             server_serial_number[MAX_QUERY_LEN];
    char             server_version[MAX_QUERY_LEN];
    char             server_load[MAX_QUERY_LEN];
    char             product_name[MAX_QUERY_LEN];
    char             build_level[MAX_QUERY_LEN];
    char             build_date[MAX_QUERY_LEN];
    char             cluster_info[MAX_QUERY_LEN];
} QueryResponse;

void kmip_print_query_request_payload(int, QueryRequestPayload *);
void kmip_free_query_request_payload(KMIP *, QueryRequestPayload *);
int kmip_compare_query_request_payload(const QueryRequestPayload *, const QueryRequestPayload *);
int kmip_encode_query_request_payload(KMIP *, const QueryRequestPayload *);
int kmip_decode_query_request_payload(KMIP *, QueryRequestPayload *);

void kmip_print_query_response_payload(int, QueryResponsePayload *);
void kmip_free_query_response_payload(KMIP *, QueryResponsePayload *);
int kmip_compare_query_response_payload(const QueryResponsePayload *, const QueryResponsePayload *);
int kmip_encode_query_response_payload(KMIP *, const QueryResponsePayload *);
int kmip_decode_query_response_payload(KMIP *, QueryResponsePayload *);

void kmip_print_query_function_enum(int indent, enum query_function value);
void kmip_print_query_functions(int indent, QueryRequestPayload* value);
void kmip_free_query_functions(KMIP *ctx, QueryRequestPayload* value);
int  kmip_compare_query_functions(const QueryRequestPayload* a, const QueryRequestPayload* b);
int  kmip_encode_query_functions(KMIP *ctx, const QueryRequestPayload* value);
int  kmip_decode_query_functions(KMIP *ctx, QueryRequestPayload* value);


void kmip_copy_operations(int ops[], size_t* ops_size, Operations *value, int max_ops);
void kmip_copy_objects(int objs[], size_t* objs_size, ObjectTypes *value, int max_objs);
void kmip_copy_query_result(QueryResponse* query_result, QueryResponsePayload *pld);

