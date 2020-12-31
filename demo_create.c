/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kmip.h"
#include "kmip_bio.h"
#include "kmip_memset.h"
#include "ssl_connect.h"

void
print_help(const char *app)
{
    printf("Usage: %s [flag value | flag] ...\n\n", app);
    printf("Flags:\n");
    printf("-a addr : the IP address of the KMIP server\n");
    printf("-c path : path to client certificate file\n");
    printf("-h      : print this help info\n");
    printf("-k path : path to client key file\n");
    printf("-p port : the port number of the KMIP server\n");
    printf("-r path : path to CA certificate file\n");
    printf("-n name : name of new key\n");
    printf("-g group : name of object group\n");
}

int
parse_arguments(int argc, char **argv,
                char **server_address, char **server_port,
                char **client_certificate, char **client_key, char **ca_certificate,
                char** key_name,
                char **group,
                int *print_usage)
{
    if(argc <= 1)
    {
        print_help(argv[0]);
        return(-1);
    }
    
    for(int i = 1; i < argc; i++)
    {
        if(strncmp(argv[i], "-a", 2) == 0)
            *server_address = argv[++i];
        else if(strncmp(argv[i], "-c", 2) == 0)
            *client_certificate = argv[++i];
        else if(strncmp(argv[i], "-h", 2) == 0)
            *print_usage = 1;
        else if(strncmp(argv[i], "-k", 2) == 0)
            *client_key = argv[++i];
        else if(strncmp(argv[i], "-p", 2) == 0)
            *server_port = argv[++i];
        else if(strncmp(argv[i], "-r", 2) == 0)
            *ca_certificate = argv[++i];
        else if(strncmp(argv[i], "-n", 2) == 0)
            *key_name = argv[++i];
        else if(strncmp(argv[i], "-g", 2) == 0)
            *group = argv[++i];
        else
        {
            printf("Invalid option: '%s'\n", argv[i]);
            print_help(argv[0]);
            return(-1);
        }
    }
    
    return(0);
}

int
use_low_level_api(BIO* bio,
                  const char *key_name,
                  const char *group)
{
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP kmip_context = {0};
    kmip_init(&kmip_context, NULL, 0, KMIP_1_0);
    
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = kmip_context.calloc_func(kmip_context.state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&kmip_context);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(&kmip_context, encoding, buffer_total_size);
    
    /* Build the request message. */
    Attribute a[6] = {{0}};
    for(int i = 0; i < 6; i++)
        kmip_init_attribute(&a[i]);
    
    enum cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
    a[0].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    a[0].value = &algorithm;
    
    int32 length = 256;
    a[1].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    a[1].value = &length;
    
    int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
    a[2].type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
    a[2].value = &mask;

    int idx = 3;

    TextString g = { 0 };
    if (group)
    {
        g.value = (char*) group;
        g.size = kmip_strnlen_s(group, 50);

        a[idx].type = KMIP_ATTR_OBJECT_GROUP;
        a[idx].value = &g;

        idx++;
    }

    TextString s = { 0 };
    Name n = { 0 };
    if (key_name)
    {
        s.value = (char*) key_name;
        s.size = kmip_strnlen_s(key_name, 50);

        n.value = &s;
        n.type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;

        a[idx].type = KMIP_ATTR_NAME;
        a[idx].value = &n;

        idx++;
    }

    int attrib_count = idx;
    
    TemplateAttribute ta = {0};
    ta.attributes = a;
    ta.attribute_count = attrib_count;
    
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, kmip_context.version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = kmip_context.max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    CreateRequestPayload crp = {0};
    crp.object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
    crp.template_attribute = &ta;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_CREATE;
    rbi.request_payload = &crp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;

    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(&kmip_context, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(&kmip_context);
        kmip_context.free_func(kmip_context.state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = kmip_context.calloc_func(kmip_context.state, buffer_blocks, buffer_block_size);
        if(encoding == NULL)
        {
            printf("Failure: Could not automatically enlarge the encoding ");
            printf("buffer for the Create request.\n");

            kmip_destroy(&kmip_context);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(&kmip_context, encoding, buffer_total_size);
        encode_result = kmip_encode_request_message(&kmip_context, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        printf("An error occurred while encoding the Create request.\n");
        printf("Error Code: %d\n", encode_result);
        printf("Error Name: ");
        kmip_print_error_string(encode_result);
        printf("\n");
        printf("Context Error: %s\n", kmip_context.error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(&kmip_context);

        kmip_free_buffer(&kmip_context, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(&kmip_context, NULL, 0);
        kmip_destroy(&kmip_context);
        return(encode_result);
    }
    
    kmip_print_request_message(&rm);
    printf("\n");
    
    char *response = NULL;
    int response_size = 0;
    
    int result = kmip_bio_send_request_encoding(&kmip_context, bio, (char *)encoding, kmip_context.index - kmip_context.buffer, &response, &response_size);
    
    printf("\n");
    if(result < 0)
    {
        printf("An error occurred while creating the symmetric key.\n");
        printf("Error Code: %d\n", result);
        printf("Error Name: ");
        kmip_print_error_string(result);
        printf("\n");
        printf("Context Error: %s\n", kmip_context.error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(&kmip_context);
        
        kmip_free_buffer(&kmip_context, encoding, buffer_total_size);
        kmip_free_buffer(&kmip_context, response, response_size);
        encoding = NULL;
        response = NULL;
        kmip_set_buffer(&kmip_context, NULL, 0);
        kmip_destroy(&kmip_context);
        return(result);
    }
    
    kmip_free_buffer(&kmip_context, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(&kmip_context, response, response_size);
    
    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(&kmip_context, &resp_m);
    if(decode_result != KMIP_OK)
    {
        printf("An error occurred while decoding the Create response.\n");
        printf("Error Code: %d\n", decode_result);
        printf("Error Name: ");
        kmip_print_error_string(decode_result);
        printf("\n");
        printf("Context Error: %s\n", kmip_context.error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(&kmip_context);

        kmip_free_response_message(&kmip_context, &resp_m);
        kmip_free_buffer(&kmip_context, response, response_size);
        response = NULL;
        kmip_set_buffer(&kmip_context, NULL, 0);
        kmip_destroy(&kmip_context);
        return(decode_result);
    }
    
    kmip_print_response_message(&resp_m);
    printf("\n");

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        printf("Expected to find one batch item in the Create response.\n");
        kmip_free_response_message(&kmip_context, &resp_m);
        kmip_free_buffer(&kmip_context, response, response_size);
        response = NULL;
        kmip_set_buffer(&kmip_context, NULL, 0);
        kmip_destroy(&kmip_context);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem req = resp_m.batch_items[0];
    enum result_status result_status = req.result_status;
    
    printf("The KMIP operation was executed with no errors.\n");
    printf("Result: ");
    kmip_print_result_status_enum(result_status);
    printf(" (%d)\n\n", result_status);

    if (result_status != KMIP_STATUS_SUCCESS)
    {
        printf("Result Reason: ");
        kmip_print_result_reason_enum(req.result_reason);
        printf("\n");

        kmip_print_text_string(0, "Result Message", req.result_message);
    }

    if(result == KMIP_STATUS_SUCCESS)
    {
        CreateResponsePayload *pld = (CreateResponsePayload *)req.response_payload;
        if(pld != NULL)
        {
            TextString *uuid = pld->unique_identifier;
            
            if(uuid != NULL)
                printf("Symmetric Key ID: %.*s\n", (int)uuid->size, uuid->value);
        }
    }
    
    /* Clean up the response message, the response buffer, and the KMIP */
    /* context.                                                         */
    kmip_free_response_message(&kmip_context, &resp_m);
    kmip_free_buffer(&kmip_context, response, response_size);
    response = NULL;
    kmip_set_buffer(&kmip_context, NULL, 0);
    kmip_destroy(&kmip_context);
    
    return(result_status);
}


int
use_mid_level_api(BIO* bio,
                  const char *key_name,
                  const char *group,
                  char* id,
                  int*  idlen
                  )
{
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP kmip_context = {0};
    kmip_init(&kmip_context, NULL, 0, KMIP_1_0);

    /* Build the request message. */
    Attribute a[6] = {{0}};
    for(int i = 0; i < 6; i++)
        kmip_init_attribute(&a[i]);

    enum cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
    a[0].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    a[0].value = &algorithm;

    int32 length = 256;
    a[1].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    a[1].value = &length;

    int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
    a[2].type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
    a[2].value = &mask;

    int idx = 3;

    TextString g = { 0 };
    if (group)
    {
        g.value = (char*) group;
        g.size = kmip_strnlen_s(group, 50);

        a[idx].type = KMIP_ATTR_OBJECT_GROUP;
        a[idx].value = &g;

        idx++;
    }

    TextString s = { 0 };
    Name n = { 0 };
    if (key_name)
    {
        s.value = (char*) key_name;
        s.size = kmip_strnlen_s(key_name, 50);

        n.value = &s;
        n.type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;

        a[idx].type = KMIP_ATTR_NAME;
        a[idx].value = &n;

        idx++;
    }

    int attrib_count = idx;

    TemplateAttribute ta = {0};
    ta.attributes = a;
    ta.attribute_count = attrib_count;

    char* uuid = NULL;
    int uuid_size = 0;
    int result = kmip_bio_create_symmetric_key_with_context(&kmip_context, bio, &ta, &uuid, &uuid_size);

    if (uuid)
    {
        strncpy(id, uuid, uuid_size);
        id[uuid_size] = 0;
        *idlen = uuid_size;
        kmip_context.free_func(kmip_context.state, uuid);
    }
    kmip_destroy(&kmip_context);

    return(result);
}

int
main(int argc, char **argv)
{
    char *server_address = NULL;
    char *server_port = NULL;
    char *client_certificate = NULL;
    char *client_key = NULL;
    char *ca_certificate = NULL;
    char *key_name = NULL;
    char *group = NULL;
    int help = 0;
    
    int error = parse_arguments(argc, argv, &server_address, &server_port, &client_certificate, &client_key, &ca_certificate, &key_name, &group, &help);
    if(error)
        return(error);
    if(help)
    {
        print_help(argv[0]);
        return(0);
    }

    ssl_initialize();
    SSL_CTX* ctx = ssl_create_context(client_certificate, client_key, ca_certificate);
    if (!ctx)
        return 1;

    SSL_SESSION* session = NULL;
    
    BIO* bio = ssl_connect(ctx, server_address, server_port, &session);
    if (!bio)
        return 1;

    //int rc = use_low_level_api(bio, key_name, group);
    char id[128] = {0};
    int id_len = 0;
    int rc = use_mid_level_api(bio, key_name, group, id, &id_len);

    printf("create rc=%d, id=%s\n", rc, id);

    ssl_disconnect(bio);

    if (session)
        SSL_SESSION_free(session);

    SSL_CTX_free(ctx);

    return(0);
}
