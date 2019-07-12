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
}

int
parse_arguments(int argc, char **argv,
                char **server_address, char **server_port,
                char **client_certificate, char **client_key, char **ca_certificate,
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
use_low_level_api(const char *server_address,
                  const char *server_port,
                  const char *client_certificate,
                  const char *client_key,
                  const char *ca_certificate)
{
    /* Set up the TLS connection to the KMIP server. */
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());
    
    printf("\n");
    printf("Loading the client certificate: %s\n", client_certificate);
    if(SSL_CTX_use_certificate_file(ctx, client_certificate, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Loading the client certificate failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    printf("Loading the client key: %s\n", client_key);
    if(SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Loading the client key failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    printf("Loading the CA certificate: %s\n", ca_certificate);
    if(SSL_CTX_load_verify_locations(ctx, ca_certificate, NULL) != 1)
    {
        fprintf(stderr, "Loading the CA certificate failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    BIO *bio = NULL;
    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        fprintf(stderr, "BIO_new_ssl_connect failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, server_address);
    BIO_set_conn_port(bio, server_port);
    if(BIO_do_connect(bio) != 1)
    {
        fprintf(stderr, "BIO_do_connect failed\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    printf("\n");
    
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
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(&kmip_context, encoding, buffer_total_size);
    
    /* Build the request message. */
    Attribute a[3] = {0};
    for(int i = 0; i < 3; i++)
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
    
    TemplateAttribute ta = {0};
    ta.attributes = a;
    ta.attribute_count = ARRAY_LENGTH(a);
    
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
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
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
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(encode_result);
    }
    
    kmip_print_request_message(&rm);
    printf("\n");
    
    char *response = NULL;
    int response_size = 0;
    
    int result = kmip_bio_send_request_encoding(&kmip_context, bio, (char *)encoding, kmip_context.index - kmip_context.buffer, &response, &response_size);
    
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    
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
    kmip_print_result_status_enum(result);
    printf(" (%d)\n\n", result);
    
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
main(int argc, char **argv)
{
    char *server_address = NULL;
    char *server_port = NULL;
    char *client_certificate = NULL;
    char *client_key = NULL;
    char *ca_certificate = NULL;
    int help = 0;
    
    int error = parse_arguments(argc, argv, &server_address, &server_port, &client_certificate, &client_key, &ca_certificate, &help);
    if(error)
        return(error);
    if(help)
    {
        print_help(argv[0]);
        return(0);
    }
    
    use_low_level_api(server_address, server_port, client_certificate, client_key, ca_certificate);
    return(0);
}
