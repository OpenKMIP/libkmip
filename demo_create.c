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

#include <openssl/ssl.h>
#include <stdio.h>
#include <time.h>

#include "kmip.h"
#include "kmip_bio.h"
#include "kmip_memset.h"

int
use_high_level_api(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());
    
    int result = SSL_CTX_use_certificate_file(
        ctx,
        "/etc/pykmip/certs/slugs/client_certificate_john_doe.pem",
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client certificate failed (%d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    result = SSL_CTX_use_PrivateKey_file(
        ctx,
        "/etc/pykmip/certs/slugs/client_key_john_doe.pem",
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client key failed (%d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    result = SSL_CTX_load_verify_locations(
        ctx, 
        "/etc/pykmip/certs/slugs/root_certificate.pem",
        NULL);
    if(result != 1)
    {
        printf("Loading the CA file failed (%d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    BIO *bio = NULL;
    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        printf("BIO_new_ssl_connect failed\n");
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, "127.0.0.1");
    BIO_set_conn_port(bio, "5696");
    result = BIO_do_connect(bio);
    if(result != 1)
    {
        printf("BIO_do_connect failed (%d)\n", result);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    Attribute a[3] = {0};
    for(int i = 0; i < 3; i++)
    {
        init_attribute(&a[i]);
    }
    
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
    
    char *id = NULL;
    int id_size = 0;
    
    result = kmip_bio_create_symmetric_key(bio, &ta, &id, &id_size);
    
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    
    if(result < 0)
    {
        printf("An error occurred while creating the symmetric key.");
        printf("Error Code: %d\n", result);
    }
    else if(result >= 0)
    {
        printf("The KMIP operation was executed with no errors.\n");
        printf("Result: ");
        print_result_status_enum(result);
        printf(" (%d)\n\n", result);
        printf("Symmetric Key ID: %s\n", id);
    }
    
    if(id != NULL)
    {
        kmip_memset(id, 0, id_size);
        kmip_free(NULL, id);
    }
    
    return(result);
}

int
use_mid_level_api(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());
    
    int result = SSL_CTX_use_certificate_file(
        ctx,
        "/etc/pykmip/certs/slugs/client_certificate_john_doe.pem",
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client certificate failed (%d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    result = SSL_CTX_use_PrivateKey_file(
        ctx,
        "/etc/pykmip/certs/slugs/client_key_john_doe.pem",
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client key failed (%d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    result = SSL_CTX_load_verify_locations(
        ctx, 
        "/etc/pykmip/certs/slugs/root_certificate.pem",
        NULL);
    if(result != 1)
    {
        printf("Loading the CA file failed (%d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    BIO *bio = NULL;
    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        printf("BIO_new_ssl_connect failed\n");
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, "127.0.0.1");
    BIO_set_conn_port(bio, "5696");
    result = BIO_do_connect(bio);
    if(result != 1)
    {
        printf("BIO_do_connect failed (%d)\n", result);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    Attribute a[3] = {0};
    for(int i = 0; i < 3; i++)
    {
        init_attribute(&a[i]);
    }
    
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
    
    char *id = NULL;
    int id_size = 0;
    
    KMIP kmip_context = {0};
    kmip_init(&kmip_context, NULL, 0, KMIP_1_0);
    
    result = kmip_bio_create_symmetric_key_with_context(
        &kmip_context, bio,
        &ta,
        &id, &id_size);
    
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    
    if(result < 0)
    {
        printf("An error occurred while creating the symmetric key.");
        printf("Error Code: %d\n", result);
        printf("Error Name: ");
        print_error_string(result);
        printf("\n");
        printf("Context Error: %s\n", kmip_context.error_message);
        printf("Stack trace:\n");
        print_stack_trace(&kmip_context);
    }
    else if(result >= 0)
    {
        printf("The KMIP operation was executed with no errors.\n");
        printf("Result: ");
        print_result_status_enum(result);
        printf(" (%d)\n\n", result);
        
        if(result == KMIP_STATUS_SUCCESS)
        {
            printf("Symmetric Key ID: %s\n", id);
        }
    }
    
    if(id != NULL)
    {
        kmip_memset(id, 0, id_size);
        kmip_free(NULL, id);
    }
    
    kmip_destroy(&kmip_context);
    return(result);
}

int
use_low_level_api(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());
    
    char *client_certificate = "/etc/pykmip/certs/slugs/client_certificate_john_doe.pem";
    char *client_key = "/etc/pykmip/certs/slugs/client_key_john_doe.pem";
    char *ca_certificate = "/etc/pykmip/certs/slugs/root_certificate.pem";
    
    printf("Loading the client certificate: %s\n", client_certificate);
    int result = SSL_CTX_use_certificate_file(
        ctx,
        client_certificate,
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client certificate failed (error: %d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    printf("Loading the client key: %s\n", client_key);
    result = SSL_CTX_use_PrivateKey_file(
        ctx,
        client_key,
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client key failed (error: %d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    printf("Loading the CA certificate: %s\n", ca_certificate);
    result = SSL_CTX_load_verify_locations(
        ctx, 
        ca_certificate,
        NULL);
    if(result != 1)
    {
        printf("Loading the CA certificate failed (error: %d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    BIO *bio = NULL;
    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        printf("BIO_new_ssl_connect failed\n");
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, "127.0.0.1");
    BIO_set_conn_port(bio, "5696");
    result = BIO_do_connect(bio);
    if(result != 1)
    {
        printf("BIO_do_connect failed (%d)\n", result);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    printf("\n");
    
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP kmip_context = {0};
    kmip_init(&kmip_context, NULL, 0, KMIP_1_0);
    
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = kmip_context.calloc_func(
        kmip_context.state, buffer_blocks,
        buffer_block_size);
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
    {
        init_attribute(&a[i]);
    }
    
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
    init_protocol_version(&pv, kmip_context.version);
    
    RequestHeader rh = {0};
    init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = kmip_context.max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    CreateRequestPayload crp = {0};
    crp.object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
    crp.template_attribute = &ta;
    
    RequestBatchItem rbi = {0};
    rbi.operation = KMIP_OP_CREATE;
    rbi.request_payload = &crp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = encode_request_message(&kmip_context, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(&kmip_context);
        kmip_context.free_func(kmip_context.state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = kmip_context.calloc_func(
            kmip_context.state, buffer_blocks,
            buffer_block_size);
        if(encoding == NULL)
        {
            kmip_destroy(&kmip_context);
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            &kmip_context,
            encoding,
            buffer_total_size);
        encode_result = encode_request_message(&kmip_context, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        free_buffer(&kmip_context, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(&kmip_context, NULL, 0);
        kmip_destroy(&kmip_context);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(encode_result);
    }
    
    print_request_message(&rm);
    printf("\n");
    
    char *response = NULL;
    int response_size = 0;
    
    result = kmip_bio_send_request_encoding(
        &kmip_context, bio,
        (char *)encoding, buffer_total_size,
        &response, &response_size);
    
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    
    if(result < 0)
    {
        printf("An error occurred while creating the symmetric key.");
        printf("Error Code: %d\n", result);
        printf("Error Name: ");
        print_error_string(result);
        printf("\n");
        printf("Context Error: %s\n", kmip_context.error_message);
        printf("Stack trace:\n");
        print_stack_trace(&kmip_context);
        
        free_buffer(&kmip_context, encoding, buffer_total_size);
        free_buffer(&kmip_context, response, response_size);
        encoding = NULL;
        response = NULL;
        kmip_set_buffer(&kmip_context, NULL, 0);
        kmip_destroy(&kmip_context);
        return(result);
    }
    
    free_buffer(&kmip_context, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(&kmip_context, response, response_size);
    
    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = decode_response_message(&kmip_context, &resp_m);
    if(decode_result != KMIP_OK)
    {
        free_response_message(&kmip_context, &resp_m);
        free_buffer(&kmip_context, response, response_size);
        response = NULL;
        kmip_set_buffer(&kmip_context, NULL, 0);
        kmip_destroy(&kmip_context);
        return(decode_result);
    }
    
    print_response_message(&resp_m);
    printf("\n");
    
    enum result_status result_status = KMIP_STATUS_OPERATION_FAILED;
    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        free_response_message(&kmip_context, &resp_m);
        free_buffer(&kmip_context, response, response_size);
        response = NULL;
        kmip_set_buffer(&kmip_context, NULL, 0);
        kmip_destroy(&kmip_context);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem req = resp_m.batch_items[0];
    result_status = req.result_status;
    
    printf("The KMIP operation was executed with no errors.\n");
    printf("Result: ");
    print_result_status_enum(result);
    printf(" (%d)\n\n", result);
    
    if(result == KMIP_STATUS_SUCCESS)
    {
        CreateResponsePayload *pld = (CreateResponsePayload *)req.response_payload;
        if(pld != NULL)
        {
            TextString *uuid = pld->unique_identifier;
            
            if(uuid != NULL)
            {
                printf("Symmetric Key ID: %.*s\n", (int)uuid->size, uuid->value);
            }
        }
    }
    
    /* Clean up the response message, the response buffer, and the KMIP */
    /* context.                                                         */
    free_response_message(&kmip_context, &resp_m);
    free_buffer(&kmip_context, response, response_size);
    response = NULL;
    kmip_set_buffer(&kmip_context, NULL, 0);
    kmip_destroy(&kmip_context);
    
    return(result_status);
}

int
main(void)
{
    /*use_high_level_api();*/
    /*use_mid_level_api();*/
    use_low_level_api();
}