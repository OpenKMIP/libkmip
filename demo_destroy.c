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

int
main(void)
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
        return(result);
    }
    result = SSL_CTX_use_PrivateKey_file(
        ctx,
        "/etc/pykmip/certs/slugs/client_key_john_doe.pem",
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client key failed (%d)\n", result);
        return(result);
    }
    result = SSL_CTX_load_verify_locations(
        ctx, 
        "/etc/pykmip/certs/slugs/root_certificate.pem",
        NULL);
    if(result != 1)
    {
        printf("Loading the CA file failed (%d)\n", result);
        return(result);
    }
    
    BIO *bio = NULL;
    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        printf("BIO_new_ssl_connect failed\n");
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
        return(result);
    }
    
    uint8 observed[1024] = {0};
    struct kmip kmip_ctx = {0};
    kmip_init(&kmip_ctx, observed, ARRAY_LENGTH(observed), KMIP_1_0);
    
    struct protocol_version pv = {0};
    pv.major = 1;
    pv.minor = 0;
    
    struct request_header rh = {0};
    init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    struct text_string uuid = {0};
    uuid.value = "1";
    uuid.size = 1;
    
    struct destroy_request_payload drp = {0};
    drp.unique_identifier = &uuid;
    
    struct request_batch_item rbi = {0};
    rbi.operation = KMIP_OP_DESTROY;
    rbi.request_payload = &drp;
    
    struct request_message rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    print_request_message(&rm);
    printf("\n");
    
    int encode_result = encode_request_message(&kmip_ctx, &rm);
    if(encode_result != KMIP_OK)
    {
        printf("Encoding failure detected. Aborting request.");
        return(encode_result);
    }
    
    printf("Sending bytes: %ld\n", kmip_ctx.index - kmip_ctx.buffer);
    
    /* TODO (ph) Make response buffer dynamically sized off of response. */
    uint8 response[300] = {0};
    
    BIO_write(bio, kmip_ctx.buffer, kmip_ctx.index - kmip_ctx.buffer);
    int recv = BIO_read(bio, response, 300);
    
    printf("Received bytes: %d\n\n", recv);
    
    kmip_reset(&kmip_ctx);
    kmip_set_buffer(&kmip_ctx, response, recv);
    
    struct response_message resp_m = {0};
    
    int decode_result = decode_response_message(&kmip_ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        printf("Decoding failure detected. Error: %d\n", decode_result);
        printf("- error code: %d\n", decode_result);
        printf("- error name: ");
        print_error_string(decode_result);
        printf("\n");;
        printf("- context error: %s\n", kmip_ctx.error_message);
        printf("Stack trace:\n");
        print_stack_trace(&kmip_ctx);
        return(decode_result);
    }
    else
    {
        printf("Decoding succeeded!\n\n");
    }
    
    print_response_message(&resp_m);
    
    free_response_message(&kmip_ctx, &resp_m);
    kmip_destroy(&kmip_ctx);
    
    return(0);
}


