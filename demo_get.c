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
use_mid_level_api(int argc, char **argv)
{
    if(argc != 2)
    {
        printf("\nUsage: %s <id>\n\n", argv[0]);
        return(-1);
    }
    
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
    
    char *key = NULL;
    int key_size = 0;
    size_t id_size = kmip_strnlen_s(argv[1], 50);
    
    KMIP kmip_context = {0};
    kmip_init(&kmip_context, NULL, 0, KMIP_1_0);
    
    result = kmip_bio_get_symmetric_key_with_context(
        &kmip_context, bio,
        argv[1], id_size,
        &key, &key_size);
    
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    
    if(result < 0)
    {
        printf("An error occurred while creating the symmetric key.");
        printf("Error Code: %d\n", result);
        printf("Error Name: ");
        kmip_print_error_string(result);
        printf("\n");
        printf("Context Error: %s\n", kmip_context.error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(&kmip_context);
    }
    else if(result >= 0)
    {
        printf("The KMIP operation was executed with no errors.\n");
        printf("Result: ");
        kmip_print_result_status_enum(result);
        printf(" (%d)\n\n", result);
        
        if(result == KMIP_STATUS_SUCCESS)
        {
            printf("Symmetric Key ID: %s\n", argv[1]);
            printf("Symmetric Key Size: %d bits\n", key_size * 8);
            printf("Symmetric Key:");
            kmip_print_buffer(key, key_size);
            printf("\n");
        }
    }
    
    if(key != NULL)
    {
        kmip_memset(key, 0, key_size);
        kmip_free(NULL, key);
    }
    
    kmip_destroy(&kmip_context);
    return(result);
}

int
main(int argc, char **argv)
{
    use_mid_level_api(argc, argv);
}
