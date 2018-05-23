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

#include "kmip.h"

int
scratch(void)
{
    uint8 buffer[40] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF};
    
    struct kmip ctx = {0};
    ctx.buffer = buffer;
    ctx.index = ctx.buffer;
    ctx.size = ARRAY_LENGTH(buffer);
    
    struct protocol_version pv = {0};
    pv.major = 1;
    pv.minor = 2;
    
    int error = encode_protocol_version(&ctx, &pv);
    
    if(error == 0)
    {
        printf("No errors occurred during encoding.\n");
    }
    else
    {
        printf("Errors occurred during encoding.\n");
    }
    
    return(0);
}

int
main(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());
    
    /* load certs and keys and coordinate cipher choices for TLS */
    int result = SSL_CTX_use_certificate_file(
        ctx,
        "/etc/pykmip/certs/slugs/client_certificate_john_doe.pem",
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client certificate failed.\n");
    }
    result = SSL_CTX_use_PrivateKey_file(
        ctx,
        "/etc/pykmip/certs/slugs/client_key_john_doe.pem",
        SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client key failed.\n");
    }
    result = SSL_CTX_load_verify_locations(
        ctx, 
        "/etc/pykmip/certs/slugs/root_certificate.pem",
        NULL);
    if(result != 1)
    {
        printf("Loading the CA file failed.\n");
    }
    
    BIO *bio = NULL;
    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, "127.0.0.1");
    BIO_set_conn_port(bio, "5696");
    BIO_do_connect(bio);
    
    /* Get a SymmetricKey with ID: 1*/
    uint8 request[120] = {
        0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x70,
        0x42, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00, 0x38,
        0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20,
        0x42, 0x00, 0x6A, 0x02, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x6B, 0x02, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x0F, 0x01, 0x00, 0x00, 0x00, 0x48,
        0x42, 0x00, 0x5C, 0x05, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x79, 0x01, 0x00, 0x00, 0x00, 0x30,
        0x42, 0x00, 0x94, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8 response[300] = {0};
    
    BIO_write(bio, request, 120);
    int recv = BIO_read(bio, response, 300);
    
    printf("Received bytes: %d\n", recv);
    
    for(int i = 0; i < recv; i++)
    {
        if(i % 16 == 0)
        {
            printf("\n0x");
        }
        printf("%02X", response[i]);
    }
    printf("\n");
    
    return(0);
}