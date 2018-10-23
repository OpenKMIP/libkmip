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
#include <string.h>
#include <time.h>

#include "kmip.h"
#include "kmip_bio.h"

void
print_help(const char *app)
{
    printf("Usage: %s [flag value | flag] ...\n\n", app);
    printf("Flags:\n");
    printf("-a addr : the IP address of the KMIP server\n");
    printf("-c path : path to client certificate file\n");
    printf("-h      : print this help info\n");
    printf("-i id   : the ID of the symmetric key to destroy\n");
    printf("-k path : path to client key file\n");
    printf("-p port : the port number of the KMIP server\n");
    printf("-r path : path to CA certificate file\n");
}

int
parse_arguments(int argc, char **argv,
                char **server_address, char **server_port,
                char **client_certificate, char **client_key, char **ca_certificate,
                char **id,
                int *print_usage)
{
    for(int i = 1; i < argc; i++)
    {
        if(strncmp(argv[i], "-a", 2) == 0)
        {
            *server_address = argv[++i];
        }
        else if(strncmp(argv[i], "-c", 2) == 0)
        {
            *client_certificate = argv[++i];
        }
        else if(strncmp(argv[i], "-h", 2) == 0)
        {
            *print_usage = 1;
        }
        else if(strncmp(argv[i], "-i", 2) == 0)
        {
            *id = argv[++i];
        }
        else if(strncmp(argv[i], "-k", 2) == 0)
        {
            *client_key = argv[++i];
        }
        else if(strncmp(argv[i], "-p", 2) == 0)
        {
            *server_port = argv[++i];
        }
        else if(strncmp(argv[i], "-r", 2) == 0)
        {
            *ca_certificate = argv[++i];
        }
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
use_high_level_api(const char *server_address,
                   const char *server_port,
                   const char *client_certificate,
                   const char *client_key,
                   const char *ca_certificate,
                   char *id)
{
    /* Set up the TLS connection to the KMIP server. */
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());
    
    printf("\n");
    printf("Loading the client certificate: %s\n", client_certificate);
    int result = SSL_CTX_use_certificate_file(ctx, client_certificate, SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client certificate failed (error: %d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    printf("Loading the client key: %s\n", client_key);
    result = SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM);
    if(result != 1)
    {
        printf("Loading the client key failed (error: %d)\n", result);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    printf("Loading the CA certificate: %s\n", ca_certificate);
    result = SSL_CTX_load_verify_locations(ctx, ca_certificate, NULL);
    if(result != 1)
    {
        printf("Loading the CA file failed (error: %d)\n", result);
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
    BIO_set_conn_hostname(bio, server_address);
    BIO_set_conn_port(bio, server_port);
    result = BIO_do_connect(bio);
    if(result != 1)
    {
        printf("BIO_do_connect failed (error: %d)\n", result);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(result);
    }
    
    /* Send the request message. */
    result = kmip_bio_destroy_symmetric_key(bio, id, kmip_strnlen_s(id, 50));
    
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    
    /* Handle the response results. */
    printf("\n");
    if(result < 0)
    {
        printf("An error occurred while deleting object: %s\n", id);
        printf("Error Code: %d\n", result);
    }
    else if(result >= 0)
    {
        printf("The KMIP operation was executed with no errors.\n");
        printf("Result: ");
        kmip_print_result_status_enum(result);
        printf(" (%d)\n", result);
    }
    
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
    char *id = NULL;
    int help = 0;
    
    int error = parse_arguments(
        argc, argv,
        &server_address, &server_port,
        &client_certificate, &client_key, &ca_certificate, &id,
        &help);
    if(error)
    {
        return(error);
    }
    if(help)
    {
        print_help(argv[0]);
        return(0);
    }
    
    int result = use_high_level_api(server_address, server_port,
                                    client_certificate, client_key, ca_certificate,
                                    id);
    return(result);
}
