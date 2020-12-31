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
    printf("-i id   : the ID of the symmetric key to retrieve\n");
    printf("-k path : path to client key file\n");
    printf("-p port : the port number of the KMIP server\n");
    printf("-r path : path to CA certificate file\n");
    printf("-s pass : the password for KMIP server authentication\n");
    printf("-u user : the username for KMIP server authentication\n");
}

int
parse_arguments(int argc, char **argv,
                char **server_address, char **server_port,
                char **client_certificate, char **client_key, char **ca_certificate,
                char **username, char **password,
                char **id,
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
        else if(strncmp(argv[i], "-s", 2) == 0)
        {
            *password = argv[++i];
        }
        else if(strncmp(argv[i], "-u", 2) == 0)
        {
            *username = argv[++i];
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

void *
demo_calloc(void *state, size_t num, size_t size)
{
    printf("demo_calloc called: state = %p, num = %zu, size = %zu\n", state, num, size);
    return(calloc(num, size));
}

void *
demo_realloc(void *state, void *ptr, size_t size)
{
    printf("demo_realloc called: state = %p, ptr = %p, size = %zu\n", state, ptr, size);
    return(realloc(ptr, size));
}

void
demo_free(void *state, void *ptr)
{
    printf("demo_free called: state = %p, ptr = %p\n", state, ptr);
    free(ptr);
    return;
}

int
use_mid_level_api(BIO* bio,
                  char *username,
                  char *password,
                  char *id)
{
    char *key = NULL;
    int key_size = 0;
    size_t id_size = kmip_strnlen_s(id, 100);
    
    /* Set up the KMIP context and send the request message. */
    KMIP kmip_context = {0};
    
    kmip_context.calloc_func = &demo_calloc;
    kmip_context.realloc_func = &demo_realloc;
    kmip_context.free_func = &demo_free;
    
    kmip_init(&kmip_context, NULL, 0, KMIP_1_0);
    
    int result;

    TextString u = { 0 };
    TextString p = {0};
    UsernamePasswordCredential upc = {0};
    Credential credential = {0};
    if (username && password)
    {
        u.value = username;
        u.size = kmip_strnlen_s(username, 50);

        p.value = password;
        p.size = kmip_strnlen_s(password, 50);

        upc.username = &u;
        upc.password = &p;

        credential.credential_type = KMIP_CRED_USERNAME_AND_PASSWORD;
        credential.credential_value = &upc;
    
        result = kmip_add_credential(&kmip_context, &credential);
    
        if(result != KMIP_OK)
        {
            printf("Failed to add credential to the KMIP context.\n");
            kmip_destroy(&kmip_context);
            return(result);
        }
    }
    
    result = kmip_bio_get_symmetric_key_with_context(&kmip_context, bio, id, id_size, &key, &key_size);
    
    /* Handle the response results. */
    printf("\n");
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
        printf(" (%d)\n", result);
        
        if(result == KMIP_STATUS_SUCCESS)
        {
            printf("Symmetric Key ID: %s\n", id);
            printf("Symmetric Key Size: %d bits\n", key_size * 8);
            printf("Symmetric Key:");
            kmip_print_buffer(key, key_size);
            printf("\n");
        }
    }
    
    printf("\n");
    
    if(key != NULL)
    {
        kmip_memset(key, 0, key_size);
        kmip_free(NULL, key);
    }
    
    /* Clean up the KMIP context and return the results. */
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
    char *username = NULL;
    char *password = NULL;
    char *id = NULL;
    int help = 0;
    
    int error = parse_arguments(argc, argv, &server_address, &server_port, &client_certificate, &client_key, &ca_certificate, &username, &password, &id, &help);
    if(error)
    {
        return(error);
    }
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

    int result = use_mid_level_api(bio, username, password, id);

    ssl_disconnect(bio);

    if (session)
        SSL_SESSION_free(session);

    SSL_CTX_free(ctx);

    return(result);
}
