#include <stdbool.h>
#include <openssl/err.h>
#include "ssl_connect.h"

int  ssl_reused = 0;
int  ssl_error = 0;
int  ssl_error_type = 0;
char ssl_saved_error[512] = "";

//------------------------------------------------------------------------------
void ssl_initialize()
{
    #if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    OPENSSL_init_ssl(0, NULL);
    #else
    SSL_library_init();
    #endif
}

// we don't really need to verify the caller's certificate
static int always_true_callback(X509_STORE_CTX *ctx, void *arg)
{
#if 1
    (void) ctx;
    (void) arg;
#else
    fprintf(stderr, "cert callback = true\n");

    if (ctx->cert)
    {
        char subject_name[256];
        char issuer_name[256];
        X509_NAME_oneline(X509_get_subject_name(ctx->cert), subject_name, 256);
        X509_NAME_oneline(X509_get_issuer_name(ctx->cert), issuer_name, 256);
        fprintf(stderr, "Verifying %s\n  issuer: %s\n", subject_name, issuer_name);
    }
#endif
    return 1;
}

SSL_CTX* ssl_create_context(char *client_certificate, char *client_key, char *ca_certificate)
{
    bool err = false;
    ssl_error = 0;

    #if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    #else
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    #endif

    if (!ctx)
    {
        sprintf(ssl_saved_error, "SSL_CTX_new failed!\n");
        return 0;
    }

    do
    {
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_set_verify_depth(ctx, 4);
        SSL_CTX_set_cert_verify_callback(ctx, always_true_callback, 0);

        if (SSL_CTX_load_verify_locations(ctx, ca_certificate, NULL) != 1)
        {
            sprintf(ssl_saved_error, "Failed to load root certificates\n");
            ssl_error_type = 1;
            err = true;
            break;
        }

        if (SSL_CTX_use_certificate_file(ctx, client_certificate, SSL_FILETYPE_PEM) != 1)
        {
            sprintf(ssl_saved_error, "Failed to Load the client certificate\n");
            ssl_error_type = 2;
            err = true;
            break;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1)
        {
            sprintf(ssl_saved_error, "Failed to Load the client key\n");
            ssl_error_type = 2;
            err = true;
            break;
        }
    } while (0);

    if (err)
    {
        ssl_error = ERR_get_error();
        SSL_CTX_free(ctx);
        ctx = 0;
    }

    return ctx;
}

const char* openssl_strerror()
{
    static int error_strings_loaded = 0;

    if (!error_strings_loaded)
    {
        SSL_load_error_strings();
        error_strings_loaded = 1;
    }
	return ERR_error_string(ERR_get_error(), NULL);
}

//------------------------------------------------------------------------------
BIO* ssl_connect(SSL_CTX *ctx, const char* server_address, const char* server_port, SSL_SESSION** session)
{
    /* Set up the TLS connection to the KMIP server. */
    SSL* ssl = 0;
    BIO* bio = 0;
    ssl_error = 0;

    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        sprintf(ssl_saved_error, "BIO_new_ssl_connect failed: %s\n", openssl_strerror());
        ssl_error = ERR_get_error();
        return (0);
    }

    BIO_set_conn_hostname(bio, server_address);
    BIO_set_conn_port(bio, server_port);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    if (*session)
        SSL_set_session(ssl, *session);

    if (BIO_do_connect(bio) != 1)
    {
        const char* certerr = NULL;
        int rc = ERR_peek_error();
        if ( rc )
        {
            if ( ( ERR_GET_LIB(rc) == ERR_LIB_SSL ) &&
                 ( ERR_GET_REASON(rc) == SSL_R_CERTIFICATE_VERIFY_FAILED ) )
            {
                int certrc = SSL_get_verify_result(ssl);
                certerr = (char *)X509_verify_cert_error_string(certrc);
            }
        }

        ssl_error = rc;
        sprintf(ssl_saved_error,"BIO_do_connect failed: %s\n", openssl_strerror());
        if (certerr)
            sprintf(ssl_saved_error, "SSL cert error: %s\n", certerr );

        BIO_free_all(bio);
        return(0);
    }


    if (SSL_session_reused(ssl)) {
        ssl_reused = 1;
        // printf("REUSED SESSION\n");
    } else {
        ssl_reused = 0;
        // printf("NEW SESSION\n");
    }

    if (*session)
        SSL_SESSION_free(*session);

    *session = SSL_get1_session(ssl);

    return bio;
}

void ssl_disconnect(BIO* bio)
{
    BIO_ssl_shutdown(bio);
    BIO_free_all(bio);
}


