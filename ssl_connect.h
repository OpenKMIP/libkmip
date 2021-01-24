
#include <openssl/ssl.h>

#if 0
int do_ssl_connect(char *server_address, char *server_port, char *client_certificate, char *client_key, char *ca_certificate,
                   SSL_CTX** outctx, BIO** outbio) ;

int do_ssl_free(SSL_CTX** ctx, BIO** bio);
#endif


extern char ssl_saved_error[];
extern int  ssl_reused;
extern int  ssl_error;
extern int  ssl_error_type;  // 1=server, 2=client

void ssl_initialize();
const char* openssl_strerror();
SSL_CTX* ssl_create_context(char *client_certificate, char *client_key, char *ca_certificate);
BIO*     ssl_connect(SSL_CTX *ctx, const char* server_address, const char* server_port, SSL_SESSION** session);
void ssl_disconnect(BIO* bio);
