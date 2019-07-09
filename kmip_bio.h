/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIP_BIO_H
#define KMIP_BIO_H

#include <openssl/ssl.h>
#include "kmip.h"

/*
OpenSSH BIO API
*/

int kmip_bio_create_symmetric_key(BIO *, TemplateAttribute *, char **, int *);
int kmip_bio_get_symmetric_key(BIO *, char *, int, char **, int *);
int kmip_bio_destroy_symmetric_key(BIO *, char *, int);

int kmip_bio_create_symmetric_key_with_context(KMIP *, BIO *, TemplateAttribute *, char **, int *);
int kmip_bio_get_symmetric_key_with_context(KMIP *, BIO *, char *, int, char **, int *);
int kmip_bio_destroy_symmetric_key_with_context(KMIP *, BIO *, char *, int);

int kmip_bio_send_request_encoding(KMIP *, BIO *, char *, int, char **, int *);

#endif  /* KMIP_BIO_H */