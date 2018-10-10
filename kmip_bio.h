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