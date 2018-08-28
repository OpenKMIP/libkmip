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

/*
OpenSSH BIO API
*/

int kmip_bio_create(BIO *,
                    int,
                    struct template_attribute *,
                    char **,
                    size_t *);
int kmip_bio_destroy(BIO *,
                     int,
                     char *,
                     size_t);
int kmip_bio_get_symmetric_key(BIO *,
                               int,
                               char *,
                               size_t,
                               char **,
                               size_t *);

int kmip_bio_create_with_context(struct kmip *,
                                 BIO *,
                                 int,
                                 struct template_attribute *,
                                 char **,
                                 size_t *);
int kmip_bio_destroy_with_context(struct kmip *,
                                  BIO *,
                                  int,
                                  char *,
                                  size_t);
int kmip_bio_get_symmetric_key_with_context(struct kmip *,
                                            BIO *,
                                            int,
                                            char *,
                                            size_t,
                                            char **,
                                            size_t *);

int kmip_bio_send_request(BIO *,
                          int,
                          struct request_message *,
                          struct response_message **);
int kmip_bio_send_request_with_context(struct kmip *,
                                       BIO *,
                                       int,
                                       struct request_message *,
                                       struct response_message **);
int kmip_bio_send_request_encoding(BIO *,
                                   int,
                                   char *,
                                   size_t,
                                   char **,
                                   size_t *);
int kmip_bio_send_request_encoding_with_context(struct kmip *,
                                                BIO *,
                                                int,
                                                char *,
                                                size_t,
                                                char **,
                                                size_t *);

#endif  /* KMIP_BIO_H */