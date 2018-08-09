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

/*
OpenSSH BIO API
*/

int kmip_bio_create(BIO *bio, );
int kmip_bio_destroy(BIO *bio, char *uuid);
int kmip_bio_get(BIO *bio, char *uuid, char **key, int *key_size);

int kmip_bio_create_with_context(struct kmip *ctx, BIO *bio);
int kmip_bio_destroy_with_context(struct kmip *ctx, BIO *bio, char *uuid);
int kmip_bio_get_with_context(
struct kmip *ctx,
BIO *bio,
char *uuid,
char **key,
int *key_size);

int kmip_bio_send_request(BIO *bio, char *request, int request_size);
int kmip_bio_send_request_with_context(
struct kmip *ctx,
BIO *bio,
char *request, 
int request_size);
