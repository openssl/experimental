/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/crypto.h>

#define OSSL_TOY_MAX_TOY_CONNECTIONS 10
#define OSSL_TOY_MAX_TOY_STREAMS 10
#define OSSL_TOY_NULL_CONNECTION_ID 0xffffffff
#define OSSL_TOY_PACKET_HEADER_SIZE 12
#define OSSL_TOY_MAX_APP_DATA_SIZE 1024
#define OSSL_TOY_MAX_PACKETS 128

typedef struct ossl_toy_packet_st OSSL_TOY_PACKET;
typedef struct ossl_toy_stream_st OSSL_TOY_STREAM;
typedef struct ossl_toy_conn_st OSSL_TOY_CONN;
typedef struct ossl_toy_ctx_st OSSL_TOY_CTX;


OSSL_TOY_CTX *OSSL_TOY_CTX_new(OSSL_LIB_CTX *libctx, int isserver);
void OSSL_TOY_CTX_free(OSSL_TOY_CTX *ctx);
int OSSL_TOY_CTX_set0_bios(OSSL_TOY_CTX *ctx, BIO *rbio, BIO *wbio);
OSSL_TOY_CONN *OSSL_TOY_CTX_get0_connection(OSSL_TOY_CTX *ctx, uint32_t id);
int OSSL_TOY_CTX_process_packet(OSSL_TOY_CTX *ctx, OSSL_TOY_CONN **conn,
                                OSSL_TOY_STREAM **stream);

OSSL_TOY_STREAM *OSSL_TOY_CONN_get0_stream(OSSL_TOY_CONN *conn, uint32_t streamid);
uint32_t OSSL_TOY_CONN_get_id(OSSL_TOY_CONN *conn);
void OSSL_TOY_CONN_set0_peer(OSSL_TOY_CONN *conn, BIO_ADDR *peer);

int OSSL_TOY_STREAM_read(OSSL_TOY_STREAM *stream, unsigned char *buf,
                         size_t bufsize, size_t *bytesread);
int OSSL_TOY_STREAM_write(OSSL_TOY_STREAM *stream, const unsigned char *buf,
                          size_t bufsize, size_t *byteswritten);
uint32_t OSSL_TOY_STREAM_get_id(OSSL_TOY_STREAM *stream);
