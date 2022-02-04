/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include "ssl_local.h"
#include <openssl/toy.h>

static ossl_inline OSSL_TOY_CTX *ossl_toy_get_ctx(SSL *s)
{
    return s->ctx->ctx_meth_data;
}

static ossl_inline OSSL_TOY_CONN *ossl_toy_get_conn(SSL *s)
{
    return s->meth_data;
}

int ossl_toy_new(SSL *s)
{
    OSSL_TOY_CTX *ctx = ossl_toy_get_ctx(s);

    /* Nothing to be done if we are a server */
    if (OSSL_TOY_CTX_is_server(ctx))
        return 1;

    s->meth_data = OSSL_TOY_CTX_get0_connection(ossl_toy_get_ctx(s),
                                                OSSL_TOY_NULL_CONNECTION_ID);
    return s->meth_data != NULL;
}

void ossl_toy_free(SSL *s)
{
}

int ossl_toy_clear(SSL *s)
{
    return 1;
}

static void *ossl_toy_ctx_new(SSL_CTX *ctx, int isserver)
{
    return OSSL_TOY_CTX_new(ctx->libctx, isserver);
}

void *ossl_toy_client_ctx_new(SSL_CTX *ctx)
{
    return ossl_toy_ctx_new(ctx, 0);
}

void *ossl_toy_server_ctx_new(SSL_CTX *ctx)
{
    return ossl_toy_ctx_new(ctx, 1);
}

int ossl_toy_read(SSL *s, void *buf, size_t len, size_t *readbytes)
{
    /* We only support stream 0 at the moment */
    OSSL_TOY_STREAM *stream = OSSL_TOY_CONN_get0_stream(ossl_toy_get_conn(s), 0);

    if (!OSSL_TOY_STREAM_read(stream, buf, len, readbytes)) {
        int ret, isnew;
        OSSL_TOY_STREAM *tmpstream;
        OSSL_TOY_CONN *conn;

        /* See if we can get more data */
        do {
            ret = OSSL_TOY_CTX_process_packet(ossl_toy_get_ctx(s), &conn,
                                              &tmpstream, &isnew);
        } while (ret > 0 && stream != tmpstream);
        return ret > 0 && OSSL_TOY_STREAM_read(stream, buf, len, readbytes);
    }
    return 1;
}

int ossl_toy_write(SSL *s, const void *buf, size_t len, size_t *written)
{
    /* We only support stream 0 at the moment */
    OSSL_TOY_STREAM *stream = OSSL_TOY_CONN_get0_stream(ossl_toy_get_conn(s), 0);

    return OSSL_TOY_STREAM_write(stream, buf, len, written);
}

int ossl_toy_num_ciphers(void)
{
    return 0;
}

long ossl_toy_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    return 0;
}

int ossl_toy_connect(SSL *s)
{
    OSSL_TOY_CTX *ctx = ossl_toy_get_ctx(s);

    if (s->rbio != OSSL_TOY_CTX_get0_rbio(ctx)) {
        if (!BIO_up_ref(s->rbio))
            return -1;
        OSSL_TOY_CTX_set0_rbio(ctx, s->rbio);
    }

    if (s->wbio != OSSL_TOY_CTX_get0_wbio(ctx)) {
        if (!BIO_up_ref(s->wbio))
            return -1;
        OSSL_TOY_CTX_set0_wbio(ctx, s->wbio);
    }

    return 1;
}

int ossl_toy_accept(SSL *s)
{
    OSSL_TOY_CTX *ctx = ossl_toy_get_ctx(s);
    OSSL_TOY_CONN *conn = NULL;
    OSSL_TOY_STREAM *stream = NULL;
    int isnew, ret;

    if (s->rbio != OSSL_TOY_CTX_get0_rbio(ctx)) {
        if (!BIO_up_ref(s->rbio))
            return -1;
        OSSL_TOY_CTX_set0_rbio(ctx, s->rbio);
    }

    if (s->wbio != OSSL_TOY_CTX_get0_wbio(ctx)) {
        if (!BIO_up_ref(s->wbio))
            return -1;
        OSSL_TOY_CTX_set0_wbio(ctx, s->wbio);
    }

    do {
        ret = OSSL_TOY_CTX_process_packet(ctx, &conn, &stream, &isnew);
    } while(ret > 0 && !isnew);

    if (ret > 0)
        s->meth_data = conn;

    return ret;
}

int ossl_toy_renegotiate_check(SSL *s, int initok)
{
    return 1;
}
