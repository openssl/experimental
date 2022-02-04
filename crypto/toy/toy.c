/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/toy.h>
#include <time.h>
#include <sys/time.h>

struct ossl_toy_packet_st {
    /* The connection id */
    uint32_t connid;
    /* The stream id within the connection */
    uint32_t streamid;
    /* The packet id within the stream */
    uint32_t packetid;

    /* Start of the packet data (including the header) */
    unsigned char *data;
    /* Start of the application data within the packet */
    unsigned char *appdata;
    /* Length of the application data */
    size_t length;
    /* Size of the data buffer */
    size_t datasize;
};

struct ossl_toy_stream_st {
    /* The parent connection */
    OSSL_TOY_CONN *conn;
    /* The stream id */
    uint32_t id;
    /* Id of the next packet we expect to read from this stream */
    uint32_t rnxtpkt;
    /* Id of the next packet we will write to this stream */
    uint32_t wnxtpkt;
    OSSL_TOY_PACKET *packets[OSSL_TOY_MAX_PACKETS];
};

struct ossl_toy_conn_st {
    /* The parent context */
    OSSL_TOY_CTX *ctx;
    /* Unique id for this connection */
    uint32_t id;
    /* Address of peer */
    BIO_ADDR *peer;
    /* All of our child streams */
    OSSL_TOY_STREAM *streams[OSSL_TOY_MAX_TOY_STREAMS];
};

struct ossl_toy_ctx_st {
    OSSL_LIB_CTX *libctx;
    /* Whether we are a server or a client */
    int isserver;
    /* Currently active connections */
    OSSL_TOY_CONN *conns[OSSL_TOY_MAX_TOY_CONNECTIONS];
    /* Read BIO */
    BIO *rbio;
    /* Write BIO */
    BIO *wbio;
};

static void ossl_toy_conn_free(OSSL_TOY_CONN *conn);

static OSSL_TOY_STREAM *ossl_toy_stream_new(OSSL_TOY_CONN *conn,
                                            uint32_t streamid);
static void ossl_toy_stream_free(OSSL_TOY_STREAM *stream);
static int ossl_toy_stream_add0_packet(OSSL_TOY_STREAM *stream,
                                       OSSL_TOY_PACKET *packet);

static OSSL_TOY_PACKET *ossl_toy_packet_new(void);
static void ossl_toy_packet_free(OSSL_TOY_PACKET *packet);

OSSL_TOY_CTX *OSSL_TOY_CTX_new(OSSL_LIB_CTX *libctx, int isserver)
{
    OSSL_TOY_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    ctx->libctx = libctx;
    ctx->isserver = isserver;

    return ctx;
}

void OSSL_TOY_CTX_free(OSSL_TOY_CTX *ctx)
{
    size_t i;

    for (i = 0; i < OSSL_TOY_MAX_TOY_CONNECTIONS; i++) {
        if (ctx->conns[i] != NULL) {
            ossl_toy_conn_free(ctx->conns[i]);
            ctx->conns[i] = NULL;
        }
    }

    BIO_free(ctx->rbio);
    BIO_free(ctx->wbio);
    OPENSSL_free(ctx);
}

BIO *OSSL_TOY_CTX_get0_rbio(OSSL_TOY_CTX *ctx)
{
    return ctx->rbio;
}

BIO *OSSL_TOY_CTX_get0_wbio(OSSL_TOY_CTX *ctx)
{
    return ctx->wbio;
}

int OSSL_TOY_CTX_set0_rbio(OSSL_TOY_CTX *ctx, BIO *rbio)
{
    BIO_free(ctx->rbio);
    ctx->rbio = rbio;

    return 1;
}

int OSSL_TOY_CTX_set0_wbio(OSSL_TOY_CTX *ctx, BIO *wbio)
{
    BIO_free(ctx->wbio);
    ctx->wbio = wbio;

    return 1;
}


OSSL_TOY_CONN *OSSL_TOY_CTX_get0_connection(OSSL_TOY_CTX *ctx, uint32_t id)
{
    OSSL_TOY_CONN *conn;
    size_t i;

    if (id == OSSL_TOY_NULL_CONNECTION_ID) {
        if (RAND_bytes_ex(ctx->libctx, (unsigned char *)&id, sizeof(id), 0) <= 0
                || id == OSSL_TOY_NULL_CONNECTION_ID)
            return NULL;
    }

    conn = OPENSSL_zalloc(sizeof(*conn));
    if (conn == NULL)
        return NULL;

    conn->ctx = ctx;
    conn->id = id;

    for (i = 0; i < OSSL_TOY_MAX_TOY_CONNECTIONS; i++) {
        if (ctx->conns[i] == NULL) {
            ctx->conns[i] = conn;
            return conn;
        }
    }

    /* It is an error if we get this far */
    ossl_toy_conn_free(conn);
    return NULL;
}

int OSSL_TOY_CTX_process_packet(OSSL_TOY_CTX *ctx, OSSL_TOY_CONN **conn,
                                OSSL_TOY_STREAM **stream, int *isnew)
{
    int ret;
    OSSL_TOY_PACKET *packet = ossl_toy_packet_new();
    uint32_t *uiptr;
    size_t i;

    if (packet == NULL)
        return -1;

    ret = BIO_read(ctx->rbio, packet->data, packet->datasize);
    if (ret <= 0)
        goto err;

    if (ret < OSSL_TOY_PACKET_HEADER_SIZE) {
        ret = -1;
        goto err;
    }

    uiptr = (uint32_t *)packet->data;
    packet->connid = *uiptr++;
    packet->streamid = *uiptr++;
    packet->packetid = *uiptr++;
    packet->appdata = packet->data + OSSL_TOY_PACKET_HEADER_SIZE;
    packet->length = ret - OSSL_TOY_PACKET_HEADER_SIZE;

    *isnew = 0;
    *conn = NULL;
    /* Find the connection */
    for (i = 0; i < OSSL_TOY_MAX_TOY_CONNECTIONS; i++) {
        if (ctx->conns[i] != NULL && ctx->conns[i]->id == packet->connid) {
            *conn = ctx->conns[i];
            break;
        }
    }
    if (*conn == NULL) {
        /* New connection */
        if (!ctx->isserver) {
            /* Only servers can receive new connection requests */
            ret = -1;
            goto err;
        }
        *conn = OSSL_TOY_CTX_get0_connection(ctx, packet->connid);
        if (*conn == NULL) {
            ret = -1;
            goto err;
        }
        *isnew = 1;
    }

    if (ctx->isserver && (*conn)->peer == NULL) {
        if (((*conn)->peer = BIO_ADDR_new()) == NULL) {
            ret = -1;
            goto err;
        }

        if (BIO_dgram_get_peer(ctx->rbio, (*conn)->peer) <= 0) {
            ret = -1;
            goto err;
        }
    }

    *stream = OSSL_TOY_CONN_get0_stream(*conn, packet->streamid);
    if (*stream == NULL) {
        ret = -1;
        goto err;
    }

    if (!ossl_toy_stream_add0_packet(*stream, packet)) {
        ret = -1;
        goto err;
    }
    /* Packet has been assigned to the stream, so don't free it below */
    packet = NULL;
    ret = 1;
 err:
    ossl_toy_packet_free(packet);
    return ret;
}

int OSSL_TOY_CTX_handle_timeout(struct timeval *nxttimeout, int *havenewtimeout)
{
    struct timeval timenow;


    *havenewtimeout = 1;

    /* Get current time */
    gettimeofday(&timenow, NULL);
    timenow.tv_sec += 2;
    *nxttimeout = timenow;

    return 1;
}

int OSSL_TOY_CTX_is_server(OSSL_TOY_CTX *ctx)
{
    return ctx->isserver;
}

void ossl_toy_conn_free(OSSL_TOY_CONN *conn)
{
    size_t i;
    if (conn == NULL)
        return;

    BIO_ADDR_free(conn->peer);

    /* Remove any associated streams */
    for (i = 0; i < OSSL_TOY_MAX_TOY_STREAMS; i++)
        ossl_toy_stream_free(conn->streams[i]);

    /* Remove the connection from the context's connection list */
    if (conn->ctx != NULL) {
        for (i = 0; i < OSSL_TOY_MAX_TOY_CONNECTIONS; i++) {
            if (conn->ctx->conns[i] == conn) {
                conn->ctx->conns[i] = NULL;
                break;
            }
        }
    }

    OPENSSL_free(conn);
}

OSSL_TOY_STREAM *OSSL_TOY_CONN_get0_stream(OSSL_TOY_CONN *conn, uint32_t streamid)
{
    if (conn == NULL || streamid >= OSSL_TOY_MAX_TOY_STREAMS)
        return NULL;

    if (conn->streams[streamid] == NULL)
        conn->streams[streamid] = ossl_toy_stream_new(conn, streamid);

    return conn->streams[streamid];
}

uint32_t OSSL_TOY_CONN_get_id(OSSL_TOY_CONN *conn)
{
    return conn->id;
}

void OSSL_TOY_CONN_set0_peer(OSSL_TOY_CONN *conn, BIO_ADDR *peer)
{
    BIO_ADDR_free(conn->peer);
    conn->peer = peer;
}

static OSSL_TOY_STREAM *ossl_toy_stream_new(OSSL_TOY_CONN *conn,
                                            uint32_t streamid)
{
    OSSL_TOY_STREAM *stream = OPENSSL_zalloc(sizeof(*stream));

    if (stream == NULL)
        return NULL;

    stream->conn = conn;
    stream->id = streamid;

    return stream;
}

static void ossl_toy_stream_free(OSSL_TOY_STREAM *stream)
{
    size_t i;

    if (stream == NULL)
        return;

    /* Remove the stream from the connection */
    stream->conn->streams[stream->id] = NULL;

    /* Free any received packets */
    for (i = 0; i < OSSL_TOY_MAX_PACKETS; i++)
        ossl_toy_packet_free(stream->packets[i]);

    OPENSSL_free(stream);
}

static int ossl_toy_stream_add0_packet(OSSL_TOY_STREAM *stream,
                                       OSSL_TOY_PACKET *packet)
{
    if (stream == NULL
            || packet == NULL
            || packet->packetid >= OSSL_TOY_MAX_PACKETS
            || stream->packets[packet->packetid] != NULL)
        return 0;

    stream->packets[packet->packetid] = packet;

    return 1;
}

int OSSL_TOY_STREAM_read(OSSL_TOY_STREAM *stream, unsigned char *buf,
                         size_t bufsize, size_t *bytesread)
{
    if (bytesread == NULL)
        return 0;
    *bytesread = 0;
    if (stream == NULL)
        return 0;
    if (bufsize == 0)
        return 1;
    if (buf == NULL)
        return 0;

    for (; stream->rnxtpkt < OSSL_TOY_MAX_PACKETS
           && stream->packets[stream->rnxtpkt] != NULL; stream->rnxtpkt++) {
        OSSL_TOY_PACKET *packet = stream->packets[stream->rnxtpkt];

        if (packet->length > 0) {
            if (bufsize > packet->length) {
                /* Read all the available data from the packet */
                memcpy(buf, packet->appdata, packet->length);
                *bytesread += packet->length;
                packet->appdata += packet->length;
                packet->length = 0;
            } else {
                /* Partial read of data from the packet */
                memcpy(buf, packet->appdata, bufsize);
                *bytesread += bufsize;
                packet->appdata += bufsize;
                packet->length -= bufsize;

                /* We've consumed the whole buffer, so just return */
                return 1;
            }
        }
    }
    if (*bytesread > 0)
        return 1;

    /* Nothing available to read */
    return 0;
}

int OSSL_TOY_STREAM_write(OSSL_TOY_STREAM *stream, const unsigned char *buf,
                          size_t bufsize, size_t *byteswritten)
{
    if (byteswritten == NULL)
        return 0;
    *byteswritten = 0;
    if (stream == NULL)
        return 0;
    if (bufsize == 0)
        return 1;
    if (buf == NULL)
        return 0;

    do {
        size_t towrite, written;
        unsigned char packetdata[OSSL_TOY_PACKET_HEADER_SIZE
                                 + OSSL_TOY_MAX_APP_DATA_SIZE];
        uint32_t *uiptr = (uint32_t *)packetdata;

        if (bufsize > OSSL_TOY_MAX_APP_DATA_SIZE)
            towrite = OSSL_TOY_MAX_APP_DATA_SIZE;
        else
            towrite = bufsize;

        /* Header data */
        /* Connection id */
        *uiptr++ = stream->conn->id;
        /* Stream id */
        *uiptr++ = stream->id;
        /* Packet id */
        *uiptr++ = stream->wnxtpkt;

        /* App data */
        memcpy(packetdata + OSSL_TOY_PACKET_HEADER_SIZE, buf, towrite);

        if (stream->conn->ctx->isserver) {
            if (stream->conn->peer == NULL)
                return 0;
            if (BIO_dgram_set_peer(stream->conn->ctx->wbio,
                                   stream->conn->peer) <= 0) {
                return 0;
            }
        }
        if (!BIO_write_ex(stream->conn->ctx->wbio, packetdata,
                          OSSL_TOY_PACKET_HEADER_SIZE + towrite, &written)) {
            /* We might have written partial data!! */
            break;
        }
        if (written != OSSL_TOY_PACKET_HEADER_SIZE + towrite) {
            /* Should not happen!! */
            return 0;
        }
        *byteswritten += towrite;

        stream->wnxtpkt++;
        buf += towrite;
        bufsize -= towrite;
    } while (bufsize > 0);

    if (*byteswritten > 0)
        return 1;

    /* We failed to write anything */
    return 0;
}

uint32_t OSSL_TOY_STREAM_get_id(OSSL_TOY_STREAM *stream)
{
    return stream->id;
}

static OSSL_TOY_PACKET *ossl_toy_packet_new(void)
{
    OSSL_TOY_PACKET *packet = OPENSSL_zalloc(sizeof(*packet));

    packet->datasize = OSSL_TOY_PACKET_HEADER_SIZE + OSSL_TOY_MAX_APP_DATA_SIZE;
    packet->data = OPENSSL_malloc(packet->datasize);

    if (packet->data == NULL) {
        OPENSSL_free(packet);
        return NULL;
    }

    return packet;
}

static void ossl_toy_packet_free(OSSL_TOY_PACKET *packet)
{
    if (packet == NULL)
        return;
    OPENSSL_free(packet->data);
    OPENSSL_free(packet);
}
