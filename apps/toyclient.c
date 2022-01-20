/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/toy.h>
#include "apps.h"
#include "s_apps.h"
#include "progs.h"
#include "opt.h"

#define CBUFSIZE    1024

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_6,
    OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS toyclient_options[] = {

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Toy Client Options"),
    {"6", OPT_6, '-', "Use IPv6"},

    OPT_PROV_OPTIONS,
    {NULL}
};

int toyclient_main(int argc, char **argv)
{
    char *prog;
    OPTION_CHOICE o;
    int ret = 0;
    int socket_family = AF_INET, sock;
    int inlen;
    OSSL_TOY_CTX *ctx;
    OSSL_TOY_CONN *conn;
    OSSL_TOY_STREAM *stream;
    size_t bytesread, byteswritten;
    BIO *rbio = NULL, *wbio = NULL;
    unsigned char buf[4097];
    union BIO_sock_info_u peer_info;
    char *cbuf = NULL;
    uint32_t streamid = 0;
    struct timeval timeout, *timeoutp = NULL;
    int width;
    fd_set readfds;
    int i, havenewtimeout;

    prog = opt_init(argc, argv, toyclient_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:  /* Never hit, but suppresses warning */
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            return 1;
        case OPT_HELP:
            opt_help(toyclient_options);
            return 0;
        case OPT_6:
            socket_family = AF_INET6;
            break;

        case OPT_PROV_CASES:
            if (!opt_provider(o))
                return 1;
            break;
        }
    }

    /* No extra arguments. */
    if (!opt_check_rest_arg(NULL))
        goto opthelp;

    BIO_printf(bio_out, "Toy Client starting\n");

    cbuf = app_malloc(CBUFSIZE, "cbuf");

    if (init_client(&sock, NULL, "9964", NULL, NULL, socket_family,
                    SOCK_DGRAM, 0) == 0) {
        BIO_printf(bio_err, "connect:errno=%d\n", get_last_socket_error());
        BIO_closesocket(sock);
        goto err;
    }
    BIO_printf(bio_out, "CONNECTED(%08X)\n", sock);

    rbio = BIO_new_dgram(sock, BIO_NOCLOSE);
    if (rbio == NULL) {
        BIO_printf(bio_err, "Failed to create read BIO\n");
        goto err;
    }

    if ((peer_info.addr = BIO_ADDR_new()) == NULL) {
        BIO_printf(bio_err, "Failed to create BIO_ADDR\n");
        BIO_closesocket(sock);
        goto err;
    }
    if (!BIO_sock_info(sock, BIO_SOCK_INFO_ADDRESS, &peer_info)) {
        BIO_printf(bio_err, "getsockname:errno=%d\n",
                    get_last_socket_error());
        BIO_ADDR_free(peer_info.addr);
        BIO_closesocket(sock);
        goto err;
    }

    (void)BIO_ctrl_set_connected(rbio, peer_info.addr);
    BIO_ADDR_free(peer_info.addr);

    if (!BIO_up_ref(rbio)) {
        BIO_printf(bio_err, "Failed to create write BIO\n");
        goto err;
    }
    wbio = rbio;

    ctx = OSSL_TOY_CTX_new(app_get0_libctx(), 0);
    if (ctx == NULL) {
        BIO_printf(bio_err, "Failed to create toy context\n");
        goto err;
    }
    OSSL_TOY_CTX_set0_bios(ctx, rbio, wbio);
    rbio = wbio = NULL;

    conn = OSSL_TOY_CTX_get0_connection(ctx, OSSL_TOY_NULL_CONNECTION_ID);
    if (conn == NULL) {
        BIO_printf(bio_err, "Failed to create toy connection\n");
        goto err;
    }

    BIO_printf(bio_out, "Enter a command. Type \"help\" for a list of commands.\n");

    if (sock > fileno_stdin())
        width = sock + 1;
    else
        width = fileno_stdin() + 1;

    for (;;) {
        FD_ZERO(&readfds);

        openssl_fdset(fileno_stdin(), &readfds);
        openssl_fdset(sock, &readfds);

        if (!OSSL_TOY_CTX_handle_timeout(&timeout, &havenewtimeout)) {
            BIO_printf(bio_err, "Error handling timeout\n");
            goto err;
        }
        if (havenewtimeout)
            timeoutp = &timeout;
        else
            timeoutp = NULL;
        i = select(width, (void *)&readfds, NULL, NULL, timeoutp);
        if (i < 0) {
            BIO_printf(bio_err, "Bad select %d\n", get_last_socket_error());
            goto err;
        }

        if (FD_ISSET(fileno_stdin(), &readfds)) {
            inlen = raw_read_stdin(cbuf, CBUFSIZE);
            if (inlen == 0) {
                /* EOF */
                break;
            }
            if (strstr(cbuf, "stream ") == cbuf) {
                uint32_t tmpstreamid;

                tmpstreamid = (uint32_t)atoi(cbuf + 7);
                if (tmpstreamid >= OSSL_TOY_MAX_TOY_STREAMS) {
                    BIO_printf(bio_out, "Invalid stream number. Must be 0 or above, and less than %u\n", OSSL_TOY_MAX_TOY_STREAMS);
                } else {
                    streamid = tmpstreamid;
                    BIO_printf(bio_out, "Default stream set to %u\n", streamid);
                }
            } else if (strstr(cbuf, "quit") == cbuf) {
                BIO_printf(bio_out, "Quitting\n");
                break;
            } else if (strstr(cbuf, "help") == cbuf) {
                BIO_printf(bio_out, "Command list:\n");
                BIO_printf(bio_out, "stream x\n");
                BIO_printf(bio_out, "    Set the default stream to x where x is a number that is 0 or above and less\n    than %u\n", OSSL_TOY_MAX_TOY_STREAMS);
                BIO_printf(bio_out, "quit\n");
                BIO_printf(bio_out, "    Quit toyclient\n");
                BIO_printf(bio_out, "help\n");
                BIO_printf(bio_out, "    Print this help message\n");
                BIO_printf(bio_out, "send msg\n");
                BIO_printf(bio_out, "    Send \"msg\" to the server, where \"msg\" is any string\n");
                BIO_printf(bio_out, "\n");
                continue;
            } else if (strstr(cbuf, "send ") == cbuf) {
                stream = OSSL_TOY_CONN_get0_stream(conn, streamid);
                if (stream == NULL) {
                    BIO_printf(bio_err, "Failed to get toy stream\n");
                    goto err;
                }
                if (!OSSL_TOY_STREAM_write(stream, (unsigned char *)(cbuf + 5),
                                        inlen - 5, &byteswritten)) {
                    BIO_printf(bio_err, "Failed to write data to toy stream\n");
                    goto err;
                }
                BIO_printf(bio_out, "Data written, Connection Id(%u), Stream Id(%u):\n",
                        OSSL_TOY_CONN_get_id(conn),
                        OSSL_TOY_STREAM_get_id(stream));
                BIO_printf(bio_out, "%s\n", cbuf + 5);
            } else {
                BIO_printf(bio_out, "Invalid command entered\n");
            }
        }

        if (FD_ISSET(sock, &readfds)) {
            if (OSSL_TOY_CTX_process_packet(ctx, &conn, &stream) <= 0) {
                BIO_printf(bio_err, "Failed processing a packet\n");
                goto err;
            }
            BIO_printf(bio_out, "Data received, Connection Id(%u), Stream Id(%u):\n",
                    OSSL_TOY_CONN_get_id(conn),
                    OSSL_TOY_STREAM_get_id(stream));

            if (!OSSL_TOY_STREAM_read(stream, buf, sizeof(buf) - 1, &bytesread)) {
                BIO_printf(bio_err, "Error reading data\n");
                goto err;
            }
            buf[bytesread] = '\0';
            BIO_printf(bio_out, "%s\n", buf);
        }
    }

    BIO_printf(bio_out, "Toy Client closing down\n");

    ret = 1;
 err:
    return ret == 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
