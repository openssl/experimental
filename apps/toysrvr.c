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


typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_6,
    OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS toysrvr_options[] = {

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Toy Server Options"),
    {"6", OPT_6, '-', "Use IPv6"},

    OPT_PROV_OPTIONS,
    {NULL}
};

static int toy_server_cb(int sock, int type, int protocol,
                         unsigned char *context)
{
    OSSL_TOY_CTX *ctx;
    OSSL_TOY_CONN *conn;
    OSSL_TOY_STREAM *stream;
    unsigned char buf[4097];
    size_t bytesread, byteswritten;
    int ret = -1;
    BIO *rbio = NULL, *wbio = NULL;

    rbio = BIO_new_dgram(sock, BIO_NOCLOSE);
    if (rbio == NULL) {
        BIO_printf(bio_err, "Failed to create read BIO\n");
        goto err;
    }
    if (!BIO_up_ref(rbio)) {
        BIO_printf(bio_err, "Failed to create write BIO\n");
        goto err;
    }
    wbio = rbio;

    ctx = OSSL_TOY_CTX_new(app_get0_libctx(), 1);
    if (ctx == NULL) {
        BIO_printf(bio_err, "Failed to create toy context\n");
        goto err;
    }
    OSSL_TOY_CTX_set0_bios(ctx, rbio, wbio);
    rbio = wbio = NULL;

    for (;;) {
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

        /* Echo back the data */
        if (!OSSL_TOY_STREAM_write(stream, buf, bytesread, &byteswritten)) {
            BIO_printf(bio_err, "Error writing data\n");
            goto err;
        }
    }

    ret = 1;
 err:
    OSSL_TOY_CTX_free(ctx);
    BIO_free(rbio);
    BIO_free(wbio);
    return ret;
}

int toysrvr_main(int argc, char **argv)
{
    char *prog;
    OPTION_CHOICE o;
    int ret = 0;
    int socket_family = AF_INET, accept_sock;

    prog = opt_init(argc, argv, toysrvr_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:  /* Never hit, but suppresses warning */
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            return 1;
        case OPT_HELP:
            opt_help(toysrvr_options);
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

    BIO_printf(bio_out, "Toy Server starting\n");

    ret = do_server(&accept_sock, NULL, "9964", socket_family, SOCK_DGRAM, 0,
                    toy_server_cb, NULL, -1, bio_out);

    BIO_printf(bio_out, "Toy Server closing down\n");

    return ret == 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
