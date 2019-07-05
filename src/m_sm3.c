/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

//#include "internal/cryptlib.h"

#include <openssl/evp.h>
#include "libcrypto-compat.h"
#if OPENSSL_VERSION_NUMBER < 0x10101000L

#define SN_sm3          "SM3"
#define LN_sm3          "sm3"
#define NID_sm3         1143
#define OBJ_sm3         OBJ_sm_scheme,401L

#define SN_sm3WithRSAEncryption         "RSA-SM3"
#define LN_sm3WithRSAEncryption         "sm3WithRSAEncryption"
#define NID_sm3WithRSAEncryption                1144
#define OBJ_sm3WithRSAEncryption                OBJ_sm_scheme,504L
#ifndef OPENSSL_NO_SM3
//# include "internal/evp_int.h"
//# include "internal/sm3.h"
#include "sm3_locl.h"
#include "sm3.h"


int sm3_update(SM3_CTX *c, const void *data_, size_t len)
{
    const unsigned char *data = data_;
    unsigned char *p;
    HASH_LONG l;
    size_t n;

    if (len == 0)
        return 1;

    l = (c->Nl + (((HASH_LONG) len) << 3)) & 0xffffffffUL;
    if (l < c->Nl)              /* overflow */
        c->Nh++;
    c->Nh += (HASH_LONG) (len >> 29); /* might cause compiler warning on
                                       * 16-bit */
    c->Nl = l;

    n = c->num;
    if (n != 0) {
        p = (unsigned char *)c->data;

        if (len >= HASH_CBLOCK || len + n >= HASH_CBLOCK) {
            memcpy(p + n, data, HASH_CBLOCK - n);
            HASH_BLOCK_DATA_ORDER(c, p, 1);
            n = HASH_CBLOCK - n;
            data += n;
            len -= n;
            c->num = 0;
            /*
             * We use memset rather than OPENSSL_cleanse() here deliberately.
             * Using OPENSSL_cleanse() here could be a performance issue. It
             * will get properly cleansed on finalisation so this isn't a
             * security problem.
             */
            memset(p, 0, HASH_CBLOCK); /* keep it zeroed */
        } else {
            memcpy(p + n, data, len);
            c->num += (unsigned int)len;
            return 1;
        }
    }

    n = len / HASH_CBLOCK;
    if (n > 0) {
        HASH_BLOCK_DATA_ORDER(c, data, n);
        n *= HASH_CBLOCK;
        data += n;
        len -= n;
    }

    if (len != 0) {
        p = (unsigned char *)c->data;
        c->num = (unsigned int)len;
        memcpy(p, data, len);
    }
    return 1;
}

// void HASH_TRANSFORM(HASH_CTX *c, const unsigned char *data)
// {
//     HASH_BLOCK_DATA_ORDER(c, data, 1);
// }

int sm3_final(unsigned char *md, HASH_CTX *c)
{
    unsigned char *p = (unsigned char *)c->data;
    size_t n = c->num;

    p[n] = 0x80;                /* there is always room for one */
    n++;

    if (n > (HASH_CBLOCK - 8)) {
        memset(p + n, 0, HASH_CBLOCK - n);
        n = 0;
        HASH_BLOCK_DATA_ORDER(c, p, 1);
    }
    memset(p + n, 0, HASH_CBLOCK - 8 - n);

    p += HASH_CBLOCK - 8;
#if   defined(DATA_ORDER_IS_BIG_ENDIAN)
    (void)HOST_l2c(c->Nh, p);
    (void)HOST_l2c(c->Nl, p);
#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)
    (void)HOST_l2c(c->Nl, p);
    (void)HOST_l2c(c->Nh, p);
#endif
    p -= HASH_CBLOCK;
    HASH_BLOCK_DATA_ORDER(c, p, 1);
    c->num = 0;
    OPENSSL_cleanse(p, HASH_CBLOCK);

#ifndef HASH_MAKE_STRING
# error "HASH_MAKE_STRING must be defined!"
#else
    HASH_MAKE_STRING(c, md);
#endif

    return 1;
}

static int init(EVP_MD_CTX *ctx)
{
    return sm3_init(EVP_MD_CTX_md_data(ctx));
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return sm3_update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return sm3_final(md, EVP_MD_CTX_md_data(ctx));
}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static const EVP_MD sm3_md = {
    NID_sm3,
    NID_sm3WithRSAEncryption,
    SM3_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    NULL,
    NULL,
    {0,0,0,0},
    SM3_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SM3_CTX),
};
#else
struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    int (*cleanup) (EVP_MD_CTX *ctx);
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* EVP_MD */ ;

static const EVP_MD sm3_md = {
    NID_sm3,
    NID_sm3WithRSAEncryption,
    SM3_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    SM3_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SM3_CTX),
};
#endif
const EVP_MD *EVP_sm3(void)
{
    return &sm3_md;
}

#endif
#endif