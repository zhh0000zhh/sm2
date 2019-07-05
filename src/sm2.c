//#include "sm2ToOC.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "libcrypto-compat.h"
#include "sm3.h"
# define SM2err(f,r) ERR_PUT_error(ERR_LIB_SM2,(f),(r),OPENSSL_FILE,OPENSSL_LINE)

/*
 * SM2 function codes.
 */
#  define SM2_F_PKEY_SM2_COPY                              115
#  define SM2_F_PKEY_SM2_CTRL                              109
#  define SM2_F_PKEY_SM2_CTRL_STR                          110
#  define SM2_F_PKEY_SM2_DIGEST_CUSTOM                     114
#  define SM2_F_PKEY_SM2_INIT                              111
#  define SM2_F_PKEY_SM2_SIGN                              112
#  define SM2_F_SM2_COMPUTE_MSG_HASH                       100
#  define SM2_F_SM2_COMPUTE_USERID_DIGEST                  101
#  define SM2_F_SM2_COMPUTE_Z_DIGEST                       113
#  define SM2_F_SM2_DECRYPT                                102
#  define SM2_F_SM2_ENCRYPT                                103
#  define SM2_F_SM2_PLAINTEXT_SIZE                         104
#  define SM2_F_SM2_SIGN                                   105
#  define SM2_F_SM2_SIG_GEN                                106
#  define SM2_F_SM2_SIG_VERIFY                             107
#  define SM2_F_SM2_VERIFY                                 108

/*
 * SM2 reason codes.
 */
#  define SM2_R_ASN1_ERROR                                 100
#  define SM2_R_BAD_SIGNATURE                              101
#  define SM2_R_BUFFER_TOO_SMALL                           107
#  define SM2_R_DIST_ID_TOO_LARGE                          110
#  define SM2_R_ID_NOT_SET                                 112
#  define SM2_R_ID_TOO_LARGE                               111
#  define SM2_R_INVALID_CURVE                              108
#  define SM2_R_INVALID_DIGEST                             102
#  define SM2_R_INVALID_DIGEST_TYPE                        103
#  define SM2_R_INVALID_ENCODING                           104
#  define SM2_R_INVALID_FIELD                              105
#  define SM2_R_NO_PARAMETERS_SET                          109
#  define SM2_R_USER_ID_TOO_LARGE                          106

static const ERR_STRING_DATA SM2_str_functs[] = {
    {ERR_PACK(ERR_LIB_SM2, SM2_F_PKEY_SM2_COPY, 0), "pkey_sm2_copy"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_PKEY_SM2_CTRL, 0), "pkey_sm2_ctrl"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_PKEY_SM2_CTRL_STR, 0), "pkey_sm2_ctrl_str"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_PKEY_SM2_DIGEST_CUSTOM, 0),
        "pkey_sm2_digest_custom"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_PKEY_SM2_INIT, 0), "pkey_sm2_init"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_PKEY_SM2_SIGN, 0), "pkey_sm2_sign"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_SM2_COMPUTE_MSG_HASH, 0),
        "sm2_compute_msg_hash"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_SM2_COMPUTE_USERID_DIGEST, 0),
        "sm2_compute_userid_digest"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_SM2_COMPUTE_Z_DIGEST, 0),
        "sm2_compute_z_digest"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_SM2_DECRYPT, 0), "sm2_decrypt"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_SM2_ENCRYPT, 0), "sm2_encrypt"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_SM2_PLAINTEXT_SIZE, 0), "sm2_plaintext_size"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_SM2_SIGN, 0), "sm2_sign"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_SM2_SIG_GEN, 0), "sm2_sig_gen"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_SM2_SIG_VERIFY, 0), "sm2_sig_verify"},
    {ERR_PACK(ERR_LIB_SM2, SM2_F_SM2_VERIFY, 0), "sm2_verify"},
    {0, NULL}
};

static const ERR_STRING_DATA SM2_str_reasons[] = {
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_ASN1_ERROR), "asn1 error"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_BAD_SIGNATURE), "bad signature"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_BUFFER_TOO_SMALL), "buffer too small"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_DIST_ID_TOO_LARGE), "dist id too large"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_ID_NOT_SET), "id not set"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_ID_TOO_LARGE), "id too large"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_INVALID_CURVE), "invalid curve"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_INVALID_DIGEST), "invalid digest"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_INVALID_DIGEST_TYPE),
        "invalid digest type"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_INVALID_ENCODING), "invalid encoding"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_INVALID_FIELD), "invalid field"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_NO_PARAMETERS_SET), "no parameters set"},
    {ERR_PACK(ERR_LIB_SM2, 0, SM2_R_USER_ID_TOO_LARGE), "user id too large"},
    {0, NULL}
};
//const unsigned char* id = "1234567812345678";
static int sm2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    uint8_t *buf = NULL;
    uint16_t entl = 0;
    uint8_t e_byte = 0;
    
    hash = EVP_MD_CTX_new();
    ctx = BN_CTX_new();
    if (hash == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);
    
    if (yA == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    
    if (!EVP_DigestInit(hash, digest)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }
    
    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */
    
    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, SM2_R_ID_TOO_LARGE);
        goto done;
    }
    
    entl = (uint16_t)(8 * id_len);
    
    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }
    
    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }
    
    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EC_LIB);
        goto done;
    }
    
    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    
    if (BN_bn2binpad(a, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(b, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
                                            EC_GROUP_get0_generator(group),
                                            xG, yG, ctx)
        || BN_bn2binpad(xG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
                                            EC_KEY_get0_public_key(key),
                                            xA, yA, ctx)
        || BN_bn2binpad(xA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EVP_DigestFinal(hash, out, NULL)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    //printf("123\n");
    
    rc = 1;
    
done:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}

static BIGNUM *sm2_compute_msg_hash(const EVP_MD *digest,
                                    const EC_KEY *key,
                                    const uint8_t *id,
                                    const size_t id_len,
                                    const uint8_t *msg, size_t msg_len)
{
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    const int md_size = EVP_MD_size(digest);
    uint8_t *z = NULL;
    BIGNUM *e = NULL;
    
    if (md_size < 0) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, SM2_R_INVALID_DIGEST);
        goto done;
    }
    
    z = OPENSSL_zalloc(md_size);
    if (hash == NULL || z == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    
    if (!sm2_compute_z_digest(z, digest, id, id_len, key)) {
        /* SM2err already called */
        goto done;
    }
    
    if (!EVP_DigestInit(hash, digest)
        || !EVP_DigestUpdate(hash, z, md_size)
        || !EVP_DigestUpdate(hash, msg, msg_len)
        /* reuse z buffer to hold H(Z || M) */
        || !EVP_DigestFinal(hash, z, NULL)) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_EVP_LIB);
        goto done;
    }
    
    e = BN_bin2bn(z, md_size, NULL);
    if (e == NULL)
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_INTERNAL_ERROR);
    
done:
    OPENSSL_free(z);
    EVP_MD_CTX_free(hash);
    return e;
}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
typedef struct ec_extra_data_st {
    struct ec_extra_data_st *next;
    void *data;
    void *(*dup_func) (void *);
    void (*free_func) (void *);
    void (*clear_free_func) (void *);
} EC_EXTRA_DATA;             
struct ec_group_st {
    const EC_METHOD *meth;
    EC_POINT *generator;        /* optional */
    BIGNUM order, cofactor;
    int curve_name;             /* optional NID for named curve */
    int asn1_flag;              /* flag to control the asn1 encoding */
    /*
     * Kludge: upper bit of ans1_flag is used to denote structure
     * version. If set, then last field is present. This is done
     * for interoperation with FIPS code.
     */
#define EC_GROUP_ASN1_FLAG_MASK 0x7fffffff
#define EC_GROUP_VERSION(p) (p->asn1_flag&~EC_GROUP_ASN1_FLAG_MASK)
    point_conversion_form_t asn1_form;
    unsigned char *seed;        /* optional seed for parameters (appears in
                                 * ASN1) */
    size_t seed_len;
    EC_EXTRA_DATA *extra_data;  /* linked list */
    /*
     * The following members are handled by the method functions, even if
     * they appear generic
     */
    /*
     * Field specification. For curves over GF(p), this is the modulus; for
     * curves over GF(2^m), this is the irreducible polynomial defining the
     * field.
     */
    BIGNUM field;
    /*
     * Field specification for curves over GF(2^m). The irreducible f(t) is
     * then of the form: t^poly[0] + t^poly[1] + ... + t^poly[k] where m =
     * poly[0] > poly[1] > ... > poly[k] = 0. The array is terminated with
     * poly[k+1]=-1. All elliptic curve irreducibles have at most 5 non-zero
     * terms.
     */
    int poly[6];
    /*
     * Curve coefficients. (Here the assumption is that BIGNUMs can be used
     * or abused for all kinds of fields, not just GF(p).) For characteristic
     * > 3, the curve is defined by a Weierstrass equation of the form y^2 =
     * x^3 + a*x + b. For characteristic 2, the curve is defined by an
     * equation of the form y^2 + x*y = x^3 + a*x^2 + b.
     */
    BIGNUM a, b;
    /* enable optimized point arithmetics for special case */
    int a_is_minus3;
    /* method-specific (e.g., Montgomery structure) */
    void *field_data1;
    /* method-specific */
    void *field_data2;
    /* method-specific */
    int (*field_mod_func) (BIGNUM *, const BIGNUM *, const BIGNUM *,
                           BN_CTX *);
    BN_MONT_CTX *mont_data;     /* data for ECDSA inverse */
} /* EC_GROUP */ ;

#else
struct ec_group_st {
    const EC_METHOD *meth;
    EC_POINT *generator;        /* optional */
    BIGNUM *order, *cofactor;
    int curve_name;             /* optional NID for named curve */
    int asn1_flag;              /* flag to control the asn1 encoding */
    point_conversion_form_t asn1_form;
    unsigned char *seed;        /* optional seed for parameters (appears in
                                 * ASN1) */
    size_t seed_len;
    /*
     * The following members are handled by the method functions, even if
     * they appear generic
     */
    /*
     * Field specification. For curves over GF(p), this is the modulus; for
     * curves over GF(2^m), this is the irreducible polynomial defining the
     * field.
     */
    BIGNUM *field;
    /*
     * Field specification for curves over GF(2^m). The irreducible f(t) is
     * then of the form: t^poly[0] + t^poly[1] + ... + t^poly[k] where m =
     * poly[0] > poly[1] > ... > poly[k] = 0. The array is terminated with
     * poly[k+1]=-1. All elliptic curve irreducibles have at most 5 non-zero
     * terms.
     */
    int poly[6];
    /*
     * Curve coefficients. (Here the assumption is that BIGNUMs can be used
     * or abused for all kinds of fields, not just GF(p).) For characteristic
     * > 3, the curve is defined by a Weierstrass equation of the form y^2 =
     * x^3 + a*x + b. For characteristic 2, the curve is defined by an
     * equation of the form y^2 + x*y = x^3 + a*x^2 + b.
     */
    BIGNUM *a, *b;
    /* enable optimized point arithmetics for special case */
    int a_is_minus3;
    /* method-specific (e.g., Montgomery structure) */
    void *field_data1;
    /* method-specific */
    void *field_data2;
    /* method-specific */
    int(*field_mod_func) (BIGNUM *, const BIGNUM *, const BIGNUM *,
                          BN_CTX *);
    /* data for ECDSA inverse */
    BN_MONT_CTX *mont_data;
    
    /*
     * Precomputed values for speed. The PCT_xxx names match the
     * pre_comp.xxx union names; see the SETPRECOMP and HAVEPRECOMP
     * macros, below.
     */
    enum {
        PCT_none,
        PCT_nistp224, PCT_nistp256, PCT_nistp521, PCT_nistz256,
        PCT_ec
    } pre_comp_type;
    union {
        void *nistp224;
        void *nistp256;
        void *nistp521;
        void *nistz256;
        void *ec;
    } pre_comp;
};
#endif
static int ec_field_inverse_mod_ord(const EC_GROUP *group, BIGNUM *r,
                                    const BIGNUM *x, BN_CTX *ctx)
{
    BIGNUM *e = NULL;
    BN_CTX *new_ctx = NULL;
    int ret = 0;
    
    if (group->mont_data == NULL)
        ((EC_GROUP *)group)->mont_data = BN_MONT_CTX_new();
    
    if (ctx == NULL && (ctx = new_ctx = BN_CTX_secure_new()) == NULL)
        return 0;
    
    BN_CTX_start(ctx);
    if ((e = BN_CTX_get(ctx)) == NULL)
        goto err;
    
    /*-
     * We want inverse in constant time, therefore we utilize the fact
     * order must be prime and use Fermats Little Theorem instead.
     */
    if (!BN_set_word(e, 2))
        goto err;

    if (!BN_sub(e, &group->order, e))
        goto err;
    /*-
     * Exponent e is public.
     * No need for scatter-gather or BN_FLG_CONSTTIME.
     */
    if (!BN_mod_exp_mont(r, x, e, &group->order, ctx, group->mont_data))
        goto err;
    
    ret = 1;
    
err:
    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

static int ec_group_do_inverse_ord(const EC_GROUP *group, BIGNUM *res,
                            const BIGNUM *x, BN_CTX *ctx)
{
    // if (group->meth->field_inverse_mod_ord != NULL)
    //     return group->meth->field_inverse_mod_ord(group, res, x, ctx);
    // else
    return ec_field_inverse_mod_ord(group, res, x, ctx);
}

static ECDSA_SIG *sm2_sig_gen(const EC_KEY *key, const BIGNUM *e)
{
    const BIGNUM *dA = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    ECDSA_SIG *sig = NULL;
    EC_POINT *kG = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *rk = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *tmp = NULL;
    
    kG = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    
    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    rk = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    
    /*
     * These values are returned and so should not be allocated out of the
     * context
     */
    r = BN_new();
    s = BN_new();
    
    if (r == NULL || s == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    
    for (;;) {
        if (!BN_priv_rand_range(k, order)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }
        
        if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, NULL,
                                                ctx)
            || !BN_mod_add(r, e, x1, order, ctx)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }
        
        /* try again if r == 0 or r+k == n */
        if (BN_is_zero(r))
            continue;
        
        if (!BN_add(rk, r, k)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }
        
        if (BN_cmp(rk, order) == 0)
            continue;
        
        if (!BN_add(s, dA, BN_value_one())
            || !ec_group_do_inverse_ord(group, s, s, ctx)
            || !BN_mod_mul(tmp, dA, r, order, ctx)
            || !BN_sub(tmp, k, tmp)
            || !BN_mod_mul(s, s, tmp, order, ctx)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_BN_LIB);
            goto done;
        }
        
        sig = ECDSA_SIG_new();
        if (sig == NULL) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
            goto done;
        }
        
        /* takes ownership of r and s */
        ECDSA_SIG_set0(sig, r, s);
        break;
    }
    
done:
    if (sig == NULL) {
        BN_free(r);
        BN_free(s);
    }
    
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    return sig;
}

static ECDSA_SIG *sm2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const uint8_t *id,
                       const size_t id_len,
                       const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *sig = NULL;
    
    e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }
    
    sig = sm2_sig_gen(key, e);
    
done:
    BN_free(e);
    return sig;
}
static char* hex2bin(char* hex, int len)
{
    char* rt = malloc(len / 2 + 1);
    char h;
    char l;
    for (int i = 0, j = 0; i < len; i++, j++)
    {
        if (hex[i] >= '0' && hex[i] <= '9')
        {
            h = hex[i] - '0';
        }
        else
        {
            h = hex[i] - 'A' + 10;
        }
        i++;
        if (hex[i] >= '0' && hex[i] <= '9')
        {
            l = hex[i] - '0';
        }
        else
        {
            l = hex[i] - 'A' + 10;
        }
        rt[j] = (h << 4) | l;
    }
    rt[len / 2] = 0;
    return  rt;
}
#define _P  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
#define _a  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
#define _b  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
#define _n  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
#define _Gx "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
#define _Gy "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
static EC_GROUP *create_EC_group(const char *p_hex, const char *a_hex,
                                 const char *b_hex, const char *x_hex,
                                 const char *y_hex, const char *order_hex,
                                 const char *cof_hex)
{
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *g_x = NULL;
    BIGNUM *g_y = NULL;
    BIGNUM *order = NULL;
    BIGNUM *cof = NULL;
    EC_POINT *generator = NULL;
    EC_GROUP *group = NULL;
    
    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&a, a_hex);
    BN_hex2bn(&b, b_hex);
    
    group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    
    if (group == NULL)
        return NULL;
    
    generator = EC_POINT_new(group);
    if (generator == NULL)
        return NULL;
    
    BN_hex2bn(&g_x, x_hex);
    BN_hex2bn(&g_y, y_hex);
    
    if (EC_POINT_set_affine_coordinates_GFp(group, generator, g_x, g_y, NULL) ==
        0)
        return NULL;
    
    BN_free(g_x);
    BN_free(g_y);
    
    BN_hex2bn(&order, order_hex);
    BN_hex2bn(&cof, cof_hex);
    
    if (EC_GROUP_set_generator(group, generator, order, cof) == 0)
        return NULL;
    
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    
    return group;
}
void my_sm2_sign(const char* content, int contentlen, const char* prikey, char* out)
{
    BIGNUM *pk = NULL;
    BN_hex2bn(&pk, prikey);
    EC_KEY *ec_key = EC_KEY_new();
    EC_KEY_set_group(ec_key, create_EC_group(_P, _a, _b, _Gx, _Gy, _n, "1"));
    EC_KEY_set_private_key(ec_key, pk);
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* pubkey = EC_POINT_new(group);
    EC_POINT_mul(group, pubkey, pk, NULL, NULL, NULL);
    EC_KEY_set_public_key(ec_key, pubkey);
re1:
    {}
    
    ECDSA_SIG* sig = sm2_do_sign(ec_key, EVP_sm3(), "1234567812345678", 16, content, contentlen);
    const BIGNUM *r;
    const BIGNUM *s;
    ECDSA_SIG_get0(sig, &r, &s);
    char* p;
    p = out;
    memset(out, 0, 64);
    char* tmp = BN_bn2hex(r);
    int ti = strlen(tmp);
    if (ti > 64)
    {
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        printf("%s", tmp);
        OPENSSL_free(tmp);
        tmp = BN_bn2hex(s);
        printf("%s\n", tmp);
        OPENSSL_free(tmp);
        goto re1;
    }
    while (ti < 64)
    {
        *p = 0;
        p++;
        ti += 2;
    }
    OPENSSL_free(tmp);
    BN_bn2bin(r, p);
    p = out + 32;
    tmp = BN_bn2hex(s);
    ti = strlen(tmp);
    if (ti > 64)
    {
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        tmp = BN_bn2hex(r);
        OPENSSL_free(tmp);
        printf("%s", tmp);
        tmp = BN_bn2hex(s);
        printf("%s\n", tmp);
        OPENSSL_free(tmp);
        goto re1;
    }
    while (ti < 64)
    {
        *p = 0;
        p++;
        ti += 2;
    }
    OPENSSL_free(tmp);
    BN_bn2bin(s, p);
    ECDSA_SIG_free(sig);
    EC_KEY_free(ec_key);
    BN_free(pk);//»Áπ˚±®¥Ì◊¢ Õ¥À¥¶ ‘ ‘
}

// int main()
// {
//     char tmp[64];
//     sm2_sign("111111111122222222223333333333",30,"E2BF2233AC20E6CB311F97B69791E53F4DA28683C5BFDE48B559D24DD59CC7DD",tmp);
// }