#ifndef SECP256K1_SM2_IMPL_H
#define SECP256K1_SM2_IMPL_H

#include "eckey.h"

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"
#include "sm3.h"
#include "endian.h"
#include "sm2.h"
#include <random.h>

static int sm2_kdf(const uint8_t *in, size_t inlen, size_t outlen, uint8_t *out)
{
    SM3_CTX ctx;
    uint8_t counter_be[4];
    uint8_t dgst[SM3_DIGEST_SIZE];
    uint32_t counter = 1;
    size_t len;

    /*
    size_t i; fprintf(stderr, "kdf input : ");
    for (i = 0; i < inlen; i++) fprintf(stderr, "%02x", in[i]); fprintf(stderr, "\n");
    */

    while (outlen)
    {
        PUTU32(counter_be, counter);
        counter++;

        sm3_init(&ctx);
        sm3_update(&ctx, in, inlen);
        sm3_update(&ctx, counter_be, sizeof(counter_be));
        sm3_finish(&ctx, dgst);

        len = outlen < SM3_DIGEST_SIZE ? outlen : SM3_DIGEST_SIZE;
        memcpy(out, dgst, len);
        out += len;
        outlen -= len;
    }

    memset(&ctx, 0, sizeof(SM3_CTX));
    memset(dgst, 0, sizeof(dgst));
    return 1;
}

static int secp256k1_sm2_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid)
{
    /*
        code here
    */
    secp256k1_gej rj;
    secp256k1_ge r;
    secp256k1_scalar tmp;
    unsigned char b[32];
    int overflow = 0;
    /*
     computer [k]G = (x, y)
    */
    secp256k1_ecmult_gen(ctx, &rj, nonce);
    secp256k1_ge_set_gej_var(&r, &rj);
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_normalize(&r.y);
    secp256k1_fe_get_b32(b, &r.x);
    secp256k1_scalar_set_b32(sigr, b, &overflow);
    if (recid)
    {
        /* The overflow condition is cryptographically unreachable as hitting it requires finding the discrete log
         * of some P where P.x >= order, and only 1 in about 2^127 points meet this criteria.
         */
        *recid = (overflow << 1) | secp256k1_fe_is_odd(&r.y);
    }
    /*
     computer r = x + e mod n
    */
    secp256k1_scalar_add(sigr, sigr, message);
    /*
     computer tmp = r + k mod n
    */
    secp256k1_scalar_add(&tmp, sigr, nonce);
    /*
     test r == 0 || r + k == n
    */
    if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(&tmp)){
        return 0;
    }

    /*
     computer tmp = 1 + d
    */
   secp256k1_scalar_add(&tmp, &secp256k1_scalar_one, seckey);
    /*
     computer tmp = (1+d)^{-1}
    */
   secp256k1_scalar_inverse_var(&tmp, &tmp);
   /*
     computer sigs = (1+d)^{-1} * k
    */
   secp256k1_scalar_mul(sigs, &tmp, nonce);
   /*
     computer tmp = (1+d)^{-1} * d
    */
   secp256k1_scalar_mul(&tmp, &tmp, seckey);
   /*
     computer tmp = (1+d)^{-1} * d * r
    */
   secp256k1_scalar_mul(&tmp, &tmp, sigr);
   /*
     computer tmp =  - (1+d)^{-1} * d * r
    */
   secp256k1_scalar_negate(&tmp, &tmp);
   /*
     computer sigs =  (1+d)^{-1} * k - (1+d)^{-1} * d * r
    */
   secp256k1_scalar_add(sigs, sigs, &tmp);
   /*
     test sigs == 0 ?
    */
   if (secp256k1_scalar_is_zero(sigs)){
       return 0;
   }
    return 1;
}

static int secp256k1_sm2_sig_verify(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message)
{
    /*
        code here
    */
    unsigned char b[32];
    secp256k1_scalar t, r;
    secp256k1_gej pubkeyj, tmpgej;
    secp256k1_ge tmpge;
    /*
     computer t = r + s
    */
    secp256k1_scalar_add(&t, sigr, sigs);
    /*
     test t == 0?
    */
    if (secp256k1_scalar_is_zero(&t)){
        return 0;
    }
    /*

     convert pk to jocb
    */
    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    /*
     computer [s]G + [t]P = (x, y)
    */
    secp256k1_ecmult(&tmpgej, &pubkeyj, &t, sigs);
    
    /*
     computer r = x + e
    */
    secp256k1_ge_set_gej_var(&tmpge, &tmpgej);
    secp256k1_fe_normalize_var(&tmpge.x);
    secp256k1_fe_get_b32(b, &tmpge.x);
    secp256k1_scalar_set_b32(&r, b, NULL);
    secp256k1_scalar_add(&r, &r, message);
    return secp256k1_scalar_eq(sigr, &r);
}

static int secp256k1_sm2_do_encrypt(const secp256k1_ecmult_gen_context *ctx, unsigned char *ciphertext, const secp256k1_ge *pubkey, const unsigned char *message, const unsigned char kLen, const secp256k1_scalar *nonce)
{
    /*
        code here
    */
    return 0;
}

static int secp256k1_sm2_do_decrypt(unsigned char *messsage, const unsigned char kLen, const unsigned char *ciphertext, const secp256k1_scalar sec)
{
    /*
        code here
    */
    return 0;
}
#endif /* SECP256K1_SM2_IMPL_H */
