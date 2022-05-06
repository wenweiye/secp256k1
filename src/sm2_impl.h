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

static int secp256k1_sm2_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid) {
    /*
        code here
    */
    return 0;
}

static int secp256k1_sm2_sig_verify(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message)
{
    /*
        code here
    */
    return 0;
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
