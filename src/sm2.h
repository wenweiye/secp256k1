#ifndef SECP256K1_SM2_H
#define SECP256K1_SM2_H

#include <stddef.h>
#include "scalar.h"
#include "group.h"
#include "ecmult.h"

#define SM2_MAX_PLAINTEXT_SIZE	256 // re-compute SM2_MAX_CIPHERTEXT_SIZE when modify

static int secp256k1_sm2_sig_verify(const secp256k1_scalar* r, const secp256k1_scalar* s, const secp256k1_ge *pubkey, const secp256k1_scalar *message);
static int secp256k1_sm2_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar* r, secp256k1_scalar* s, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid);
#endif /* SECP256K1_SM2_H */