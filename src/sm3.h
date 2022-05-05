#ifndef SECP256K1_SM3_H
#define SECP256K1_SM3_H

#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SM3_IS_BIG_ENDIAN	1

#define SM3_DIGEST_SIZE		32
#define SM3_BLOCK_SIZE		64
#define SM3_STATE_WORDS		8
#define SM3_HMAC_SIZE		(SM3_DIGEST_SIZE)


typedef struct {
	uint32_t digest[SM3_STATE_WORDS];
	uint64_t nblocks;
	uint8_t block[SM3_BLOCK_SIZE];
	size_t num;
} SM3_CTX;

void sm3_init(SM3_CTX *ctx);
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t datalen);
void sm3_finish(SM3_CTX *ctx, uint8_t dgst[SM3_DIGEST_SIZE]);
void sm3_digest(const uint8_t *data, size_t datalen, uint8_t dgst[SM3_DIGEST_SIZE]);


typedef struct {
	SM3_CTX sm3_ctx;
	unsigned char key[SM3_BLOCK_SIZE];
} SM3_HMAC_CTX;

void sm3_hmac_init(SM3_HMAC_CTX *ctx, const uint8_t *key, size_t keylen);
void sm3_hmac_update(SM3_HMAC_CTX *ctx, const uint8_t *data, size_t datalen);
void sm3_hmac_finish(SM3_HMAC_CTX *ctx, uint8_t mac[SM3_HMAC_SIZE]);
void sm3_hmac(const uint8_t *key, size_t keylen,
	const uint8_t *data, size_t datalen,
	uint8_t mac[SM3_HMAC_SIZE]);


#ifdef __cplusplus
}
#endif
#endif