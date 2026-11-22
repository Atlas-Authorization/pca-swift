/* CMLDSA: the SHAKE interface the ML-DSA reference code uses (the names liboqs' PQClean shim gives it), on the vendored Keccak permutation in keccak/.
 * Every exported function carries the cmldsa_ prefix, so nothing here collides with another SHA-3 / Keccak linked into the same binary. */
#ifndef CMLDSA_FIPS202_H
#define CMLDSA_FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

/* 25 lanes of Keccak state plus the count of absorbed (or not yet squeezed) bytes, as in the upstream incremental context */
typedef struct { uint64_t s[26]; } shake128incctx;
typedef struct { uint64_t s[26]; } shake256incctx;

#define shake256 cmldsa_shake256
void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

#define shake128_inc_init cmldsa_shake128_inc_init
#define shake128_inc_absorb cmldsa_shake128_inc_absorb
#define shake128_inc_finalize cmldsa_shake128_inc_finalize
#define shake128_inc_squeeze cmldsa_shake128_inc_squeeze
#define shake128_inc_ctx_release cmldsa_shake128_inc_ctx_release
#define shake128_inc_ctx_reset cmldsa_shake128_inc_ctx_reset
void shake128_inc_init(shake128incctx *state);
void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen);
void shake128_inc_finalize(shake128incctx *state);
void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state);
void shake128_inc_ctx_release(shake128incctx *state);
void shake128_inc_ctx_reset(shake128incctx *state);

#define shake256_inc_init cmldsa_shake256_inc_init
#define shake256_inc_absorb cmldsa_shake256_inc_absorb
#define shake256_inc_finalize cmldsa_shake256_inc_finalize
#define shake256_inc_squeeze cmldsa_shake256_inc_squeeze
#define shake256_inc_ctx_release cmldsa_shake256_inc_ctx_release
#define shake256_inc_ctx_reset cmldsa_shake256_inc_ctx_reset
void shake256_inc_init(shake256incctx *state);
void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen);
void shake256_inc_finalize(shake256incctx *state);
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state);
void shake256_inc_ctx_release(shake256incctx *state);
void shake256_inc_ctx_reset(shake256incctx *state);

#define shake128_squeezeblocks(OUT, NBLOCKS, STATE) shake128_inc_squeeze(OUT, (NBLOCKS) * SHAKE128_RATE, STATE)
#define shake256_squeezeblocks(OUT, NBLOCKS, STATE) shake256_inc_squeeze(OUT, (NBLOCKS) * SHAKE256_RATE, STATE)

#endif
