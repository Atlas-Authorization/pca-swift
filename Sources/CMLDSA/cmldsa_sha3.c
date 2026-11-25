/* SHAKE128 / SHAKE256 over the vendored XKCP generic 64-bit Keccak-p[1600] (keccak/). The sponge below is liboqs 0.14.0's src/common/sha3/xkcp_sha3.c
 * (itself from PQClean's fips202.c, SPDX MIT) with the runtime dispatch, the callback table and the heap allocation taken out: the context is a plain
 * struct and the permutation is called directly. */
#include "fips202.h"
#include "KeccakP-1600-SnP.h"

static void keccak_inc_reset(uint64_t *s) {
  KeccakP1600_Initialize(s);
  s[25] = 0;
}

static void keccak_inc_absorb(uint64_t *s, uint32_t r, const uint8_t *m, size_t mlen) {
  uint64_t c = r - s[25];
  if (s[25] && mlen >= c) {
    KeccakP1600_AddBytes(s, m, (unsigned int)s[25], (unsigned int)c);
    KeccakP1600_Permute_24rounds(s);
    mlen -= c;
    m += c;
    s[25] = 0;
  }
  while (mlen >= r) {
    KeccakP1600_AddBytes(s, m, 0, r);
    KeccakP1600_Permute_24rounds(s);
    mlen -= r;
    m += r;
  }
  KeccakP1600_AddBytes(s, m, (unsigned int)s[25], (unsigned int)mlen);
  s[25] += mlen;
}

static void keccak_inc_finalize(uint64_t *s, uint32_t r, uint8_t p) {
  /* after keccak_inc_absorb s[25] < r, so one more byte for the domain separator always fits */
  KeccakP1600_AddByte(s, p, (unsigned int)s[25]);
  KeccakP1600_AddByte(s, 0x80, (unsigned int)(r - 1));
  s[25] = 0;
}

static void keccak_inc_squeeze(uint8_t *h, size_t outlen, uint64_t *s, uint32_t r) {
  while (outlen > s[25]) {
    KeccakP1600_ExtractBytes(s, h, (unsigned int)(r - s[25]), (unsigned int)s[25]);
    KeccakP1600_Permute_24rounds(s);
    h += s[25];
    outlen -= s[25];
    s[25] = r;
  }
  KeccakP1600_ExtractBytes(s, h, (unsigned int)(r - s[25]), (unsigned int)outlen);
  s[25] -= outlen;
}

static void wipe(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--) *v++ = 0;
}

void shake128_inc_init(shake128incctx *state) { keccak_inc_reset(state->s); }
void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen) { keccak_inc_absorb(state->s, SHAKE128_RATE, input, inlen); }
void shake128_inc_finalize(shake128incctx *state) { keccak_inc_finalize(state->s, SHAKE128_RATE, 0x1F); }
void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state) { keccak_inc_squeeze(output, outlen, state->s, SHAKE128_RATE); }
void shake128_inc_ctx_release(shake128incctx *state) { wipe(state, sizeof *state); }
void shake128_inc_ctx_reset(shake128incctx *state) { keccak_inc_reset(state->s); }

void shake256_inc_init(shake256incctx *state) { keccak_inc_reset(state->s); }
void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen) { keccak_inc_absorb(state->s, SHAKE256_RATE, input, inlen); }
void shake256_inc_finalize(shake256incctx *state) { keccak_inc_finalize(state->s, SHAKE256_RATE, 0x1F); }
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state) { keccak_inc_squeeze(output, outlen, state->s, SHAKE256_RATE); }
void shake256_inc_ctx_release(shake256incctx *state) { wipe(state, sizeof *state); }
void shake256_inc_ctx_reset(shake256incctx *state) { keccak_inc_reset(state->s); }

void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
  shake256incctx s;
  shake256_inc_init(&s);
  shake256_inc_absorb(&s, input, inlen);
  shake256_inc_finalize(&s);
  shake256_inc_squeeze(output, outlen, &s);
  shake256_inc_ctx_release(&s);
}
