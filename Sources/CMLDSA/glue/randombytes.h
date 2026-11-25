/* CMLDSA: the randomness the ML-DSA reference code draws for key generation (the 32-byte seed) and for hedged signing (the 32-byte rnd). It comes from the
 * operating system's CSPRNG (SecRandomCopyBytes on Apple platforms, getrandom on Linux), unless a test hook is installed (see cmldsa_keygen). */
#ifndef CMLDSA_RANDOMBYTES_H
#define CMLDSA_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#define randombytes cmldsa_randombytes
void randombytes(uint8_t *out, size_t n);

/* Installs (or, with NULL, removes) a replacement source. Only cmldsa.c calls this, under its lock. */
void cmldsa_randombytes_hook(void (*fn)(uint8_t *, size_t));

#endif
