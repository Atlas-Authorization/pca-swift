#ifndef CMLDSA_H
#define CMLDSA_H
#include <stddef.h>
#include <stdint.h>

/* ML-DSA-65 and ML-DSA-87 (FIPS 204, pure mode, EMPTY context): the pq-crystals reference code liboqs 0.14.0 ships, vendored. Level is 65 or 87. */

/* 1 iff sig is a valid ML-DSA-<level> signature on msg under pk; exact lengths, anything else is 0. */
int cmldsa_verify(int level, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len, const uint8_t *pk, size_t pk_len);
/* Key pair. seed: NULL for a random key (OS CSPRNG), else the 32-byte FIPS 204 xi (key generation draws exactly xi, so KeyGen(xi)). pk / sk need the
   FIPS 204 sizes (65: 1952 / 4032, 87: 2592 / 4896). 1 on success. */
int cmldsa_keygen(int level, const uint8_t *seed, uint8_t *pk, uint8_t *sk);
/* Hedged signature with the EMPTY context (as CryptoKit signs). sig needs 3309 (65) / 4627 (87) bytes. 1 on success. */
int cmldsa_sign(int level, const uint8_t *msg, size_t msg_len, const uint8_t *sk, uint8_t *sig, size_t *sig_len);
/* The FIPS 204 sizes for a level: which 0 = public key, 1 = secret key, 2 = signature; 0 for anything else. */
int cmldsa_len(int level, int which);

#endif
