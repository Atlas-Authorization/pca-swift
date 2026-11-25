#include "cmldsa.h"
#include "randombytes.h"
#include <pthread.h>
#include <string.h>

/* The two reference builds, namespaced by their config.h (cmldsa_ml_dsa_<level>_ref_*). Signing and verification take a context string; NULL, 0 is the empty one. */
extern int cmldsa_ml_dsa_65_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int cmldsa_ml_dsa_65_ref_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
extern int cmldsa_ml_dsa_65_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
extern int cmldsa_ml_dsa_87_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int cmldsa_ml_dsa_87_ref_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
extern int cmldsa_ml_dsa_87_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

#define PK65 1952
#define SK65 4032
#define SIG65 3309
#define PK87 2592
#define SK87 4896
#define SIG87 4627

int cmldsa_len(int level, int which) {
  if (level == 65) return which == 0 ? PK65 : which == 1 ? SK65 : which == 2 ? SIG65 : 0;
  if (level == 87) return which == 0 ? PK87 : which == 1 ? SK87 : which == 2 ? SIG87 : 0;
  return 0;
}

int cmldsa_verify(int level, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len, const uint8_t *pk, size_t pk_len) {
  static const uint8_t empty = 0;
  const uint8_t *m = msg_len ? msg : &empty;
  if (sig == NULL || pk == NULL) return 0;
  if (level == 65) {
    if (sig_len != SIG65 || pk_len != PK65) return 0;
    return cmldsa_ml_dsa_65_ref_verify(sig, sig_len, m, msg_len, NULL, 0, pk) == 0;
  }
  if (level == 87) {
    if (sig_len != SIG87 || pk_len != PK87) return 0;
    return cmldsa_ml_dsa_87_ref_verify(sig, sig_len, m, msg_len, NULL, 0, pk) == 0;
  }
  return 0;
}

/* A seeded key generation swaps the randomness source for one call; signing and unseeded generation take the same lock so they cannot draw from it. */
static pthread_mutex_t seed_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t seed_buf[32];
static void seeded_rng(uint8_t *out, size_t n) {
  for (size_t i = 0; i < n; i++) out[i] = i < 32 ? seed_buf[i] : 0;
}

int cmldsa_keygen(int level, const uint8_t *seed, uint8_t *pk, uint8_t *sk) {
  if (level != 65 && level != 87) return 0;
  int rc;
  pthread_mutex_lock(&seed_lock);
  if (seed) {
    memcpy(seed_buf, seed, 32);
    cmldsa_randombytes_hook(seeded_rng);
  }
  rc = level == 65 ? cmldsa_ml_dsa_65_ref_keypair(pk, sk) : cmldsa_ml_dsa_87_ref_keypair(pk, sk);
  if (seed) {
    cmldsa_randombytes_hook(NULL);
    for (size_t i = 0; i < sizeof seed_buf; i++) ((volatile uint8_t *)seed_buf)[i] = 0; /* the seed does not outlive key generation */
  }
  pthread_mutex_unlock(&seed_lock);
  return rc == 0;
}

int cmldsa_sign(int level, const uint8_t *msg, size_t msg_len, const uint8_t *sk, uint8_t *sig, size_t *sig_len) {
  static const uint8_t empty = 0;
  const uint8_t *m = msg_len ? msg : &empty;
  if (level != 65 && level != 87) return 0;
  pthread_mutex_lock(&seed_lock);
  int rc = level == 65 ? cmldsa_ml_dsa_65_ref_signature(sig, sig_len, m, msg_len, NULL, 0, sk) : cmldsa_ml_dsa_87_ref_signature(sig, sig_len, m, msg_len, NULL, 0, sk);
  pthread_mutex_unlock(&seed_lock);
  return rc == 0;
}
