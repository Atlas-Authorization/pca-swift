#include "randombytes.h"
#include <stdlib.h>

#if defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#include <sys/types.h>
#else
#error "CMLDSA has an OS CSPRNG only on Apple platforms (SecRandomCopyBytes) and Linux (getrandom)"
#endif

static void (*hook_fn)(uint8_t *, size_t) = NULL;

void cmldsa_randombytes_hook(void (*fn)(uint8_t *, size_t)) { hook_fn = fn; }

void randombytes(uint8_t *out, size_t n) {
  if (hook_fn != NULL) { hook_fn(out, n); return; }
#if defined(__APPLE__)
  if (n != 0 && SecRandomCopyBytes(kSecRandomDefault, n, out) != 0) abort(); /* no entropy: never sign or derive a key from a weak value */
#else
  while (n > 0) {
    ssize_t got = getrandom(out, n, 0);
    if (got < 0) { if (errno == EINTR) continue; abort(); }
    out += got;
    n -= (size_t)got;
  }
#endif
}
