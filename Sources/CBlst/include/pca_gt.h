#ifndef PCA_GT_H
#define PCA_GT_H
#include <stddef.h>

/* GT (BLS12-381 pairing target group) operations over blst's public API. GT values are 576 bytes (12 Fp coordinates,
 * 48-byte big-endian each, in struct order). Every function returns 1 on success and 0 on malformed input. */
int pca_gt_mul(unsigned char *out, const unsigned char *a, const unsigned char *b);
int pca_gt_pow(unsigned char *out, const unsigned char *a, const unsigned char *k);
int pca_gt_is_element(const unsigned char *a);
int pca_gt_pairing(unsigned char *out, const unsigned char *g1s, const unsigned char *g2s, size_t n);

#endif
