#ifndef ATLAS_PCA_CADA_H
#define ATLAS_PCA_CADA_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* The WHATWG URL host parser's domain-to-ASCII, as Node's url.domainToASCII does it: set the hostname of "ws://x" and read it back (Ada,
 * UTS 46 non-transitional, CheckBidi, forbidden host code points, IPv4 numbers). 1 and the A-label host in out/out_len on success; 0 when the
 * host is refused or does not fit in cap. */
int atlas_ada_domain_to_ascii(const uint8_t *input, size_t input_len, uint8_t *out, size_t cap, size_t *out_len);
/* The WHATWG URL parser (Ada, the one Node uses). Both return 0 when `input` does not parse or the answer does not fit in cap.
 * atlas_ada_url_part: which = 0 protocol ("https:"), 1 hostname, 2 host (with a non-default port), 3 href (the serialised URL).
 * atlas_ada_url_set_param: URLSearchParams.set(key, value) on the URL's query (the first pair of that name replaced in place, later ones
 * dropped, others kept; values application/x-www-form-urlencoded), then the serialised URL. */
int atlas_ada_url_part(const uint8_t *input, size_t input_len, int which, uint8_t *out, size_t cap, size_t *out_len);
int atlas_ada_url_set_param(const uint8_t *input, size_t input_len, const uint8_t *key, size_t key_len, const uint8_t *value, size_t value_len,
                            uint8_t *out, size_t cap, size_t *out_len);
#ifdef __cplusplus
}
#endif
#endif
