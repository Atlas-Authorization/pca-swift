#include "ada.h"
#include "CAda.h"
#include <cstring>
#include <string>
#include <string_view>

extern "C" int atlas_ada_domain_to_ascii(const uint8_t *input, size_t input_len, uint8_t *out, size_t cap, size_t *out_len) {
  if (input == nullptr || out == nullptr || out_len == nullptr || input_len == 0) return 0;
  auto url = ada::parse<ada::url>("ws://x");
  if (!url) return 0;
  if (!url->set_hostname(std::string_view(reinterpret_cast<const char *>(input), input_len))) return 0;
  std::string host(url->get_hostname());
  if (host.empty() || host.size() > cap) return 0;
  std::memcpy(out, host.data(), host.size());
  *out_len = host.size();
  return 1;
}

static int atlas_put(std::string_view s, uint8_t *out, size_t cap, size_t *out_len) {
  if (s.size() > cap) return 0;
  if (!s.empty()) std::memcpy(out, s.data(), s.size());
  *out_len = s.size();
  return 1;
}

static std::string_view atlas_view(const uint8_t *p, size_t n) { return n == 0 ? std::string_view() : std::string_view(reinterpret_cast<const char *>(p), n); }

extern "C" int atlas_ada_url_part(const uint8_t *input, size_t input_len, int which, uint8_t *out, size_t cap, size_t *out_len) {
  if (out == nullptr || out_len == nullptr) return 0;
  auto url = ada::parse<ada::url_aggregator>(atlas_view(input, input_len));
  if (!url) return 0;
  switch (which) {
    case 0: return atlas_put(url->get_protocol(), out, cap, out_len);
    case 1: return atlas_put(url->get_hostname(), out, cap, out_len);
    case 2: return atlas_put(url->get_host(), out, cap, out_len);
    case 3: return atlas_put(url->get_href(), out, cap, out_len);
    default: return 0;
  }
}

extern "C" int atlas_ada_url_set_param(const uint8_t *input, size_t input_len, const uint8_t *key, size_t key_len, const uint8_t *value, size_t value_len,
                                       uint8_t *out, size_t cap, size_t *out_len) {
  if (out == nullptr || out_len == nullptr) return 0;
  auto url = ada::parse<ada::url_aggregator>(atlas_view(input, input_len));
  if (!url) return 0;
  ada::url_search_params params(url->get_search());
  params.set(atlas_view(key, key_len), atlas_view(value, value_len));
  url->set_search(params.to_string());
  return atlas_put(url->get_href(), out, cap, out_len);
}
