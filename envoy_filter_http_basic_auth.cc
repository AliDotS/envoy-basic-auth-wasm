// NOLINT(namespace-envoy)
#include <string>
#include <string_view>
#include <unordered_map>

#include "proxy_wasm_intrinsics.h"

class BasicAuthRootContext : public RootContext {
  static const std::string base64_chars;
  std::string base64_encode(std::string&);

public:
  explicit BasicAuthRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}
  bool onConfigure(size_t) override;
};

class BasicAuthContext : public Context {

public:
  explicit BasicAuthContext(uint32_t id, RootContext* root) : Context(id, root) {}

  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
};
static RegisterContextFactory register_ExampleContext(CONTEXT_FACTORY(BasicAuthContext),
                                                      ROOT_FACTORY(BasicAuthRootContext),
                                                      "basic_auth");

bool BasicAuthRootContext::onConfigure(size_t configSize) {
  auto configuration =
      getBufferBytes(WasmBufferType::PluginConfiguration, 0, configSize)->toString();
  LOG_INFO("--------------------- " + base64_encode(configuration));

  return true;
}

FilterHeadersStatus BasicAuthContext::onRequestHeaders(uint32_t, bool) {
  LOG_DEBUG(std::string("onRequestHeaders ") + std::to_string(id()));
  auto result = getRequestHeaderPairs();
  auto pairs = result->pairs();
  LOG_INFO(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_INFO(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }
  return FilterHeadersStatus::Continue;
}

const std::string BasicAuthRootContext::base64_chars{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                     "abcdefghijklmnopqrstuvwxyz"
                                                     "0123456789+/"};


std::string BasicAuthRootContext::base64_encode(std::string& input) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];
  for (auto& character : input) {
    char_array_3[i++] = character;
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for (i = 0; (i < 4); i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

	if (i) {
    for (j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while ((i++ < 3))
      ret += '=';
  }

  return ret;
}
