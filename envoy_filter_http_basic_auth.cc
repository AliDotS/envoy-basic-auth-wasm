// NOLINT(namespace-envoy)
#include <string>
#include <string_view>
#include <unordered_set>
#include "include/nlohmann/json.hpp"

#include "proxy_wasm_intrinsics.h"

class BasicAuthRootContext : public RootContext {
  static const std::string base64_chars_;
  std::string base64_encode_(std::string&&);

public:
  std::unordered_set<std::string> users;
  explicit BasicAuthRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}
  bool onConfigure(size_t) override;
};

class BasicAuthContext : public Context {
  void respondWith401_();
  BasicAuthRootContext* rootContext;

public:
  explicit BasicAuthContext(uint32_t id, RootContext* root)
      : Context(id, root), rootContext{reinterpret_cast<BasicAuthRootContext*>(root)} {}

  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
};
static RegisterContextFactory register_ExampleContext(CONTEXT_FACTORY(BasicAuthContext),
                                                      ROOT_FACTORY(BasicAuthRootContext),
                                                      "basic_auth");

bool BasicAuthRootContext::onConfigure(size_t configSize) {
  auto configuration =
      getBufferBytes(WasmBufferType::PluginConfiguration, 0, configSize)->toString();
  if (!nlohmann::json::accept(configuration)) {
    LOG_ERROR("invalid json configuration");
    return 0;
  }
  auto config = nlohmann::json::parse(configuration);
  if (!config.contains("credentials")) {
    LOG_ERROR("Provided configuration doesn't contain 'credentials' key");
    return 0;
  }

  auto credentials = config["credentials"];
  if (!credentials.is_array()) {
    LOG_ERROR("Credentials value should be an array!");
    return 0;
  }

  for (auto& cred : credentials) {
    if (!cred.is_string() or std::string(cred).find(':') == std::string::npos) {
      LOG_ERROR("Each credential should be an string in the form of user:pass");
      return 0;
    }

    this->users.insert(BasicAuthRootContext::base64_encode_(std::string(cred)));
  }

  return true;
}

FilterHeadersStatus BasicAuthContext::onRequestHeaders(uint32_t, bool) {
  auto result = getRequestHeaderPairs();
  auto pairs = result->pairs();
  auto authHeaderExists = false;
  std::string authHeader;
  for (auto& p : pairs) {
    if (p.first == "proxy-authorization") {
      authHeaderExists = true;
      authHeader = p.second;
    }
  }

  if (!authHeaderExists) {
    this->respondWith401_();
    return FilterHeadersStatus::StopIteration;
  }

  if (authHeader.length() <= 7) {
    this->respondWith401_();
    return FilterHeadersStatus::StopIteration;
  }

  if (this->rootContext->users.count(authHeader.substr(6, authHeader.length() - 5)) == 0) {
    this->respondWith401_();
    return FilterHeadersStatus::StopIteration;
  }
  return FilterHeadersStatus::Continue;
}

const std::string BasicAuthRootContext::base64_chars_{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                      "abcdefghijklmnopqrstuvwxyz"
                                                      "0123456789+/"};

std::string BasicAuthRootContext::base64_encode_(std::string&& input) {
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
        ret += base64_chars_[char_array_4[i]];
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
      ret += base64_chars_[char_array_4[j]];

    while ((i++ < 3))
      ret += '=';
  }

  return ret;
}

void BasicAuthContext::respondWith401_() {
  HeaderStringPairs temp;
  sendLocalResponse(401, "Unauthorized", "401 Unauthorized", temp, GrpcStatus::InvalidCode);
}