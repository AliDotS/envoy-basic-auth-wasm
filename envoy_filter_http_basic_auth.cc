// NOLINT(namespace-envoy)
#include <string>
#include <string_view>
#include <unordered_set>
#include "include/nlohmann/json.hpp"
#include "absl/strings/escaping.h"

#include "proxy_wasm_intrinsics.h"

class BasicAuthRootContext : public RootContext {
public:
  std::unordered_set<std::string> users;
  std::string authHeaderName;
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
  if (!config.contains("credentials") || !config.contains("auth_header")) {
    LOG_ERROR("Provided configuration doesn't contain 'credentials' or 'auth_header' key");
    return 0;
  }

  auto credentials = config["credentials"];
  if (!credentials.is_array()) {
    LOG_ERROR("credentials value should be an array!");
    return 0;
  }

  auto authHeader = config["auth_header"];
  if (!authHeader.is_string()) {
    LOG_ERROR("auth_header value should be a string!");
    return 0;
  }
  this->authHeaderName = std::string(authHeader);

  for (auto& cred : credentials) {
    if (!cred.is_string() or std::string(cred).find(':') == std::string::npos) {
      LOG_ERROR("Each credential should be an string in the form of user:pass");
      return 0;
    }

    this->users.insert("Basic " + absl::Base64Escape(std::string(cred)));
  }

  return true;
}

FilterHeadersStatus BasicAuthContext::onRequestHeaders(uint32_t, bool) {
  auto authHeader = getRequestHeader(this->rootContext->authHeaderName);
  auto authHeaderSize = authHeader->size();

  if (authHeaderSize <= 7) {
    this->respondWith401_();
    return FilterHeadersStatus::StopIteration;
  }

  if (this->rootContext->users.count(authHeader->toString()) == 0) {
    this->respondWith401_();
    return FilterHeadersStatus::StopIteration;
  }
  return FilterHeadersStatus::Continue;
}

void BasicAuthContext::respondWith401_() {
  HeaderStringPairs temp;
  sendLocalResponse(401, "Unauthorized", "401 Unauthorized", temp, GrpcStatus::InvalidCode);
}