load("@bazel_skylib//lib:selects.bzl", "selects")
load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
    "envoy_cc_library",
    "envoy_cc_contrib_extension",
    "envoy_contrib_package",
)

load("//bazel/wasm:wasm.bzl", "envoy_wasm_cc_binary")
load("//bazel:envoy_internal.bzl","envoy_external_dep_path")

licenses(["notice"])  # Apache 2

envoy_package()

selects.config_setting_group(
    name = "include_wasm_config",
    match_all = [
        "//bazel:x86",
        "//bazel:wasm_v8",
    ],
)

filegroup(
    name = "configs",
    srcs = glob([
        "**/*.wasm",
    ]) + select({
        ":include_wasm_config": glob(
            [
                "**/*.yaml",
            ],
            exclude = [
                "**/*docker-compose*.yaml",
            ],
        ),
        "//conditions:default": [],
    }),
)

envoy_cc_library(
    name = "nlohmann_json_lib",
    external_deps = [
        "json",
    ],
)

envoy_wasm_cc_binary(
    name = "envoy_filter_http_basic_auth.wasm",
    srcs = [ "envoy_filter_http_basic_auth.cc", ],
    deps = [
        envoy_external_dep_path("json"),
        "@com_google_absl//absl/strings",
    ],
)


filegroup(
    name = "files",
    srcs = glob(["**/*"]),
)
