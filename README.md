# Envoy Basic Authentication Plugin
This plugin works when envoy is used as a dynamic forward proxy.

### Sample http filter config:
```
http_filters:
  - name: envoy.filters.http.wasm
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
      config:
        name: "basic_auth_plugin"
        root_id: "basic_auth"
        configuration:
          "@type": "type.googleapis.com/google.protobuf.StringValue"
          value: |
            {
              "credentials": ["user1:pass1", "user2:pass2"]
            }
        vm_config:
          vm_id: "basic_auth"
          code:
            local:
              filename: "./envoy_filter_http_basic_auth.wasm"
```

To configure it, a valid JSON should be provided having "credentials" key in it's root and an array of strings as it's values. </br>
Each element of the array should be in the form of "user:pass".