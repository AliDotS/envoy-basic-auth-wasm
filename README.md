# Envoy Basic Authentication Plugin
This plugin works when envoy is used as a reverse proxy and as a dynamic forward proxy.</br>
For reverse proxy, auth_header should be set to "authorization" and for dynamic forward proxy, auth_header should be set to "proxy-authorization".</br>
On startup, it will base64 encode the credentials in a hash map and on every request the auth_header existence in the hash map will be checked.</br>

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
              "credentials": ["user1:pass1", "user2:pass2"],
              "auth_header": "proxy-authorization"
            }
        vm_config:
          vm_id: "basic_auth"
          code:
            local:
              filename: "./envoy_filter_http_basic_auth.wasm"
```

To configure it, a valid JSON should be provided having "credentials" and "auth_header" keys in it's root.</br>
`"credentials"` is an array. Each element of the array should be in the form of "user:pass". The static string "Basic " will be added to the begining of base64 encoded elements in the array.</br>
`"auth_header"` is a string. It's value is the header that will be checked for authorization.