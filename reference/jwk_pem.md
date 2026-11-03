# Write a key as PEM

`jwk_pem()` writes an RSA, EC or X25519 key as PEM: the public key as
SubjectPublicKeyInfo (`PUBLIC KEY`), or with `private = TRUE` the
private key as PKCS#8 (`PRIVATE KEY`), byte for byte as OpenSSL writes
them.

## Usage

``` r
jwk_pem(key, private = FALSE)
```

## Arguments

- key:

  An RSA, EC or X25519 `jwk`.

- private:

  Whether to write the private key.

## Value

A single string.

## Secrets in memory

zujose is pure R, and so are its keys: an `oct` secret, and the private
members of an RSA, EC or X25519 key, are ordinary R vectors. R copies
vectors freely and has no way to wipe one, so a secret may stay in
memory after the key is gone, and may reach a saved workspace or a core
dump. zujose never prints secret members and never puts them in an error
message, but it cannot do more than that. Keep long-lived secrets out of
saved workspaces (`.RData`) and load them from a secret store when they
are needed.

## See also

[`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md),
which reads PEM.

## Examples

``` r
key <- jwk_generate("RSA")
cat(jwk_pem(key))
#> -----BEGIN PUBLIC KEY-----
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsX6WXo8BVRkS3iFNuull
#> gAV6PhwEMVoG3M+Yexhj3r3vUEfiZsBOXIIWgsCC1EqG406Bavi/8UC9/NVK+H9x
#> fEcFKXVDu64fB6VIE4NqPcDO7vJZ+9BOPphujhtwrexr4jCi3P9gdHf+2KqYSxMo
#> JkbB3EWMrooBO9fx9YMMzdD3VZF3/NOETbQ4YmDhkzThi6GHnE6Y0YUYeMqliDjL
#> 4urBRWwosQF470PzgjE27aDo2hE8L6ws/4zI2o5mHxl2rxXtvdL0aGcEjCzCUKUr
#> t53Icx3mhSLwEUn/25FxlEjyUoQd4pEbWqwol7Rcf4F+XYrZP8qiHbPL4tilyjz0
#> RQIDAQAB
#> -----END PUBLIC KEY-----
```
