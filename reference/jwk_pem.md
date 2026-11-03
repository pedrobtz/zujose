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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7wMqUJO+9UrlJ4IZWBQm
#> +mIbafQgbXAJwusnW+ogjmZ9dtVffI4J+L76y1vo/7a/4OxEvPlucUNSpTU5LpEB
#> y9QngW5ZbBl89QGpret9URi9CqIe9ut/uwOFaR4HHwkkQwULy0lctnRHaZ/DGQtR
#> uNM4Ie1Z7Pv8ZrGm0fAFcNeK+ZUlWlabKrhHfkw11nZit3cC+ktVBaNTG1ShrW3Z
#> GqmeXyoHpvNKC/Z4UEODvk8hQ+bGuffj/T/54c7JFUhUBXRcoHvkfBxrH6PpVkpr
#> y0VstGu1k2t+0kZimnSvNQrG5uyXeKve2w2O9F/C2RJ7vq376CFJ6cygvtrnX9a3
#> dQIDAQAB
#> -----END PUBLIC KEY-----
```
