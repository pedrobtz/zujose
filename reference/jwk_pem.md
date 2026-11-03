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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwDwKPNyTyM84l1OCIJYp
#> T9dYa/LrFlTLICTK+ctgpMBiyAJKZOZKkbeKjvMBRN+b8tl9yl8WVbu+Iu8TD/xE
#> iSxLUeM7gXSKQ8SnTvVxSpb3Bu0JG7MXZyo2P81vHQxGFYrLTc8kEZ1wXSrtRH+C
#> f5MQ2INFnt+vgZwz7yjE8ShylrgWZb0liBRrkxG1Zy5yulmcM+Ya+48E9idovHXI
#> c/W3tBS/x88u/Oi7DR+lFirQBYmbwGCa2bRZ+ZFT7/v2kGWJgNy6/fqLMdglws8j
#> FOpIV+K131gDMk3IKD977WtvthqpsgKh26j8b8nlbR8Z2rPoYd7I5tF9is5LC1du
#> 4wIDAQAB
#> -----END PUBLIC KEY-----
```
