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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz+Nha2G9UGC/8DnZFmgN
#> BtPY6RiJqwi39yDs8XjDrR7GDy9oaFUm5jUHez7Q/GJ/IuKaE/SFdk/MVo2dAAEl
#> hF0m/ZsrOpIgRxheC0ZrtAotDqR+yH5e8+FPKRGtvdPdDnDv7sCg67MZstSePegX
#> Si8yw7I+2U3bEld3cYjjLk2QT+PjLndMN84JngQ70FQKREmsasd50mxIcyMATegZ
#> Hxr+fj/uHVLVpwh2WT4EJd7pPEtvIkiDQVVEso9/MeKqaBxL6APR/chKXVcYcDO6
#> KNVl2VEy8YahvPOdKjczZnwR7JkQwJ8+H/3OoF4+FlHHzIFMsawmo37liGLMzTZD
#> pQIDAQAB
#> -----END PUBLIC KEY-----
```
