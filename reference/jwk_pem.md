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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvcDKNeusFgs2J/iO853
#> hXA+PkIki8hUFI58W3d4s2YeGtjRLGr36YS2paJ64RuzCwXGf5DKf1exT8UmXYcY
#> qJMpa4RiQh4rb/xdecGrgswvxkCbPqrQiB5fADp5MlkAHzQxfam3M+2C+5k92FGu
#> FIpNDtbHGaVysqg57yjD/5NviHaRh1brUxffJqkKJ7yCmb0DFEsPWXzklzYvh1y7
#> Goalpk51nFaNJkFWHlHTZuVtOCDrI7ZVE4wGzGrp+L1rbju9mR5apG9jamKdvWK6
#> QeKCZvuhxh4bZDDXz6FHSMEBjClSEV6zaE+wOOVkV3aTEYn17UILUKS5AwZ1IYWd
#> kwIDAQAB
#> -----END PUBLIC KEY-----
```
