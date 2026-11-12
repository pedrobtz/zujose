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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqOH0PuKkqCooPoGLBt9g
#> kpYaRPyS+Sogpk3ETRAxx/SulPwYVR++xY5fsz/JLbnFRVvwoyeWiMhzfE+Rm6XP
#> 8xPKuhJv9Zs8175U78s4sSrOUDVcoCZPB3DxLPXoM+g1cdwxGwm81DyJ0Wt/sdnJ
#> PXn7y5ng4AExixdzVF8EF8amohIo3qjihxBrKzWQljFpTi2TocpZrIDM+uQe0xAB
#> 8wHsMKx9Qg4XoxxhgxGxwQsyxAxGTgF5ENGW/QasTFMnb7gKiHnKptsXlUq8Lrqd
#> 0fWCzW6hHrMKb1v2W3Ls+GGTVLFIQqh8MgnuujU+s9g2SQuIcHLtXKV7KneemyTb
#> wQIDAQAB
#> -----END PUBLIC KEY-----
```
