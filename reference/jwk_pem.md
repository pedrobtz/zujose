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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtFpDKuBiDy9Lxx6bUNNy
#> ezX/qBvIs+qJQQcRoL0vEYhmuEanynsXBNFhi4nDk3KWZ8vIhYRoJ+33103pszhZ
#> DDU0gc69B8iTOIxgPzL7KmkLg1jzqpYfTj5IN4FWSIZXegT42KaXrh4upXgpDz9I
#> Rf7tgCWtxnUbf4e4RIQP2YWGXFwSJ+SgYmp0c0p3kwQvot5eir069fu8Td9ZspwR
#> R8YpBeioGK9uLYjeWisp5qHR0VRlq67RODhyC3GxOH6SNhO4AOw/U68NtOw2mUbz
#> 5flqROso5HG8bCPxn644wd03XN+Iv2cSL3WhexrPWGpTjeV7Ituf/KBl+YC2XRJL
#> pwIDAQAB
#> -----END PUBLIC KEY-----
```
