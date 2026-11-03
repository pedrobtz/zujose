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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr3tr5gOUBzl9Py+M3sCB
#> nQFy2mOCQNGtZCLzw4mTTmAephOtZXJ6X+6BPtW5DjwXneORe2+5mXJPLU877AtH
#> 842bWhxm8Emv/FbUsmS748Hg8J4JrQwKsPehdNdyFeq0XeMIObyxvx9ekqW8iklM
#> SHKe7dJyBciBvXoDW4yvATtAG5LialB7kL6EJfeK8mRZD437mtCNo6YSoJKqoQJN
#> AavbZZr3xneNw9EdSLbg0IqyW+syrZAEM+iNCnVPgGlSKje7J16OAsnVvfDivWpe
#> LpPHrVxOOdMRpDD17y/wxtulygV/PXoaetxw+FgVrMDWIMS+oOJmDfd9m+BYdDS8
#> FQIDAQAB
#> -----END PUBLIC KEY-----
```
