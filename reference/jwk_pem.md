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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnukdsUFO7ooqktK4Flya
#> IsYNh+u1rxWJh5XCTNs34Pl4Nkyz+bSKu14xwv2+1Y0QAEA1ddtRuc3xBgPs7koA
#> W7Mz9tyED4cd14RDRX27/PNUl2+MPKFZ8TIyQR5jqtFcGrmuqRqUK2QFCy3eYwhH
#> jEY3X4OlVQniPWrvSY9ueDAOzL29KnqONaD5KvqdWi5eGQn4uu08RmN+7u7yYACG
#> nzsQny8C5eIjTXWVId19ncaHUJA52jKwxSqnyd0s9Z5xIlaa7kN1l9MzBUkewf1t
#> 14n1dbZrzO6h3kZtA6eeXAqRMAnxXsvKtTDgXVKTRgFRisfOZB4TeMGmDPb71UVz
#> 5wIDAQAB
#> -----END PUBLIC KEY-----
```
