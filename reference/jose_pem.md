# Write an RSA key as PEM

`jose_pem()` writes an RSA key as PEM: the public key as
SubjectPublicKeyInfo (`PUBLIC KEY`), or with `private = TRUE` the
private key as PKCS#8 (`PRIVATE KEY`), byte for byte as the openssl
package writes them.

## Usage

``` r
jose_pem(key, private = FALSE)
```

## Arguments

- key:

  An RSA `jose_key`.

- private:

  Whether to write the private key.

## Value

A single string.

## See also

[`as_jose_key()`](https://pedrobtz.github.io/zujwt/reference/as_jose_key.md),
which reads PEM.

## Examples

``` r
key <- jose_key_generate("RSA")
cat(jose_pem(key))
#> -----BEGIN PUBLIC KEY-----
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsfwjyZLNYXaJ6voljIA4
#> SdqVi8Ybj6CFX6eTPWzgNhMuI81ZRaA+PhpR4/nDNX+gArdMImivIhHL/D2JO34a
#> /3vsyi9zp8R6B2tz6sn77EQ0E6R74BhPDRqXAUmYCdKGeFHybelCDl0NZ8ZT7AN2
#> V5ayoHmxMQXqqUdGaZDRpkzEX6X6qmoIxfcL/FLpB7JQBRzf1UJUuxHC1ECFLqY7
#> RNG9kmX0Y/djuk4TGmHJJTlckgjzEGmMxax2zgYW2oCueBf6AaEtZXvF2occi/he
#> wtgpJ2Ltr6k2GN7adv+0vVdIhm0xqE8NC9VCxRWlZUop3/uMttb/ugDvCOH7atjn
#> 4QIDAQAB
#> -----END PUBLIC KEY-----
```
