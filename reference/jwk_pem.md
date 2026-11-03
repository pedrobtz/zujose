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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7e5iCU4qY+2E7QBLX3zq
#> 7ENcoVQkYnoYwheH1drgvt9DR9UW4JvCTuR5Cty5aHgv6PJ2nmtNP6RfRSKRd+bi
#> /LqvJ2lXzpi0O2VrbvVRr0IK3VnV2Q0PVQIH3Yh5HqmyG1RUbxM8Uvk9OmK52kld
#> AB7iQXNZYmkoMUWOacAWEufHFzSRtfgNBeJRcxKOpaJLqEq7QJECEe3vdjNGrmPE
#> L1xheE4kF4ZNE7ywRwtYWoLW9UnKikKywqm0piZB4HghuGRilPJC2hQIhb/z8il5
#> N/2GPKNz4irCpE2sLVaT7pkxqJju4jjMHkFLeoBuN6gbKbVznHDCjgwAypv+xAeK
#> KwIDAQAB
#> -----END PUBLIC KEY-----
```
