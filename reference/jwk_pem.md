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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwFeFCj0VLBSFRMTDqDm+
#> PdVpMQPjXJq4c0Evj5zcR0kaJYz3srIBIZlc3s76J3I8BvX4y4EC8YoRVisdbcFK
#> aoREbCvfHG8WelU1jR/j2U+ngvMU1too7JjL0wepqNiwJtcqK3kT1AWeks4FuzFm
#> jy/b8FytQM6k0teFv2Bz8xPEGYm6ZOrS8fT4H/4oGhBpoC/3+2UfygOTMEMhIpVd
#> VZwUb5+uRSp4SNMn9PjxSDwjalkhAetWQqI5rdKqMB9B2gHYPraF3rPm/i67ie5F
#> aUbUW0nUZOynlAOuduxj+65na86ifo7igpAcehj2Jf3MQHevoEvZmmsYa4cw9qby
#> kQIDAQAB
#> -----END PUBLIC KEY-----
```
