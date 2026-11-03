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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLGtZCXG7pUkR7i2ndWZ
#> dqg1blxk3RqrLoJd/hjY8PBCyuGHcerlpdA9Iv8LrF5884Hg+GonZva/6SG96DNJ
#> 9JrCReL4FOUZsZAtZ2hjuoQMRX51di76jkE/xvIgzPcPRfkaFPT9Sc5OYkQ+0e4M
#> cuiI1557UUpzWDrPdUmI9u+NQy4TbZ0dDC66C5n1x2bC9uWcf0G1tbYI13X3+8vZ
#> D7C4nILntA3u7mlL9PTWAEmyXsHLbkki7jD6Nd5c1fEKuju+741CPdbBHqMAPJ8O
#> QNWnQ7M6ICzJVRNzFd00Gxf3Dmz4VHhUnNIW630XHbmB/5e+nu8n/PEQQ73Phjit
#> VwIDAQAB
#> -----END PUBLIC KEY-----
```
