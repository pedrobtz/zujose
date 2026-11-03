# Write a key as PEM

`jose_pem()` writes an RSA, EC or X25519 key as PEM: the public key as
SubjectPublicKeyInfo (`PUBLIC KEY`), or with `private = TRUE` the
private key as PKCS#8 (`PRIVATE KEY`), byte for byte as OpenSSL writes
them.

## Usage

``` r
jose_pem(key, private = FALSE)
```

## Arguments

- key:

  An RSA, EC or X25519 `jose_key`.

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

[`as_jose_key()`](https://pedrobtz.github.io/zujose/reference/as_jose_key.md),
which reads PEM.

## Examples

``` r
key <- jose_key_generate("RSA")
cat(jose_pem(key))
#> -----BEGIN PUBLIC KEY-----
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhTw/DQjA5XwQ/RqKETl
#> EfKrqiLQgDvu0vB0GKIhPLvWhnewjW7OALX1iNjaaHIr4Rj2cFqfvApzVKfFJMtX
#> CdSbhCJjJn5UYOVYlCmIim3xlbRiUfiAWqrmp9hwjMoyDP76iXn386BDDfZwvrSQ
#> rZxi/CA8Js5qt7DN0ZeXIUKU4u3P0AKWgiLz1mSmM8OdZniB2vZ426F0i9rcdN3b
#> b5Kn38ncWBhrYG0IW1m6fjV56Vv7No344tIFp0q4bJDYwmDt7M1C+GTjAGTFwKDd
#> 8LaaL6t/stZteMEYwIhsRfQ7A1WtGYm6DyEh+cIiyjLrTSjRUdNvr/i36Utjqewv
#> /wIDAQAB
#> -----END PUBLIC KEY-----
```
