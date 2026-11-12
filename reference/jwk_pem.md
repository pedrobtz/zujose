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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzMUCheZ8D3/1XY5GM+dT
#> fFuLiSpotTEHYf4czbm7sOL+2VFxpjU8gFR9c0dBI+9lmPSQEo0H5QsK31YahKIr
#> d4dbz3t1kDYUSPQoYAXkVRkzAHbeZRifF8nt+fdj0uBckU16Mqm0Y19aSUJ262iz
#> neT4sTnzp8dZ01RkcxGcPegQFOBiL0qIQpsqCsXaT5pt1KobAnOhaZiI1zPcVftY
#> vCL1frA+dQcF1TeL3vM5Srj1Gl0P7h1cMdxxsA4rxUljZ5o5ufB4LULX+CLSKpYM
#> /gOezfSxmIn7b32yNlOLEoEiUVlNM/RZvJGMxNHe/L52NrhfesbjIn5/lRlxGqsO
#> BwIDAQAB
#> -----END PUBLIC KEY-----
```
