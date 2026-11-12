# Read a JSON Web Key

`as_jwk()` reads a JWK (RFC 7517) from its JSON text or from a list
already parsed. A raw vector is taken as an `oct` secret, as by
[`jwk_oct()`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md).

## Usage

``` r
as_jwk(x, ...)
```

## Arguments

- x:

  JWK text, a parsed JWK as a named list, a raw secret, or a `jwk`.

- ...:

  Not used.

## Value

A `jwk`.

## Details

`RSA` keys need `n` and `e`, and for a private key all of `d`, `p`, `q`,
`dp`, `dq` and `qi`; they are checked when read. A PEM string holding an
RSA key, in PKCS#1, PKCS#8 or SubjectPublicKeyInfo, is read too.

`EC` keys on P-256, P-384 and P-521 and `OKP` keys on X25519 are checked
when read: the point must be on its curve. PEM holding an EC or X25519
key is read too. Other `OKP` keys, such as Ed25519, are read and kept so
that they can be listed, selected and thumbprinted, but cannot be used.

## Secrets in memory

zujose is pure R, and so are its keys: an `oct` secret, and the private
members of an RSA, EC or X25519 key, are ordinary R vectors. R copies
vectors freely and has no way to wipe one, so a secret may stay in
memory after the key is gone, and may reach a saved workspace or a core
dump. zujose never prints secret members and never puts them in an error
message, but it cannot do more than that. Keep long-lived secrets out of
saved workspaces (`.RData`) and load them from a secret store when they
are needed.

## Examples

``` r
key <- as_jwk(paste0(
  '{"kty":"oct","kid":"k1","alg":"HS256",',
  '"k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}'
))
key
#> <jwk> oct, 256 bits
#>   kid "k1"
#>   alg HS256
#>   private: yes (not shown)
```
