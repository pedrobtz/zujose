# Read a JSON Web Key

`as_jose_key()` reads a JWK (RFC 7517) from its JSON text or from a list
already parsed. A raw vector is taken as an `oct` secret, as by
[`jose_key_oct()`](https://pedrobtz.github.io/zujwt/reference/jose_key_oct.md).

## Usage

``` r
as_jose_key(x, ...)
```

## Arguments

- x:

  JWK text, a parsed JWK as a named list, a raw secret, or a `jose_key`.

- ...:

  Not used.

## Value

A `jose_key`.

## Details

`RSA` keys need `n` and `e`, and for a private key all of `d`, `p`, `q`,
`dp`, `dq` and `qi`; they are checked when read. A PEM string holding an
RSA key, in PKCS#1, PKCS#8 or SubjectPublicKeyInfo, is read too.

`EC` keys on P-256, P-384 and P-521 and `OKP` keys on X25519 are checked
when read: the point must be on its curve. PEM holding an EC or X25519
key is read too. Other `OKP` keys, such as Ed25519, are read and kept so
that they can be listed, selected and thumbprinted, but cannot be used.

## Examples

``` r
key <- as_jose_key(
  '{"kty":"oct","kid":"k1","alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}'
)
key
#> <jose_key> oct, 256 bits
#>   kid "k1"
#>   alg HS256
#>   private: yes (not shown)
```
