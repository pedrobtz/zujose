# JWK thumbprint

`jose_thumbprint()` computes a key's RFC 7638 thumbprint: the hash of
its required members, in lexicographic order, as JSON without
whitespace. With `uri = TRUE` it returns the RFC 9278 thumbprint URI.

## Usage

``` r
jose_thumbprint(key, hash = "sha256", uri = FALSE)
```

## Arguments

- key:

  A `jose_key`.

- hash:

  `"sha256"`, `"sha384"` or `"sha512"`.

- uri:

  Whether to return a `urn:ietf:params:oauth:jwk-thumbprint` URI rather
  than the bare Base64url value.

## Value

A single string.

## Details

The thumbprint of a private key equals that of its public key, since
private members are never part of it. It is a common `kid`; see
[`jose_with_kid()`](https://pedrobtz.github.io/zujwt/reference/jose_with_kid.md).

## Examples

``` r
key <- jose_key_oct(as.raw(1:32))
jose_thumbprint(key)
#> [1] "f7NOASX-o7koLb0W4ErF0hSMzu1Fp3joD078YB3yAyY"
jose_thumbprint(key, uri = TRUE)
#> [1] "urn:ietf:params:oauth:jwk-thumbprint:sha-256:f7NOASX-o7koLb0W4ErF0hSMzu1Fp3joD078YB3yAyY"
```
