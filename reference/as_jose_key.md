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

Keys of type `RSA`, `EC` and `OKP` are read and kept, so they can be
listed, selected, written and thumbprinted, but using one before zujwt
supports it raises `zujwt_unsupported_error`.

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
