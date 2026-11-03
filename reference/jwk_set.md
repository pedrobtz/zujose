# Key sets

A `jwk_set` holds several keys, as a JWK Set does (RFC 7517 section 5).
Select one by `kid` with `[[`, or several with `[`; combine with
[`c()`](https://rdrr.io/r/base/c.html) or `jwk_set()`.

## Usage

``` r
jwk_set(...)

as_jwk_set(x)
```

## Arguments

- ...:

  `jwk` and `jwk_set` objects, combined in order.

- x:

  JWK Set text, a parsed JWK Set, or a `jwk_set`.

## Value

A `jwk_set`.

## Details

`as_jwk_set()` reads a JWK Set from its JSON text or from a parsed list.
Following RFC 7517 section 5, a member of `keys` that is not a
well-formed JWK is ignored rather than failing the whole set, as is a
key of a type zujose does not know. A key of a known type that zujose
cannot use, such as an Ed25519 `OKP` key, is kept: it can be listed,
selected and thumbprinted, and using it raises
`zujose_unsupported_error`.

## Examples

``` r
set <- jwk_set(
  jwk_oct(as.raw(1:32), kid = "a"),
  jwk_oct(as.raw(33:64), kid = "b")
)
set[["b"]]
#> <jwk> oct, 256 bits
#>   kid "b"
#>   private: yes (not shown)
length(set)
#> [1] 2
```
