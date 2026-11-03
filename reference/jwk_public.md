# The public part of a key or key set

`jwk_public()` removes private members: `d`, `p`, `q`, `dp`, `dq`, `qi`
and `oth`. A symmetric (`oct`) key is entirely secret, so it is an error
alone and dropped from a key set.

## Usage

``` r
jwk_public(x)
```

## Arguments

- x:

  A `jwk` or `jwk_set`.

## Value

An object of the same class.

## Examples

``` r
set <- as_jwk_set('{"keys":[{"kty":"oct","k":"AAAA"}]}')
length(jwk_public(set))
#> [1] 0
```
