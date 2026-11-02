# The public part of a key or key set

`jose_public()` removes private members: `d`, `p`, `q`, `dp`, `dq`, `qi`
and `oth`. A symmetric (`oct`) key is entirely secret, so it is an error
alone and dropped from a key set.

## Usage

``` r
jose_public(x)
```

## Arguments

- x:

  A `jose_key` or `jose_keyset`.

## Value

An object of the same class.

## Examples

``` r
set <- as_jose_keyset('{"keys":[{"kty":"oct","k":"AAAA"}]}')
length(jose_public(set))
#> [1] 0
```
