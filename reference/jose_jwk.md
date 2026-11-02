# Write a key or key set as JSON

`jose_jwk()` writes a `jose_key` as a JWK, or a `jose_keyset` as a JWK
Set, in compact JSON. By default only public members are written, so the
result is safe to publish; a symmetric (`oct`) key has no public part,
and is refused alone or dropped from a set.

## Usage

``` r
jose_jwk(x, private = FALSE)
```

## Arguments

- x:

  A `jose_key` or `jose_keyset`.

- private:

  Whether to write private members, including the secrets of `oct` keys.

## Value

A single string.

## Examples

``` r
key <- jose_key_oct(as.raw(1:32), alg = "HS256", kid = "k1")
jose_jwk(key, private = TRUE)
#> [1] "{\"kty\":\"oct\",\"k\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA\",\"kid\":\"k1\",\"alg\":\"HS256\"}"
```
