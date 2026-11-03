# Write a key or key set as JSON

`jwk_json()` writes a `jwk` as a JWK, or a `jwk_set` as a JWK Set, in
compact JSON. By default only public members are written, so the result
is safe to publish; a symmetric (`oct`) key has no public part, and is
refused alone or dropped from a set.

## Usage

``` r
jwk_json(x, private = FALSE)
```

## Arguments

- x:

  A `jwk` or `jwk_set`.

- private:

  Whether to write private members, including the secrets of `oct` keys.

## Value

A single string.

## Examples

``` r
key <- jwk_oct(as.raw(1:32), alg = "HS256", kid = "k1")
jwk_json(key, private = TRUE)
#> [1] "{\"kty\":\"oct\",\"k\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA\",\"kid\":\"k1\",\"alg\":\"HS256\"}"
```
