# Set a key's identifier

`jwk_with_kid()` sets `kid`, by default to the key's RFC 7638
thumbprint, which is stable and needs no registry.

## Usage

``` r
jwk_with_kid(key, kid = jwk_thumbprint(key))
```

## Arguments

- key:

  A `jwk`.

- kid:

  The identifier.

## Value

The key, with `kid` set.

## Examples

``` r
key <- jwk_with_kid(jwk_oct(as.raw(1:32)))
key$kid
#> [1] "f7NOASX-o7koLb0W4ErF0hSMzu1Fp3joD078YB3yAyY"
```
