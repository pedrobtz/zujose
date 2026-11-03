# Algorithms available in this installation

`zujwt_info()` lists every JOSE algorithm zujwt knows and whether it can
be used here. An algorithm is available when this version of zujwt
implements it and the installed zucrypt provides what it needs: zucrypt
is the version in the `zucrypt` column or later, or already exports the
functions that version adds. Using one that is not raises
`zujwt_unsupported_error`.

## Usage

``` r
zujwt_info()
```

## Value

A data frame with columns `algorithm`, `kind` (`"signature"`,
`"key management"` or `"content encryption"`), `available`, and
`zucrypt`, the zucrypt version the algorithm needs.

## Examples

``` r
info <- zujwt_info()
info[info$available, ]
#>             algorithm               kind available zucrypt
#> 1               HS256          signature      TRUE   0.1.0
#> 2               HS384          signature      TRUE   0.1.0
#> 3               HS512          signature      TRUE   0.1.0
#> 13                dir     key management      TRUE   0.1.0
#> 14             A128KW     key management      TRUE   0.1.0
#> 15             A192KW     key management      TRUE   0.1.0
#> 16             A256KW     key management      TRUE   0.1.0
#> 17          A128GCMKW     key management      TRUE   0.3.0
#> 18          A192GCMKW     key management      TRUE   0.3.0
#> 19          A256GCMKW     key management      TRUE   0.3.0
#> 20 PBES2-HS256+A128KW     key management      TRUE   0.3.0
#> 21 PBES2-HS384+A192KW     key management      TRUE   0.3.0
#> 22 PBES2-HS512+A256KW     key management      TRUE   0.3.0
#> 30      A128CBC-HS256 content encryption      TRUE   0.1.0
#> 31      A192CBC-HS384 content encryption      TRUE   0.1.0
#> 32      A256CBC-HS512 content encryption      TRUE   0.1.0
#> 33            A128GCM content encryption      TRUE   0.3.0
#> 34            A192GCM content encryption      TRUE   0.3.0
#> 35            A256GCM content encryption      TRUE   0.3.0
```
