# Algorithms available in this installation

`zujwt_info()` lists every JOSE algorithm zujwt knows and whether it can
be used here. An algorithm is available when this version of zujwt
implements it and the installed zucrypt is recent enough. Using one that
is not raises `zujwt_unsupported_error`.

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
#>   algorithm      kind available zucrypt
#> 1     HS256 signature      TRUE   0.1.0
#> 2     HS384 signature      TRUE   0.1.0
#> 3     HS512 signature      TRUE   0.1.0
```
