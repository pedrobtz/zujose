# Algorithms available in this installation

`zujose_info()` lists every JOSE algorithm zujose knows and whether it
can be used here. An algorithm is available when this version of zujose
implements it and the installed zucrypt provides what it needs: zucrypt
is the version in the `zucrypt` column or later, or already exports the
functions that version adds. Using one that is not raises
`zujose_unsupported_error`.

## Usage

``` r
zujose_info()
```

## Value

A data frame with columns `algorithm`, `kind` (`"signature"`,
`"key management"` or `"content encryption"`), `available`, and
`zucrypt`, the zucrypt version the algorithm needs.

## Examples

``` r
info <- zujose_info()
info[info$available, ]
#>             algorithm               kind available zucrypt
#> 1               HS256          signature      TRUE   0.1.1
#> 2               HS384          signature      TRUE   0.1.1
#> 3               HS512          signature      TRUE   0.1.1
#> 4               RS256          signature      TRUE   0.1.1
#> 5               RS384          signature      TRUE   0.1.1
#> 6               RS512          signature      TRUE   0.1.1
#> 7               PS256          signature      TRUE   0.1.1
#> 8               PS384          signature      TRUE   0.1.1
#> 9               PS512          signature      TRUE   0.1.1
#> 10              ES256          signature      TRUE   0.1.1
#> 11              ES384          signature      TRUE   0.1.1
#> 12              ES512          signature      TRUE   0.1.1
#> 13                dir     key management      TRUE   0.1.1
#> 14             A128KW     key management      TRUE   0.1.1
#> 15             A192KW     key management      TRUE   0.1.1
#> 16             A256KW     key management      TRUE   0.1.1
#> 17          A128GCMKW     key management      TRUE   0.1.1
#> 18          A192GCMKW     key management      TRUE   0.1.1
#> 19          A256GCMKW     key management      TRUE   0.1.1
#> 20 PBES2-HS256+A128KW     key management      TRUE   0.1.1
#> 21 PBES2-HS384+A192KW     key management      TRUE   0.1.1
#> 22 PBES2-HS512+A256KW     key management      TRUE   0.1.1
#> 23           RSA-OAEP     key management      TRUE   0.1.1
#> 24       RSA-OAEP-256     key management      TRUE   0.1.1
#> 25             RSA1_5     key management      TRUE   0.1.1
#> 26            ECDH-ES     key management      TRUE   0.1.1
#> 27     ECDH-ES+A128KW     key management      TRUE   0.1.1
#> 28     ECDH-ES+A192KW     key management      TRUE   0.1.1
#> 29     ECDH-ES+A256KW     key management      TRUE   0.1.1
#> 30      A128CBC-HS256 content encryption      TRUE   0.1.1
#> 31      A192CBC-HS384 content encryption      TRUE   0.1.1
#> 32      A256CBC-HS512 content encryption      TRUE   0.1.1
#> 33            A128GCM content encryption      TRUE   0.1.1
#> 34            A192GCM content encryption      TRUE   0.1.1
#> 35            A256GCM content encryption      TRUE   0.1.1
```
