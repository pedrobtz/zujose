# One recipient of a multi-recipient JWE

`jwe_recipient()` pairs a key with its key management algorithm and
per-recipient header, for
[`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md)
to produce a general JSON serialization with several recipients.

## Usage

``` r
jwe_recipient(key, alg = NULL, header = NULL)
```

## Arguments

- key:

  A `jwk`.

- alg:

  The key management algorithm, or `NULL` for the key's own.

- header:

  Per-recipient unprotected header members, as a named list.

## Value

A `jwe_recipient`.

## Examples

``` r
jwe_recipient(jwk_oct(as.raw(1:16)), "A128KW")
#> $key
#> <jwk> oct, 128 bits
#>   private: yes (not shown)
#> 
#> $alg
#> [1] "A128KW"
#> 
#> $header
#> named list()
#> 
#> attr(,"class")
#> [1] "jwe_recipient"
```
