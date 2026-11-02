# One recipient of a multi-recipient JWE

`jose_recipient()` pairs a key with its key management algorithm and
per-recipient header, for
[`jose_encrypt()`](https://pedrobtz.github.io/zujwt/reference/jose_encrypt.md)
to produce a general JSON serialization with several recipients.

## Usage

``` r
jose_recipient(key, alg = NULL, header = NULL)
```

## Arguments

- key:

  A `jose_key`.

- alg:

  The key management algorithm, or `NULL` for the key's own.

- header:

  Per-recipient unprotected header members, as a named list.

## Value

A `jose_recipient`.

## Examples

``` r
jose_recipient(jose_key_oct(as.raw(1:16)), "A128KW")
#> $key
#> <jose_key> oct, 128 bits
#>   private: yes (not shown)
#> 
#> $alg
#> [1] "A128KW"
#> 
#> $header
#> named list()
#> 
#> attr(,"class")
#> [1] "jose_recipient"
```
