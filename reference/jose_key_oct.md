# Make a symmetric key

`jose_key_oct()` wraps a secret as a JSON Web Key of type `oct` (RFC
7518 section 6.4), the key type of the `HS*`, `A*KW`, `A*GCMKW` and
`dir` algorithms.

## Usage

``` r
jose_key_oct(secret, alg = NULL, kid = NULL, use = NULL, key_ops = NULL)
```

## Arguments

- secret:

  The key, as a raw vector of at least one byte.

- alg:

  The one algorithm the key is meant for, such as `"HS256"`, or `NULL`.
  When set, a token whose `alg` differs is refused.

- kid:

  A key identifier, or `NULL`. See
  [`jose_with_kid()`](https://pedrobtz.github.io/zujose/reference/jose_with_kid.md).

- use:

  `"sig"` or `"enc"`, or `NULL`.

- key_ops:

  The operations the key may be used for, from `"sign"`, `"verify"`,
  `"encrypt"`, `"decrypt"`, `"wrapKey"`, `"unwrapKey"`, `"deriveKey"`
  and `"deriveBits"`, or `NULL`.

## Value

A `jose_key`.

## Details

The secret is a raw vector, never a string: a key is bytes, and a
password is not a key. Secrets live in ordinary R memory, which R can
copy and cannot reliably wipe; keep long-lived secrets out of saved
workspaces.

## See also

[`as_jose_key()`](https://pedrobtz.github.io/zujose/reference/as_jose_key.md)
to read a JWK,
[`jose_jwk()`](https://pedrobtz.github.io/zujose/reference/jose_jwk.md)
to write one.

## Examples

``` r
key <- jose_key_oct(as.raw(1:32), alg = "HS256", kid = "k1")
key
#> <jose_key> oct, 256 bits
#>   kid "k1"
#>   alg HS256
#>   private: yes (not shown)
```
