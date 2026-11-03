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
password is not a key.

## Secrets in memory

zujose is pure R, and so are its keys: an `oct` secret, and the private
members of an RSA, EC or X25519 key, are ordinary R vectors. R copies
vectors freely and has no way to wipe one, so a secret may stay in
memory after the key is gone, and may reach a saved workspace or a core
dump. zujose never prints secret members and never puts them in an error
message, but it cannot do more than that. Keep long-lived secrets out of
saved workspaces (`.RData`) and load them from a secret store when they
are needed.

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
