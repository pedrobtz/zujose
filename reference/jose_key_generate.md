# Generate a random key

`jose_key_generate()` makes a new key from the operating system's
cryptographic random source, through zucrypt. Only `oct` keys can be
generated in this version. `RSA`, `EC` and `OKP` keys raise
`zujwt_unsupported_error`, naming the zucrypt version that will add
them.

## Usage

``` r
jose_key_generate(
  kty,
  size = NULL,
  crv = NULL,
  alg = NULL,
  kid = NULL,
  use = NULL,
  key_ops = NULL
)
```

## Arguments

- kty:

  The key type: `"oct"`, `"RSA"`, `"EC"` or `"OKP"`.

- size:

  The key size in bits, a multiple of 8 and at least 128. For an `oct`
  key, `NULL` takes the size `alg` needs.

- crv:

  The curve of an `EC` or `OKP` key. Not used for `oct`.

- alg:

  The one algorithm the key is meant for, such as `"HS256"`, or `NULL`.
  When set, a token whose `alg` differs is refused.

- kid:

  A key identifier, or `NULL`. See
  [`jose_with_kid()`](https://pedrobtz.github.io/zujwt/reference/jose_with_kid.md).

- use:

  `"sig"` or `"enc"`, or `NULL`.

- key_ops:

  The operations the key may be used for, from `"sign"`, `"verify"`,
  `"encrypt"`, `"decrypt"`, `"wrapKey"`, `"unwrapKey"`, `"deriveKey"`
  and `"deriveBits"`, or `NULL`.

## Value

A `jose_key`.

## Details

Without `size`, an `oct` key is as long as `alg` needs: the hash size
for `HS256`, `HS384` and `HS512` (RFC 7518 section 3.2), the key size
for `A*KW` and `A*GCMKW`, and 256 bits otherwise. A `dir` key must match
the content encryption: 256 bits for `A128CBC-HS256`, 384 for
`A192CBC-HS384` and 512 for `A256CBC-HS512`.

## See also

[`jose_key_oct()`](https://pedrobtz.github.io/zujwt/reference/jose_key_oct.md)
to wrap a secret you already have,
[`jose_with_kid()`](https://pedrobtz.github.io/zujwt/reference/jose_with_kid.md)
to name the new key by its thumbprint.

## Examples

``` r
key <- jose_key_generate("oct", alg = "HS256")
key
#> <jose_key> oct, 256 bits
#>   alg HS256
#>   private: yes (not shown)

# A key encryption key, named by its thumbprint.
jose_with_kid(jose_key_generate("oct", alg = "A256KW"))
#> <jose_key> oct, 256 bits
#>   kid "9IAjSXV1FnNibet59TwEz4JEL06ZxWuwvC-18CgwA9M"
#>   alg A256KW
#>   private: yes (not shown)
```
