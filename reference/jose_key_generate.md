# Generate a random key

`jose_key_generate()` makes a new key from the operating system's
cryptographic random source, through zucrypt: `oct`, `RSA`, `EC` (on
P-256, P-384 or P-521) and `OKP` (X25519) keys. There is no Ed25519.

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

  The key size in bits. For an `oct` key, a multiple of 8 and at least
  128, and `NULL` takes the size `alg` needs; for an `RSA` key, 2048 to
  4096, and `NULL` is 2048.

- crv:

  The curve: `"P-256"` (the default), `"P-384"` or `"P-521"` for an `EC`
  key, `"X25519"` for an `OKP` key. Not used otherwise.

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

Without `size`, an `oct` key is as long as `alg` needs: the hash size
for `HS256`, `HS384` and `HS512` (RFC 7518 section 3.2), the key size
for `A*KW` and `A*GCMKW`, and 256 bits otherwise. A `dir` key must match
the content encryption: 256 bits for `A128CBC-HS256`, 384 for
`A192CBC-HS384` and 512 for `A256CBC-HS512`.

An `RSA` key's `size` is its modulus, 2048 bits by default and at most
4096, with public exponent 65537. Generating one takes a moment.

## See also

[`jose_key_oct()`](https://pedrobtz.github.io/zujose/reference/jose_key_oct.md)
to wrap a secret you already have,
[`jose_with_kid()`](https://pedrobtz.github.io/zujose/reference/jose_with_kid.md)
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
#>   kid "3aXScjQNqmR2zS7aAY7tCEuELzdGjufwOwILMyCNGLE"
#>   alg A256KW
#>   private: yes (not shown)
```
