# Accept an encrypted JWT

`jwe_decryption()` bundles the key and algorithms that
[`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
uses to decrypt a JWT sent as a JWE. Without it, a JWE is refused where
a JWT is expected, which keeps a signed-token check from silently
accepting encrypted tokens (jwcrypto's CVE-2022-3102).

## Usage

``` r
jwe_decryption(key, algorithms, encryptions)
```

## Arguments

- key:

  A `jwk`, a `jwk_set`, or a function of the header returning one.

- algorithms:

  The key management algorithms to accept, such as `"A256KW"`.

- encryptions:

  The content encryption algorithms to accept, such as
  `"A256CBC-HS512"`.

## Value

A `jwe_decryption`.

## Examples

``` r
jwe_decryption(jwk_oct(as.raw(1:16)), "A128KW", "A128CBC-HS256")
#> <jwe_decryption> A128KW with A128CBC-HS256
```
