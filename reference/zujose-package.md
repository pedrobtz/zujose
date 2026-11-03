# zujose: Sign, Verify, Encrypt and Decrypt JSON Web Tokens

Signs, verifies, encrypts and decrypts JSON Object Signing and
Encryption ('JOSE') objects: JSON Web Signatures (RFC 7515)
[doi:10.17487/RFC7515](https://doi.org/10.17487/RFC7515) , JSON Web
Encryption (RFC 7516)
[doi:10.17487/RFC7516](https://doi.org/10.17487/RFC7516) , JSON Web Keys
(RFC 7517) [doi:10.17487/RFC7517](https://doi.org/10.17487/RFC7517) and
JSON Web Tokens (RFC 7519)
[doi:10.17487/RFC7519](https://doi.org/10.17487/RFC7519) , in the
compact and JSON serializations. The caller names the algorithms it
accepts, and tokens are checked against the current best practices of
RFC 8725 [doi:10.17487/RFC8725](https://doi.org/10.17487/RFC8725) .
Written in R over 'zucrypt', so no system cryptography library is
needed.

## Details

Start with the Get started article, at
<https://pedrobtz.github.io/zujose/articles/zujose.html>. The main
functions are:

- JWT:
  [`jose_jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jose_jwt_encode.md),
  [`jose_jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jose_jwt_decode.md),
  [`jose_jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jose_jwt_decoder.md).

- JWS:
  [`jose_sign()`](https://pedrobtz.github.io/zujose/reference/jose_sign.md),
  [`jose_verify()`](https://pedrobtz.github.io/zujose/reference/jose_verify.md).

- JWE:
  [`jose_encrypt()`](https://pedrobtz.github.io/zujose/reference/jose_encrypt.md),
  [`jose_decrypt()`](https://pedrobtz.github.io/zujose/reference/jose_decrypt.md).

- Keys:
  [`jose_key_oct()`](https://pedrobtz.github.io/zujose/reference/jose_key_oct.md),
  [`jose_key_generate()`](https://pedrobtz.github.io/zujose/reference/jose_key_generate.md),
  [`as_jose_key()`](https://pedrobtz.github.io/zujose/reference/as_jose_key.md),
  [`jose_keyset()`](https://pedrobtz.github.io/zujose/reference/jose_keyset.md),
  [`as_jose_keyset()`](https://pedrobtz.github.io/zujose/reference/jose_keyset.md),
  [`jose_jwk()`](https://pedrobtz.github.io/zujose/reference/jose_jwk.md),
  [`jose_pem()`](https://pedrobtz.github.io/zujose/reference/jose_pem.md).

- Inspection:
  [`jose_peek()`](https://pedrobtz.github.io/zujose/reference/jose_peek.md),
  [`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md).

zujose never fetches anything: keys come only from the caller, as a key,
a key set, or a function that returns one (a resolver).

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

Useful links:

- <https://github.com/pedrobtz/zujose>

- <https://pedrobtz.github.io/zujose/>

- Report bugs at <https://github.com/pedrobtz/zujose/issues>

## Author

**Maintainer**: Pedro Baltazar <pedrobtz@gmail.com> \[copyright holder\]

Authors:

- Pedro Baltazar <pedrobtz@gmail.com> \[copyright holder\]

## Examples

``` r
key <- jose_key_generate("oct", alg = "HS256")
jwt <- jose_jwt_encode(list(sub = "user-1"), key, expires_in = 3600)
jose_jwt_decode(jwt, key, algorithms = "HS256")$sub
#> [1] "user-1"
```
