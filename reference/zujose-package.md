# zujose: Sign, Verify, Encrypt and Decrypt JSON Web Tokens

Signs, verifies, encrypts and decrypts JavaScript Object Notation (JSON)
Object Signing and Encryption ('JOSE') objects: JSON Web Signatures
(Request for Comments (RFC) 7515)
[doi:10.17487/RFC7515](https://doi.org/10.17487/RFC7515) , JSON Web
Encryption (RFC 7516)
[doi:10.17487/RFC7516](https://doi.org/10.17487/RFC7516) , JSON Web Keys
(RFC 7517) [doi:10.17487/RFC7517](https://doi.org/10.17487/RFC7517) and
JSON Web Tokens (RFC 7519)
[doi:10.17487/RFC7519](https://doi.org/10.17487/RFC7519) , in the
compact and JSON serializations. The caller names the algorithms it
accepts, and tokens are checked against the current best practices of
RFC 8725 [doi:10.17487/RFC8725](https://doi.org/10.17487/RFC8725) .
Written in 'R' over 'zucrypt', so no system cryptography library is
needed.

## Details

Start with the Get started article, at
<https://pedrobtz.github.io/zujose/articles/zujose.html>. The main
functions are:

- JWT:
  [`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md),
  [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md),
  [`jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jwt_decoder.md).

- JWS:
  [`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md),
  [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md).

- JWE:
  [`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md),
  [`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md).

- Keys:
  [`jwk_oct()`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md),
  [`jwk_generate()`](https://pedrobtz.github.io/zujose/reference/jwk_generate.md),
  [`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md),
  [`jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md),
  [`as_jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md),
  [`jwk_json()`](https://pedrobtz.github.io/zujose/reference/jwk_json.md),
  [`jwk_pem()`](https://pedrobtz.github.io/zujose/reference/jwk_pem.md).

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
key <- jwk_generate("oct", alg = "HS256")
jwt <- jwt_encode(list(sub = "user-1"), key, expires_in = 3600)
jwt_decode(jwt, key, algorithms = "HS256")$sub
#> [1] "user-1"
```
