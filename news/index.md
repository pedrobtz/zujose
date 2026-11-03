# Changelog

## zujwt 0.0.0.9000

- Condition classes for every error the package will raise, all
  inheriting from `zujwt_error`
  ([`?zujwt_error`](https://pedrobtz.github.io/zujwt/reference/zujwt_error.md)).

- [`jose_peek()`](https://pedrobtz.github.io/zujwt/reference/jose_peek.md)
  reads a JWS or JWE in the compact, flattened or general JSON
  serialization, without verifying it, and returns its headers and, for
  a JWS, its payload and claims.

- [`jose_limits()`](https://pedrobtz.github.io/zujwt/reference/jose_limits.md)
  sets the resource limits every token is checked against before
  anything is decoded.

- Keys:
  [`jose_key_oct()`](https://pedrobtz.github.io/zujwt/reference/jose_key_oct.md)
  makes a symmetric key,
  [`as_jose_key()`](https://pedrobtz.github.io/zujwt/reference/as_jose_key.md)
  reads a JWK,
  [`jose_jwk()`](https://pedrobtz.github.io/zujwt/reference/jose_jwk.md)
  writes one,
  [`jose_public()`](https://pedrobtz.github.io/zujwt/reference/jose_public.md)
  strips private members, and
  [`jose_thumbprint()`](https://pedrobtz.github.io/zujwt/reference/jose_thumbprint.md)
  computes RFC 7638 thumbprints and RFC 9278 thumbprint URIs.
  [`jose_with_kid()`](https://pedrobtz.github.io/zujwt/reference/jose_with_kid.md)
  sets `kid`, by default to the thumbprint. `RSA`, `EC` and `OKP` keys
  are read and kept but cannot be used yet.

- Key sets:
  [`jose_keyset()`](https://pedrobtz.github.io/zujwt/reference/jose_keyset.md)
  and
  [`as_jose_keyset()`](https://pedrobtz.github.io/zujwt/reference/jose_keyset.md),
  with `[[` selecting by `kid`. Malformed entries in a JWK Set are
  ignored, as RFC 7517 asks.

- [`jose_sign()`](https://pedrobtz.github.io/zujwt/reference/jose_sign.md)
  and
  [`jose_verify()`](https://pedrobtz.github.io/zujwt/reference/jose_verify.md)
  sign and verify JWS with `HS256`, `HS384` and `HS512`, in all three
  serializations, with several signers through
  [`jose_signer()`](https://pedrobtz.github.io/zujwt/reference/jose_signer.md),
  detached payloads, and RFC 7797 unencoded payloads.
  [`jose_verify()`](https://pedrobtz.github.io/zujwt/reference/jose_verify.md)
  needs `algorithms`, has no way to accept `none`, and refuses a key
  that does not fit the token’s algorithm.

- [`zujwt_info()`](https://pedrobtz.github.io/zujwt/reference/zujwt_info.md)
  lists every JOSE algorithm and whether this installation can use it.

- [`jose_jwt_encode()`](https://pedrobtz.github.io/zujwt/reference/jose_jwt_encode.md)
  and
  [`jose_jwt_decode()`](https://pedrobtz.github.io/zujwt/reference/jose_jwt_decode.md)
  sign and check JWTs. Decoding checks `exp`, `nbf`, `iat`, `max_age`,
  `iss`, `sub`, `aud`, `typ`, required claims, per-claim expectations
  and a `validate` hook in one call; `exp` is required by default. Each
  failure has its own condition class under `zujwt_claim_error`.
  [`jose_jwt_decoder()`](https://pedrobtz.github.io/zujwt/reference/jose_jwt_decoder.md)
  fixes a policy once and returns a checking function.

- [`jose_decrypt()`](https://pedrobtz.github.io/zujwt/reference/jose_decrypt.md)
  decrypts JWE with `dir`, `A128KW`, `A192KW` and `A256KW` key
  management and `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`
  content encryption, in all three serializations and for several
  recipients. Every decryption failure raises one class with one
  message. Compressed (`zip`) tokens are refused.

- [`jose_encrypt()`](https://pedrobtz.github.io/zujwt/reference/jose_encrypt.md)
  encrypts to one recipient, or to several through
  [`jose_recipient()`](https://pedrobtz.github.io/zujwt/reference/jose_recipient.md),
  with the same algorithms. Every message gets a fresh content
  encryption key and IV from the operating system’s random source, which
  cannot be supplied by the caller.

- [`jose_key_generate()`](https://pedrobtz.github.io/zujwt/reference/jose_key_generate.md)
  makes a random `oct` key, sized for its `alg`. `RSA`, `EC` and `OKP`
  generation names the zucrypt version it needs.

- `jose_jwt_encode(jti = TRUE)` adds a random 128-bit `jti`.

- zujwt now needs the development version of zucrypt, for
  `crypt_rand_bytes()`.

- [`jose_jwt_decode()`](https://pedrobtz.github.io/zujwt/reference/jose_jwt_decode.md)
  accepts a JWT sent as a JWE only with
  `decrypt = jose_decryption(...)`.
