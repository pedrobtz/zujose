# Changelog

## zujose 0.0.0.9000

- Documentation: a README, and three articles on the package website:
  Get started, migrating from `jose`, and verifying tokens against a
  provider’s JWKS with a caching resolver. The key help pages explain
  how secrets are held in R memory.

- `jose_key_generate("oct")` accepts 128-bit keys when no `alg` is
  given, or for `dir`, as documented; it required 256 bits
  ([\#30](https://github.com/pedrobtz/zujose/issues/30)).

- The package, developed as `zujwt`, is renamed `zujose`, the name of
  its design: conditions are `zujose_*` and `zujwt_info()` is
  [`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md).

- Condition classes for every error the package will raise, all
  inheriting from `zujose_error`
  ([`?zujose_error`](https://pedrobtz.github.io/zujose/reference/zujose_error.md)).

- [`jose_peek()`](https://pedrobtz.github.io/zujose/reference/jose_peek.md)
  reads a JWS or JWE in the compact, flattened or general JSON
  serialization, without verifying it, and returns every part decoded:
  its headers; for a JWS, its payload, claims, signatures and signing
  inputs; for a JWE, its encrypted keys, IV, ciphertext, tag and AAD.

- [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md)
  sets the resource limits every token is checked against before
  anything is decoded.

- Keys:
  [`jose_key_oct()`](https://pedrobtz.github.io/zujose/reference/jose_key_oct.md)
  makes a symmetric key,
  [`as_jose_key()`](https://pedrobtz.github.io/zujose/reference/as_jose_key.md)
  reads a JWK,
  [`jose_jwk()`](https://pedrobtz.github.io/zujose/reference/jose_jwk.md)
  writes one,
  [`jose_public()`](https://pedrobtz.github.io/zujose/reference/jose_public.md)
  strips private members, and
  [`jose_thumbprint()`](https://pedrobtz.github.io/zujose/reference/jose_thumbprint.md)
  computes RFC 7638 thumbprints and RFC 9278 thumbprint URIs.
  [`jose_with_kid()`](https://pedrobtz.github.io/zujose/reference/jose_with_kid.md)
  sets `kid`, by default to the thumbprint. `RSA`, `EC` and `OKP` keys
  are read and kept but cannot be used yet.

- Key sets:
  [`jose_keyset()`](https://pedrobtz.github.io/zujose/reference/jose_keyset.md)
  and
  [`as_jose_keyset()`](https://pedrobtz.github.io/zujose/reference/jose_keyset.md),
  with `[[` selecting by `kid`. Malformed entries in a JWK Set are
  ignored, as RFC 7517 asks.

- [`jose_sign()`](https://pedrobtz.github.io/zujose/reference/jose_sign.md)
  and
  [`jose_verify()`](https://pedrobtz.github.io/zujose/reference/jose_verify.md)
  sign and verify JWS with `HS256`, `HS384` and `HS512`, in all three
  serializations, with several signers through
  [`jose_signer()`](https://pedrobtz.github.io/zujose/reference/jose_signer.md),
  detached payloads, and RFC 7797 unencoded payloads.
  [`jose_verify()`](https://pedrobtz.github.io/zujose/reference/jose_verify.md)
  needs `algorithms`, has no way to accept `none`, and refuses a key
  that does not fit the token’s algorithm.

- [`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md)
  lists every JOSE algorithm and whether this installation can use it.

- [`jose_jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jose_jwt_encode.md)
  and
  [`jose_jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jose_jwt_decode.md)
  sign and check JWTs. Decoding checks `exp`, `nbf`, `iat`, `max_age`,
  `iss`, `sub`, `aud`, `typ`, required claims, per-claim expectations
  and a `validate` hook in one call; `exp` is required by default. Each
  failure has its own condition class under `zujose_claim_error`.
  [`jose_jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jose_jwt_decoder.md)
  fixes a policy once and returns a checking function.

- [`jose_decrypt()`](https://pedrobtz.github.io/zujose/reference/jose_decrypt.md)
  decrypts JWE with `dir`, `A128KW`, `A192KW` and `A256KW` key
  management and `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`
  content encryption, in all three serializations and for several
  recipients. Every decryption failure raises one class with one
  message. Compressed (`zip`) tokens are refused.

- [`jose_encrypt()`](https://pedrobtz.github.io/zujose/reference/jose_encrypt.md)
  encrypts to one recipient, or to several through
  [`jose_recipient()`](https://pedrobtz.github.io/zujose/reference/jose_recipient.md),
  with the same algorithms. Every message gets a fresh content
  encryption key and IV from the operating system’s random source, which
  cannot be supplied by the caller.

- JWE gains `A128GCM`, `A192GCM` and `A256GCM` content encryption, and
  `A128GCMKW`, `A192GCMKW`, `A256GCMKW` and the three `PBES2-*` key
  management algorithms, over zucrypt’s AES-GCM and PBKDF2. A PBES2
  token whose `p2c` exceeds `jose_limits()$p2c`, or whose `p2s` is
  shorter than 8 bytes, is refused before any key is derived. A `dir`
  key whose `alg` names the content encryption, as in RFC 7520 section
  5.6, is accepted.

- RSA: `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512`
  signatures, and `RSA-OAEP` and `RSA-OAEP-256` key management. `RSA1_5`
  decrypts only when `algorithms` names it, never encrypts, and fails
  like a wrong key when its padding is bad. RSA keys are read from JWKs
  (with all CRT parameters for a private key) and from PEM, written with
  the new
  [`jose_pem()`](https://pedrobtz.github.io/zujose/reference/jose_pem.md),
  generated with `jose_key_generate("RSA")`, and must be at least 2048
  bits to be used.

- Elliptic curves: `ES256`, `ES384` and `ES512` signatures (raw
  `r || s`), and `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW` and
  `ECDH-ES+A256KW` key agreement on P-256, P-384, P-521 and X25519, with
  the Concat KDF of RFC 7518. An ephemeral key that is malformed or off
  its curve is a parse error, and one on another curve than the key a
  key error, before any key agreement. EC and X25519 keys are read from
  JWKs and PEM, written by
  [`jose_pem()`](https://pedrobtz.github.io/zujose/reference/jose_pem.md)
  and generated by `jose_key_generate("EC")` and `("OKP")`. Ed25519 keys
  are read and kept but cannot be used.

- [`jose_key_generate()`](https://pedrobtz.github.io/zujose/reference/jose_key_generate.md)
  makes a random `oct` key, sized for its `alg`. `RSA`, `EC` and `OKP`
  generation names the zucrypt version it needs.

- `jose_jwt_encode(jti = TRUE)` adds a random 128-bit `jti`.

- zujose now needs the development version of zucrypt, for
  `crypt_rand_bytes()`, `crypt_aes_gcm_encrypt()` and `crypt_pbkdf2()`.
  [`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md)
  reports an algorithm available when the installed zucrypt exports what
  it needs, so a development zucrypt counts.

- [`jose_jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jose_jwt_decode.md)
  accepts a JWT sent as a JWE only with
  `decrypt = jose_decryption(...)`.
