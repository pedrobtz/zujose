# Changelog

## zujose 0.0.0.9000

- [`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
  counts `limits$keys` across all of a token’s recipients, not per
  recipient, so a JWE with many PBES2 or RSA recipients cannot multiply
  the key-derivation work
  ([\#37](https://github.com/pedrobtz/zujose/issues/37)).

- [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
  and
  [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  skip a key in a set that is too weak for the token’s algorithm, such
  as a legacy 1024-bit RSA key in a provider’s JWKS, instead of failing
  on it. A set with only weak keys is still a `zujose_key_error`
  ([\#39](https://github.com/pedrobtz/zujose/issues/39)).

- Argument errors, such as a wrong type, an out-of-range limit or
  `format = "compact"` with several recipients, now raise
  `zujose_argument_error`, a `zujose_error`, instead of a plain error
  ([\#40](https://github.com/pedrobtz/zujose/issues/40)).

- [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  refuses an encrypted-only JWT whose key management is public-key
  (`RSA-OAEP*`, `RSA1_5`, `ECDH-ES*`), because anyone holding the
  recipient’s public key could have made it. Its claims must come inside
  a signed JWT (`cty: "JWT"`). Encrypted-only JWTs with symmetric key
  management are still accepted
  ([\#34](https://github.com/pedrobtz/zujose/issues/34)).

- Functions are named after the object they work on:
  [`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md),
  [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  and
  [`jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jwt_decoder.md);
  [`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md),
  [`jws_signer()`](https://pedrobtz.github.io/zujose/reference/jws_signer.md)
  and
  [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md);
  [`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md),
  [`jwe_recipient()`](https://pedrobtz.github.io/zujose/reference/jwe_recipient.md),
  [`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
  and
  [`jwe_decryption()`](https://pedrobtz.github.io/zujose/reference/jwe_decryption.md);
  [`jwk_oct()`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md),
  [`jwk_generate()`](https://pedrobtz.github.io/zujose/reference/jwk_generate.md),
  [`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md),
  [`jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md),
  [`as_jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md),
  [`jwk_public()`](https://pedrobtz.github.io/zujose/reference/jwk_public.md),
  [`jwk_json()`](https://pedrobtz.github.io/zujose/reference/jwk_json.md),
  [`jwk_pem()`](https://pedrobtz.github.io/zujose/reference/jwk_pem.md),
  [`jwk_with_kid()`](https://pedrobtz.github.io/zujose/reference/jwk_with_kid.md)
  and
  [`jwk_thumbprint()`](https://pedrobtz.github.io/zujose/reference/jwk_thumbprint.md).
  They replace the `jose_` names of the development version;
  [`jose_peek()`](https://pedrobtz.github.io/zujose/reference/jose_peek.md)
  and
  [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md)
  keep theirs. Classes follow: `jwk`, `jwk_set`, `jws_verified`,
  `jwe_decrypted`, `jwt_claims`.

- Documentation: a README, and three articles on the package website:
  Get started, migrating from `jose`, and verifying tokens against a
  provider’s JWKS with a caching resolver. The key help pages explain
  how secrets are held in R memory.

- `jwk_generate("oct")` accepts 128-bit keys when no `alg` is given, or
  for `dir`, as documented; it required 256 bits
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
  [`jwk_oct()`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md)
  makes a symmetric key,
  [`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md)
  reads a JWK,
  [`jwk_json()`](https://pedrobtz.github.io/zujose/reference/jwk_json.md)
  writes one,
  [`jwk_public()`](https://pedrobtz.github.io/zujose/reference/jwk_public.md)
  strips private members, and
  [`jwk_thumbprint()`](https://pedrobtz.github.io/zujose/reference/jwk_thumbprint.md)
  computes RFC 7638 thumbprints and RFC 9278 thumbprint URIs.
  [`jwk_with_kid()`](https://pedrobtz.github.io/zujose/reference/jwk_with_kid.md)
  sets `kid`, by default to the thumbprint. `RSA`, `EC` and `OKP` keys
  are read and kept but cannot be used yet.

- Key sets:
  [`jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md)
  and
  [`as_jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md),
  with `[[` selecting by `kid`. Malformed entries in a JWK Set are
  ignored, as RFC 7517 asks.

- [`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md)
  and
  [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
  sign and verify JWS with `HS256`, `HS384` and `HS512`, in all three
  serializations, with several signers through
  [`jws_signer()`](https://pedrobtz.github.io/zujose/reference/jws_signer.md),
  detached payloads, and RFC 7797 unencoded payloads.
  [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
  needs `algorithms`, has no way to accept `none`, and refuses a key
  that does not fit the token’s algorithm.

- [`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md)
  lists every JOSE algorithm and whether this installation can use it.

- [`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md)
  and
  [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  sign and check JWTs. Decoding checks `exp`, `nbf`, `iat`, `max_age`,
  `iss`, `sub`, `aud`, `typ`, required claims, per-claim expectations
  and a `validate` hook in one call; `exp` is required by default. Each
  failure has its own condition class under `zujose_claim_error`.
  [`jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jwt_decoder.md)
  fixes a policy once and returns a checking function.

- [`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
  decrypts JWE with `dir`, `A128KW`, `A192KW` and `A256KW` key
  management and `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`
  content encryption, in all three serializations and for several
  recipients. Every decryption failure raises one class with one
  message. Compressed (`zip`) tokens are refused.

- [`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md)
  encrypts to one recipient, or to several through
  [`jwe_recipient()`](https://pedrobtz.github.io/zujose/reference/jwe_recipient.md),
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
  [`jwk_pem()`](https://pedrobtz.github.io/zujose/reference/jwk_pem.md),
  generated with `jwk_generate("RSA")`, and must be at least 2048 bits
  to be used.

- Elliptic curves: `ES256`, `ES384` and `ES512` signatures (raw
  `r || s`), and `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW` and
  `ECDH-ES+A256KW` key agreement on P-256, P-384, P-521 and X25519, with
  the Concat KDF of RFC 7518. An ephemeral key that is malformed or off
  its curve is a parse error, and one on another curve than the key a
  key error, before any key agreement. EC and X25519 keys are read from
  JWKs and PEM, written by
  [`jwk_pem()`](https://pedrobtz.github.io/zujose/reference/jwk_pem.md)
  and generated by `jwk_generate("EC")` and `("OKP")`. Ed25519 keys are
  read and kept but cannot be used.

- [`jwk_generate()`](https://pedrobtz.github.io/zujose/reference/jwk_generate.md)
  makes a random `oct` key, sized for its `alg`. `RSA`, `EC` and `OKP`
  generation names the zucrypt version it needs.

- `jwt_encode(jti = TRUE)` adds a random 128-bit `jti`.

- zujose now needs the development version of zucrypt, for
  `crypt_rand_bytes()`, `crypt_aes_gcm_encrypt()` and `crypt_pbkdf2()`.
  [`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md)
  reports an algorithm available when the installed zucrypt exports what
  it needs, so a development zucrypt counts.

- [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  accepts a JWT sent as a JWE only with `decrypt = jwe_decryption(...)`.
