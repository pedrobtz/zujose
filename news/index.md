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
