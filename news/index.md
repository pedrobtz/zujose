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
