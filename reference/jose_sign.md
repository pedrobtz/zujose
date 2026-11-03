# Sign a payload as a JWS

`jose_sign()` signs `payload` with one key, or with several through
[`jose_signer()`](https://pedrobtz.github.io/zujose/reference/jose_signer.md),
and returns the JWS in the compact, flattened JSON or general JSON
serialization (RFC 7515).

## Usage

``` r
jose_sign(
  payload,
  key,
  alg = NULL,
  header = NULL,
  unprotected = NULL,
  format = c("compact", "flattened", "general"),
  b64 = TRUE,
  detached = FALSE
)
```

## Arguments

- payload:

  The payload: a raw vector, or a single string taken as UTF-8 text.

- key:

  A `jose_key`, or a list of
  [`jose_signer()`](https://pedrobtz.github.io/zujose/reference/jose_signer.md)
  objects for several signatures.

- alg:

  The signature algorithm, such as `"HS256"` or `"RS256"`. `NULL` takes
  the key's own `alg`.

- header:

  Further protected header members, as a named list.

- unprotected:

  Unprotected header members, as a named list. Only the JSON
  serializations carry them.

- format:

  `"compact"`, `"flattened"` or `"general"`. Several signatures need
  `"general"`.

- b64:

  Whether the payload is Base64url-encoded in the signing input and the
  token. `FALSE` follows RFC 7797.

- detached:

  Whether to leave the payload out of the token. The verifier then
  supplies it to
  [`jose_verify()`](https://pedrobtz.github.io/zujose/reference/jose_verify.md).

## Value

The JWS, as a single string.

## Details

The protected header holds `alg`, the key's `kid` unless `header` or
`unprotected` sets one, and the members of `header`. With `b64 = FALSE`,
the payload is signed and carried unencoded (RFC 7797), and the header
gains `b64: false` and `crit: ["b64"]`.

The algorithms are `HS256`, `HS384` and `HS512` with an `oct` key, and
`RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` with a private
RSA key of at least 2048 bits, and `ES256`, `ES384` and `ES512` with a
private EC key on P-256, P-384 and P-521 respectively. `RS*` signatures
are deterministic; `PS*` and `ES*` ones are randomised. An `ES*`
signature is `r` followed by `s`, each of fixed length, as RFC 7518
section 3.4 specifies.

## Examples

``` r
key <- jose_key_oct(as.raw(1:32), kid = "k1")
token <- jose_sign("hello", key, alg = "HS256")
token
#> [1] "eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0.aGVsbG8.X2gFwW_6UvgW7Bh1zZ_A-dSWyDix7IWMYIFm10uAmnw"
rawToChar(jose_verify(token, key, algorithms = "HS256")$payload)
#> [1] "hello"
```
