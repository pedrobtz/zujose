# Check a JWT and return its claims

`jose_jwt_decode()` verifies a JWT's signature with
[`jose_verify()`](https://pedrobtz.github.io/zujose/reference/jose_verify.md)'s
rules and then checks its claims (RFC 7519, RFC 8725). The checks happen
here, in one call, so none can be forgotten.

## Usage

``` r
jose_jwt_decode(
  token,
  key,
  algorithms,
  audience = NULL,
  issuer = NULL,
  subject = NULL,
  type = "JWT",
  required = "exp",
  claims = list(),
  validate = NULL,
  max_age = NULL,
  leeway = 60,
  now = Sys.time(),
  decrypt = NULL,
  limits = jose_limits()
)
```

## Arguments

- token:

  The JWT, in the compact serialization.

- key:

  A `jose_key`, a `jose_keyset`, or a function of the header returning
  one.

- algorithms:

  The signature algorithms to accept, such as `"HS256"`.

- audience:

  The audiences this caller accepts, or `NULL`.

- issuer:

  The issuer this caller accepts, or `NULL`.

- subject:

  The subject this caller accepts, or `NULL`.

- type:

  The expected `typ`, or `NULL` to skip the check.

- required:

  Names of claims that must be present.

- claims:

  Further expectations, as a named list of values or functions.

- validate:

  A function of the claims list that must return `TRUE`, or `NULL`.

- max_age:

  The greatest age, in seconds, of `iat`, or `NULL`.

- leeway:

  Seconds of clock skew to allow.

- now:

  The current time, as `POSIXct`.

- decrypt:

  For a JWT sent as a JWE, the key and algorithms to decrypt it, from
  [`jose_decryption()`](https://pedrobtz.github.io/zujose/reference/jose_decryption.md);
  `NULL` refuses a JWE.

- limits:

  Resource limits, from
  [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md).

## Value

The claims, as a named list of class `jose_claims`, with `exp`, `nbf`
and `iat` as `POSIXct` and the verified header as the `header`
attribute.

## Details

- `exp`, `nbf` and `iat` must be numbers. The token must not have
  expired, must already be valid, and must not be issued in the future,
  each allowing `leeway` seconds. `max_age` bounds how long ago `iat`
  was.

- `required` names claims that must be present. The default requires
  `exp`: a token that never expires has to be accepted on purpose.

- `issuer` and `subject` must equal `iss` and `sub` exactly. An `iss` or
  `sub` that is not a single string is refused.

- `aud` must contain one of `audience`. A token that names an audience
  is refused when `audience` is `NULL` (RFC 7519 section 4.1.3), and one
  without `aud` is refused when `audience` is given.

- `type` must match the `typ` header, ignoring case and an
  `application/` prefix. A token without `typ` passes only when `type`
  is `"JWT"`.

- `claims` holds further expectations, one per claim: a value the claim
  must equal, or a function of the claim that must return `TRUE`.
  `validate` is a function of the whole claims list, for checks across
  claims.

A JWT whose header has `cty: "JWT"` carries another JWT as its payload.
That inner JWT is verified with the same `key` and `algorithms`, and its
claims are checked. Deeper nesting is refused.

A JWT sent as a JWE is accepted only when `decrypt` says how to decrypt
it, so a check meant for signed tokens never silently accepts encrypted
ones. The JWE either carries a signed JWT (`cty: "JWT"`), verified as
above, or the claims themselves.

Each failed check raises a subclass of `zujose_claim_error` carrying the
claim name: `zujose_expired_error`, `zujose_not_yet_valid_error`,
`zujose_audience_error`, `zujose_issuer_error`, `zujose_subject_error`
or `zujose_missing_claim_error`. Time errors also carry `time` and
`now`.

## See also

[`jose_jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jose_jwt_decoder.md)
to fix these arguments once.

## Examples

``` r
key <- jose_key_oct(as.raw(1:32))
jwt <- jose_jwt_encode(list(iss = "me", aud = "api"), key, "HS256",
                       expires_in = 60)
claims <- jose_jwt_decode(jwt, key, "HS256", audience = "api",
                          issuer = "me")
claims$iss
#> [1] "me"

# Claim failures have classes of their own.
tryCatch(
  jose_jwt_decode(jwt, key, "HS256", audience = "other"),
  zujose_audience_error = function(e) "wrong audience"
)
#> [1] "wrong audience"
```
