# Check a JWT and return its claims

`jwt_decode()` verifies a JWT's signature with
[`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)'s
rules and then checks its claims (RFC 7519, RFC 8725). The checks happen
here, in one call, so none can be forgotten.

## Usage

``` r
jwt_decode(
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

  A `jwk`, a `jwk_set`, or a function of the header returning one.

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

  Further expectations, as a list of values or functions with unique
  names.

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
  [`jwe_decryption()`](https://pedrobtz.github.io/zujose/reference/jwe_decryption.md);
  `NULL` refuses a JWE.

- limits:

  Resource limits, from
  [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md).

## Value

The claims, as a named list of class `jwt_claims`, with `exp`, `nbf` and
`iat` as `POSIXct` and the verified header as the `header` attribute.

## Details

- `exp`, `nbf` and `iat` must be numbers that `POSIXct` can hold as a
  time, within about two billion years of 1970. The token must not have
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

A value in `claims` is compared with the claim as JSON values, the value
taken as
[`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md)
would write it. Object members may come in any order, and `3L` equals
`3`. A vector of length one is a scalar and a longer one an array, so
`"a"` does not match `["a"]`; write `list("a")` for an array of one.
`NULL` matches a JSON `null`. `NA` and non-finite numbers have no JSON
form and are refused. `exp`, `nbf` and `iat` are compared, and passed to
a function, as the `POSIXct` times `jwt_decode()` returns; a number
expects the same NumericDate.

A JWT must not use the unencoded payload option, `b64: false` (RFC 7797
section 7), and one that does is refused with `zujose_policy_error`.

A JWT sent as a JWE is accepted only when `decrypt` says how to decrypt
it, so a check meant for signed tokens never silently accepts encrypted
ones. Each layer has its own allow-list: `decrypt` for the JWE, and
`key` and `algorithms` for the signature. The JWE's key management must
be in `decrypt`'s algorithms, checked first. The JWE then carries a
signed JWT (`cty: "JWT"`), verified as above, or, when its key
management is symmetric (`dir`, `A*KW`, `A*GCMKW` or `PBES2-*`), the
claims themselves. With RSA or ECDH key management anyone holding the
recipient's public key can encrypt a token, so the claims must be
signed: an encrypted-only JWT is refused with `zujose_policy_error`.

Nesting is one level only, a signed JWT inside a JWE. A signed JWT whose
header has `cty: "JWT"` is refused with `zujose_policy_error` before its
signature is checked, whether it is the token or inside a JWE. To accept
a signed JWT inside another, call
[`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
on each.

Each failed check raises a subclass of `zujose_claim_error` carrying the
claim name: `zujose_expired_error`, `zujose_not_yet_valid_error`,
`zujose_audience_error`, `zujose_issuer_error`, `zujose_subject_error`
or `zujose_missing_claim_error`. Time errors also carry `time` and
`now`.

## See also

[`jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jwt_decoder.md)
to fix these arguments once.

## Examples

``` r
key <- jwk_oct(as.raw(1:32))
jwt <- jwt_encode(
  list(iss = "me", aud = "api"),
  key,
  "HS256",
  expires_in = 60
)
claims <- jwt_decode(jwt, key, "HS256", audience = "api", issuer = "me")
claims$iss
#> [1] "me"

# Claim failures have classes of their own.
tryCatch(
  jwt_decode(jwt, key, "HS256", audience = "other"),
  zujose_audience_error = function(e) "wrong audience"
)
#> [1] "wrong audience"
```
