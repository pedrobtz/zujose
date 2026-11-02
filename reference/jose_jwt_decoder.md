# A reusable JWT check

`jose_jwt_decoder()` fixes the key and every check of
[`jose_jwt_decode()`](https://pedrobtz.github.io/zujwt/reference/jose_jwt_decode.md)
once, and returns a function of the token that applies them. Use it
where the same policy guards many requests.

## Usage

``` r
jose_jwt_decoder(
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
  limits = jose_limits()
)
```

## Arguments

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

- limits:

  Resource limits, from
  [`jose_limits()`](https://pedrobtz.github.io/zujwt/reference/jose_limits.md).

## Value

A function `function(token, now = Sys.time())` returning the claims, as
[`jose_jwt_decode()`](https://pedrobtz.github.io/zujwt/reference/jose_jwt_decode.md)
does.

## Examples

``` r
key <- jose_key_oct(as.raw(1:32))
check <- jose_jwt_decoder(key, "HS256", audience = "api", issuer = "me")
jwt <- jose_jwt_encode(list(iss = "me", aud = "api"), key, "HS256",
                       expires_in = 60)
check(jwt)$iss
#> [1] "me"
```
