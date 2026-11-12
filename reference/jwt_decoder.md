# A reusable JWT check

`jwt_decoder()` fixes the key and every check of
[`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
once, and returns a function of the token that applies them. Use it
where the same policy guards many requests.

## Usage

``` r
jwt_decoder(
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
  decrypt = NULL,
  limits = jose_limits()
)
```

## Arguments

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

- decrypt:

  For a JWT sent as a JWE, the key and algorithms to decrypt it, from
  [`jwe_decryption()`](https://pedrobtz.github.io/zujose/reference/jwe_decryption.md);
  `NULL` refuses a JWE.

- limits:

  Resource limits, from
  [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md).

## Value

A function `function(token, now = Sys.time())` returning the claims, as
[`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
does.

## Examples

``` r
key <- jwk_oct(as.raw(1:32))
check <- jwt_decoder(key, "HS256", audience = "api", issuer = "me")
jwt <- jwt_encode(list(iss = "me", aud = "api"), key, "HS256",
                       expires_in = 60)
check(jwt)$iss
#> [1] "me"
```
