# RFC vectors -------------------------------------------------------------

test_that("RFC 7519 §3.1 decodes before it expires", {
  claims <- jwt_decode(
    rfc7519_jwt(),
    rfc7515_key(),
    algorithms = "HS256",
    now = as_posixct(1300819000)
  )
  expect_s3_class(claims, "jwt_claims")
  expect_identical(claims$iss, "joe")
  expect_identical(claims$exp, as_posixct(1300819380))
  expect_true(claims[["http://example.com/is_root"]])
  expect_identical(attr(claims, "header"), list(typ = "JWT", alg = "HS256"))
})

test_that("RFC 7519 §3.1 is expired now", {
  err <- expect_error(
    jwt_decode(rfc7519_jwt(), rfc7515_key(), algorithms = "HS256"),
    class = "zujose_expired_error"
  )
  expect_s3_class(err, "zujose_claim_error")
  expect_identical(err$claim, "exp")
  expect_identical(err$time, as_posixct(1300819380))
  expect_s3_class(err$now, "POSIXct")
})

test_that("RFC 7519 §6.1, the unsecured JWT, is refused", {
  unsecured <- paste0(
    "eyJhbGciOiJub25lIn0.",
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
  )
  expect_error(
    jwt_decode(
      unsecured,
      rfc7515_key(),
      "HS256",
      now = as_posixct(1300819000)
    ),
    class = "zujose_policy_error"
  )
})

# Encoding ----------------------------------------------------------------

test_that("encode and decode round-trip, with times", {
  key <- jwk_oct(as.raw(1:32), kid = "k")
  local_mocked_bindings(jwt_now = function() 1800000000)
  jwt <- jwt_encode(
    list(sub = "u1", aud = "api", roles = c("a", "b")),
    key,
    "HS256",
    expires_in = as.difftime(1, units = "hours"),
    not_before = 0
  )
  claims <- jwt_decode(
    jwt,
    key,
    "HS256",
    audience = "api",
    subject = "u1",
    now = as_posixct(1800000010)
  )
  expect_identical(claims$exp, as_posixct(1800003600))
  expect_identical(claims$nbf, as_posixct(1800000000))
  expect_identical(claims$iat, as_posixct(1800000000))
  expect_identical(claims$roles, list("a", "b"))
  expect_identical(
    attr(claims, "header"),
    list(alg = "HS256", kid = "k", typ = "JWT")
  )
})

test_that("POSIXct claims are written as NumericDate", {
  key <- jwk_oct(as.raw(1:32))
  jwt <- jwt_encode(
    list(exp = as_posixct(2000000000.7), iat = as_posixct(1)),
    key,
    "HS256"
  )
  claims <- jose_peek(jwt)$claims
  expect_identical(claims$exp, 2000000000L)
  expect_identical(claims$iat, 1L)
})

test_that("issued_at, header and empty claims behave", {
  key <- jwk_oct(as.raw(1:32))
  jwt <- jwt_encode(list(), key, "HS256", issued_at = FALSE, header = NULL)
  peek <- jose_peek(jwt)
  expect_identical(peek$claims, structure(list(), names = character()))
  expect_identical(peek$headers[[1]], list(alg = "HS256"))
})

test_that("jwt_encode() refuses bad arguments", {
  key <- jwk_oct(as.raw(1:32))
  expect_error(
    jwt_encode(list(1), key, "HS256"),
    class = "zujose_argument_error"
  )
  expect_error(
    jwt_encode(list(a = 1, a = 2), key, "HS256"),
    class = "zujose_argument_error"
  )
  expect_error(jwt_encode("x", key, "HS256"), class = "zujose_argument_error")
  expect_error(
    jwt_encode(list(), key, "HS256", expires_in = "1h"),
    class = "zujose_argument_error"
  )
  expect_error(
    jwt_encode(list(exp = "soon"), key, "HS256"),
    class = "zujose_argument_error"
  )
  expect_error(
    jwt_encode(list(), key, "HS256", issued_at = NA),
    class = "zujose_argument_error"
  )
  expect_error(
    jwt_encode(list(), key, "HS256", jti = NA),
    class = "zujose_argument_error"
  )
})

test_that("jti = TRUE adds a random identifier, unless the claims set one", {
  key <- jwk_oct(as.raw(1:32))
  jti_of <- function(jwt) {
    jwt_decode(jwt, key, "HS256", required = character())$jti
  }
  a <- jti_of(jwt_encode(list(), key, "HS256", jti = TRUE))
  b <- jti_of(jwt_encode(list(), key, "HS256", jti = TRUE))
  # 128 random bits, as unpadded Base64url.
  expect_match(a, "^[A-Za-z0-9_-]{22}$")
  expect_false(identical(a, b))
  expect_identical(
    jti_of(jwt_encode(list(jti = "mine"), key, "HS256", jti = TRUE)),
    "mine"
  )
  expect_null(jti_of(jwt_encode(list(), key, "HS256")))
})

# Claim checks (design §8.5) ----------------------------------------------

test_that("expiry and not-before allow the leeway, and no more", {
  expect_no_error(decode_at_1000(list(exp = 950)))
  expect_error(decode_at_1000(list(exp = 940)), class = "zujose_expired_error")
  expect_error(
    decode_at_1000(list(exp = 999), leeway = 0),
    class = "zujose_expired_error"
  )
  expect_error(
    decode_at_1000(list(exp = 1000), leeway = 0),
    class = "zujose_expired_error"
  )
  expect_no_error(decode_at_1000(list(exp = 1001), leeway = 0))

  expect_no_error(decode_at_1000(list(nbf = 1060)))
  err <- expect_error(
    decode_at_1000(list(nbf = 1061)),
    class = "zujose_not_yet_valid_error"
  )
  expect_identical(err$claim, "nbf")
})

test_that("iat in the future and max_age are checked", {
  expect_no_error(decode_at_1000(list(iat = 1060)))
  err <- expect_error(
    decode_at_1000(list(iat = 1061)),
    class = "zujose_not_yet_valid_error"
  )
  expect_identical(err$claim, "iat")

  expect_no_error(decode_at_1000(list(iat = 900), max_age = 100))
  err <- expect_error(
    decode_at_1000(list(iat = 800), max_age = 100),
    class = "zujose_expired_error"
  )
  expect_identical(err$claim, "iat")
  expect_error(
    decode_at_1000(list(), max_age = 100),
    class = "zujose_missing_claim_error"
  )
})

test_that("time claims must be numbers", {
  key <- jwk_oct(as.raw(1:32))
  # jwt_encode() refuses these, so they are signed as raw payloads. A
  # JSON null is not a missing claim.
  for (payload in c('{"exp":"2030-01-01"}', '{"nbf":[1]}', '{"exp":null}')) {
    jwt <- jws_sign(payload, key, "HS256", header = list(typ = "JWT"))
    expect_error(
      jwt_decode(jwt, key, "HS256", required = character()),
      class = "zujose_parse_error",
      info = payload
    )
  }
})

test_that("exp is required by default", {
  key <- jwk_oct(as.raw(1:32))
  jwt <- jwt_encode(list(sub = "u"), key, "HS256")
  err <- expect_error(
    jwt_decode(jwt, key, "HS256"),
    class = "zujose_missing_claim_error"
  )
  expect_identical(err$claim, "exp")
  expect_no_error(jwt_decode(jwt, key, "HS256", required = character()))
  expect_error(
    decode_at_1000(list(a = 1), required = c("a", "b")),
    class = "zujose_missing_claim_error"
  )
})

test_that("issuer and subject are exact single-string matches", {
  expect_no_error(decode_at_1000(list(iss = "me"), issuer = "me"))
  expect_error(
    decode_at_1000(list(iss = "me2"), issuer = "me"),
    class = "zujose_issuer_error"
  )
  expect_error(
    decode_at_1000(list(iss = "Me"), issuer = "me"),
    class = "zujose_issuer_error"
  )
  expect_error(
    decode_at_1000(list(), issuer = "me"),
    class = "zujose_missing_claim_error"
  )
  # An array is never a membership test.
  expect_error(
    decode_at_1000(list(iss = list("me", "x")), issuer = "me"),
    class = "zujose_issuer_error"
  )
  expect_error(
    decode_at_1000(list(iss = list("me"))),
    class = "zujose_issuer_error"
  )

  expect_no_error(decode_at_1000(list(sub = "u"), subject = "u"))
  expect_error(
    decode_at_1000(list(sub = "v"), subject = "u"),
    class = "zujose_subject_error"
  )
  expect_error(decode_at_1000(list(sub = 1)), class = "zujose_subject_error")
})

test_that("aud must contain one of audience", {
  expect_no_error(decode_at_1000(list(aud = "api"), audience = "api"))
  expect_no_error(decode_at_1000(
    list(aud = list("x", "api")),
    audience = c("api", "web")
  ))
  expect_error(
    decode_at_1000(list(aud = "x"), audience = "api"),
    class = "zujose_audience_error"
  )
  expect_error(
    decode_at_1000(list(), audience = "api"),
    class = "zujose_missing_claim_error"
  )
  # RFC 7519 §4.1.3: a token with an audience needs a caller who names one.
  err <- expect_error(
    decode_at_1000(list(aud = "api")),
    class = "zujose_audience_error"
  )
  expect_identical(err$claim, "aud")
  expect_error(
    decode_at_1000(list(aud = list())),
    class = "zujose_audience_error"
  )
  expect_error(
    decode_at_1000(list(aud = list(1))),
    class = "zujose_audience_error"
  )
})

test_that("claims holds values and predicates", {
  expect_no_error(decode_at_1000(
    list(scope = "read write"),
    claims = list(scope = "read write")
  ))
  expect_no_error(decode_at_1000(list(n = 3), claims = list(n = 3L)))
  expect_no_error(decode_at_1000(
    list(r = c("a", "b")),
    claims = list(r = c("a", "b"))
  ))
  expect_error(
    decode_at_1000(list(n = 4), claims = list(n = 3)),
    class = "zujose_claim_error"
  )
  has_read <- function(scope) "read" %in% strsplit(scope, " ")[[1]]
  expect_no_error(decode_at_1000(
    list(scope = "read write"),
    claims = list(scope = has_read)
  ))
  err <- expect_error(
    decode_at_1000(list(scope = "write"), claims = list(scope = has_read)),
    class = "zujose_claim_error"
  )
  expect_identical(err$claim, "scope")
  expect_error(
    decode_at_1000(list(), claims = list(scope = has_read)),
    class = "zujose_missing_claim_error"
  )
})

test_that("validate sees every claim", {
  ok <- function(cl) cl$nbf < cl$exp
  expect_no_error(decode_at_1000(list(nbf = 900, exp = 1100), validate = ok))
  expect_error(
    decode_at_1000(list(nbf = 1050, exp = 1040), validate = ok, leeway = 100),
    class = "zujose_claim_error"
  )
})

test_that("typ must match type", {
  expect_no_error(decode_at_1000(
    list(),
    header = list(typ = "at+jwt"),
    type = "at+jwt"
  ))
  expect_no_error(decode_at_1000(
    list(),
    header = list(typ = "application/AT+JWT"),
    type = "at+jwt"
  ))
  expect_no_error(decode_at_1000(list(), header = NULL))
  expect_no_error(decode_at_1000(list(), header = list(typ = "x"), type = NULL))
  expect_error(
    decode_at_1000(list(), header = list(typ = "JWT"), type = "at+jwt"),
    class = "zujose_policy_error"
  )
  expect_error(
    decode_at_1000(list(), header = NULL, type = "at+jwt"),
    class = "zujose_policy_error"
  )
})

test_that("claims must be a JSON object", {
  key <- jwk_oct(as.raw(1:32))
  for (payload in c("[1]", "not json", '{"a":1,"a":2}')) {
    jwt <- jws_sign(payload, key, "HS256")
    expect_error(
      jwt_decode(jwt, key, "HS256", required = character()),
      class = "zujose_parse_error",
      info = payload
    )
  }
})

# Shape of the token ------------------------------------------------------

test_that("a nested JWT is unwrapped one level", {
  key <- jwk_oct(as.raw(1:32))
  inner <- jwt_encode(list(sub = "u", exp = 2e9), key, "HS256")
  outer <- jws_sign(inner, key, "HS256", header = list(cty = "JWT"))
  expect_identical(jwt_decode(outer, key, "HS256")$sub, "u")

  # The inner token must use an allowed algorithm too.
  inner512 <- jwt_encode(
    list(exp = 2e9),
    jwk_oct(as.raw(1:64)),
    "HS512"
  )
  outer <- jws_sign(inner512, key, "HS256", header = list(cty = "JWT"))
  expect_error(
    jwt_decode(outer, key, "HS256"),
    class = "zujose_policy_error"
  )

  twice <- jws_sign(
    jws_sign(inner, key, "HS256", header = list(cty = "JWT")),
    key,
    "HS256",
    header = list(cty = "JWT")
  )
  expect_error(
    jwt_decode(twice, key, "HS256"),
    class = "zujose_policy_error"
  )
})

test_that("only the compact JWS serialization is a JWT", {
  key <- jwk_oct(as.raw(1:32))
  json <- jws_sign('{"exp":2000000000}', key, "HS256", format = "flattened")
  expect_error(jwt_decode(json, key, "HS256"), class = "zujose_parse_error")
  expect_error(
    jwt_decode(rfc7520_token(81), key, "HS256"),
    class = "zujose_policy_error"
  )
})

test_that("signature checks come first", {
  key <- jwk_oct(as.raw(1:32))
  jwt <- jwt_encode(list(exp = 1), jwk_oct(as.raw(2:33)), "HS256")
  expect_error(
    jwt_decode(jwt, key, "HS256"),
    class = "zujose_signature_error"
  )
  expect_error(jwt_decode(jwt, key), "algorithms")
})

test_that("jwt_decode() refuses bad arguments", {
  key <- jwk_oct(as.raw(1:32))
  jwt <- jwt_encode(list(), key, "HS256", expires_in = 60)
  decode <- function(...) jwt_decode(jwt, key, "HS256", ...)
  expect_error(decode(audience = 1), class = "zujose_argument_error")
  expect_error(decode(issuer = c("a", "b")), class = "zujose_argument_error")
  expect_error(decode(type = NA_character_), class = "zujose_argument_error")
  expect_error(decode(required = NA), class = "zujose_argument_error")
  expect_error(decode(claims = list(1)), class = "zujose_argument_error")
  expect_error(decode(validate = TRUE), class = "zujose_argument_error")
  expect_error(decode(max_age = -1), class = "zujose_argument_error")
  expect_error(decode(leeway = NA), class = "zujose_argument_error")
  expect_error(decode(now = 1000), class = "zujose_argument_error")
})

# The decoder -------------------------------------------------------------

test_that("jwt_decoder() applies the same checks every time", {
  key <- jwk_oct(as.raw(1:32))
  check_token <- jwt_decoder(key, "HS256", audience = "api", issuer = "me")
  good <- jwt_encode(
    list(iss = "me", aud = "api"),
    key,
    "HS256",
    expires_in = 60
  )
  bad <- jwt_encode(
    list(iss = "you", aud = "api"),
    key,
    "HS256",
    expires_in = 60
  )
  expect_identical(check_token(good)$iss, "me")
  expect_error(check_token(bad), class = "zujose_issuer_error")
  expect_error(
    check_token(good, now = Sys.time() + 3600),
    class = "zujose_expired_error"
  )
  expect_error(jwt_decoder(key, "none"), class = "zujose_policy_error")
  expect_error(
    jwt_decoder(key, "HS256", leeway = -1),
    class = "zujose_argument_error"
  )
})

test_that("an error's call never holds the token's text", {
  key <- jwk_oct(as.raw(1:32))
  check_token <- jwt_decoder(key, "HS256")
  jwt <- jwt_encode(list(), key, "HS256", expires_in = -3600)
  err <- expect_error(check_token(jwt), class = "zujose_expired_error")
  expect_no_match(
    paste(deparse(conditionCall(err)), collapse = ""),
    jwt,
    fixed = TRUE
  )
})

test_that("printing claims shows times in UTC", {
  key <- jwk_oct(as.raw(1:32), kid = "k")
  local_mocked_bindings(jwt_now = function() 1800000000)
  jwt <- jwt_encode(list(sub = "u1"), key, "HS256", expires_in = 60)
  expect_snapshot(print(jwt_decode(
    jwt,
    key,
    "HS256",
    now = as_posixct(1800000000)
  )))
})

test_that("a token that is not a single string is a parse error", {
  key <- jwk_oct(as.raw(1:32))
  for (token in list(
    NA_character_,
    123,
    c("a.b.c", "d.e.f"),
    NULL,
    character()
  )) {
    expect_error(jwt_decode(token, key, "HS256"), class = "zujose_parse_error")
  }
})

test_that("printing claims reads `kid` by its exact name (#122)", {
  key <- jwk_oct(as.raw(1:32))
  jwt <- jwt_encode(
    list(sub = "u"),
    key,
    "HS256",
    header = list(typ = "JWT", kidnap = "zzz")
  )
  claims <- jwt_decode(jwt, key, "HS256", required = character())
  expect_no_match(capture_output(print(claims)), "zzz", fixed = TRUE)
})

test_that("claims with repeated, NA or empty names are refused (#119)", {
  key <- jwk_oct(as.raw(1:32))
  bad <- list(
    list(o = c(a = 1, a = 2)),
    list(o = list(a = 1, a = 2)),
    list(o = list(p = list(a = 1, a = 2))),
    stats::setNames(list(1), NA),
    list(o = stats::setNames(list(1), NA)),
    list(o = list(a = 1, 2)),
    data.frame(a = 1:2),
    list(1, 2)
  )
  for (claims in bad) {
    expect_error(
      jwt_encode(claims, key, "HS256"),
      class = "zujose_argument_error"
    )
  }
})

test_that("a claim value JSON cannot represent is an argument error (#123)", {
  key <- jwk_oct(as.raw(1:32))
  for (value in list(as.raw(1), 1i, list(a = 1i))) {
    expect_error(
      jwt_encode(list(a = value), key, "HS256"),
      class = "zujose_argument_error"
    )
  }
})
