test_that("a key set is narrowed by kid, then by algorithm", {
  set <- jwk_set(
    jwk_oct(as.raw(1), kid = "a"),
    jwk_oct(as.raw(2), kid = "b"),
    as_jwk(rfc7520_key(3))
  )
  picked <- resolve_keys(
    set,
    list(alg = "HS256", kid = "b"),
    "verify",
    jose_limits()
  )
  expect_length(picked, 1L)
  expect_identical(picked[[1]]$kid, "b")

  # Without a kid, every key that fits the algorithm is a candidate.
  picked <- resolve_keys(set, list(alg = "HS256"), "verify", jose_limits())
  expect_identical(vapply(picked, `[[`, "", "kid"), c("a", "b"))
})

test_that("a resolver that returns a key set selects by kid", {
  seen <- NULL
  resolver <- function(header) {
    seen <<- header
    as_jwk_set(rfc7520_jwks())
  }
  header <- list(alg = "HS256", kid = "018c0ae5-4d9b-471b-bfd6-eef314bc7037")
  picked <- resolve_keys(resolver, header, "verify", jose_limits())
  expect_identical(seen, header)
  expect_identical(picked, list(as_jwk(rfc7520_key(5))))
})

test_that("a resolver must return a key or key set", {
  expect_error(
    resolve_keys(
      function(h) "key",
      list(alg = "HS256"),
      "verify",
      jose_limits()
    ),
    class = "zujose_key_error"
  )
  expect_error(
    resolve_keys("key", list(alg = "HS256"), "verify", jose_limits()),
    class = "zujose_key_error"
  )
})

test_that("a single key that does not fit is a policy error", {
  verify <- function(key, alg = "HS256") {
    resolve_keys(key, list(alg = alg), "verify", jose_limits())
  }
  expect_length(verify(jwk_oct(as.raw(1))), 1L)
  # The wrong key type, algorithm, use or operations (design §8.2).
  expect_error(
    verify(jwk_oct(as.raw(1)), "RS256"),
    class = "zujose_policy_error"
  )
  expect_error(
    verify(jwk_oct(as.raw(1)), "none"),
    class = "zujose_policy_error"
  )
  expect_error(
    verify(jwk_oct(as.raw(1), alg = "HS512")),
    class = "zujose_policy_error"
  )
  expect_error(
    verify(jwk_oct(as.raw(1), use = "enc")),
    class = "zujose_policy_error"
  )
  expect_error(
    verify(jwk_oct(as.raw(1), key_ops = "sign")),
    class = "zujose_policy_error"
  )
  expect_length(
    verify(jwk_oct(as.raw(1), key_ops = c("sign", "verify"))),
    1L
  )
})

test_that("a single key is used whatever kid the token names", {
  key <- jwk_oct(as.raw(1), kid = "mine")
  picked <- resolve_keys(
    key,
    list(alg = "HS256", kid = "other"),
    "verify",
    jose_limits()
  )
  expect_identical(picked, list(key))
})

test_that("no fitting key in a set is a key error", {
  set <- jwk_set(jwk_oct(as.raw(1), kid = "a"))
  expect_error(
    resolve_keys(set, list(alg = "HS256", kid = "b"), "verify", jose_limits()),
    class = "zujose_key_error"
  )
  expect_error(
    resolve_keys(jwk_set(), list(alg = "HS256"), "verify", jose_limits()),
    class = "zujose_key_error"
  )
})

test_that("keys zujose cannot use yet raise zujose_unsupported_error", {
  # With a zucrypt that lacks the curve functions, EC keys are read and kept
  # but not usable.
  local_mocked_bindings(zucrypt_provides = function(version, installed) {
    version != "0.5.0"
  })
  set <- as_jwk_set(rfc7520_jwks())
  err <- expect_error(
    resolve_keys(
      set,
      list(alg = "ES512", kid = "bilbo.baggins@hobbiton.example"),
      "verify",
      jose_limits()
    ),
    class = "zujose_unsupported_error"
  )
  expect_identical(err$needs, "0.5.0")
})

test_that("more fitting keys than limits$keys is a key error", {
  set <- do.call(jwk_set, lapply(1:3, function(i) jwk_oct(as.raw(i))))
  expect_length(
    resolve_keys(set, list(alg = "HS256"), "verify", jose_limits(keys = 3)),
    3L
  )
  expect_error(
    resolve_keys(set, list(alg = "HS256"), "verify", jose_limits(keys = 2)),
    class = "zujose_key_error"
  )
})

test_that("every JWA algorithm maps to its key types", {
  expect_identical(alg_key_types("HS384"), "oct")
  expect_identical(alg_key_types("A192GCMKW"), "oct")
  expect_identical(alg_key_types("PBES2-HS512+A256KW"), "oct")
  expect_identical(alg_key_types("dir"), "oct")
  expect_identical(alg_key_types("PS256"), "RSA")
  expect_identical(alg_key_types("RSA-OAEP-256"), "RSA")
  expect_identical(alg_key_types("ES512"), "EC")
  expect_identical(alg_key_types("ECDH-ES+A128KW"), c("EC", "OKP"))
  expect_identical(alg_key_types("none"), character())
  expect_identical(alg_key_types("HS1"), character())
})

test_that("a weak key in a set is skipped, not fatal", {
  # A provider JWKS may still list a legacy key; without a kid, every key
  # that fits is tried, and a too-weak one must not stop the search (#39).
  good <- jwk_oct(as.raw(1:32))
  token <- jws_sign("x", good, "HS256")
  set <- jwk_set(jwk_oct(as.raw(1:16)), good)
  expect_identical(
    rawToChar(jws_verify(token, set, "HS256")$payload),
    "x"
  )

  rsa <- jwk_generate("RSA")
  token <- jws_sign("x", rsa, "RS256")
  legacy <- as_jwk(oracle_pem("rsa-1024", public = TRUE))
  set <- jwk_set(legacy, jwk_public(rsa))
  expect_identical(
    rawToChar(jws_verify(token, set, "RS256")$payload),
    "x"
  )
})

test_that("a set with only weak keys is still a key error", {
  token <- jws_sign("x", jwk_oct(as.raw(1:32)), "HS256")
  expect_error(
    jws_verify(token, jwk_set(jwk_oct(as.raw(1:16))), "HS256"),
    class = "zujose_key_error"
  )
})
