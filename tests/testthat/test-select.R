test_that("a key set is narrowed by kid, then by algorithm", {
  set <- jose_keyset(
    jose_key_oct(as.raw(1), kid = "a"),
    jose_key_oct(as.raw(2), kid = "b"),
    as_jose_key(rfc7520_key(3))
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
    as_jose_keyset(rfc7520_jwks())
  }
  header <- list(alg = "HS256", kid = "018c0ae5-4d9b-471b-bfd6-eef314bc7037")
  picked <- resolve_keys(resolver, header, "verify", jose_limits())
  expect_identical(seen, header)
  expect_identical(picked, list(as_jose_key(rfc7520_key(5))))
})

test_that("a resolver must return a key or key set", {
  expect_error(
    resolve_keys(
      function(h) "key",
      list(alg = "HS256"),
      "verify",
      jose_limits()
    ),
    class = "zujwt_key_error"
  )
  expect_error(
    resolve_keys("key", list(alg = "HS256"), "verify", jose_limits()),
    class = "zujwt_key_error"
  )
})

test_that("a single key that does not fit is a policy error", {
  verify <- function(key, alg = "HS256") {
    resolve_keys(key, list(alg = alg), "verify", jose_limits())
  }
  expect_length(verify(jose_key_oct(as.raw(1))), 1L)
  # The wrong key type, algorithm, use or operations (design §8.2).
  expect_error(
    verify(jose_key_oct(as.raw(1)), "RS256"),
    class = "zujwt_policy_error"
  )
  expect_error(
    verify(jose_key_oct(as.raw(1)), "none"),
    class = "zujwt_policy_error"
  )
  expect_error(
    verify(jose_key_oct(as.raw(1), alg = "HS512")),
    class = "zujwt_policy_error"
  )
  expect_error(
    verify(jose_key_oct(as.raw(1), use = "enc")),
    class = "zujwt_policy_error"
  )
  expect_error(
    verify(jose_key_oct(as.raw(1), key_ops = "sign")),
    class = "zujwt_policy_error"
  )
  expect_length(
    verify(jose_key_oct(as.raw(1), key_ops = c("sign", "verify"))),
    1L
  )
})

test_that("a single key is used whatever kid the token names", {
  key <- jose_key_oct(as.raw(1), kid = "mine")
  picked <- resolve_keys(
    key,
    list(alg = "HS256", kid = "other"),
    "verify",
    jose_limits()
  )
  expect_identical(picked, list(key))
})

test_that("no fitting key in a set is a key error", {
  set <- jose_keyset(jose_key_oct(as.raw(1), kid = "a"))
  expect_error(
    resolve_keys(set, list(alg = "HS256", kid = "b"), "verify", jose_limits()),
    class = "zujwt_key_error"
  )
  expect_error(
    resolve_keys(jose_keyset(), list(alg = "HS256"), "verify", jose_limits()),
    class = "zujwt_key_error"
  )
})

test_that("keys zujwt cannot use yet raise zujwt_unsupported_error", {
  set <- as_jose_keyset(rfc7520_jwks())
  err <- expect_error(
    resolve_keys(
      set,
      list(alg = "ES512", kid = "bilbo.baggins@hobbiton.example"),
      "verify",
      jose_limits()
    ),
    class = "zujwt_unsupported_error"
  )
  expect_identical(err$needs, "0.5.0")
})

test_that("more fitting keys than limits$keys is a key error", {
  set <- do.call(jose_keyset, lapply(1:3, function(i) jose_key_oct(as.raw(i))))
  expect_length(
    resolve_keys(set, list(alg = "HS256"), "verify", jose_limits(keys = 3)),
    3L
  )
  expect_error(
    resolve_keys(set, list(alg = "HS256"), "verify", jose_limits(keys = 2)),
    class = "zujwt_key_error"
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
