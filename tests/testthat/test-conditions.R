test_that("every kind inherits from zujose_error, error and condition", {
  kinds <- c("parse", "policy", "key", "signature", "claim")
  for (kind in kinds) {
    err <- expect_error(
      abort_zujose(kind, "Something is wrong."),
      class = paste0("zujose_", kind, "_error")
    )
    expect_s3_class(err, c("zujose_error", "error", "condition"))
    expect_identical(
      class(err),
      c(paste0("zujose_", kind, "_error"), "zujose_error", "error", "condition")
    )
  }
})

test_that("extra fields are kept on the condition", {
  err <- expect_error(
    abort_zujose("claim", "The token has expired.", claim = "exp"),
    class = "zujose_claim_error"
  )
  expect_identical(err$claim, "exp")
})

test_that("an unknown kind is a programming error, not a zujose_error", {
  expect_error(abort_zujose("nonsense", "x"), "kind")
  expect_false(inherits(
    tryCatch(abort_zujose("nonsense", "x"), error = identity),
    "zujose_error"
  ))
})

test_that("the call is recorded when given", {
  f <- function() abort_zujose("parse", "Bad token.", call = sys.call())
  err <- expect_error(f(), class = "zujose_parse_error")
  expect_identical(err$call, quote(f()))
})

test_that("decryption failures share one class and one message", {
  a <- expect_error(abort_decrypt(), class = "zujose_decrypt_error")
  b <- expect_error(abort_decrypt(), class = "zujose_decrypt_error")
  expect_s3_class(a, "zujose_error")
  expect_identical(conditionMessage(a), conditionMessage(b))
  # No field may carry a detail of the failure.
  raw_condition <- tryCatch(abort_decrypt(), error = identity)
  expect_named(raw_condition, c("message", "call"))
})

test_that("unsupported algorithms name the zucrypt version they need", {
  err <- expect_error(
    abort_unsupported("RS256", "0.1.1"),
    class = "zujose_unsupported_error"
  )
  expect_s3_class(err, "zujose_error")
  expect_identical(err$algorithm, "RS256")
  expect_identical(err$needs, "0.1.1")
  expect_snapshot(conditionMessage(err))
})

test_that("claim errors have a leaf class under zujose_claim_error", {
  for (leaf in claim_leaves) {
    err <- expect_error(
      abort_claim(leaf, "No.", claim = "exp"),
      class = paste0("zujose_", leaf, "_error")
    )
    expect_s3_class(err, c("zujose_claim_error", "zujose_error"))
    expect_identical(err$claim, "exp")
  }
  err <- expect_error(
    abort_claim(NULL, "No.", claim = "x"),
    class = "zujose_claim_error"
  )
  expect_identical(class(err)[[1]], "zujose_claim_error")
  expect_error(
    abort_claim("late", "No.", claim = "x"),
    "leaf"
  )
})

test_that("argument errors are zujose errors", {
  key <- jwk_oct(as.raw(1:32), alg = "HS256")
  err <- expect_error(
    jws_sign("x", key, format = "compact", unprotected = list(a = 1)),
    class = "zujose_argument_error"
  )
  expect_s3_class(err, "zujose_error")
  expect_error(
    jws_verify(jws_sign("x", key), key, "HS256", limits = list()),
    class = "zujose_error"
  )
})

test_that("argument errors say which argument is wrong", {
  key <- jwk_oct(as.raw(1:32), alg = "HS256")
  kek <- jwk_oct(as.raw(1:16))
  expect_snapshot(error = TRUE, {
    jws_sign("x", key, format = "compact", unprotected = list(a = 1))
    jwe_encrypt("x", kek, "A128KW", header = list(epk = list()))
    jwt_decode(jwt_encode(list(), key), key, "HS256", leeway = "a")
    jose_limits(token = 0)
    jwk_thumbprint(key, uri = NA)
  })
})

test_that("a bad format or require is an argument error", {
  # These used match.arg(), which raised an unclassed error (#70).
  key <- jwk_oct(as.raw(1:32), alg = "HS256")
  kek <- jwk_oct(as.raw(1:16))
  token <- jws_sign("x", key)
  for (bad in list("bogus", NA_character_, 1, c("compact", "general"))) {
    expect_error(
      jws_sign("x", key, format = bad),
      class = "zujose_argument_error"
    )
    expect_error(
      jwe_encrypt("x", kek, "A128KW", format = bad),
      class = "zujose_argument_error"
    )
    expect_error(
      jws_verify(token, key, "HS256", require = bad),
      class = "zujose_argument_error"
    )
  }
  # The defaults and every valid choice still work.
  expect_true(is.character(jws_sign("x", key, format = "general")))
  expect_true(is.character(jwe_encrypt(
    "x",
    kek,
    "A128KW",
    format = "flattened"
  )))
  expect_s3_class(
    jws_verify(token, key, "HS256", require = "any"),
    "jws_verified"
  )
  expect_snapshot(jws_sign("x", key, format = "bogus"), error = TRUE)
})
