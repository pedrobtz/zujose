test_that("every kind inherits from zujwt_error, error and condition", {
  kinds <- c("parse", "policy", "key", "signature", "claim")
  for (kind in kinds) {
    err <- expect_error(
      abort_zujwt(kind, "Something is wrong."),
      class = paste0("zujwt_", kind, "_error")
    )
    expect_s3_class(err, c("zujwt_error", "error", "condition"))
    expect_identical(
      class(err),
      c(paste0("zujwt_", kind, "_error"), "zujwt_error", "error", "condition")
    )
  }
})

test_that("extra fields are kept on the condition", {
  err <- expect_error(
    abort_zujwt("claim", "The token has expired.", claim = "exp"),
    class = "zujwt_claim_error"
  )
  expect_identical(err$claim, "exp")
})

test_that("an unknown kind is a programming error, not a zujwt_error", {
  expect_error(abort_zujwt("nonsense", "x"), "kind")
  expect_false(inherits(
    tryCatch(abort_zujwt("nonsense", "x"), error = identity),
    "zujwt_error"
  ))
})

test_that("the call is recorded when given", {
  f <- function() abort_zujwt("parse", "Bad token.", call = sys.call())
  err <- expect_error(f(), class = "zujwt_parse_error")
  expect_identical(err$call, quote(f()))
})

test_that("decryption failures share one class and one message", {
  a <- expect_error(abort_decrypt(), class = "zujwt_decrypt_error")
  b <- expect_error(abort_decrypt(), class = "zujwt_decrypt_error")
  expect_s3_class(a, "zujwt_error")
  expect_identical(conditionMessage(a), conditionMessage(b))
  # No field may carry a detail of the failure.
  raw_condition <- tryCatch(abort_decrypt(), error = identity)
  expect_named(raw_condition, c("message", "call"))
})

test_that("unsupported algorithms name the zucrypt version they need", {
  err <- expect_error(
    abort_unsupported("RS256", "0.4.0"),
    class = "zujwt_unsupported_error"
  )
  expect_s3_class(err, "zujwt_error")
  expect_identical(err$algorithm, "RS256")
  expect_identical(err$needs, "0.4.0")
  expect_snapshot(conditionMessage(err))
})
