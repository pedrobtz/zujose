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
    abort_unsupported("RS256", "0.4.0"),
    class = "zujose_unsupported_error"
  )
  expect_s3_class(err, "zujose_error")
  expect_identical(err$algorithm, "RS256")
  expect_identical(err$needs, "0.4.0")
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
  expect_error(abort_claim("late", "No.", claim = "x"), "leaf")
})
