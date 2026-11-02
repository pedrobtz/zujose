test_that("jose_limits() has the documented defaults", {
  limits <- jose_limits()
  expect_s3_class(limits, "jose_limits")
  expect_identical(
    unclass(limits),
    list(
      token = 2^20,
      header = 2^14,
      payload = 2^20,
      signatures = 16,
      recipients = 16,
      keys = 16,
      p2c = 600000
    )
  )
})

test_that("limits must be whole numbers of at least 1, or Inf", {
  expect_no_error(jose_limits(token = Inf, keys = 1))
  for (bad in list(0, -1, 1.5, NA_real_, "10", c(1, 2), NULL)) {
    expect_error(jose_limits(token = bad), "token")
  }
})

test_that("jose_limits() prints every limit", {
  expect_snapshot(print(jose_limits(signatures = 2)))
})

test_that("a token is checked against `limits` that are not jose_limits", {
  expect_error(jose_peek("a.b.c", limits = list(token = 10)), "jose_limits")
})
