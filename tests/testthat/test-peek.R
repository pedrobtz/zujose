test_that("jose_peek() returns the header and claims of a JWT", {
  peek <- jose_peek(rfc7519_jwt())
  expect_s3_class(peek, "jose_unverified")
  expect_identical(peek$type, "JWS")
  expect_identical(peek$serialization, "compact")
  expect_identical(peek$headers, list(list(typ = "JWT", alg = "HS256")))
  expect_identical(peek$claims$iss, "joe")
  expect_equal(peek$claims$exp, 1300819380)
  expect_true(peek$claims[["http://example.com/is_root"]])
})

test_that("a payload that is not a JSON object has no claims", {
  peek <- jose_peek(rfc7520_token(13))
  expect_null(peek$claims)
  expect_type(peek$payload, "raw")
})

test_that("a JWE shows one merged header per recipient and no payload", {
  peek <- jose_peek(rfc7520_token(221))
  expect_identical(peek$type, "JWE")
  expect_length(peek$headers, 3L)
  for (header in peek$headers) {
    expect_true(all(c("alg", "enc") %in% names(header)))
  }
  expect_null(peek$payload)
  expect_null(peek$claims)
})

test_that("jose_peek() refuses a malformed token", {
  expect_error(jose_peek("a.b"), class = "zujose_parse_error")
})

test_that("printing says the token is not verified", {
  expect_snapshot(print(jose_peek(rfc7519_jwt())))
  expect_snapshot(print(jose_peek(rfc7520_token(81))))
})
