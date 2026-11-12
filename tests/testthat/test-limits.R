test_that("jose_limits() has the documented defaults", {
  limits <- jose_limits()
  expect_s3_class(limits, "jose_limits")
  expect_identical(
    unclass(limits),
    list(
      token = 2^21,
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
    expect_error(jose_limits(token = bad), class = "zujose_argument_error")
  }
})

test_that("jose_limits() prints every limit", {
  expect_snapshot(print(jose_limits(signatures = 2)))
})

test_that("a token is checked against `limits` that are not jose_limits", {
  expect_error(
    jose_peek("a.b.c", limits = list(token = 10)),
    class = "zujose_argument_error"
  )
})

test_that("the header and payload limits are exact in bytes", {
  key <- jwk_oct(as.raw(1:32))
  token <- jws_sign("abcdef", key, alg = "HS256")
  header <- nchar('{"alg":"HS256"}')
  expect_no_error(
    jws_verify(token, key, "HS256", limits = jose_limits(header = header))
  )
  expect_error(
    jws_verify(token, key, "HS256", limits = jose_limits(header = header - 1)),
    class = "zujose_parse_error"
  )
  expect_no_error(
    jws_verify(token, key, "HS256", limits = jose_limits(payload = 6))
  )
  expect_error(
    jws_verify(token, key, "HS256", limits = jose_limits(payload = 5)),
    class = "zujose_parse_error"
  )
  json <- jws_sign("abcdef", key, alg = "HS256", format = "flattened")
  expect_error(
    jws_verify(json, key, "HS256", limits = jose_limits(payload = 4)),
    class = "zujose_parse_error"
  )
  part <- strsplit(token, ".", fixed = TRUE)[[1]][[1]]
  header <- length(b64url_decode(part, "header"))
  expect_error(
    jwe_decrypt(
      token,
      key,
      "A128KW",
      "A128GCM",
      limits = jose_limits(header = header - 1)
    ),
    class = "zujose_parse_error"
  )
})

test_that("the payload limit bounds a JWE ciphertext exactly", {
  key <- jwk_oct(as.raw(1:16))
  token <- jwe_encrypt("abcdef", key, alg = "A128KW", enc = "A128GCM")
  expect_no_error(
    jwe_decrypt(
      token,
      key,
      "A128KW",
      "A128GCM",
      limits = jose_limits(payload = 6)
    )
  )
  expect_error(
    jwe_decrypt(
      token,
      key,
      "A128KW",
      "A128GCM",
      limits = jose_limits(payload = 4)
    ),
    class = "zujose_parse_error"
  )
  part <- strsplit(token, ".", fixed = TRUE)[[1]][[1]]
  header <- length(b64url_decode(part, "header"))
  expect_error(
    jwe_decrypt(
      token,
      key,
      "A128KW",
      "A128GCM",
      limits = jose_limits(header = header - 1)
    ),
    class = "zujose_parse_error"
  )
})

test_that("a payload at the default limit fits the default token limit", {
  key <- jwk_oct(as.raw(1:32))
  payload <- as.raw(rep_len(0:255, 2^20))
  token <- jws_sign(payload, key, alg = "HS256")
  expect_identical(jws_verify(token, key, "HS256")$payload, payload)
  token <- jwe_encrypt(payload, key, alg = "dir", enc = "A256GCM")
  expect_identical(jwe_decrypt(token, key, "dir", "A256GCM")$plaintext, payload)
})

test_that("jose_limits() prints the same under a comma decimal mark", {
  withr::local_options(OutDec = ",", warn = 2)
  expect_snapshot(print(jose_limits(token = Inf)))
})
