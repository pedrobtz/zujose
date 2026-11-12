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

test_that("a JWS shows each signature and the bytes it covers", {
  token <- rfc7519_jwt()
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  peek <- jose_peek(token)
  expect_identical(peek$signatures, list(b64url_decode(parts[[3]], "part")))
  expect_identical(
    peek$signing_input,
    list(charToRaw(paste0(parts[[1]], ".", parts[[2]])))
  )
})

test_that("a general JWS has one signature per header", {
  peek <- jose_peek(rfc7520_token(71))
  expect_length(peek$signatures, length(peek$headers))
  expect_length(peek$signing_input, length(peek$headers))
})

test_that("a detached payload has no signing input", {
  peek <- jose_peek(rfc7520_token(43))
  expect_null(peek$payload)
  expect_null(peek$signing_input[[1]])
  expect_type(peek$signatures[[1]], "raw")
})

test_that("a compact and a flattened detached JWS peek alike (#131)", {
  key <- jwk_oct(as.raw(1:32))
  compact <- jose_peek(jws_sign("hello", key, "HS256", detached = TRUE))
  flattened <- jose_peek(jws_sign(
    "hello",
    key,
    "HS256",
    detached = TRUE,
    format = "flattened"
  ))
  expect_null(compact$payload)
  expect_null(compact$signing_input[[1]])
  expect_identical(compact$payload, flattened$payload)
  expect_identical(compact$signing_input, flattened$signing_input)
})

test_that("a JWE shows its encrypted keys, IV, ciphertext and tag", {
  token <- rfc7520_token(81)
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  peek <- jose_peek(token)
  expect_identical(peek$encrypted_keys, list(b64url_decode(parts[[2]], "part")))
  expect_identical(peek$iv, b64url_decode(parts[[3]], "part"))
  expect_identical(peek$ciphertext, b64url_decode(parts[[4]], "part"))
  expect_identical(peek$tag, b64url_decode(parts[[5]], "part"))
  expect_null(peek$aad)
})

test_that("a dir JWE has an empty encrypted key", {
  peek <- jose_peek(rfc7520_token(136))
  expect_identical(peek$encrypted_keys, list(raw()))
})

test_that("a JWE with AAD shows it", {
  peek <- jose_peek(rfc7520_token(183))
  expect_type(peek$aad, "raw")
  expect_gt(length(peek$aad), 0L)
})

test_that("jose_peek() refuses a malformed token", {
  expect_error(jose_peek("a.b"), class = "zujose_parse_error")
})

test_that("printing says the token is not verified", {
  expect_snapshot(print(jose_peek(rfc7519_jwt())))
  expect_snapshot(print(jose_peek(rfc7520_token(81))))
  expect_snapshot(print(jose_peek(rfc7520_token(183))))
})
