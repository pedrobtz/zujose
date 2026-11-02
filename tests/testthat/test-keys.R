test_that("jose_key_oct() wraps a raw secret", {
  key <- jose_key_oct(as.raw(1:32), alg = "HS256", kid = "k1", use = "sig")
  expect_s3_class(key, "jose_key")
  expect_identical(key$kty, "oct")
  expect_identical(key$k, as.raw(1:32))
  expect_identical(key$alg, "HS256")
  expect_true(key$supported)
})

test_that("jose_key_oct() refuses what is not a key", {
  for (bad in list("secret", raw(), 1:32, NULL)) {
    expect_error(jose_key_oct(bad), class = "zujwt_key_error")
  }
  expect_error(jose_key_oct(as.raw(1), kid = 1), class = "zujwt_key_error")
  expect_error(
    jose_key_oct(as.raw(1), alg = c("a", "b")),
    class = "zujwt_key_error"
  )
  expect_error(
    jose_key_oct(as.raw(1), key_ops = "fly"),
    class = "zujwt_key_error"
  )
  expect_error(
    jose_key_oct(as.raw(1), key_ops = c("sign", "sign")),
    class = "zujwt_key_error"
  )
})

test_that("printing a key never shows its secret", {
  key <- jose_key_oct(charToRaw("correct horse battery staple!!!!"), kid = "k1")
  out <- paste(capture.output(print(key)), collapse = "\n")
  expect_no_match(out, "horse")
  expect_no_match(out, b64url_encode(key$k), fixed = TRUE)
  expect_snapshot(print(key))
})

test_that("RFC 7520 §3.5 and §3.6 symmetric keys read", {
  mac <- as_jose_key(rfc7520_key(5))
  expect_identical(mac$kty, "oct")
  expect_identical(mac$kid, "018c0ae5-4d9b-471b-bfd6-eef314bc7037")
  expect_identical(mac$use, "sig")
  expect_identical(mac$alg, "HS256")
  expect_length(mac$k, 32L)

  enc <- as_jose_key(rfc7520_key(6))
  expect_identical(enc$alg, "A256GCM")
  expect_length(enc$k, 32L)
})

test_that("RSA, EC and OKP keys read but are marked not usable yet", {
  rsa <- as_jose_key(rfc7520_key(3))
  expect_identical(rsa$kty, "RSA")
  expect_false(rsa$supported)
  expect_identical(rsa$needs, "0.4.0")

  ec <- as_jose_key(rfc7520_key(1))
  expect_identical(ec$members$crv, "P-521")
  expect_identical(ec$needs, "0.5.0")

  okp <- as_jose_key('{"kty":"OKP","crv":"X25519","x":"AAAA"}')
  expect_identical(okp$needs, "0.5.0")
  expect_snapshot(print(rsa))
})

test_that("as_jose_key() accepts a parsed list, a raw secret or a key", {
  parsed <- zujson::json_parse(rfc7520_key(5), simplify = "none")
  expect_identical(as_jose_key(parsed), as_jose_key(rfc7520_key(5)))
  expect_identical(as_jose_key(as.raw(1:4))$k, as.raw(1:4))
  key <- jose_key_oct(as.raw(1:4))
  expect_identical(as_jose_key(key), key)
})

test_that("malformed JWKs are key errors", {
  bad <- c(
    "not json",
    "[1]",
    '{"k":"AAAA"}',
    '{"kty":1}',
    '{"kty":"oct"}',
    '{"kty":"oct","k":""}',
    '{"kty":"oct","k":"AA=="}',
    '{"kty":"oct","k":"AAAA","kid":1}',
    '{"kty":"oct","k":"AAAA","key_ops":"sign"}',
    '{"kty":"oct","k":"AAAA","key_ops":["fly"]}',
    '{"kty":"oct","k":"AAAA","kty":"oct"}',
    '{"kty":"RSA","n":1,"e":"AQAB"}'
  )
  for (text in bad) {
    expect_error(as_jose_key(text), class = "zujwt_key_error", info = text)
  }
  expect_error(as_jose_key(c("a", "b")), class = "zujwt_key_error")
  expect_error(as_jose_key(42), class = "zujwt_key_error")
  expect_error(as_jose_key(list(1, 2)), class = "zujwt_key_error")
})

test_that("PEM is recognised and deferred to the RSA stage", {
  pem <- "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"
  err <- expect_error(as_jose_key(pem), class = "zujwt_unsupported_error")
  expect_identical(err$needs, "0.4.0")
})

test_that("jose_jwk() round-trips every RFC 7520 key", {
  for (figure in c(1:6, 84, 120, 138, 151)) {
    key <- as_jose_key(rfc7520_key(figure))
    again <- as_jose_key(jose_jwk(key, private = TRUE))
    expect_identical(again, key, info = figure)
  }
})

test_that("jose_jwk() writes only public members by default", {
  rsa <- as_jose_key(rfc7520_key(4))
  public <- zujson::json_parse(jose_jwk(rsa), simplify = "none")
  expect_false(any(c("d", "p", "q", "dp", "dq", "qi") %in% names(public)))
  expect_true(all(c("kty", "n", "e") %in% names(public)))

  expect_error(jose_jwk(jose_key_oct(as.raw(1:4))), class = "zujwt_key_error")
  expect_error(jose_jwk(rsa, private = NA), class = "zujwt_key_error")
})

test_that("jose_public() strips secrets and refuses oct keys", {
  rsa <- jose_public(as_jose_key(rfc7520_key(4)))
  expect_false(any(c("d", "p", "q") %in% names(rsa$members)))
  expect_identical(
    rsa$members[c("n", "e")],
    as_jose_key(rfc7520_key(3))$members[c("n", "e")]
  )
  expect_error(jose_public(jose_key_oct(as.raw(1))), class = "zujwt_key_error")
  expect_error(jose_public("x"), class = "zujwt_key_error")
})

test_that("jose_with_kid() defaults to the thumbprint", {
  key <- jose_with_kid(jose_key_oct(as.raw(1:32)))
  expect_identical(key$kid, jose_thumbprint(key))
  expect_identical(jose_with_kid(key, "mine")$kid, "mine")
  expect_error(jose_with_kid(key, 1), class = "zujwt_key_error")
})
