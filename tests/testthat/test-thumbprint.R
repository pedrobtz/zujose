test_that("RFC 7638 §3.1 thumbprint", {
  key <- as_jwk(rfc7638_jwk())
  expect_identical(jwk_thumbprint(key), rfc7638_thumbprint())
})

test_that("RFC 9278 §3 thumbprint URI", {
  key <- as_jwk(rfc7638_jwk())
  expect_identical(
    jwk_thumbprint(key, uri = TRUE),
    paste0(
      "urn:ietf:params:oauth:jwk-thumbprint:sha-256:",
      rfc7638_thumbprint()
    )
  )
})

test_that("a private key has its public key's thumbprint", {
  expect_identical(
    jwk_thumbprint(as_jwk(rfc7520_key(4))),
    jwk_thumbprint(as_jwk(rfc7520_key(3)))
  )
  expect_identical(
    jwk_thumbprint(as_jwk(rfc7520_key(2))),
    jwk_thumbprint(as_jwk(rfc7520_key(1)))
  )
})

test_that("optional members do not change the thumbprint", {
  bare <- jwk_oct(as.raw(1:32))
  dressed <- jwk_oct(as.raw(1:32), alg = "HS256", kid = "x", use = "sig")
  expect_identical(jwk_thumbprint(dressed), jwk_thumbprint(bare))
})

test_that("the hash sets the length and the URI's hash name", {
  key <- jwk_oct(as.raw(1:32))
  expect_identical(nchar(jwk_thumbprint(key, "sha384")), 64L)
  expect_identical(nchar(jwk_thumbprint(key, "sha512")), 86L)
  expect_match(jwk_thumbprint(key, "sha512", uri = TRUE), ":sha-512:")
  expect_error(jwk_thumbprint(key, "md5"), class = "zujose_key_error")
})

test_that("a key without its required members has no thumbprint", {
  expect_error(
    jwk_thumbprint(as_jwk('{"kty":"EC","crv":"P-256","x":"AAAA"}')),
    class = "zujose_key_error"
  )
  expect_error(jwk_thumbprint("x"), class = "zujose_key_error")
})
