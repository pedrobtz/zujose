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

test_that("RFC 8037 A.3 Ed25519 thumbprint", {
  # zujose keeps Ed25519 keys without using them, and thumbprints them
  # from their members (#105).
  key <- as_jwk(paste0(
    '{"kty":"OKP","crv":"Ed25519",',
    '"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}'
  ))
  expect_identical(
    jwk_thumbprint(key),
    "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
  )
})

test_that("every key type's thumbprint is jwcrypto's, under every hash", {
  rows <- oracle_thumbprints()
  expect_setequal(
    unique(rows$id),
    c(
      "rsa-2048",
      "ec-p256",
      "ec-p384",
      "ec-p521",
      "x25519",
      "ed25519",
      "oct-16",
      "oct-32",
      "oct-64"
    )
  )
  for (i in seq_len(nrow(rows))) {
    row <- rows[i, ]
    info <- paste(row$id, row$hash)
    key <- as_jwk(row$jwk)
    expect_identical(jwk_thumbprint(key, row$hash), row$thumbprint, info = info)
    if (key$kty != "oct") {
      public <- as_jwk(jwk_json(key))
      expect_identical(
        jwk_thumbprint(public, row$hash),
        row$thumbprint,
        info = info
      )
    }
  }
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
  expect_error(jwk_thumbprint(key, "md5"), class = "zujose_argument_error")
})

test_that("a key without its required members has no thumbprint", {
  expect_error(
    jwk_thumbprint(as_jwk('{"kty":"EC","crv":"P-256","x":"AAAA"}')),
    class = "zujose_key_error"
  )
  expect_error(jwk_thumbprint("x"), class = "zujose_argument_error")
})

test_that("a key RFC 7638 has no thumbprint for, or lacking a member, is refused", {
  # Kept keys of an unknown type, or missing a member, read but have none.
  for (json in c('{"kty":"foo","k":"AQID"}', '{"kty":"OKP","crv":"Ed25519"}')) {
    key <- as_jwk(json)
    expect_error(jwk_thumbprint(key), class = "zujose_key_error", info = json)
  }
})
