test_that("jwk_oct() wraps a raw secret", {
  key <- jwk_oct(as.raw(1:32), alg = "HS256", kid = "k1", use = "sig")
  expect_s3_class(key, "jwk")
  expect_identical(key$kty, "oct")
  expect_identical(key$k, as.raw(1:32))
  expect_identical(key$alg, "HS256")
  expect_true(key$supported)
})

test_that("jwk_oct() refuses what is not a key", {
  for (bad in list("secret", raw(), 1:32, NULL)) {
    expect_error(jwk_oct(bad), class = "zujose_key_error")
  }
  expect_error(jwk_oct(as.raw(1), kid = 1), class = "zujose_key_error")
  expect_error(
    jwk_oct(as.raw(1), alg = c("a", "b")),
    class = "zujose_key_error"
  )
  expect_error(
    jwk_oct(as.raw(1), key_ops = "fly"),
    class = "zujose_key_error"
  )
  expect_error(
    jwk_oct(as.raw(1), key_ops = c("sign", "sign")),
    class = "zujose_key_error"
  )
})

test_that("printing a key never shows its secret", {
  key <- jwk_oct(charToRaw("correct horse battery staple!!!!"), kid = "k1")
  out <- paste(capture.output(print(key)), collapse = "\n")
  expect_no_match(out, "horse")
  expect_no_match(out, b64url_encode(key$k), fixed = TRUE)
  expect_snapshot(print(key))
})

test_that("RFC 7520 §3.5 and §3.6 symmetric keys read", {
  mac <- as_jwk(rfc7520_key(5))
  expect_identical(mac$kty, "oct")
  expect_identical(mac$kid, "018c0ae5-4d9b-471b-bfd6-eef314bc7037")
  expect_identical(mac$use, "sig")
  expect_identical(mac$alg, "HS256")
  expect_length(mac$k, 32L)

  enc <- as_jwk(rfc7520_key(6))
  expect_identical(enc$alg, "A256GCM")
  expect_length(enc$k, 32L)
})

test_that("RSA, EC and X25519 keys are usable, and Ed25519 keys are kept", {
  rsa <- as_jwk(rfc7520_key(3))
  expect_true(rsa$supported)
  ec <- as_jwk(rfc7520_key(1))
  expect_identical(ec$members$crv, "P-521")
  expect_true(ec$supported)
  expect_null(ec$needs)

  ed <- as_jwk(paste0(
    '{"kty":"OKP","crv":"Ed25519","kid":"ed",',
    '"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}'
  ))
  expect_false(ed$supported)
  expect_null(ed$needs)
  expect_snapshot(print(ed))
})

test_that("as_jwk() accepts a parsed list, a raw secret or a key", {
  parsed <- zujson::json_parse(rfc7520_key(5), simplify = "none")
  expect_identical(as_jwk(parsed), as_jwk(rfc7520_key(5)))
  expect_identical(as_jwk(as.raw(1:4))$k, as.raw(1:4))
  key <- jwk_oct(as.raw(1:4))
  expect_identical(as_jwk(key), key)
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
    expect_error(as_jwk(text), class = "zujose_key_error", info = text)
  }
  expect_error(as_jwk(c("a", "b")), class = "zujose_key_error")
  expect_error(as_jwk(42), class = "zujose_key_error")
  expect_error(as_jwk(list(1, 2)), class = "zujose_key_error")
})

test_that("a PEM that is not a readable RSA key is a key error", {
  pem <- "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"
  expect_error(as_jwk(pem), class = "zujose_key_error")
})

test_that("jwk_json() round-trips every RFC 7520 key", {
  for (figure in c(1:6, 84, 120, 138, 151)) {
    key <- as_jwk(rfc7520_key(figure))
    again <- as_jwk(jwk_json(key, private = TRUE))
    expect_identical(again, key, info = figure)
  }
})

test_that("jwk_json() writes only public members by default", {
  rsa <- as_jwk(rfc7520_key(4))
  public <- zujson::json_parse(jwk_json(rsa), simplify = "none")
  expect_false(any(c("d", "p", "q", "dp", "dq", "qi") %in% names(public)))
  expect_true(all(c("kty", "n", "e") %in% names(public)))

  expect_error(jwk_json(jwk_oct(as.raw(1:4))), class = "zujose_key_error")
  expect_error(jwk_json(rsa, private = NA), class = "zujose_key_error")
})

test_that("jwk_public() strips secrets and refuses oct keys", {
  rsa <- jwk_public(as_jwk(rfc7520_key(4)))
  expect_false(any(c("d", "p", "q") %in% names(rsa$members)))
  expect_identical(
    rsa$members[c("n", "e")],
    as_jwk(rfc7520_key(3))$members[c("n", "e")]
  )
  expect_error(jwk_public(jwk_oct(as.raw(1))), class = "zujose_key_error")
  expect_error(jwk_public("x"), class = "zujose_key_error")
})

test_that("jwk_with_kid() defaults to the thumbprint", {
  key <- jwk_with_kid(jwk_oct(as.raw(1:32)))
  expect_identical(key$kid, jwk_thumbprint(key))
  expect_identical(jwk_with_kid(key, "mine")$kid, "mine")
  expect_error(jwk_with_kid(key, 1), class = "zujose_key_error")
})

# jwk_generate() (design §7.2) ---------------------------------------

test_that("jwk_generate() makes a random oct key", {
  key <- jwk_generate("oct")
  expect_s3_class(key, "jwk")
  expect_identical(key$kty, "oct")
  expect_length(key$k, 32L)
  expect_false(identical(key$k, jwk_generate("oct")$k))
  expect_length(jwk_generate("oct", size = 384)$k, 48L)
  key <- jwk_generate("oct", alg = "A256KW", kid = "k", use = "enc")
  expect_identical(key$alg, "A256KW")
  expect_identical(key$kid, "k")
  expect_identical(key$use, "enc")
  # The secret never shows when the key prints.
  expect_false(any(grepl(
    b64url_encode(key$k),
    capture.output(print(key)),
    fixed = TRUE
  )))
})

test_that("the default size follows alg", {
  sizes <- c(
    HS256 = 32L,
    HS384 = 48L,
    HS512 = 64L,
    A128KW = 16L,
    A192KW = 24L,
    A256KW = 32L,
    A128GCMKW = 16L,
    A192GCMKW = 24L,
    A256GCMKW = 32L,
    dir = 32L
  )
  for (alg in names(sizes)) {
    expect_length(jwk_generate("oct", alg = alg)$k, sizes[[alg]])
  }
})

test_that("a generated key signs, verifies and wraps", {
  key <- jwk_generate("oct", alg = "HS512")
  token <- jws_sign("hi", key)
  expect_identical(jws_verify(token, key, "HS512")$payload, charToRaw("hi"))
  kek <- jwk_generate("oct", alg = "A192KW")
  token <- jwe_encrypt("hi", kek)
  out <- jwe_decrypt(token, kek, "A192KW", "A128CBC-HS256")
  expect_identical(out$plaintext, charToRaw("hi"))
})

test_that("jwk_generate() refuses sizes and algorithms that do not fit", {
  bad_sizes <- list(0, 64, 120, 129, 255.5, -256, NA, Inf, "256", c(256, 512))
  for (size in bad_sizes) {
    expect_error(
      jwk_generate("oct", size = size),
      class = "zujose_key_error"
    )
  }
  # Shorter than the hash (RFC 7518 §3.2), or not the key wrap's size.
  expect_error(
    jwk_generate("oct", size = 128, alg = "HS256"),
    class = "zujose_key_error"
  )
  expect_length(jwk_generate("oct", size = 512, alg = "HS256")$k, 64L)
  expect_error(
    jwk_generate("oct", size = 256, alg = "A128KW"),
    class = "zujose_key_error"
  )
  # Without `alg`, or for `dir`, 256 bits is the default, not the minimum.
  expect_length(jwk_generate("oct", size = 128)$k, 16L)
  expect_length(jwk_generate("oct", size = 192, alg = "dir")$k, 24L)
  # Not an oct algorithm at all.
  for (alg in c("RS256", "ES256", "A128CBC-HS256", "PBES2-HS256+A128KW")) {
    expect_error(
      jwk_generate("oct", alg = alg),
      class = "zujose_key_error"
    )
  }
  expect_error(
    jwk_generate("oct", crv = "P-256"),
    class = "zujose_key_error"
  )
  expect_error(jwk_generate("DSA"), class = "zujose_key_error")
})

test_that("EC and OKP keys are generated on the curves zujose has", {
  expect_identical(jwk_generate("EC")$members$crv, "P-256")
  expect_identical(jwk_generate("OKP")$members$crv, "X25519")
  expect_error(
    jwk_generate("OKP", crv = "Ed25519"),
    class = "zujose_key_error"
  )
})

test_that("a refused oct size has a message", {
  expect_snapshot(
    jwk_generate("oct", size = 120),
    error = TRUE
  )
  expect_snapshot(
    jwk_generate("oct", size = 128, alg = "HS256"),
    error = TRUE
  )
})

test_that("an empty `key_ops` permits no operation, and survives JSON", {
  # #121: a present empty array is no operations, not no restriction.
  k <- b64url_encode(as.raw(1:32))
  read <- as_jwk(sprintf('{"kty":"oct","k":"%s","key_ops":[]}', k))
  expect_identical(read$key_ops, character())
  expect_error(jws_sign("x", read, "HS256"), class = "zujose_policy_error")
  made <- jwk_oct(as.raw(1:32), key_ops = character())
  back <- as_jwk(jwk_json(made, TRUE))
  expect_identical(back$key_ops, character())
  expect_error(jws_sign("x", back, "HS256"), class = "zujose_policy_error")
})

test_that("`key_ops` must be an array of strings", {
  k <- b64url_encode(as.raw(1:32))
  for (ops in c('{}', '{"a":"sign"}', '"sign"', '[1]', '["sign",null]')) {
    json <- sprintf('{"kty":"oct","k":"%s","key_ops":%s}', k, ops)
    expect_error(as_jwk(json), class = "zujose_key_error", info = ops)
  }
  key <- as_jwk(list(kty = "oct", k = k, key_ops = c("sign", "verify")))
  expect_identical(key$key_ops, c("sign", "verify"))
  set <- as_jwk_set(list(
    keys = list(
      list(kty = "oct", k = k, key_ops = c("sign", "verify"))
    )
  ))
  expect_length(set, 1L)
  text <- sprintf('{"keys":[{"kty":"oct","k":"%s","key_ops":"sign"}]}', k)
  expect_length(as_jwk_set(text), 0L)
})
