test_that("jwk_oct() wraps a raw secret", {
  key <- jwk_oct(as.raw(1:32), alg = "HS256", kid = "k1", use = "sig")
  expect_s3_class(key, "jwk")
  expect_identical(key$kty, "oct")
  expect_identical(key$k, as.raw(1:32))
  expect_identical(key$alg, "HS256")
  expect_true(key$supported)
})

test_that("jwk_oct() refuses what is not a key", {
  # A secret of the wrong type is the caller's mistake (#78); an empty
  # one is no key.
  for (bad in list("secret", 1:32, NULL)) {
    expect_error(jwk_oct(bad), class = "zujose_argument_error")
  }
  expect_error(jwk_oct(raw()), class = "zujose_key_error")
  expect_error(jwk_oct(as.raw(1), kid = 1), class = "zujose_argument_error")
  expect_error(
    jwk_oct(as.raw(1), alg = c("a", "b")),
    class = "zujose_argument_error"
  )
  expect_error(
    jwk_oct(as.raw(1), key_ops = "fly"),
    class = "zujose_argument_error"
  )
  expect_error(
    jwk_oct(as.raw(1), key_ops = c("sign", "sign")),
    class = "zujose_argument_error"
  )
})

test_that("a key argument of the wrong R type is an argument error (#78)", {
  key <- jwk_oct(as.raw(1:32))
  token <- jws_sign("x", key, "HS256")
  jwe <- jwe_encrypt("x", key, "dir", "A128CBC-HS256")
  calls <- list(
    function() jwk_oct(1),
    function() jwk_set(1),
    function() jwk_set(key, "b"),
    function() c(key, 1),
    function() jwk_thumbprint(1),
    function() as_jwk(123),
    function() as_jwk(c("a", "b")),
    function() as_jwk_set(1),
    function() jwk_public("x"),
    function() jwk_pem(1),
    function() jwk_json(1),
    function() jwk_with_kid(1, "a"),
    function() jws_signer(1, "HS256"),
    function() jwe_recipient(1, "dir"),
    function() jws_sign("x", 1, "HS256"),
    function() jwe_encrypt("x", 1, "dir"),
    function() jwt_encode(list(a = 1), 1, "HS256"),
    function() jws_verify(token, 1, "HS256"),
    function() jwt_decode(token, 1, "HS256"),
    function() jwt_decoder(1, "HS256"),
    function() jwe_decrypt(jwe, 1, "dir", "A128CBC-HS256"),
    function() jwe_decryption(1, "dir", "A128CBC-HS256")
  )
  for (i in seq_along(calls)) {
    expect_error(calls[[i]](), class = "zujose_argument_error", info = i)
  }
  # A malformed or too weak key is still a key error.
  expect_error(as_jwk('{"kty":"oct"}'), class = "zujose_key_error")
  expect_error(
    jws_sign("x", jwk_oct(as.raw(1:16)), "HS256"),
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

test_that("printing private EC and X25519 keys, or a set, hides secrets", {
  shown <- function(x) {
    c(format(x), capture.output(print(x)))
  }
  ec <- as_jwk(rfc7520_key(2))
  x25519 <- jwk_generate("OKP", crv = "X25519")
  for (key in list(ec, x25519)) {
    d <- key$members$d
    expect_true(is.character(d) && nzchar(d))
    out <- shown(key)
    expect_false(any(grepl(d, out, fixed = TRUE)), info = key$kty)
    expect_true(any(grepl("private: yes", out, fixed = TRUE)))
  }

  secret <- jwk_oct(charToRaw("correct horse battery staple!!!!"))
  set <- jwk_set(secret, ec, x25519)
  out <- shown(set)
  for (s in c(b64url_encode(secret$k), ec$members$d, x25519$members$d)) {
    expect_false(any(grepl(s, out, fixed = TRUE)))
  }
  expect_false(any(grepl("horse", out, fixed = TRUE)))
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
  expect_error(as_jwk(c("a", "b")), class = "zujose_argument_error")
  expect_error(as_jwk(42), class = "zujose_argument_error")
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
  expect_error(jwk_json(rsa, private = NA), class = "zujose_argument_error")
})

test_that("jwk_public() strips secrets and refuses oct keys", {
  rsa <- jwk_public(as_jwk(rfc7520_key(4)))
  expect_false(any(c("d", "p", "q") %in% names(rsa$members)))
  expect_identical(
    rsa$members[c("n", "e")],
    as_jwk(rfc7520_key(3))$members[c("n", "e")]
  )
  expect_error(jwk_public(jwk_oct(as.raw(1))), class = "zujose_key_error")
  expect_error(jwk_public("x"), class = "zujose_argument_error")
})

test_that("jwk_with_kid() defaults to the thumbprint", {
  key <- jwk_with_kid(jwk_oct(as.raw(1:32)))
  expect_identical(key$kid, jwk_thumbprint(key))
  expect_identical(jwk_with_kid(key, "mine")$kid, "mine")
  expect_error(jwk_with_kid(key, 1), class = "zujose_argument_error")
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

test_that("jwk_generate() refuses a crv or size the key type does not take", {
  expect_error(
    jwk_generate("oct", crv = "P-256"),
    class = "zujose_argument_error"
  )
  expect_error(
    jwk_generate("RSA", crv = "P-256"),
    class = "zujose_argument_error"
  )
  expect_error(jwk_generate("EC", size = 256), class = "zujose_argument_error")
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
    dir = 32L,
    "PBES2-HS256+A128KW" = 32L,
    "PBES2-HS384+A192KW" = 32L,
    "PBES2-HS512+A256KW" = 32L,
    "A128CBC-HS256" = 32L,
    "A192CBC-HS384" = 48L,
    "A256CBC-HS512" = 64L,
    A128GCM = 16L,
    A192GCM = 24L,
    A256GCM = 32L
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
  # A size that is not one number is the caller's mistake (#78); one
  # that makes no key, or too short a key, is a key error.
  for (size in list(NA, Inf, "256", c(256, 512))) {
    expect_error(
      jwk_generate("oct", size = size),
      class = "zujose_argument_error"
    )
  }
  for (size in list(0, 64, 120, 129, 255.5, -256)) {
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
  for (alg in c("RS256", "ES256", "ECDH-ES", "A128GCMX")) {
    expect_error(
      jwk_generate("oct", alg = alg),
      class = "zujose_argument_error"
    )
  }
  expect_error(
    jwk_generate("oct", crv = "P-256"),
    class = "zujose_argument_error"
  )
  expect_error(jwk_generate("DSA"), class = "zujose_argument_error")
})

test_that("EC and OKP keys are generated on the curves zujose has", {
  expect_identical(jwk_generate("EC")$members$crv, "P-256")
  expect_identical(jwk_generate("OKP")$members$crv, "X25519")
  expect_error(
    jwk_generate("OKP", crv = "Ed25519"),
    class = "zujose_argument_error"
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

test_that("jwk_generate() makes an oct key for every oct algorithm", {
  # #132: PBES2, and a `dir` key named by its content encryption, as
  # jwk_oct() and key selection allow.
  password <- jwk_generate("oct", alg = "PBES2-HS256+A128KW")
  token <- jwe_encrypt("hi", password)
  out <- jwe_decrypt(token, password, "PBES2-HS256+A128KW", "A128CBC-HS256")
  expect_identical(out$plaintext, charToRaw("hi"))
  expect_length(jwk_generate("oct", 128, alg = "PBES2-HS512+A256KW")$k, 16L)
  cek <- jwk_generate("oct", alg = "A256GCM")
  token <- jwe_encrypt("hi", cek, alg = "dir", enc = "A256GCM")
  expect_identical(
    jwe_decrypt(token, cek, "dir", "A256GCM")$plaintext,
    charToRaw("hi")
  )
  expect_error(
    jwk_generate("oct", size = 256, alg = "A128GCM"),
    class = "zujose_key_error"
  )
})

test_that("jwk_public() maps private key_ops to their public counterparts", {
  # #133: the public half of a signing key verifies.
  key <- jwk_generate("EC", key_ops = "sign", alg = "ES256")
  public <- jwk_public(key)
  expect_identical(public$key_ops, "verify")
  token <- jws_sign("p", key)
  expect_no_error(jws_verify(token, public, "ES256"))
  both <- jwk_generate("OKP", key_ops = c("deriveKey", "decrypt", "encrypt"))
  expect_identical(jwk_public(both)$key_ops, "encrypt")
  wrap <- jwk_generate("OKP", key_ops = c("unwrapKey", "wrapKey"))
  expect_identical(jwk_public(wrap)$key_ops, "wrapKey")
  derive <- jwk_public(jwk_generate("OKP", key_ops = "deriveKey"))
  expect_null(derive$key_ops)
  expect_false(grepl("key_ops", jwk_json(derive), fixed = TRUE))
  expect_null(jwk_public(jwk_generate("OKP"))$key_ops)
  set <- jwk_public(jwk_set(key))
  expect_identical(set[[1]]$key_ops, "verify")
})

test_that("a key of unknown type prints as such", {
  # #136: no zucrypt version makes it usable.
  expect_snapshot({
    print(as_jwk('{"kty":"foo","k":"AQID"}'))
    print(as_jwk('{"kty":"OCT","k":"AQID"}'))
  })
  expect_null(as_jwk('{"kty":"foo"}')$needs)
})

test_that("names on a key's kid, alg, use and key_ops are dropped (#120)", {
  key <- jwk_oct(
    as.raw(1:32),
    kid = c(a = "k"),
    alg = c(b = "HS256"),
    use = c(c = "sig")
  )
  expect_identical(
    jose_peek(jws_sign("x", key))$headers[[1]],
    list(alg = "HS256", kid = "k")
  )
  expect_identical(key$kid, "k")
})
