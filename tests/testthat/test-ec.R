# Stage 9: EC and X25519 keys, ES* signatures and ECDH-ES (design §8.2,
# §8.3, §8.4, §8.6).

# RFC vectors ------------------------------------------------------------

test_that("RFC 7515 A.3 (ES256) and A.4 (ES512) verify", {
  for (v in list(rfc7515_a3(), rfc7515_a4())) {
    key <- jose_public(as_jose_key(v$key))
    alg <- jose_peek(v$token)$headers[[1]]$alg
    expect_identical(jose_verify(v$token, key, alg)$alg, alg)
  }
})

test_that("RFC 7520 §4.3 (ES512) and all three of §4.8's signatures verify", {
  key <- jose_public(as_jose_key(rfc7520_key(2)))
  for (figure in 27:29) {
    expect_identical(
      jose_verify(rfc7520_token(figure), key, "ES512")$alg,
      "ES512",
      info = figure
    )
  }
  set <- jose_keyset(
    jose_public(as_jose_key(rfc7520_key(4))),
    key,
    as_jose_key(rfc7520_key(5))
  )
  out <- jose_verify(rfc7520_token(71), set, c("RS256", "ES512", "HS256"))
  # require = "all" (the default): every signature verified.
  algs <- vapply(out$signatures, function(s) s$alg %||% s$header$alg, "")
  expect_setequal(algs, c("RS256", "ES512", "HS256"))
})

test_that("RFC 7518 Appendix C's Concat KDF and ECDH reproduce", {
  v <- rfc7518_c()
  bob <- as_jose_key(v$bob)
  alice <- as_jose_key(v$alice)
  expect_identical(ecdh_secret(bob, jose_public(alice)), v$z)
  expect_identical(
    b64url_encode(concat_kdf(
      v$z,
      128,
      "A128GCM",
      charToRaw("Alice"),
      charToRaw("Bob")
    )),
    v$derived
  )
  # And the whole key agreement, with Alice's key as the ephemeral one.
  got <- wrap_cek(
    "ECDH-ES",
    jose_public(bob),
    NULL,
    enc = "A128GCM",
    apu = charToRaw("Alice"),
    apv = charToRaw("Bob"),
    fixed = list(epk = alice)
  )
  expect_identical(b64url_encode(got$cek), v$derived)
  expect_identical(got$header$epk$x, alice$members$x)
})

test_that("RFC 7520 §5.4 (ECDH-ES+A128KW) and §5.5 (ECDH-ES) decrypt", {
  key <- as_jose_key(rfc7520_key(108))
  for (figure in 117:119) {
    out <- jose_decrypt(rfc7520_token(figure), key, "ECDH-ES+A128KW", "A128GCM")
    expect_identical(rawToChar(out$plaintext), rfc7520_text(72), info = figure)
  }
  key <- as_jose_key(rfc7520_key(120))
  for (figure in 128:129) {
    out <- jose_decrypt(rfc7520_token(figure), key, "ECDH-ES", "A128CBC-HS256")
    expect_identical(rawToChar(out$plaintext), rfc7520_text(72), info = figure)
  }
})

test_that("RFC 7520 §5.13 decrypts for each of its three recipients", {
  cases <- list(
    list(rfc7520_key(73), "RSA1_5"),
    list(rfc7520_key(108), "ECDH-ES+A256KW"),
    list(rfc7520_key(138), "A256GCMKW")
  )
  for (case in cases) {
    key <- as_jose_key(case[[1]])
    out <- jose_decrypt(rfc7520_token(221), key, case[[2]], "A128CBC-HS256")
    expect_identical(
      rawToChar(out$plaintext),
      rfc7520_text(72),
      info = case[[2]]
    )
    expect_identical(out$alg, case[[2]])
  }
})

test_that("RFC 8037 A.6 (ECDH-ES with X25519) agrees on Z", {
  v <- rfc8037_a6()
  bob <- as_jose_key(v$bob)
  eph <- as_jose_key(v$ephemeral)
  expect_identical(ecdh_secret(bob, jose_public(eph)), v$z)
  expect_identical(ecdh_secret(eph, jose_public(bob)), v$z)
  token <- jose_encrypt(
    "for Bob",
    jose_public(bob),
    "ECDH-ES+A128KW",
    "A128GCM"
  )
  out <- jose_decrypt(token, bob, "ECDH-ES+A128KW", "A128GCM")
  expect_identical(rawToChar(out$plaintext), "for Bob")
  expect_identical(jose_peek(token)$headers[[1]]$epk$crv, "X25519")
})

# Round trips -------------------------------------------------------------

test_that("ES256, ES384 and ES512 sign and verify on their curves", {
  for (case in list(
    c("ES256", "P-256", 64),
    c("ES384", "P-384", 96),
    c("ES512", "P-521", 132)
  )) {
    key <- jose_key_generate("EC", crv = case[[2]])
    token <- jose_sign("hello", key, case[[1]])
    sig <- b64url_decode(strsplit(token, ".", fixed = TRUE)[[1]][[3]], "sig")
    expect_length(sig, as.integer(case[[3]]))
    expect_identical(
      jose_verify(token, jose_public(key), case[[1]])$payload,
      charToRaw("hello")
    )
  }
  # A key on the wrong curve for the algorithm does not fit.
  p384 <- jose_key_generate("EC", crv = "P-384")
  expect_error(jose_sign("x", p384, "ES256"), class = "zujwt_policy_error")
})

test_that("a bad ECDSA signature is a signature error", {
  key <- jose_key_generate("EC")
  token <- jose_sign("hello", key, "ES256")
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  sig <- b64url_decode(parts[[3]], "sig")
  for (bad in list(
    c(sig[1:63], xor(sig[[64]], as.raw(1))),
    sig[-1],
    c(sig, as.raw(0)),
    raw(64)
  )) {
    t <- paste(parts[[1]], parts[[2]], b64url_encode(bad), sep = ".")
    expect_error(jose_verify(t, key, "ES256"), class = "zujwt_signature_error")
  }
  expect_error(
    jose_verify(token, jose_key_generate("EC"), "ES256"),
    class = "zujwt_signature_error"
  )
})

test_that("every ECDH-ES mode round-trips on every curve", {
  keys <- list(
    jose_key_generate("EC", crv = "P-256"),
    jose_key_generate("EC", crv = "P-384"),
    jose_key_generate("EC", crv = "P-521"),
    jose_key_generate("OKP", crv = "X25519")
  )
  for (key in keys) {
    pub <- jose_public(key)
    for (alg in c(
      "ECDH-ES",
      "ECDH-ES+A128KW",
      "ECDH-ES+A192KW",
      "ECDH-ES+A256KW"
    )) {
      for (enc in c("A128GCM", "A256CBC-HS512")) {
        token <- jose_encrypt("ecdh", pub, alg, enc)
        out <- jose_decrypt(token, key, alg, enc)
        expect_identical(
          rawToChar(out$plaintext),
          "ecdh",
          info = paste(key$members$crv, alg, enc)
        )
      }
    }
  }
})

test_that("ECDH-ES takes apu and apv, and several +KW recipients", {
  a <- jose_with_kid(jose_key_generate("EC"), "a")
  b <- jose_with_kid(jose_key_generate("OKP"), "b")
  token <- jose_encrypt(
    "both",
    list(
      jose_recipient(jose_public(a), "ECDH-ES+A128KW"),
      jose_recipient(jose_public(b), "ECDH-ES+A256KW")
    ),
    format = "general"
  )
  r <- zujson::json_parse(token, simplify = "none")$recipients
  expect_false(identical(r[[1]]$header$epk, r[[2]]$header$epk))
  for (k in list(a, b)) {
    out <- jose_decrypt(
      token,
      k,
      c("ECDH-ES+A128KW", "ECDH-ES+A256KW"),
      "A128CBC-HS256"
    )
    expect_identical(rawToChar(out$plaintext), "both")
  }
  apu <- b64url_encode(charToRaw("Alice"))
  token <- jose_encrypt(
    "x",
    jose_public(a),
    "ECDH-ES",
    header = list(apu = apu, apv = "Qm9i")
  )
  expect_identical(
    jose_decrypt(token, a, "ECDH-ES", "A128CBC-HS256")$plaintext,
    charToRaw("x")
  )
  # ECDH-ES derives the CEK, so it has one recipient.
  expect_error(
    jose_encrypt(
      "x",
      list(
        jose_recipient(jose_public(a), "ECDH-ES"),
        jose_recipient(jose_public(a), "ECDH-ES")
      ),
      format = "general"
    )
  )
  expect_error(
    jose_encrypt(
      "x",
      jose_public(a),
      "ECDH-ES",
      header = list(epk = list(kty = "EC"))
    ),
    "epk"
  )
})

# Policy before cryptography (design §8.6) -------------------------------

test_that("an ephemeral key off the curve, or malformed, is a parse error", {
  key <- jose_key_generate("EC")
  good <- jose_public(jose_key_generate("EC"))$members
  bad <- good
  y <- b64url_decode(bad$y, "y")
  y[[32]] <- xor(y[[32]], as.raw(1))
  bad$y <- b64url_encode(y)
  for (epk in list(
    c(list(kty = "EC"), bad),
    list(kty = "EC", crv = "P-256"),
    "not an object",
    list(kty = "RSA", n = "AA", e = "AQAB"),
    c(list(kty = "EC"), good[c("crv", "x")])
  )) {
    expect_error(
      jose_decrypt(ecdh_token(epk), key, "ECDH-ES", "A128GCM"),
      class = "zujwt_parse_error"
    )
  }
})

test_that("an ephemeral key on another curve than the key is refused", {
  key <- jose_key_generate("EC", crv = "P-256")
  p384 <- jose_public(jose_key_generate("EC", crv = "P-384"))$members
  expect_error(
    jose_decrypt(
      ecdh_token(c(list(kty = "EC"), p384)),
      key,
      "ECDH-ES",
      "A128GCM"
    ),
    class = "zujwt_key_error"
  )
  x <- jose_public(jose_key_generate("OKP"))$members
  expect_error(
    jose_decrypt(
      ecdh_token(c(list(kty = "OKP"), x)),
      key,
      "ECDH-ES",
      "A128GCM"
    ),
    class = "zujwt_key_error"
  )
})

test_that("a low-order X25519 ephemeral key is one decrypt error", {
  key <- jose_key_generate("OKP")
  epk <- list(kty = "OKP", crv = "X25519", x = b64url_encode(raw(32)))
  err <- tryCatch(
    jose_decrypt(ecdh_token(epk), key, "ECDH-ES", "A128GCM"),
    error = identity
  )
  expect_true(inherits(err, c("zujwt_decrypt_error", "zujwt_parse_error")))
})

# Keys ---------------------------------------------------------------------

test_that("EC and X25519 keys are generated, read and written", {
  for (crv in c("P-256", "P-384", "P-521")) {
    key <- jose_key_generate("EC", crv = crv)
    expect_true(key$supported)
    again <- as_jose_key(jose_jwk(key, private = TRUE))
    expect_identical(jose_thumbprint(again), jose_thumbprint(key))
    pem <- as_jose_key(jose_pem(key, private = TRUE))
    expect_identical(
      pem$members[c("crv", "x", "y", "d")],
      key$members[c("crv", "x", "y", "d")]
    )
  }
  x <- jose_key_generate("OKP")
  expect_identical(x$members$crv, "X25519")
  expect_identical(as_jose_key(jose_pem(x))$members$x, x$members$x)
  expect_error(
    jose_key_generate("EC", crv = "P-224"),
    class = "zujwt_key_error"
  )
  expect_error(
    jose_key_generate("OKP", crv = "Ed25519"),
    class = "zujwt_key_error"
  )
  expect_error(
    jose_key_generate("EC", crv = "P-384", alg = "ES256"),
    class = "zujwt_key_error"
  )
})

test_that("an EC JWK whose point is off the curve is a key error", {
  jwk <- zujson::json_parse(rfc7520_key(1), simplify = "none")
  y <- b64url_decode(jwk$y, "y")
  y[[length(y)]] <- xor(y[[length(y)]], as.raw(1))
  jwk$y <- b64url_encode(y)
  expect_error(as_jose_key(jwk), class = "zujwt_key_error")
  expect_error(
    as_jose_key(list(kty = "EC", crv = "P-256")),
    class = "zujwt_key_error"
  )
})

test_that("Ed25519 keys are read and kept, but cannot be used", {
  key <- as_jose_key(paste0(
    '{"kty":"OKP","crv":"Ed25519",',
    '"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}'
  ))
  expect_false(key$supported)
  expect_error(jose_verify("a.b.c", key, "EdDSA"), class = "zujwt_policy_error")
})

test_that("zujwt_info() reports ES* and ECDH-ES available", {
  info <- zujwt_info()
  ec <- c(
    "ES256",
    "ES384",
    "ES512",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW"
  )
  expect_true(all(info$available[info$algorithm %in% ec]))
})
