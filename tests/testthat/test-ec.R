# Stage 9: EC and X25519 keys, ES* signatures and ECDH-ES (design §8.2,
# §8.3, §8.4, §8.6).

# RFC vectors ------------------------------------------------------------

test_that("RFC 7515 A.3 (ES256) and A.4 (ES512) verify", {
  for (v in list(rfc7515_a3(), rfc7515_a4())) {
    key <- jwk_public(as_jwk(v$key))
    alg <- jose_peek(v$token)$headers[[1]]$alg
    expect_identical(jws_verify(v$token, key, alg)$alg, alg)
  }
})

test_that("RFC 7520 §4.3 (ES512) and all three of §4.8's signatures verify", {
  key <- jwk_public(as_jwk(rfc7520_key(2)))
  for (figure in 27:29) {
    expect_identical(
      jws_verify(rfc7520_token(figure), key, "ES512")$alg,
      "ES512",
      info = figure
    )
  }
  set <- jwk_set(
    jwk_public(as_jwk(rfc7520_key(4))),
    key,
    as_jwk(rfc7520_key(5))
  )
  out <- jws_verify(rfc7520_token(71), set, c("RS256", "ES512", "HS256"))
  # require = "all" (the default): every signature verified.
  algs <- vapply(out$signatures, function(s) s$alg %||% s$header$alg, "")
  expect_setequal(algs, c("RS256", "ES512", "HS256"))
})

test_that("RFC 7518 Appendix C's Concat KDF and ECDH reproduce", {
  v <- rfc7518_c()
  bob <- as_jwk(v$bob)
  alice <- as_jwk(v$alice)
  expect_identical(ecdh_secret(bob, jwk_public(alice)), v$z)
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
    jwk_public(bob),
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
  key <- as_jwk(rfc7520_key(108))
  for (figure in 117:119) {
    out <- jwe_decrypt(rfc7520_token(figure), key, "ECDH-ES+A128KW", "A128GCM")
    expect_identical(rawToChar(out$plaintext), rfc7520_text(72), info = figure)
  }
  key <- as_jwk(rfc7520_key(120))
  for (figure in 128:129) {
    out <- jwe_decrypt(rfc7520_token(figure), key, "ECDH-ES", "A128CBC-HS256")
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
    key <- as_jwk(case[[1]])
    out <- jwe_decrypt(rfc7520_token(221), key, case[[2]], "A128CBC-HS256")
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
  bob <- as_jwk(v$bob)
  eph <- as_jwk(v$ephemeral)
  expect_identical(ecdh_secret(bob, jwk_public(eph)), v$z)
  expect_identical(ecdh_secret(eph, jwk_public(bob)), v$z)
  token <- jwe_encrypt(
    "for Bob",
    jwk_public(bob),
    "ECDH-ES+A128KW",
    "A128GCM"
  )
  out <- jwe_decrypt(token, bob, "ECDH-ES+A128KW", "A128GCM")
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
    key <- jwk_generate("EC", crv = case[[2]])
    token <- jws_sign("hello", key, case[[1]])
    sig <- b64url_decode(strsplit(token, ".", fixed = TRUE)[[1]][[3]], "sig")
    expect_length(sig, as.integer(case[[3]]))
    expect_identical(
      jws_verify(token, jwk_public(key), case[[1]])$payload,
      charToRaw("hello")
    )
  }
  # A key on the wrong curve for the algorithm does not fit.
  p384 <- jwk_generate("EC", crv = "P-384")
  expect_error(jws_sign("x", p384, "ES256"), class = "zujose_policy_error")
})

test_that("a bad ECDSA signature is a signature error", {
  key <- jwk_generate("EC")
  token <- jws_sign("hello", key, "ES256")
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  sig <- b64url_decode(parts[[3]], "sig")
  for (bad in list(
    c(sig[1:63], xor(sig[[64]], as.raw(1))),
    sig[-1],
    c(sig, as.raw(0)),
    raw(64)
  )) {
    t <- paste(parts[[1]], parts[[2]], b64url_encode(bad), sep = ".")
    expect_error(jws_verify(t, key, "ES256"), class = "zujose_signature_error")
  }
  expect_error(
    jws_verify(token, jwk_generate("EC"), "ES256"),
    class = "zujose_signature_error"
  )
})

test_that("every ECDH-ES mode round-trips on every curve", {
  keys <- list(
    jwk_generate("EC", crv = "P-256"),
    jwk_generate("EC", crv = "P-384"),
    jwk_generate("EC", crv = "P-521"),
    jwk_generate("OKP", crv = "X25519")
  )
  for (key in keys) {
    pub <- jwk_public(key)
    for (alg in c(
      "ECDH-ES",
      "ECDH-ES+A128KW",
      "ECDH-ES+A192KW",
      "ECDH-ES+A256KW"
    )) {
      for (enc in c("A128GCM", "A256CBC-HS512")) {
        token <- jwe_encrypt("ecdh", pub, alg, enc)
        out <- jwe_decrypt(token, key, alg, enc)
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
  a <- jwk_with_kid(jwk_generate("EC"), "a")
  b <- jwk_with_kid(jwk_generate("OKP"), "b")
  token <- jwe_encrypt(
    "both",
    list(
      jwe_recipient(jwk_public(a), "ECDH-ES+A128KW"),
      jwe_recipient(jwk_public(b), "ECDH-ES+A256KW")
    ),
    format = "general"
  )
  r <- zujson::json_parse(token, simplify = "none")$recipients
  expect_false(identical(r[[1]]$header$epk, r[[2]]$header$epk))
  for (k in list(a, b)) {
    out <- jwe_decrypt(
      token,
      k,
      c("ECDH-ES+A128KW", "ECDH-ES+A256KW"),
      "A128CBC-HS256"
    )
    expect_identical(rawToChar(out$plaintext), "both")
  }
  apu <- b64url_encode(charToRaw("Alice"))
  token <- jwe_encrypt(
    "x",
    jwk_public(a),
    "ECDH-ES",
    header = list(apu = apu, apv = "Qm9i")
  )
  expect_identical(
    jwe_decrypt(token, a, "ECDH-ES", "A128CBC-HS256")$plaintext,
    charToRaw("x")
  )
  # ECDH-ES derives the CEK, so it has one recipient.
  expect_error(
    jwe_encrypt(
      "x",
      list(
        jwe_recipient(jwk_public(a), "ECDH-ES"),
        jwe_recipient(jwk_public(a), "ECDH-ES")
      ),
      format = "general"
    ),
    class = "zujose_argument_error"
  )
  expect_error(
    jwe_encrypt(
      "x",
      jwk_public(a),
      "ECDH-ES",
      header = list(epk = list(kty = "EC"))
    ),
    class = "zujose_argument_error"
  )
})

test_that("apu and apv must be strings, and agreement needs the private key", {
  a <- jwk_generate("EC")
  expect_error(
    jwe_encrypt("x", jwk_public(a), "ECDH-ES", header = list(apu = 5)),
    class = "zujose_argument_error"
  )
  token <- jwe_encrypt("x", jwk_public(a), "ECDH-ES", format = "flattened")
  obj <- zujson::json_parse(token, simplify = "none")
  obj$header <- list(apv = 5)
  local_no_crypto()
  expect_error(
    jwe_decrypt(zujson::json_write(obj), a, "ECDH-ES", "A128CBC-HS256"),
    class = "zujose_parse_error"
  )
  expect_error(
    jwe_decrypt(token, jwk_public(a), "ECDH-ES", "A128CBC-HS256"),
    class = "zujose_key_error"
  )
})

# Policy before cryptography (design §8.6) -------------------------------

test_that("an ephemeral key off the curve, or malformed, is a parse error", {
  key <- jwk_generate("EC")
  good <- jwk_public(jwk_generate("EC"))$members
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
      jwe_decrypt(ecdh_token(epk), key, "ECDH-ES", "A128GCM"),
      class = "zujose_parse_error"
    )
  }
})

test_that("an ephemeral key on another curve than the key is refused", {
  key <- jwk_generate("EC", crv = "P-256")
  p384 <- jwk_public(jwk_generate("EC", crv = "P-384"))$members
  expect_error(
    jwe_decrypt(
      ecdh_token(c(list(kty = "EC"), p384)),
      key,
      "ECDH-ES",
      "A128GCM"
    ),
    class = "zujose_key_error"
  )
  x <- jwk_public(jwk_generate("OKP"))$members
  expect_error(
    jwe_decrypt(
      ecdh_token(c(list(kty = "OKP"), x)),
      key,
      "ECDH-ES",
      "A128GCM"
    ),
    class = "zujose_key_error"
  )
})

test_that("an ephemeral key's curve is checked before any key agreement", {
  # A second guard for the epk curve rule (#79): a P-256 ephemeral key
  # against a P-521 key, with ECDH-ES+A128KW, never reaches ECDH.
  key <- jwk_generate("EC", crv = "P-521")
  p256 <- jwk_public(jwk_generate("EC", crv = "P-256"))$members
  token <- ecdh_token(c(list(kty = "EC"), p256), alg = "ECDH-ES+A128KW")
  local_no_crypto()
  expect_error(
    jwe_decrypt(token, key, "ECDH-ES+A128KW", "A128GCM"),
    class = "zujose_key_error"
  )
})

test_that("a low-order X25519 ephemeral key is refused with the header", {
  # The all-zero point is rejected when the header is parsed, before any key
  # agreement, so it is a parse error, not a decryption failure.
  key <- jwk_generate("OKP")
  epk <- list(kty = "OKP", crv = "X25519", x = b64url_encode(raw(32)))
  expect_error(
    jwe_decrypt(ecdh_token(epk), key, "ECDH-ES", "A128GCM"),
    class = "zujose_parse_error"
  )
})

test_that("an ECDH-ES failure after policy is the one decrypt error", {
  # A wrong private key, a flipped tag, and an ECDH-ES token that carries an
  # encrypted key all fail with the class and message every other JWE
  # failure has, so none of them is an oracle (#41).
  for (crv in c("P-256", "X25519")) {
    kty <- if (crv == "X25519") "OKP" else "EC"
    right <- jwk_generate(kty, crv = crv)
    wrong <- jwk_generate(kty, crv = crv)
    for (alg in c("ECDH-ES", "ECDH-ES+A128KW")) {
      token <- jwe_encrypt("x", jwk_public(right), alg = alg)
      parts <- strsplit(token, ".", fixed = TRUE)[[1]]
      tag <- b64url_decode(parts[[5]], "tag")
      tag[[1]] <- xor(tag[[1]], as.raw(1))
      flipped <- paste(c(parts[1:4], b64url_encode(tag)), collapse = ".")
      cases <- list(
        list(token = token, key = wrong),
        list(token = flipped, key = right)
      )
      if (alg == "ECDH-ES") {
        keyed <- parts
        keyed[[2]] <- b64url_encode(as.raw(1:16))
        cases[[3]] <- list(token = paste(keyed, collapse = "."), key = right)
      }
      for (case in cases) {
        err <- expect_error(
          jwe_decrypt(case$token, case$key, alg, "A128CBC-HS256"),
          class = "zujose_decrypt_error",
          info = paste(crv, alg)
        )
        expect_identical(conditionMessage(err), "Decryption failed.")
      }
    }
  }
})

# Keys ---------------------------------------------------------------------

test_that("EC and X25519 keys are generated, read and written", {
  for (crv in c("P-256", "P-384", "P-521")) {
    key <- jwk_generate("EC", crv = crv)
    expect_true(key$supported)
    again <- as_jwk(jwk_json(key, private = TRUE))
    expect_identical(jwk_thumbprint(again), jwk_thumbprint(key))
    pem <- as_jwk(jwk_pem(key, private = TRUE))
    expect_identical(
      pem$members[c("crv", "x", "y", "d")],
      key$members[c("crv", "x", "y", "d")]
    )
  }
  x <- jwk_generate("OKP")
  expect_identical(x$members$crv, "X25519")
  expect_identical(as_jwk(jwk_pem(x))$members$x, x$members$x)
  expect_error(
    jwk_generate("EC", crv = "P-224"),
    class = "zujose_argument_error"
  )
  expect_error(
    jwk_generate("OKP", crv = "Ed25519"),
    class = "zujose_argument_error"
  )
  expect_error(
    jwk_generate("EC", crv = "P-384", alg = "ES256"),
    class = "zujose_argument_error"
  )
})

test_that("EC and X25519 PEM export is cryptography's, byte for byte", {
  # tools/make-oracle-fixtures.py wrote each PKCS #8 and SPKI file with
  # Python's `cryptography` (#103).
  for (name in c("ec-p256", "ec-p384", "ec-p521", "x25519")) {
    pem <- oracle_pem(name)
    pub_pem <- oracle_pem(name, public = TRUE)
    key <- as_jwk(pem)
    expect_true(key$supported, info = name)
    expect_identical(jwk_pem(key, private = TRUE), pem, info = name)
    expect_identical(jwk_pem(key), pub_pem, info = name)
    pub <- as_jwk(pub_pem)
    expect_false("d" %in% names(pub$members), info = name)
    expect_identical(pub$members$x, key$members$x, info = name)
    expect_identical(jwk_pem(pub), pub_pem, info = name)
  }
})

test_that("an EC JWK whose point is off the curve is a key error", {
  jwk <- zujson::json_parse(rfc7520_key(1), simplify = "none")
  y <- b64url_decode(jwk$y, "y")
  y[[length(y)]] <- xor(y[[length(y)]], as.raw(1))
  jwk$y <- b64url_encode(y)
  expect_error(as_jwk(jwk), class = "zujose_key_error")
  expect_error(
    as_jwk(list(kty = "EC", crv = "P-256")),
    class = "zujose_key_error"
  )
})

test_that("Ed25519 keys are read and kept, but cannot be used", {
  key <- as_jwk(paste0(
    '{"kty":"OKP","crv":"Ed25519",',
    '"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}'
  ))
  expect_false(key$supported)
  expect_error(jws_verify("a.b.c", key, "EdDSA"), class = "zujose_policy_error")
})

test_that("zujose_info() reports ES* and ECDH-ES available", {
  info <- zujose_info()
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

test_that("EC and X25519 members not of the curve's length are refused", {
  # RFC 7518 sections 6.2.1.2, 6.2.1.3 and 6.2.2.1: x, y and d are the
  # full coordinate length, so each key has one encoding (#94).
  for (crv in c("P-256", "P-521", "X25519")) {
    kty <- if (crv == "X25519") "OKP" else "EC"
    jwk <- zujson::json_parse(jwk_json(jwk_generate(kty, crv = crv), TRUE))
    for (name in intersect(c("x", "y", "d"), names(jwk))) {
      value <- b64url_decode(jwk[[name]], "x")
      for (bytes in list(c(as.raw(0), value), value[-1])) {
        bad <- jwk
        bad[[name]] <- b64url_encode(bytes)
        expect_error(as_jwk(bad), class = "zujose_key_error", info = name)
      }
    }
    expect_no_error(as_jwk(jwk))
  }
})

test_that("an ephemeral key not of the curve's length is refused", {
  key <- jwk_generate("EC")
  good <- jwk_public(jwk_generate("EC"))$members
  long <- good
  long$x <- b64url_encode(c(as.raw(0), b64url_decode(good$x, "x")))
  okp <- jwk_generate("OKP")
  x <- b64url_decode(jwk_public(jwk_generate("OKP"))$members$x, "x")
  for (case in list(
    list(c(list(kty = "EC"), long), key),
    list(list(kty = "OKP", crv = "X25519", x = b64url_encode(x[-1])), okp),
    list(
      list(kty = "OKP", crv = "X25519", x = b64url_encode(c(x, raw(1)))),
      okp
    )
  )) {
    expect_error(
      jwe_decrypt(ecdh_token(case[[1]]), case[[2]], "ECDH-ES", "A128GCM"),
      class = "zujose_parse_error"
    )
  }
})

test_that("an X25519 private JWK whose `x` does not match `d` is refused", {
  # #124: the public key derived from `d` must be `x`.
  jwk <- zujson::json_parse(jwk_json(jwk_generate("OKP"), TRUE))
  other <- jwk_public(jwk_generate("OKP"))$members$x
  for (x in c(b64url_encode(raw(32)), "AA", other)) {
    bad <- jwk
    bad$x <- x
    expect_error(as_jwk(bad), class = "zujose_key_error")
  }
  expect_no_error(as_jwk(jwk))
})
