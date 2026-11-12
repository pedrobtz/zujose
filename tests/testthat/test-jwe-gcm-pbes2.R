# Stage 7: A*GCM content encryption, A*GCMKW and PBES2 key management
# (design §8.6).

# RFC 7520 vectors -------------------------------------------------------

test_that("RFC 7520 §5.6 (dir, A128GCM) decrypts", {
  key <- as_jwk(rfc7520_key(130))
  for (figure in c(136, 137)) {
    out <- jwe_decrypt(rfc7520_token(figure), key, "dir", "A128GCM")
    expect_identical(rawToChar(out$plaintext), rfc7520_text(72), info = figure)
    expect_identical(out$enc, "A128GCM")
  }
})

test_that("RFC 7520 §5.7 (A256GCMKW, A128CBC-HS256) decrypts", {
  key <- as_jwk(rfc7520_key(138))
  for (figure in 148:150) {
    out <- jwe_decrypt(
      rfc7520_token(figure),
      key,
      "A256GCMKW",
      "A128CBC-HS256"
    )
    expect_identical(rawToChar(out$plaintext), rfc7520_text(72), info = figure)
    expect_identical(out$alg, "A256GCMKW")
  }
})

test_that("RFC 7520 §5.8, §5.10–§5.12 (A128KW, A128GCM) decrypt", {
  key <- as_jwk(rfc7520_key(151))
  for (figure in c(159:161, 182, 183, 192, 193, 200, 201)) {
    out <- jwe_decrypt(rfc7520_token(figure), key, "A128KW", "A128GCM")
    expect_identical(rawToChar(out$plaintext), rfc7520_text(72), info = figure)
  }
})

test_that("RFC 7520 §5.3 (PBES2-HS512+A256KW) decrypts with the password", {
  password <- jwk_oct(charToRaw(enc2utf8(rfc7520_text(96))))
  for (figure in 105:107) {
    out <- jwe_decrypt(
      rfc7520_token(figure),
      password,
      "PBES2-HS512+A256KW",
      "A128CBC-HS256"
    )
    expect_identical(rawToChar(out$plaintext), rfc7520_text(95), info = figure)
    expect_identical(out$header$p2c, 8192L)
  }
})

test_that("the RFC's encrypted keys are reproduced from its factors", {
  # The key management step alone, with the generated factors the RFC
  # fixes: independent of header member order, unlike the whole token.
  k151 <- as_jwk(rfc7520_key(151))
  got <- wrap_cek("A128KW", k151, rfc7520_factor(152))
  expect_identical(got$encrypted_key, rfc7520_factor(154))

  k138 <- as_jwk(rfc7520_key(138))
  got <- wrap_cek(
    "A256GCMKW",
    k138,
    rfc7520_factor(139),
    fixed = list(gcmkw_iv = rfc7520_factor(141))
  )
  expect_identical(got$encrypted_key, rfc7520_factor(142))
  header <- jose_peek(rfc7520_token(148))$headers[[1]]
  expect_identical(got$header$iv, header$iv)
  expect_identical(got$header$tag, header$tag)

  password <- jwk_oct(charToRaw(enc2utf8(rfc7520_text(96))))
  got <- wrap_cek(
    "PBES2-HS512+A256KW",
    password,
    rfc7520_factor(97),
    p2c = 8192,
    fixed = list(p2s = rfc7520_factor(99))
  )
  expect_identical(got$encrypted_key, rfc7520_factor(100))
  expect_identical(got$header$p2s, "8Q1SzinasR3xchYz6ZZcHA")
  expect_identical(got$header$p2c, 8192)
})

test_that("RFC 7517 Appendix C (PBES2-HS256+A128KW) decrypts, every step reproduced", {
  # PBES2-HS256 had no known answer at check time (#102).
  password <- jwk_oct(rfc_octets(7517, "password"))
  alg <- "PBES2-HS256+A128KW"
  out <- jwe_decrypt(rfc_value(7517, "token"), password, alg, "A128CBC-HS256")
  expect_identical(out$plaintext, rfc_octets(7517, "plaintext"))
  expect_identical(out$header$p2c, 4096L)
  expect_identical(out$header$cty, "jwk+json")

  p2s <- rfc_octets(7517, "p2s")
  expect_identical(
    pbes2_kek(alg, password$k, p2s, 4096),
    rfc_octets(7517, "derived_key")
  )
  got <- wrap_cek(
    alg,
    password,
    rfc_octets(7517, "cek"),
    p2c = 4096,
    fixed = list(p2s = p2s)
  )
  expect_identical(got$encrypted_key, rfc_octets(7517, "encrypted_key"))
  expect_identical(got$header$p2s, rfc_value(7517, "p2s"))

  # The content encryption, under the RFC's protected header bytes.
  sealed <- content_encrypt(
    "A128CBC-HS256",
    rfc_octets(7517, "cek"),
    rfc_octets(7517, "iv"),
    rfc_octets(7517, "plaintext"),
    charToRaw(b64url_encode(charToRaw(rfc_value(7517, "header"))))
  )
  expect_identical(sealed$ciphertext, rfc_octets(7517, "ciphertext"))
  expect_identical(sealed$tag, rfc_octets(7517, "tag"))
})

# Round trips --------------------------------------------------------------

test_that("every key management algorithm round-trips with every GCM size", {
  for (enc in c("A128GCM", "A192GCM", "A256GCM")) {
    size <- as.integer(substr(enc, 2, 4)) / 8
    cases <- list(
      list("dir", jwk_oct(as.raw(seq_len(size)))),
      list("A192KW", jwk_oct(as.raw(1:24))),
      list("A128GCMKW", jwk_oct(as.raw(1:16))),
      list("A256GCMKW", jwk_oct(as.raw(1:32))),
      list("PBES2-HS256+A128KW", jwk_oct(charToRaw("hunter2")))
    )
    for (case in cases) {
      for (format in c("compact", "flattened", "general")) {
        token <- jwe_encrypt(
          "round",
          case[[2]],
          case[[1]],
          enc,
          header = if (startsWith(case[[1]], "PBES2")) {
            list(p2c = 1000)
          },
          format = format
        )
        out <- jwe_decrypt(token, case[[2]], case[[1]], enc)
        expect_identical(
          rawToChar(out$plaintext),
          "round",
          info = paste(enc, case[[1]], format)
        )
      }
    }
  }
})

test_that("an algorithm zucrypt cannot run is refused before decrypting", {
  key <- jwk_oct(as.raw(1:16))
  token <- jwe_encrypt("x", key, "A128KW", "A128GCM")
  real <- zujose_info
  local_no_crypto()
  # The content encryption, then the key management, each unavailable.
  for (alg in c("A128GCM", "A128KW")) {
    local_mocked_bindings(zujose_info = function() {
      info <- real()
      info$available[info$algorithm == alg] <- FALSE
      info
    })
    err <- expect_error(
      jwe_decrypt(token, key, "A128KW", "A128GCM"),
      class = "zujose_unsupported_error"
    )
    expect_identical(err$algorithm, alg)
  }
  # With no algorithm available, the content encryption is named first.
  local_mocked_bindings(zucrypt_provides = function(version, installed) {
    FALSE
  })
  local_mocked_bindings(zujose_info = real)
  err <- expect_error(
    jwe_decrypt(token, key, "A128KW", "A128GCM"),
    class = "zujose_unsupported_error"
  )
  expect_identical(err$needs, "0.1.1")
})

test_that("an unwrapped CEK of the wrong size for GCM is the decrypt error", {
  # A128KW wraps a 32-byte CEK, but A128GCM needs 16 bytes.
  key <- jwk_oct(as.raw(1:16))
  token <- paste(
    b64_json(list(alg = "A128KW", enc = "A128GCM")),
    b64url_encode(aes_key_wrap(key$k, as.raw(1:32))),
    b64url_encode(as.raw(1:12)),
    b64url_encode(as.raw(1:4)),
    b64url_encode(as.raw(1:16)),
    sep = "."
  )
  local_mocked_bindings(gcm_decrypt = function(...) stop("GCM reached"))
  expect_error(
    jwe_decrypt(token, key, "A128KW", "A128GCM"),
    class = "zujose_decrypt_error"
  )
})

test_that("GCM takes associated data in the JSON serializations", {
  key <- jwk_oct(as.raw(1:16))
  token <- jwe_encrypt(
    "x",
    key,
    "A128KW",
    "A128GCM",
    aad = "context",
    format = "flattened"
  )
  expect_identical(
    jwe_decrypt(token, key, "A128KW", "A128GCM")$plaintext,
    charToRaw("x")
  )
  obj <- zujson::json_parse(token)
  obj$aad <- b64url_encode(charToRaw("other"))
  expect_error(
    jwe_decrypt(zujson::json_write(obj), key, "A128KW", "A128GCM"),
    class = "zujose_decrypt_error"
  )
})

test_that("each GCMKW and PBES2 recipient gets its own parameters", {
  k1 <- jwk_with_kid(jwk_oct(as.raw(1:16)), "a")
  k2 <- jwk_with_kid(jwk_oct(charToRaw("pw")), "b")
  token <- jwe_encrypt(
    "both",
    list(
      jwe_recipient(k1, "A128GCMKW"),
      jwe_recipient(k2, "PBES2-HS256+A128KW", header = list(p2c = 1000))
    ),
    enc = "A256GCM",
    format = "general"
  )
  r <- zujson::json_parse(token, simplify = "none")$recipients
  expect_setequal(names(r[[1]]$header), c("alg", "kid", "iv", "tag"))
  expect_setequal(names(r[[2]]$header), c("alg", "kid", "p2c", "p2s"))
  for (k in list(k1, k2)) {
    out <- jwe_decrypt(
      token,
      k,
      c("A128GCMKW", "PBES2-HS256+A128KW"),
      "A256GCM"
    )
    expect_identical(rawToChar(out$plaintext), "both")
  }
})

test_that("PBES2 encryption generates a 16-byte salt and defaults p2c", {
  key <- jwk_oct(charToRaw("pw"))
  a <- jose_peek(jwe_encrypt(
    "x",
    key,
    "PBES2-HS256+A128KW",
    header = list(p2c = 1000)
  ))$headers[[1]]
  b <- jose_peek(jwe_encrypt(
    "x",
    key,
    "PBES2-HS256+A128KW",
    header = list(p2c = 1000)
  ))$headers[[1]]
  expect_length(b64url_decode(a$p2s, "p2s"), 16L)
  expect_false(identical(a$p2s, b$p2s))
  expect_identical(a$p2c, 1000L)
  expect_identical(pbes2_default_p2c, 600000L)
})

# Policy before cryptography (design §8.6) -------------------------------

test_that("a p2c over the cap fails before any key derivation", {
  local_mocked_bindings(pbes2_kek = function(...) stop("derived a key"))
  key <- jwk_oct(charToRaw("pw"))
  expect_error(
    jwe_decrypt(
      pbes2_token(p2c = 600001),
      key,
      "PBES2-HS256+A128KW",
      "A128GCM"
    ),
    class = "zujose_parse_error"
  )
  expect_error(
    jwe_decrypt(
      pbes2_token(p2c = 1000),
      key,
      "PBES2-HS256+A128KW",
      "A128GCM",
      limits = jose_limits(p2c = 999)
    ),
    class = "zujose_parse_error"
  )
  for (bad in list(0, -1, 1.5, "1000", NULL)) {
    expect_error(
      jwe_decrypt(
        pbes2_token(p2c = bad),
        key,
        "PBES2-HS256+A128KW",
        "A128GCM"
      ),
      class = "zujose_parse_error"
    )
  }
})

test_that("a p2s shorter than 8 bytes fails before any key derivation", {
  local_pbes2_reached()
  key <- jwk_oct(charToRaw("pw"))
  for (p2s in list(b64url_encode(as.raw(1:7)), "", NULL, "!!", 8)) {
    expect_error(
      jwe_decrypt(
        pbes2_token(p2s = p2s),
        key,
        "PBES2-HS256+A128KW",
        "A128GCM"
      ),
      class = "zujose_parse_error"
    )
  }
  # Eight bytes passes the checks and reaches the derivation.
  expect_error(
    jwe_decrypt(
      pbes2_token(p2s = b64url_encode(as.raw(1:8))),
      key,
      "PBES2-HS256+A128KW",
      "A128GCM"
    ),
    class = "pbes2_reached"
  )
})

test_that("malformed A*GCMKW header parameters are parse errors", {
  key <- jwk_oct(as.raw(1:16))
  good_iv <- b64url_encode(as.raw(1:12))
  good_tag <- b64url_encode(as.raw(1:16))
  for (h in list(
    list(iv = good_iv),
    list(tag = good_tag),
    list(iv = b64url_encode(as.raw(1:16)), tag = good_tag),
    list(iv = good_iv, tag = b64url_encode(as.raw(1:15))),
    list(iv = 12, tag = good_tag)
  )) {
    header <- c(list(alg = "A128GCMKW", enc = "A128GCM"), h)
    token <- paste(
      b64_json(header),
      "AAAA",
      "AAAAAAAAAAAAAAAA",
      "AAAA",
      "AAAAAAAAAAAAAAAAAAAAAA",
      sep = "."
    )
    expect_error(
      jwe_decrypt(token, key, "A128GCMKW", "A128GCM"),
      class = "zujose_parse_error"
    )
  }
})

# One error for every failure after policy (D5) -------------------------

test_that("tampering, a wrong key or a wrong password is one decrypt error", {
  key <- jwk_oct(as.raw(1:16))
  token <- jwe_encrypt("secret", key, "A128GCMKW", "A128GCM")
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  flip <- function(i) {
    p <- parts
    bytes <- b64url_decode(p[[i]], "part")
    bytes[[1]] <- xor(bytes[[1]], as.raw(1))
    p[[i]] <- b64url_encode(bytes)
    paste(p, collapse = ".")
  }
  msgs <- character()
  for (bad in list(flip(2), flip(3), flip(4), flip(5))) {
    err <- expect_error(
      jwe_decrypt(bad, key, "A128GCMKW", "A128GCM"),
      class = "zujose_decrypt_error"
    )
    msgs <- c(msgs, conditionMessage(err))
  }
  err <- expect_error(
    jwe_decrypt(token, jwk_oct(as.raw(2:17)), "A128GCMKW", "A128GCM"),
    class = "zujose_decrypt_error"
  )
  msgs <- c(msgs, conditionMessage(err))
  pw <- jwe_encrypt(
    "secret",
    jwk_oct(charToRaw("right")),
    "PBES2-HS256+A128KW",
    header = list(p2c = 1000)
  )
  err <- expect_error(
    jwe_decrypt(
      pw,
      jwk_oct(charToRaw("wrong")),
      "PBES2-HS256+A128KW",
      "A128CBC-HS256"
    ),
    class = "zujose_decrypt_error"
  )
  msgs <- c(msgs, conditionMessage(err))
  expect_length(unique(msgs), 1L)
})

# Encryption arguments ---------------------------------------------------

test_that("generated parameters cannot be supplied, and p2c is checked", {
  key <- jwk_oct(charToRaw("pw"))
  kek <- jwk_oct(as.raw(1:16))
  expect_error(
    jwe_encrypt(
      "x",
      key,
      "PBES2-HS256+A128KW",
      header = list(p2s = "AAAAAAAAAAA")
    ),
    class = "zujose_argument_error"
  )
  expect_error(
    jwe_encrypt("x", kek, "A128GCMKW", header = list(iv = "AAAAAAAAAAAAAAAA")),
    class = "zujose_argument_error"
  )
  expect_error(
    jwe_encrypt("x", kek, "A128GCMKW", header = list(tag = "AAAA")),
    class = "zujose_argument_error"
  )
  for (bad in list(999, 1000.5, "1000", NA)) {
    expect_error(
      jwe_encrypt("x", key, "PBES2-HS256+A128KW", header = list(p2c = bad)),
      class = "zujose_argument_error"
    )
  }
  expect_error(
    jwe_encrypt("x", kek, "A128KW", header = list(p2c = 1000)),
    class = "zujose_argument_error"
  )
})

test_that("a dir key may name its content encryption, and only that one", {
  # RFC 7520 §5.6's key says "alg": "A128GCM" for a dir token.
  key <- jwk_oct(as.raw(1:16), alg = "A128GCM")
  token <- jwe_encrypt("x", key, "dir", "A128GCM")
  expect_identical(
    jwe_decrypt(token, key, "dir", "A128GCM")$plaintext,
    charToRaw("x")
  )
  expect_error(
    jwe_encrypt(
      "x",
      jwk_oct(as.raw(1:16), alg = "A192GCM"),
      "dir",
      "A128GCM"
    ),
    class = "zujose_policy_error"
  )
  # Naming an enc is no licence for other algorithms.
  expect_error(
    jwe_encrypt("x", key, "A128KW", "A128GCM"),
    class = "zujose_policy_error"
  )
})

test_that("limits$keys caps the key attempts across all recipients", {
  # Each recipient alone is within limits$keys, but together they are not:
  # without a cap, a token with many PBES2 recipients costs one PBKDF2 run
  # each (#37). The refusal comes before any key is derived.
  password <- jwk_oct(charToRaw("correct horse"))
  recipients <- lapply(1:3, function(i) {
    jwe_recipient(password, "PBES2-HS256+A128KW", header = list(p2c = 1000L))
  })
  token <- jwe_encrypt("x", recipients, format = "general")
  local_mocked_bindings(pbes2_kek = function(...) stop("derived a key"))
  expect_error(
    jwe_decrypt(
      token,
      password,
      "PBES2-HS256+A128KW",
      "A128CBC-HS256",
      limits = jose_limits(keys = 2)
    ),
    class = "zujose_key_error"
  )
})

test_that("a header member is read by its exact name, not as p2c (#122)", {
  local_mocked_bindings(pbes2_kek = function(alg, password, p2s, p2c) {
    expect_identical(p2c, pbes2_default_p2c)
    as.raw(1:16)
  })
  password <- jwk_oct(charToRaw("pw"))
  kek <- jwk_oct(as.raw(1:16))
  header <- jose_peek(jwe_encrypt(
    "x",
    password,
    "PBES2-HS256+A128KW",
    header = list(p2count = 1234)
  ))$headers[[1]]
  expect_identical(header$p2c, pbes2_default_p2c)
  expect_identical(header[["p2count"]], 1234L)

  header <- jose_peek(jwe_encrypt(
    "x",
    kek,
    "A128KW",
    header = list(p2count = 1234)
  ))$headers[[1]]
  expect_false("p2c" %in% names(header))
  for (where in c("unprotected", "recipient")) {
    token <- if (where == "unprotected") {
      jwe_encrypt(
        "x",
        kek,
        "A128KW",
        unprotected = list(p2count = 1),
        format = "flattened"
      )
    } else {
      jwe_encrypt(
        "x",
        list(jwe_recipient(kek, "A128KW", header = list(p2count = 1))),
        format = "general"
      )
    }
    expect_false("p2c" %in% names(jose_peek(token)$headers[[1]]))
  }
})

test_that("a named p2c or enc is written as its value (#120)", {
  local_mocked_bindings(pbes2_kek = function(...) as.raw(1:16))
  password <- jwk_oct(charToRaw("pw"))
  for (where in c("header", "unprotected", "recipient")) {
    p2c <- list(p2c = c(n = 1000))
    token <- switch(
      where,
      header = jwe_encrypt(
        "x",
        password,
        "PBES2-HS256+A128KW",
        enc = c(e = "A128GCM"),
        header = p2c
      ),
      unprotected = jwe_encrypt(
        "x",
        password,
        "PBES2-HS256+A128KW",
        unprotected = p2c,
        format = "flattened"
      ),
      recipient = jwe_encrypt(
        "x",
        list(jwe_recipient(password, c(a = "PBES2-HS256+A128KW"), p2c)),
        format = "general"
      )
    )
    header <- jose_peek(token)$headers[[1]]
    expect_identical(header$p2c, 1000L)
    expect_type(header$alg, "character")
    expect_type(header$enc, "character")
  }
})

test_that("a p2c beyond 2^32 - 1 is a parse error at any limit (#123)", {
  local_mocked_bindings(pbes2_kek = function(...) stop("derived a key"))
  key <- jwk_oct(charToRaw("pw"))
  for (bad in list(4294967296, 1e300)) {
    expect_error(
      jwe_decrypt(
        pbes2_token(p2c = bad),
        key,
        "PBES2-HS256+A128KW",
        "A128GCM",
        limits = jose_limits(p2c = Inf)
      ),
      class = "zujose_parse_error"
    )
  }
  token <- sub(
    "^[^.]*",
    b64url_encode(charToRaw(paste0(
      "{\"alg\":\"PBES2-HS256+A128KW\",\"enc\":\"A128GCM\",",
      "\"p2c\":1e400,\"p2s\":\"AQIDBAUGBwgJCgsMDQ4PEA\"}"
    ))),
    pbes2_token()
  )
  expect_error(
    jwe_decrypt(
      token,
      key,
      "PBES2-HS256+A128KW",
      "A128GCM",
      limits = jose_limits(p2c = Inf)
    ),
    class = "zujose_error"
  )
})

test_that("the default p2c written is 600 000 (#140)", {
  local_mocked_bindings(pbes2_kek = function(...) as.raw(1:16))
  token <- jwe_encrypt("x", jwk_oct(charToRaw("pw")), "PBES2-HS256+A128KW")
  expect_identical(jose_peek(token)$headers[[1]]$p2c, 600000L)
})
