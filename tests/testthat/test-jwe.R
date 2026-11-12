# RFC vectors -------------------------------------------------------------

test_that("RFC 7516 A.3 decrypts and is reproduced byte for byte", {
  v <- rfc7516_a3()
  out <- jwe_decrypt(v$token, v$key, "A128KW", "A128CBC-HS256")
  expect_s3_class(out, "jwe_decrypted")
  expect_identical(rawToChar(out$plaintext), v$plaintext)
  expect_identical(out$alg, "A128KW")
  expect_identical(out$enc, "A128CBC-HS256")
  expect_identical(
    encrypt_fixed(v$plaintext, v$key, "A128KW", cek = v$cek, iv = v$iv),
    v$token
  )
})

test_that("RFC 7516 A.4 decrypts for its A128KW recipient", {
  v <- rfc7516_a3()
  key <- jwk_with_kid(v$key, "7")
  out <- jwe_decrypt(rfc7516_a4(), jwk_set(key), "A128KW", "A128CBC-HS256")
  expect_identical(rawToChar(out$plaintext), v$plaintext)
  expect_identical(out$kid, "7")
  expect_identical(out$header$jku, "https://server.example.com/keys.jwks")
  # A single key is tried on the recipient whose algorithm fits.
  out <- jwe_decrypt(rfc7516_a4(), v$key, "A128KW", "A128CBC-HS256")
  expect_identical(rawToChar(out$plaintext), v$plaintext)
  # Allowing only RSA1_5 leaves only the RSA recipient, which a symmetric
  # key does not fit.
  expect_error(
    jwe_decrypt(rfc7516_a4(), v$key, "RSA1_5", "A128CBC-HS256"),
    class = "zujose_policy_error"
  )
})

test_that("RFC 7520 §5.9 (zip) is refused before decryption", {
  key <- as_jwk(rfc7520_key(151))
  for (figure in 170:172) {
    expect_error(
      jwe_decrypt(rfc7520_token(figure), key, "A128KW", "A128GCM"),
      class = "zujose_policy_error",
      info = figure
    )
  }
})


# Round trips -------------------------------------------------------------

test_that("dir and every AES-KW size round-trip with every CBC-HS", {
  for (enc in names(cbc_hs)) {
    dir_key <- jwk_oct(as.raw(seq_len(cbc_hs[[enc]]$key)))
    token <- encrypt_fixed("hello", dir_key, "dir", enc)
    expect_identical(
      jwe_decrypt(token, dir_key, "dir", enc)$plaintext,
      charToRaw("hello"),
      info = enc
    )
    for (alg in names(kw_key_bytes)) {
      kek <- jwk_oct(as.raw(100 + seq_len(kw_key_bytes[[alg]])))
      for (format in c("compact", "flattened", "general")) {
        token <- encrypt_fixed(as.raw(0:40), kek, alg, enc, format = format)
        expect_identical(
          jwe_decrypt(token, kek, alg, enc)$plaintext,
          as.raw(0:40),
          info = paste(enc, alg, format)
        )
      }
    }
  }
})

test_that("several recipients, shared headers and AAD round-trip", {
  a <- jwk_oct(as.raw(1:16), kid = "a")
  b <- jwk_oct(as.raw(1:32), kid = "b")
  token <- encrypt_jwe(
    "to both",
    list(jwe_recipient(a, "A128KW"), jwe_recipient(b, "A256KW", list(x = 1))),
    NULL,
    "A256CBC-HS512",
    header = list(typ = "JOSE"),
    unprotected = list(note = "shared"),
    aad = "extra",
    format = "general",
    cek = as.raw(1:64),
    iv = as.raw(1:16),
    call = NULL
  )
  for (key in list(a, b)) {
    out <- jwe_decrypt(token, key, c("A128KW", "A256KW"), "A256CBC-HS512")
    expect_identical(rawToChar(out$plaintext), "to both")
    expect_identical(out$kid, key$kid)
    expect_identical(out$header$note, "shared")
  }
  peek <- jose_peek(token)
  expect_identical(
    peek$headers[[2]][c("enc", "typ", "note", "alg", "kid", "x")],
    list(
      enc = "A256CBC-HS512",
      typ = "JOSE",
      note = "shared",
      alg = "A256KW",
      kid = "b",
      x = 1L
    )
  )
  # The AAD is authenticated.
  obj <- zujson::json_parse(token, simplify = "none")
  obj$aad <- b64url_encode(charToRaw("Extra"))
  expect_error(
    jwe_decrypt(zujson::json_write(obj), a, "A128KW", "A256CBC-HS512"),
    class = "zujose_decrypt_error"
  )
})

test_that("the key's kid goes into the header unless one is given", {
  key <- jwk_oct(as.raw(1:16), kid = "k")
  expect_identical(
    jose_peek(encrypt_fixed("x", key, "A128KW"))$headers[[1]],
    list(alg = "A128KW", enc = "A128CBC-HS256", kid = "k")
  )
  expect_identical(
    jose_peek(encrypt_fixed(
      "x",
      key,
      "A128KW",
      header = list(kid = "o")
    ))$headers[[1]]$kid,
    "o"
  )
})

# One failure, one message (design §8.6, D5) ------------------------------

test_that("every decryption failure has the same class and message", {
  v <- rfc7516_a3()
  parts <- strsplit(v$token, ".", fixed = TRUE)[[1]]
  rebuild <- function(i, bytes) {
    parts[[i]] <- b64url_encode(bytes)
    paste(parts, collapse = ".")
  }
  part <- function(i) b64url_decode(parts[[i]], "x")
  flip <- function(x, i = 1L) replace(x, i, xor(x[[i]], as.raw(1)))

  failures <- list(
    wrong_key = list(v$token, jwk_oct(as.raw(1:16))),
    unwrap = list(rebuild(2, flip(part(2))), v$key),
    wrapped_length = list(rebuild(2, part(2)[-1]), v$key),
    iv = list(rebuild(3, flip(part(3))), v$key),
    iv_length = list(rebuild(3, part(3)[-1]), v$key),
    ciphertext = list(rebuild(4, flip(part(4))), v$key),
    ciphertext_length = list(rebuild(4, part(4)[-1]), v$key),
    tag = list(rebuild(5, flip(part(5))), v$key),
    tag_length = list(rebuild(5, part(5)[-1]), v$key)
  )
  messages <- vapply(
    names(failures),
    function(name) {
      f <- failures[[name]]
      err <- expect_error(
        jwe_decrypt(f[[1]], f[[2]], "A128KW", "A128CBC-HS256"),
        class = "zujose_decrypt_error",
        info = name
      )
      expect_named(unclass(err)[c("message", "call")], c("message", "call"))
      conditionMessage(err)
    },
    ""
  )
  expect_length(unique(messages), 1L)

  # Bad padding under a valid tag, through dir.
  key <- jwk_oct(as.raw(1:32))
  token <- encrypt_fixed("x", key, "dir")
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  iv <- b64url_decode(parts[[3]], "x")
  bad <- zucrypt::crypt_aes_cbc_encrypt_nopad(
    as.raw(rep(0x11, 16)),
    key$k[17:32],
    iv
  )
  tag <- cbc_hs_tag(
    "A128CBC-HS256",
    key$k[1:16],
    charToRaw(parts[[1]]),
    iv,
    bad
  )
  parts[[4]] <- b64url_encode(bad)
  parts[[5]] <- b64url_encode(tag)
  err <- expect_error(
    jwe_decrypt(paste(parts, collapse = "."), key, "dir", "A128CBC-HS256"),
    class = "zujose_decrypt_error"
  )
  expect_identical(conditionMessage(err), messages[[1]])
})

test_that("dir with an encrypted key is a decryption failure", {
  key <- jwk_oct(as.raw(1:32))
  parts <- strsplit(encrypt_fixed("x", key, "dir"), ".", fixed = TRUE)[[1]]
  parts[[2]] <- b64url_encode(as.raw(1:24))
  expect_error(
    jwe_decrypt(paste(parts, collapse = "."), key, "dir", "A128CBC-HS256"),
    class = "zujose_decrypt_error"
  )
})

# Policy ------------------------------------------------------------------

test_that("algorithms and encryptions have no default and are checked", {
  v <- rfc7516_a3()
  expect_error(jwe_decrypt(v$token, v$key), "algorithms")
  expect_error(
    jwe_decrypt(v$token, v$key, "A128KW"),
    "encryptions"
  )
  for (bad in list("none", "HS256", "A128GCM", character(), NA_character_)) {
    expect_error(
      jwe_decrypt(v$token, v$key, bad, "A128CBC-HS256"),
      class = "zujose_policy_error"
    )
  }
  expect_error(
    jwe_decrypt(v$token, v$key, "A128KW", "A128KW"),
    class = "zujose_policy_error"
  )
  expect_error(
    jwe_decrypt(v$token, v$key, "A256KW", "A128CBC-HS256"),
    class = "zujose_policy_error"
  )
  expect_error(
    jwe_decrypt(v$token, v$key, "A128KW", "A256CBC-HS512"),
    class = "zujose_policy_error"
  )
})

test_that("keys of the wrong size, type or use are refused before decryption", {
  v <- rfc7516_a3()
  expect_error(
    jwe_decrypt(
      v$token,
      jwk_oct(as.raw(1:24)),
      "A128KW",
      "A128CBC-HS256"
    ),
    class = "zujose_key_error"
  )
  expect_error(
    jwe_decrypt(
      v$token,
      jwk_oct(as.raw(1:16), use = "sig"),
      "A128KW",
      "A128CBC-HS256"
    ),
    class = "zujose_policy_error"
  )
  expect_error(
    jwe_decrypt(
      v$token,
      jwk_oct(as.raw(1:16), key_ops = "decrypt"),
      "A128KW",
      "A128CBC-HS256"
    ),
    class = "zujose_policy_error"
  )
  expect_error(
    jwe_decrypt(
      v$token,
      as_jwk(rfc7520_key(3)),
      "A128KW",
      "A128CBC-HS256"
    ),
    class = "zujose_policy_error"
  )
  dir <- jwk_oct(as.raw(1:32))
  token <- encrypt_fixed("x", dir, "dir")
  expect_error(
    jwe_decrypt(token, jwk_oct(as.raw(1:64)), "dir", "A128CBC-HS256"),
    class = "zujose_key_error"
  )
})

test_that("a JWS is not a JWE", {
  expect_error(
    jwe_decrypt(
      rfc7520_token(34),
      jwk_oct(as.raw(1:16)),
      "A128KW",
      "A128CBC-HS256"
    ),
    class = "zujose_policy_error"
  )
})

test_that("two encryptions of one plaintext differ, and each decrypts", {
  kek <- jwk_oct(as.raw(1:16))
  cek <- jwk_oct(as.raw(1:32))
  for (format in c("compact", "flattened")) {
    for (case in list(list(kek, "A128KW"), list(cek, "dir"))) {
      a <- jwe_encrypt("same", case[[1]], case[[2]], format = format)
      b <- jwe_encrypt("same", case[[1]], case[[2]], format = format)
      expect_false(identical(a, b))
      for (token in list(a, b)) {
        out <- jwe_decrypt(token, case[[1]], case[[2]], "A128CBC-HS256")
        expect_identical(out$plaintext, charToRaw("same"))
      }
      # A fresh IV each time.
      iv_of <- function(token) {
        if (format == "compact") {
          strsplit(token, ".", fixed = TRUE)[[1]][[3]]
        } else {
          zujson::json_parse(token)$iv
        }
      }
      expect_false(identical(iv_of(a), iv_of(b)))
    }
  }
  # And for A128KW a fresh CEK: the wrapped keys differ too.
  a <- strsplit(jwe_encrypt("same", kek, "A128KW"), ".", fixed = TRUE)[[1]]
  b <- strsplit(jwe_encrypt("same", kek, "A128KW"), ".", fixed = TRUE)[[1]]
  expect_false(identical(a[[2]], b[[2]]))
  # A 16-byte IV is 22 Base64url characters.
  expect_identical(nchar(a[[3]]), 22L)
})

test_that("jwe_encrypt() exposes no CEK or IV argument", {
  expect_false(any(c("cek", "iv") %in% names(formals(jwe_encrypt))))
})

test_that("several recipients share one generated CEK", {
  k1 <- jwk_with_kid(jwk_oct(as.raw(1:16)), "1")
  k2 <- jwk_with_kid(jwk_oct(as.raw(17:48)), "2")
  token <- jwe_encrypt(
    "both",
    list(jwe_recipient(k1, "A128KW"), jwe_recipient(k2, "A256KW")),
    format = "general"
  )
  for (key in list(k1, k2)) {
    out <- jwe_decrypt(token, key, c("A128KW", "A256KW"), "A128CBC-HS256")
    expect_identical(rawToChar(out$plaintext), "both")
  }
})

test_that("encryption refuses inconsistent requests", {
  key <- jwk_oct(as.raw(1:16))
  two <- list(jwe_recipient(key, "A128KW"), jwe_recipient(key, "A128KW"))
  expect_error(encrypt_fixed("x", key), class = "zujose_policy_error")
  # ECDH-ES needs an EC or X25519 key, not a symmetric one.
  expect_error(
    encrypt_fixed("x", key, "ECDH-ES"),
    class = "zujose_policy_error"
  )
  expect_error(encrypt_fixed("x", key, "HS256"), class = "zujose_policy_error")
  expect_error(encrypt_fixed("x", key, "A256KW"), class = "zujose_key_error")
  expect_error(encrypt_fixed("x", key, "dir"), class = "zujose_key_error")
  expect_error(encrypt_fixed("x", two), class = "zujose_argument_error")
  expect_error(
    encrypt_fixed("x", two, "A128KW", format = "general"),
    class = "zujose_argument_error"
  )
  expect_error(
    encrypt_fixed("x", key, "A128KW", aad = "a"),
    class = "zujose_argument_error"
  )
  expect_error(
    encrypt_fixed("x", key, "A128KW", unprotected = list(a = 1)),
    class = "zujose_argument_error"
  )
  expect_error(
    encrypt_fixed("x", key, "A128KW", header = list(zip = "DEF")),
    class = "zujose_argument_error"
  )
  expect_error(
    encrypt_fixed("x", key, "A128KW", header = list(enc = "x")),
    class = "zujose_argument_error"
  )
  expect_error(
    encrypt_fixed(
      "x",
      list(
        jwe_recipient(jwk_oct(as.raw(1:32)), "dir"),
        jwe_recipient(key, "A128KW")
      ),
      format = "general"
    ),
    class = "zujose_argument_error"
  )
  expect_error(
    encrypt_fixed("x", "key", "A128KW"),
    class = "zujose_argument_error"
  )
})

test_that("printing shows the header, not the plaintext", {
  v <- rfc7516_a3()
  expect_snapshot(print(jwe_decrypt(
    v$token,
    v$key,
    "A128KW",
    "A128CBC-HS256"
  )))
  expect_snapshot(print(jwe_decryption(v$key, "A128KW", "A128CBC-HS256")))
})

test_that("a key of the wrong size for one recipient is only ruled out there", {
  a <- jwk_oct(as.raw(1:16), kid = "a")
  b <- jwk_oct(as.raw(1:32), kid = "b")
  token <- encrypt_jwe(
    "x",
    list(jwe_recipient(b, "A256KW"), jwe_recipient(a, "A128KW")),
    NULL,
    "A128CBC-HS256",
    NULL,
    NULL,
    NULL,
    format = "general",
    cek = as.raw(1:32),
    iv = as.raw(1:16),
    call = NULL
  )
  # `a` fits both recipients by type, but only the second by size.
  expect_identical(
    jwe_decrypt(
      token,
      jwk_oct(a$k),
      c("A128KW", "A256KW"),
      "A128CBC-HS256"
    )$alg,
    "A128KW"
  )
  # Two keys share the kid; only the size tells them apart.
  set <- jwk_set(jwk_oct(as.raw(1:24), kid = "a"), a)
  expect_identical(
    jwe_decrypt(token, set, "A128KW", "A128CBC-HS256")$plaintext,
    charToRaw("x")
  )
})

test_that("algorithms and encryptions are checked before any decryption", {
  # The key fits, so only the allow-lists can refuse the token, and they
  # must do so before a key is unwrapped or content decrypted (#36).
  kek <- jwk_oct(as.raw(1:16))
  token <- jwe_encrypt("x", kek, "A128KW", enc = "A128CBC-HS256")
  password <- jwk_oct(charToRaw("pw"))
  pbes2 <- jwe_encrypt(
    "x",
    password,
    "PBES2-HS256+A128KW",
    header = list(p2c = 1000L)
  )
  local_no_crypto()
  expect_error(
    jwe_decrypt(token, kek, "A256KW", "A128CBC-HS256"),
    class = "zujose_policy_error"
  )
  expect_error(
    jwe_decrypt(token, kek, "A128KW", "A256GCM"),
    class = "zujose_policy_error"
  )
  expect_error(
    jwe_decrypt(pbes2, password, "PBES2-HS384+A192KW", "A128CBC-HS256"),
    class = "zujose_policy_error"
  )
})

test_that("the AAD is the protected header as received, not re-serialized", {
  # jwcrypto's headers here have members out of order, spaces, a newline,
  # escapes and raw UTF-8, so re-serializing them gives other bytes and a
  # decoder that rebuilt the AAD from the parsed header would fail (#35).
  rows <- noncanonical_jwe()
  expect_gte(nrow(rows), 3L)
  for (i in seq_len(nrow(rows))) {
    row <- rows[i, ]
    received <- strsplit(row$token, ".", fixed = TRUE)[[1]][[1]]
    parsed <- jose_peek(row$token)$headers[[1]]
    expect_false(
      identical(b64url_encode(charToRaw(zujson::json_write(parsed))), received),
      info = row$id
    )
    out <- jwe_decrypt(
      row$token,
      jwk_oct(hex(row$key)),
      algorithms = row$alg,
      encryptions = row$enc
    )
    expect_identical(out$plaintext, hex(row$plaintext), info = row$id)
  }
})

test_that("every key management fails with one class and one message", {
  # A distinct message per algorithm or step would be an oracle (RFC 7516
  # section 11.5); each family is tested alone elsewhere, this compares
  # them with each other (#41).
  wrong_rsa <- jwk_generate("RSA")
  wrong_ec <- jwk_generate("EC")
  rsa <- jwk_generate("RSA")
  ec <- jwk_generate("EC")
  password <- jwk_oct(charToRaw("right"))
  cases <- list(
    A128KW = list(
      jwe_encrypt("x", jwk_oct(as.raw(1:16)), "A128KW"),
      jwk_oct(as.raw(2:17)),
      "A128CBC-HS256"
    ),
    dir = list(
      jwe_encrypt("x", jwk_oct(as.raw(1:16)), "dir", enc = "A128GCM"),
      jwk_oct(as.raw(2:17)),
      "A128GCM"
    ),
    A128GCMKW = list(
      jwe_encrypt("x", jwk_oct(as.raw(1:16)), "A128GCMKW"),
      jwk_oct(as.raw(2:17)),
      "A128CBC-HS256"
    ),
    "PBES2-HS256+A128KW" = list(
      jwe_encrypt(
        "x",
        password,
        "PBES2-HS256+A128KW",
        header = list(p2c = 1000L)
      ),
      jwk_oct(charToRaw("wrong")),
      "A128CBC-HS256"
    ),
    "RSA-OAEP-256" = list(
      jwe_encrypt("x", jwk_public(rsa), "RSA-OAEP-256"),
      wrong_rsa,
      "A128CBC-HS256"
    ),
    RSA1_5 = list(rfc7520_token(81), wrong_rsa, "A128CBC-HS256"),
    "ECDH-ES" = list(
      jwe_encrypt("x", jwk_public(ec), "ECDH-ES"),
      wrong_ec,
      "A128CBC-HS256"
    )
  )
  messages <- vapply(
    names(cases),
    function(alg) {
      case <- cases[[alg]]
      err <- expect_error(
        jwe_decrypt(case[[1]], case[[2]], alg, case[[3]]),
        class = "zujose_decrypt_error",
        info = alg
      )
      conditionMessage(err)
    },
    ""
  )
  expect_length(unique(messages), 1L)
})

test_that("jwk, x5c, jku and x5u in a JWE header are never used as keys", {
  # The attacker wraps the CEK with their own key and names it in the
  # header; were it used, the token would decrypt (#43).
  attacker <- jwk_oct(as.raw(101:116))
  caller <- jwk_oct(as.raw(1:16))
  named <- list(
    jwk = list(kty = "oct", k = b64url_encode(attacker$k)),
    x5c = list("MIIBszCCAVmgAwIBAgIU"),
    jku = "https://attacker.example/jwks.json",
    x5u = "https://attacker.example/cert.pem"
  )
  for (member in names(named)) {
    token <- jwe_encrypt(
      "x",
      attacker,
      "A128KW",
      header = stats::setNames(list(named[[member]]), member)
    )
    expect_error(
      jwe_decrypt(token, caller, "A128KW", "A128CBC-HS256"),
      class = "zujose_decrypt_error",
      info = member
    )
  }
})

test_that("a truncated tag that is a prefix of the real one is refused", {
  # A decoder that compared only the bytes it was given would accept a
  # prefix, and a 4-byte tag can be forged in about 2^32 tries (RFC 8725;
  # design §10). Every truncation is the one decryption error (#73).
  kek <- jwk_oct(as.raw(1:16))
  for (enc in c("A128CBC-HS256", "A256CBC-HS512", "A128GCM", "A256GCM")) {
    token <- jwe_encrypt("attack at dawn", kek, "A128KW", enc = enc)
    parts <- strsplit(token, ".", fixed = TRUE)[[1]]
    tag <- b64url_decode(parts[[5]], "tag")
    for (n in unique(c(length(tag) - 1L, 16L, 12L, 8L, 4L, 1L))) {
      if (n >= length(tag)) {
        next
      }
      truncated <- paste(
        c(parts[1:4], b64url_encode(tag[seq_len(n)])),
        collapse = "."
      )
      err <- expect_error(
        jwe_decrypt(truncated, kek, "A128KW", enc),
        class = "zujose_decrypt_error",
        info = paste(enc, n)
      )
      expect_identical(conditionMessage(err), "Decryption failed.")
    }
  }
})

test_that("JWE headers with repeated or empty names are refused (#119)", {
  kek <- jwk_oct(as.raw(1:16))
  bad <- list(
    list(a = 1, a = 2),
    list(x = list(a = 1, a = 2)),
    stats::setNames(list(1), NA),
    list(x = as.raw(1)),
    list(x = 1i)
  )
  for (header in bad) {
    expect_error(
      jwe_encrypt("x", kek, "A128KW", header = header),
      class = "zujose_argument_error"
    )
    expect_error(
      jwe_encrypt(
        "x",
        kek,
        "A128KW",
        unprotected = header,
        format = "flattened"
      ),
      class = "zujose_argument_error"
    )
    expect_error(
      jwe_recipient(kek, "A128KW", header = header),
      class = "zujose_argument_error"
    )
  }
  expect_error(
    jwe_encrypt(
      "x",
      kek,
      "A128KW",
      header = list(a = 1),
      unprotected = list(a = 2),
      format = "flattened"
    ),
    class = "zujose_argument_error"
  )
  expect_error(
    jwe_encrypt(
      "x",
      list(jwe_recipient(kek, "A128KW", header = list(a = 2))),
      unprotected = list(a = 1),
      format = "general"
    ),
    class = "zujose_argument_error"
  )
})

test_that("zip is refused in every header jwe_encrypt() takes (#117)", {
  kek <- jwk_oct(as.raw(1:16))
  zip <- list(zip = "DEF")
  expect_error(
    jwe_encrypt("x", kek, "A128KW", header = zip),
    class = "zujose_argument_error"
  )
  for (format in c("flattened", "general")) {
    expect_error(
      jwe_encrypt("x", kek, "A128KW", unprotected = zip, format = format),
      class = "zujose_argument_error"
    )
  }
  expect_error(
    jwe_recipient(kek, "A128KW", header = zip),
    class = "zujose_argument_error"
  )
})

test_that("a recipient header alg must agree with the algorithm (#129)", {
  kek <- jwk_oct(as.raw(1:16))
  for (format in c("flattened", "general")) {
    expect_error(
      jwe_encrypt(
        "p",
        list(jwe_recipient(kek, "A128KW", header = list(alg = "A256KW"))),
        format = format
      ),
      class = "zujose_argument_error"
    )
    expect_error(
      jwe_encrypt(
        "p",
        list(jwe_recipient(
          jwk_oct(as.raw(1:16), alg = "A128KW"),
          header = list(alg = "A256KW")
        )),
        format = format
      ),
      class = "zujose_argument_error"
    )
    # The same `alg` is written once.
    token <- jwe_encrypt(
      "p",
      list(jwe_recipient(kek, "A128KW", header = list(alg = "A128KW"))),
      format = format
    )
    expect_identical(jose_peek(token)$headers[[1]]$alg, "A128KW")
  }
})

test_that("`enc` must be one string (#123)", {
  kek <- jwk_oct(as.raw(1:16))
  for (enc in list(c("A128GCM", "A256GCM"), NA_character_, 1, NULL)) {
    expect_error(
      jwe_encrypt("x", kek, "A128KW", enc = enc),
      class = "zujose_argument_error"
    )
  }
})
