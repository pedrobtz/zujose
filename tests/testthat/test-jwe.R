# RFC vectors -------------------------------------------------------------

test_that("RFC 7516 A.3 decrypts and is reproduced byte for byte", {
  v <- rfc7516_a3()
  out <- jose_decrypt(v$token, v$key, "A128KW", "A128CBC-HS256")
  expect_s3_class(out, "jose_decrypted")
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
  key <- jose_with_kid(v$key, "7")
  out <- jose_decrypt(rfc7516_a4(), jose_keyset(key), "A128KW", "A128CBC-HS256")
  expect_identical(rawToChar(out$plaintext), v$plaintext)
  expect_identical(out$kid, "7")
  expect_identical(out$header$jku, "https://server.example.com/keys.jwks")
  # A single key is tried on the recipient whose algorithm fits.
  out <- jose_decrypt(rfc7516_a4(), v$key, "A128KW", "A128CBC-HS256")
  expect_identical(rawToChar(out$plaintext), v$plaintext)
  # Allowing only RSA1_5 leaves nothing zujwt can use yet.
  expect_error(
    jose_decrypt(rfc7516_a4(), v$key, "RSA1_5", "A128CBC-HS256"),
    class = "zujwt_unsupported_error"
  )
})

test_that("RFC 7520 §5.9 (zip) is refused before decryption", {
  key <- as_jose_key(rfc7520_key(151))
  for (figure in 170:172) {
    expect_error(
      jose_decrypt(rfc7520_token(figure), key, "A128KW", "A128GCM"),
      class = "zujwt_policy_error",
      info = figure
    )
  }
})

test_that("RFC 7520 §5.8 needs AES-GCM, which is not available yet", {
  key <- as_jose_key(rfc7520_key(151))
  expect_error(
    jose_decrypt(rfc7520_token(159), key, "A128KW", "A128GCM"),
    class = "zujwt_unsupported_error"
  )
})

# Round trips -------------------------------------------------------------

test_that("dir and every AES-KW size round-trip with every CBC-HS", {
  for (enc in names(cbc_hs)) {
    dir_key <- jose_key_oct(as.raw(seq_len(cbc_hs[[enc]]$key)))
    token <- encrypt_fixed("hello", dir_key, "dir", enc)
    expect_identical(
      jose_decrypt(token, dir_key, "dir", enc)$plaintext,
      charToRaw("hello"),
      info = enc
    )
    for (alg in names(kw_key_bytes)) {
      kek <- jose_key_oct(as.raw(100 + seq_len(kw_key_bytes[[alg]])))
      for (format in c("compact", "flattened", "general")) {
        token <- encrypt_fixed(as.raw(0:40), kek, alg, enc, format = format)
        expect_identical(
          jose_decrypt(token, kek, alg, enc)$plaintext,
          as.raw(0:40),
          info = paste(enc, alg, format)
        )
      }
    }
  }
})

test_that("several recipients, shared headers and AAD round-trip", {
  a <- jose_key_oct(as.raw(1:16), kid = "a")
  b <- jose_key_oct(as.raw(1:32), kid = "b")
  token <- encrypt_jwe(
    "to both",
    list(jose_recipient(a, "A128KW"), jose_recipient(b, "A256KW", list(x = 1))),
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
    out <- jose_decrypt(token, key, c("A128KW", "A256KW"), "A256CBC-HS512")
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
    jose_decrypt(zujson::json_write(obj), a, "A128KW", "A256CBC-HS512"),
    class = "zujwt_decrypt_error"
  )
})

test_that("the key's kid goes into the header unless one is given", {
  key <- jose_key_oct(as.raw(1:16), kid = "k")
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
    wrong_key = list(v$token, jose_key_oct(as.raw(1:16))),
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
        jose_decrypt(f[[1]], f[[2]], "A128KW", "A128CBC-HS256"),
        class = "zujwt_decrypt_error",
        info = name
      )
      expect_named(unclass(err)[c("message", "call")], c("message", "call"))
      conditionMessage(err)
    },
    ""
  )
  expect_length(unique(messages), 1L)

  # Bad padding under a valid tag, through dir.
  key <- jose_key_oct(as.raw(1:32))
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
    jose_decrypt(paste(parts, collapse = "."), key, "dir", "A128CBC-HS256"),
    class = "zujwt_decrypt_error"
  )
  expect_identical(conditionMessage(err), messages[[1]])
})

test_that("dir with an encrypted key is a decryption failure", {
  key <- jose_key_oct(as.raw(1:32))
  parts <- strsplit(encrypt_fixed("x", key, "dir"), ".", fixed = TRUE)[[1]]
  parts[[2]] <- b64url_encode(as.raw(1:24))
  expect_error(
    jose_decrypt(paste(parts, collapse = "."), key, "dir", "A128CBC-HS256"),
    class = "zujwt_decrypt_error"
  )
})

# Policy ------------------------------------------------------------------

test_that("algorithms and encryptions have no default and are checked", {
  v <- rfc7516_a3()
  expect_error(jose_decrypt(v$token, v$key), "algorithms")
  expect_error(jose_decrypt(v$token, v$key, "A128KW"), "encryptions")
  for (bad in list("none", "HS256", "A128GCM", character(), NA_character_)) {
    expect_error(
      jose_decrypt(v$token, v$key, bad, "A128CBC-HS256"),
      class = "zujwt_policy_error"
    )
  }
  expect_error(
    jose_decrypt(v$token, v$key, "A128KW", "A128KW"),
    class = "zujwt_policy_error"
  )
  expect_error(
    jose_decrypt(v$token, v$key, "A256KW", "A128CBC-HS256"),
    class = "zujwt_policy_error"
  )
  expect_error(
    jose_decrypt(v$token, v$key, "A128KW", "A256CBC-HS512"),
    class = "zujwt_policy_error"
  )
})

test_that("keys of the wrong size, type or use are refused before decryption", {
  v <- rfc7516_a3()
  expect_error(
    jose_decrypt(
      v$token,
      jose_key_oct(as.raw(1:24)),
      "A128KW",
      "A128CBC-HS256"
    ),
    class = "zujwt_key_error"
  )
  expect_error(
    jose_decrypt(
      v$token,
      jose_key_oct(as.raw(1:16), use = "sig"),
      "A128KW",
      "A128CBC-HS256"
    ),
    class = "zujwt_policy_error"
  )
  expect_error(
    jose_decrypt(
      v$token,
      jose_key_oct(as.raw(1:16), key_ops = "decrypt"),
      "A128KW",
      "A128CBC-HS256"
    ),
    class = "zujwt_policy_error"
  )
  expect_error(
    jose_decrypt(
      v$token,
      as_jose_key(rfc7520_key(3)),
      "A128KW",
      "A128CBC-HS256"
    ),
    class = "zujwt_policy_error"
  )
  dir <- jose_key_oct(as.raw(1:32))
  token <- encrypt_fixed("x", dir, "dir")
  expect_error(
    jose_decrypt(token, jose_key_oct(as.raw(1:64)), "dir", "A128CBC-HS256"),
    class = "zujwt_key_error"
  )
})

test_that("a JWS is not a JWE", {
  expect_error(
    jose_decrypt(
      rfc7520_token(34),
      jose_key_oct(as.raw(1:16)),
      "A128KW",
      "A128CBC-HS256"
    ),
    class = "zujwt_policy_error"
  )
})

test_that("jose_encrypt() needs randomness, which zucrypt 0.1.0 lacks", {
  err <- expect_error(
    jose_encrypt("x", jose_key_oct(as.raw(1:16)), "A128KW"),
    class = "zujwt_unsupported_error"
  )
  expect_identical(err$needs, "0.2.0")
})

test_that("encryption refuses inconsistent requests", {
  key <- jose_key_oct(as.raw(1:16))
  two <- list(jose_recipient(key, "A128KW"), jose_recipient(key, "A128KW"))
  expect_error(encrypt_fixed("x", key), class = "zujwt_policy_error")
  expect_error(
    encrypt_fixed("x", key, "A128GCMKW"),
    class = "zujwt_unsupported_error"
  )
  expect_error(
    encrypt_fixed("x", key, "A128KW", "A128GCM"),
    class = "zujwt_unsupported_error"
  )
  expect_error(encrypt_fixed("x", key, "HS256"), class = "zujwt_policy_error")
  expect_error(encrypt_fixed("x", key, "A256KW"), class = "zujwt_key_error")
  expect_error(encrypt_fixed("x", key, "dir"), class = "zujwt_key_error")
  expect_error(encrypt_fixed("x", two), "general")
  expect_error(
    encrypt_fixed("x", two, "A128KW", format = "general"),
    "recipient"
  )
  expect_error(encrypt_fixed("x", key, "A128KW", aad = "a"), "compact")
  expect_error(
    encrypt_fixed("x", key, "A128KW", unprotected = list(a = 1)),
    "compact"
  )
  expect_error(
    encrypt_fixed("x", key, "A128KW", header = list(zip = "DEF")),
    "zip"
  )
  expect_error(
    encrypt_fixed("x", key, "A128KW", header = list(enc = "x")),
    "enc"
  )
  expect_error(
    encrypt_fixed(
      "x",
      list(
        jose_recipient(jose_key_oct(as.raw(1:32)), "dir"),
        jose_recipient(key, "A128KW")
      ),
      format = "general"
    ),
    "dir"
  )
  expect_error(encrypt_fixed("x", "key", "A128KW"), class = "zujwt_key_error")
})

test_that("printing shows the header, not the plaintext", {
  v <- rfc7516_a3()
  expect_snapshot(print(jose_decrypt(
    v$token,
    v$key,
    "A128KW",
    "A128CBC-HS256"
  )))
  expect_snapshot(print(jose_decryption(v$key, "A128KW", "A128CBC-HS256")))
})

test_that("a key of the wrong size for one recipient is only ruled out there", {
  a <- jose_key_oct(as.raw(1:16), kid = "a")
  b <- jose_key_oct(as.raw(1:32), kid = "b")
  token <- encrypt_jwe(
    "x",
    list(jose_recipient(b, "A256KW"), jose_recipient(a, "A128KW")),
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
    jose_decrypt(
      token,
      jose_key_oct(a$k),
      c("A128KW", "A256KW"),
      "A128CBC-HS256"
    )$alg,
    "A128KW"
  )
  # Two keys share the kid; only the size tells them apart.
  set <- jose_keyset(jose_key_oct(as.raw(1:24), kid = "a"), a)
  expect_identical(
    jose_decrypt(token, set, "A128KW", "A128CBC-HS256")$plaintext,
    charToRaw("x")
  )
})
