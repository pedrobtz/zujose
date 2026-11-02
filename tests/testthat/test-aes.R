test_that("RFC 3394 §4 key wrap vectors wrap and unwrap", {
  for (case in names(rfc3394_vectors())) {
    v <- rfc3394_vectors()[[case]]
    kek <- hex(v[[1]])
    data <- hex(v[[2]])
    wrapped <- hex(v[[3]])
    expect_identical(aes_key_wrap(kek, data), wrapped, info = case)
    expect_identical(aes_key_unwrap(kek, wrapped), data, info = case)
  }
})

test_that("a tampered or wrong-length wrapped key unwraps to NULL", {
  v <- rfc3394_vectors()[["4.1"]]
  kek <- hex(v[[1]])
  wrapped <- hex(v[[3]])
  for (i in c(1L, 9L, length(wrapped))) {
    bad <- wrapped
    bad[[i]] <- xor(bad[[i]], as.raw(1))
    expect_null(aes_key_unwrap(kek, bad), info = i)
  }
  expect_null(aes_key_unwrap(hex(rfc3394_vectors()[["4.3"]][[1]]), wrapped))
  expect_null(aes_key_unwrap(kek, wrapped[-1]))
  expect_null(aes_key_unwrap(kek, wrapped[1:16]))
  expect_null(aes_key_unwrap(kek, raw()))
})

test_that("RFC 7518 Appendix B AES_CBC_HMAC_SHA2 vectors", {
  cases <- rfc7518_cbc()
  expect_identical(
    cases$enc,
    c("A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512")
  )
  for (i in seq_len(nrow(cases))) {
    v <- cases[i, ]
    sealed <- cbc_hs_encrypt(v$enc, hex(v$K), hex(v$IV), hex(v$P), hex(v$A))
    expect_identical(sealed$ciphertext, hex(v$E), info = v$enc)
    expect_identical(sealed$tag, hex(v$T), info = v$enc)
    expect_identical(
      cbc_hs_decrypt(v$enc, hex(v$K), hex(v$IV), hex(v$E), hex(v$T), hex(v$A)),
      hex(v$P),
      info = v$enc
    )
  }
})

test_that("CBC-HS returns NULL for every failure, before decrypting", {
  v <- rfc7518_cbc()[1, ]
  k <- hex(v$K)
  iv <- hex(v$IV)
  e <- hex(v$E)
  t <- hex(v$T)
  a <- hex(v$A)
  flip <- function(x, i = 1L) replace(x, i, xor(x[[i]], as.raw(1)))
  expect_null(cbc_hs_decrypt(v$enc, flip(k), iv, e, t, a))
  expect_null(cbc_hs_decrypt(v$enc, k, flip(iv), e, t, a))
  expect_null(cbc_hs_decrypt(v$enc, k, iv, flip(e, 50L), t, a))
  expect_null(cbc_hs_decrypt(v$enc, k, iv, e, flip(t), a))
  expect_null(cbc_hs_decrypt(v$enc, k, iv, e, t, flip(a)))
  expect_null(cbc_hs_decrypt(v$enc, k, iv, e, t[-1], a))
  expect_null(cbc_hs_decrypt(v$enc, k[-1], iv, e, t, a))
  expect_null(cbc_hs_decrypt(v$enc, k, iv[-1], e, t, a))
  expect_null(cbc_hs_decrypt(v$enc, k, iv, e[-1], t, a))
  expect_null(cbc_hs_decrypt(v$enc, k, iv, raw(), t, a))

  # A tag that verifies over a ciphertext whose padding is wrong.
  enc_key <- k[17:32]
  bad_padding <- zucrypt::crypt_aes_cbc_encrypt_nopad(
    as.raw(rep(0x11, 16)),
    enc_key,
    iv
  )
  tag <- cbc_hs_tag(v$enc, k[1:16], a, iv, bad_padding)
  expect_null(cbc_hs_decrypt(v$enc, k, iv, bad_padding, tag, a))
})
