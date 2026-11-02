# Constructions JWA defines over AES, composed in R from zucrypt's CBC
# functions (design §6, D4). Each is tested against its RFC vectors.

# One AES block. CBC over a single block with a zero IV is the block cipher
# itself, in both directions.
aes_block_encrypt <- function(key, block) {
  zucrypt::crypt_aes_cbc_encrypt_nopad(block, key, raw(16))
}

aes_block_decrypt <- function(key, block) {
  zucrypt::crypt_aes_cbc_decrypt_nopad(block, key, raw(16))
}

# RFC 3394 §2.2.3.1.
kw_iv <- as.raw(rep(0xa6, 8))

# XOR the 64-bit big-endian counter `t` into `a`.
kw_xor_t <- function(a, t) {
  for (i in 8:1) {
    a[[i]] <- xor(a[[i]], as.raw(t %% 256))
    t <- t %/% 256
  }
  a
}

# RFC 3394 §2.2.1. `data` is a whole number of 64-bit blocks, at least two.
aes_key_wrap <- function(kek, data) {
  n <- length(data) %/% 8L
  stopifnot(length(data) %% 8L == 0L, n >= 2L)
  a <- kw_iv
  r <- split(data, rep(seq_len(n), each = 8L))
  for (j in 0:5) {
    for (i in seq_len(n)) {
      b <- aes_block_encrypt(kek, c(a, r[[i]]))
      a <- kw_xor_t(b[1:8], n * j + i)
      r[[i]] <- b[9:16]
    }
  }
  c(a, unlist(r, use.names = FALSE))
}

# RFC 3394 §2.2.2 and §2.2.3. Returns NULL when the integrity check fails,
# so that the caller raises the one decryption error (D5).
aes_key_unwrap <- function(kek, wrapped) {
  n <- length(wrapped) %/% 8L - 1L
  if (length(wrapped) %% 8L != 0L || n < 2L) {
    return(NULL)
  }
  a <- wrapped[1:8]
  r <- split(wrapped[-(1:8)], rep(seq_len(n), each = 8L))
  for (j in 5:0) {
    for (i in n:1) {
      b <- aes_block_decrypt(kek, c(kw_xor_t(a, n * j + i), r[[i]]))
      a <- b[1:8]
      r[[i]] <- b[9:16]
    }
  }
  if (!zucrypt::crypt_equal(a, kw_iv)) {
    return(NULL)
  }
  unlist(r, use.names = FALSE)
}

# AES_CBC_HMAC_SHA2 (RFC 7518 §5.2). The key is MAC_KEY || ENC_KEY, and the
# tag is the first half of HMAC(MAC_KEY, A || IV || E || AL).
cbc_hs <- list(
  "A128CBC-HS256" = list(key = 32L, hash = "sha256"),
  "A192CBC-HS384" = list(key = 48L, hash = "sha384"),
  "A256CBC-HS512" = list(key = 64L, hash = "sha512")
)

cbc_hs_tag <- function(enc, mac_key, aad, iv, ciphertext) {
  bits <- 8 * length(aad)
  al <- as.raw(vapply(7:0, function(k) (bits %/% 256^k) %% 256, numeric(1)))
  mac <- zucrypt::crypt_hmac(
    c(aad, iv, ciphertext, al),
    mac_key,
    cbc_hs[[enc]]$hash
  )
  mac[seq_len(length(mac) %/% 2L)]
}

cbc_hs_encrypt <- function(enc, key, iv, plaintext, aad) {
  half <- length(key) %/% 2L
  mac_key <- key[seq_len(half)]
  enc_key <- key[-seq_len(half)]
  pad <- 16L - length(plaintext) %% 16L
  padded <- c(plaintext, as.raw(rep(pad, pad)))
  ciphertext <- zucrypt::crypt_aes_cbc_encrypt_nopad(padded, enc_key, iv)
  list(
    ciphertext = ciphertext,
    tag = cbc_hs_tag(enc, mac_key, aad, iv, ciphertext)
  )
}

# Verify the tag before any decryption (RFC 7518 §5.2.2.2), then remove the
# padding. Returns NULL on any failure, never saying which.
cbc_hs_decrypt <- function(enc, key, iv, ciphertext, tag, aad) {
  spec <- cbc_hs[[enc]]
  if (
    length(key) != spec$key ||
      length(iv) != 16L ||
      length(ciphertext) == 0L ||
      length(ciphertext) %% 16L != 0L ||
      length(tag) != spec$key %/% 2L
  ) {
    return(NULL)
  }
  half <- length(key) %/% 2L
  expected <- cbc_hs_tag(enc, key[seq_len(half)], aad, iv, ciphertext)
  if (!zucrypt::crypt_equal(tag, expected)) {
    return(NULL)
  }
  padded <- zucrypt::crypt_aes_cbc_decrypt_nopad(
    ciphertext,
    key[-seq_len(half)],
    iv
  )
  pad <- as.integer(padded[[length(padded)]])
  if (
    pad < 1L ||
      pad > 16L ||
      !all(padded[(length(padded) - pad + 1L):length(padded)] == as.raw(pad))
  ) {
    return(NULL)
  }
  padded[seq_len(length(padded) - pad)]
}
