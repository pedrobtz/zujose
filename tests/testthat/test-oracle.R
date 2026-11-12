# PyJWT as the oracle (design section 10). Its tokens and keys are written
# offline by tools/make-oracle-fixtures.py, so no other JOSE implementation
# is needed at check time.

test_that("zujose verifies every JWT PyJWT signs", {
  for (i in seq_len(nrow(oracle_tokens()))) {
    row <- oracle_tokens()[i, ]
    if (row$key == "hmac-wrong") {
      next
    }
    claims <- jwt_decode(
      row$token,
      oracle_key(row$key),
      row$alg,
      audience = "api",
      now = oracle_now()
    )
    expect_identical(claims$sub, "u2", info = row$id)
    expect_identical(claims$n, 42L, info = row$id)
  }
})

test_that("zujose signs exactly as PyJWT does for HS* and RS*", {
  # Both are deterministic, so the same signing input under the same key
  # gives the same signature.
  tokens <- oracle_tokens()
  tokens <- tokens[grepl("^(HS|RS)", tokens$alg) & tokens$key != "hmac-wrong", ]
  for (i in seq_len(nrow(tokens))) {
    row <- tokens[i, ]
    parts <- strsplit(row$token, ".", fixed = TRUE)[[1]]
    input <- charToRaw(paste0(parts[[1]], ".", parts[[2]]))
    ours <- jws_sign_bytes(
      row$alg,
      oracle_key(row$key, public = FALSE),
      input,
      NULL
    )
    expect_identical(b64url_encode(ours), parts[[3]], info = row$id)
  }
})

test_that("a PyJWT token signed with the wrong secret is refused", {
  row <- oracle_tokens()[oracle_tokens()$id == "hs256-wrong", ]
  expect_error(
    jwt_decode(row$token, oracle_key("hmac"), "HS256", now = oracle_now()),
    class = "zujose_signature_error"
  )
})

test_that("a PyJWT token is refused under an algorithm it was not given", {
  local_no_crypto()
  tokens <- oracle_tokens()
  tokens <- tokens[tokens$key != "hmac-wrong", ]
  for (i in seq_len(nrow(tokens))) {
    row <- tokens[i, ]
    family <- substr(row$alg, 1L, 2L)
    other <- setdiff(paste0(family, c("256", "384", "512")), row$alg)
    expect_error(
      jwt_decode(
        row$token,
        oracle_key(row$key),
        other,
        audience = "api",
        now = oracle_now()
      ),
      class = "zujose_policy_error",
      info = row$id
    )
  }
})

# jwcrypto's known answers (tools/make-jwe-vectors.py): A192*, A*GCM and the
# Concat KDF's second round, with fixed keys and ephemeral keys (#102).

test_that("zujose decrypts every jwcrypto known-answer JWE", {
  rows <- oracle_jwe_vectors()
  for (i in seq_len(nrow(rows))) {
    row <- rows[i, ]
    out <- jwe_decrypt(row$token, as_jwk(row$key), row$alg, row$enc)
    expect_identical(out$plaintext, hex(row$plaintext), info = row$id)
  }
})

test_that("zujose encrypts dir, A192KW and A192GCMKW as jwcrypto did", {
  # Their headers are the ones zujose writes, so at jwcrypto's CEK and IVs
  # the whole token is reproduced.
  rows <- oracle_jwe_vectors()
  rows <- rows[rows$alg %in% c("dir", "A192KW", "A192GCMKW"), ]
  expect_identical(nrow(rows), 7L)
  for (i in seq_len(nrow(rows))) {
    row <- rows[i, ]
    parts <- strsplit(row$token, ".", fixed = TRUE)[[1]]
    header <- zujson::json_parse(rawToChar(b64url_decode(parts[[1]], "h")))
    fixed <- if (!is.null(header$iv)) {
      list(kw_iv = b64url_decode(header$iv, "iv"))
    }
    ours <- encrypt_fixed(
      hex(row$plaintext),
      as_jwk(row$key),
      row$alg,
      row$enc,
      cek = hex(row$cek),
      iv = b64url_decode(parts[[3]], "iv"),
      fixed = as.list(fixed)
    )
    expect_identical(ours, row$token, info = row$id)
  }
})

test_that("ECDH-ES derives jwcrypto's keys, over 256 bits too", {
  # With jwcrypto's ephemeral key, zujose's Concat KDF must give the CEK
  # (direct) or the encrypted key (+A192KW) that jwcrypto's did.
  rows <- oracle_jwe_vectors()
  rows <- rows[startsWith(rows$alg, "ECDH-ES"), ]
  expect_true(all(c("A192CBC-HS384", "A256CBC-HS512") %in% rows$enc))
  for (i in seq_len(nrow(rows))) {
    row <- rows[i, ]
    parts <- strsplit(row$token, ".", fixed = TRUE)[[1]]
    header <- zujson::json_parse(rawToChar(b64url_decode(parts[[1]], "h")))
    got <- wrap_cek(
      row$alg,
      jwk_public(as_jwk(row$key)),
      hex(row$cek),
      fixed = list(epk = as_jwk(row$ephemeral)),
      enc = row$enc
    )
    expect_identical(got$header$epk$x, header$epk$x, info = row$id)
    if (row$alg == "ECDH-ES") {
      expect_identical(got$cek, hex(row$cek), info = row$id)
    } else {
      expect_identical(
        b64url_encode(got$encrypted_key),
        parts[[2]],
        info = row$id
      )
    }
  }
})

# jwcrypto's JWE JSON serializations (tools/make-jwe-json.py, #101); the
# writing direction is tools/jwe-oracle/'s, in development.

test_that("zujose decrypts jwcrypto's JWE JSON for each recipient alone", {
  rows <- oracle_jwe_json()
  expect_setequal(
    vapply(rows$token, function(t) jose_peek(t)$serialization, ""),
    c("flattened", "general")
  )
  n <- 0L
  for (i in seq_len(nrow(rows))) {
    row <- rows[i, ]
    keys <- as_jwk_set(row$keys)
    algs <- strsplit(row$algs, ",", fixed = TRUE)[[1]]
    kids <- strsplit(row$kids, ",", fixed = TRUE)[[1]]
    for (j in seq_along(kids)) {
      info <- paste(row$id, kids[[j]])
      out <- jwe_decrypt(row$token, keys[[kids[[j]]]], algs, row$enc)
      expect_identical(out$plaintext, hex(row$plaintext), info = info)
      expect_identical(out$alg, algs[[j]], info = info)
      expect_identical(out$enc, row$enc, info = info)
      expect_identical(out$kid, kids[[j]], info = info)
      # The protected, shared and per-recipient headers, merged.
      expect_identical(out$header$cty, "text/plain", info = info)
      expect_identical(out$header[["x-shared"]], "unprotected", info = info)
      expect_identical(out$header[["x-recipient"]], kids[[j]], info = info)
      n <- n + 1L
    }
  }
  expect_identical(n, 9L)
})
