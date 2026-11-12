# Project Wycheproof as the oracle (tools/make-wycheproof.py). Each case says
# whether a correct implementation must accept it, must reject it, or may
# do either ("acceptable"). zujose must agree, except for the cases listed
# here with the reason, each of which must still disagree.

test_that("the JWS verifier agrees with Wycheproof's signature verdicts", {
  keys <- wycheproof_table("keys")
  rows <- wycheproof_table("signatures")
  expect_setequal(
    rows$alg,
    paste0(rep(c("HS", "RS", "PS", "ES"), each = 3), c("256", "384", "512"))
  )
  pss_salt_0 <- "rsa_pss_2048_sha256_mgf1_0_test.json"
  expected <- rows$result
  # RFC 7518 section 3.5: a PS* salt is as long as the hash. Wycheproof's
  # verdicts in this file are for a salt of 0, so each valid signature
  # must be refused, and tcId 69, re-signed with a 32-byte salt, accepted.
  salt_0 <- rows$file == pss_salt_0
  expected[salt_0] <- ifelse(rows$tc_id[salt_0] == "69", "valid", "invalid")
  # The DigestInfo without its NULL parameters (MissingNull) is
  # "acceptable"; zujose refuses it, as zucrypt reads DigestInfo strictly.
  expected[rows$result == "acceptable"] <- "invalid"
  expect_true(any(salt_0 & rows$result == "valid"))
  expect_true(any(salt_0 & rows$tc_id == "69"))
  expect_identical(sum(rows$result == "acceptable"), 3L)

  parsed <- list()
  for (i in seq_len(nrow(rows))) {
    row <- rows[i, ]
    key <- parsed[[row$key]] %||% wycheproof_key(keys, row$key)
    parsed[[row$key]] <- key
    ok <- jws_verify_bytes(
      row$alg,
      key,
      b64url_decode(row$msg),
      b64url_decode(row$sig),
      NULL
    )
    info <- paste(row$file, row$tc_id, row$flags)
    expect_identical(if (ok) "valid" else "invalid", expected[[i]], info = info)
  }
})

test_that("JWS, JWE and JWK refusals agree with Wycheproof's JOSE vectors", {
  # Where zujose decides otherwise on purpose, by file and tcId.
  divergent <- c(
    # zujose reads the JSON serializations too (design section 1); these
    # cases expect a compact-only library to refuse them.
    "json_web_encryption_test.json 22" = "JSON serialization",
    "json_web_crypto_test.json 17" = "JSON serialization",
    "json_web_crypto_test.json 66" = "JSON serialization",
    # Design section 8.3: a token's `kid` picks the candidates in a key
    # set and only keys that fit its `alg` are tried, so a set mixing HMAC
    # and EC keys, or two keys sharing a `kid`, is not ambiguous. Wycheproof
    # flags these Ambiguous: not defined by the RFCs.
    "json_web_key_test.json 1" = "a mixed key set",
    "json_web_crypto_test.json 47" = "a mixed key set",
    "json_web_key_test.json 4" = "a repeated kid",
    # Design section 3: zujose refuses `zip` (RFC 8725 section 3.6).
    "json_web_encryption_test.json 135" = "zip",
    # Wycheproof's key names another `alg` than the RFC 7520 token it
    # verifies: PS256 for the PS384 figure 20, and ES521, which does not
    # exist, for the ES512 figure 27. A key's `alg` binds it (design 8.2).
    "json_web_signature_test.json 346" = "the key's alg disagrees",
    "json_web_signature_test.json 347" = "the key's alg disagrees",
    "json_web_signature_test.json 350" = "the key's alg disagrees",
    "json_web_signature_test.json 351" = "the key's alg disagrees",
    # Wycheproof's own errors at this commit: the "invalidBase64Padding"
    # tokens are byte for byte the valid tcId 357, and the two "valid"
    # tokens hold a `?`, which Base64url does not have.
    "json_web_signature_test.json 367" = "same token as tcId 357",
    "json_web_signature_test.json 370" = "same token as tcId 357",
    "json_web_signature_test.json 372" = "not Base64url",
    "json_web_signature_test.json 373" = "not Base64url"
  )
  keys <- wycheproof_table("keys")
  rows <- wycheproof_table("jose")
  ids <- paste(rows$file, rows$tc_id)
  expect_true(all(names(divergent) %in% ids))
  # The caller allows every algorithm zujose has, so only the key's type,
  # curve, `alg` and `use` stand between a token and a confused key.
  table <- jwa_table()
  signing <- table$algorithm[table$kind == "signature"]
  management <- table$algorithm[table$kind == "key management"]
  content <- table$algorithm[table$kind == "content encryption"]

  parsed <- list()
  for (i in seq_len(nrow(rows))) {
    row <- rows[i, ]
    ours <- tryCatch(
      {
        key <- parsed[[row$key]] %||% wycheproof_key(keys, row$key)
        parsed[[row$key]] <- key
        if (row$kind == "jws") {
          jws_verify(row$token, key, signing)
        } else {
          out <- jwe_decrypt(row$token, key, management, content)
          if (nzchar(row$pt)) {
            expect_identical(out$plaintext, hex(row$pt), info = ids[[i]])
          }
        }
        "valid"
      },
      zujose_error = function(e) "invalid"
    )
    if (ids[[i]] %in% names(divergent)) {
      expect_false(identical(ours, row$result), info = ids[[i]])
    } else {
      expect_identical(ours, row$result, info = ids[[i]])
    }
  }
})
