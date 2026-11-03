# Stage 8: RSA keys, RS*/PS* signatures, RSA-OAEP and RSA1_5 (design §8.2,
# §8.3, §8.4).

# RFC vectors ------------------------------------------------------------

test_that("RFC 7515 A.2 (RS256) is reproduced byte for byte", {
  key <- as_jose_key(paste0(
    '{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26',
    'mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPE',
    'wOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-',
    'KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH',
    '7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",',
    '"e":"AQAB","d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97',
    'IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVR',
    'UCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qA',
    'dGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3c',
    'cPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",',
    '"p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58',
    'BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-n',
    'XqhJTBgIPgtldC-KDV5z-y2XDwGUc","q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmt',
    'H4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_Hl',
    'B-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc","dp":"BwKf',
    'V3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT',
    '_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5',
    'Mbr1C1XsmvkxHQAdYo0","dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaa',
    'MwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2',
    'v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU","qi":"IYd7DHOhrWvxkwPQ',
    'sRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY',
    '7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHu',
    'LFkuQ3U"}'
  ))
  token <- paste0(
    "eyJhbGciOiJSUzI1NiJ9.",
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxl",
    "LmNvbS9pc19yb290Ijp0cnVlfQ.",
    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4B",
    "h-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZ",
    "LgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_d",
    "O--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6",
    "LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
  )
  payload <- strsplit(token, ".", fixed = TRUE)[[1]][[2]]
  signed <- jose_sign(
    b64url_decode(payload, "payload"),
    key,
    header = list(),
    alg = "RS256"
  )
  # zujose's protected header is {"alg":"RS256"}, as the RFC's is.
  expect_identical(signed, token)
  out <- jose_verify(token, jose_public(key), "RS256")
  expect_identical(out$alg, "RS256")
})

test_that("RFC 7520 §4.1 (RS256) and §4.2 (PS384) verify", {
  key <- jose_public(as_jose_key(rfc7520_key(4)))
  for (figure in 13:15) {
    expect_identical(
      jose_verify(rfc7520_token(figure), key, "RS256")$alg,
      "RS256",
      info = figure
    )
  }
  for (figure in 20:22) {
    expect_identical(
      jose_verify(rfc7520_token(figure), key, "PS384")$alg,
      "PS384",
      info = figure
    )
  }
})

test_that("RFC 7520 §4.8's RS256 signature verifies", {
  key <- jose_public(as_jose_key(rfc7520_key(4)))
  out <- jose_verify(rfc7520_token(71), key, "RS256", require = "any")
  expect_true("RS256" %in% out$alg)
})

test_that("RFC 7520 §5.1 (RSA1_5) and §5.2 (RSA-OAEP) decrypt", {
  key <- as_jose_key(rfc7520_key(73))
  for (figure in 81:83) {
    out <- jose_decrypt(rfc7520_token(figure), key, "RSA1_5", "A128CBC-HS256")
    expect_identical(rawToChar(out$plaintext), rfc7520_text(72), info = figure)
  }
  key <- as_jose_key(rfc7520_key(84))
  for (figure in 92:94) {
    out <- jose_decrypt(rfc7520_token(figure), key, "RSA-OAEP", "A256GCM")
    expect_identical(rawToChar(out$plaintext), rfc7520_text(72), info = figure)
  }
})

test_that("RFC 7520 §6 (a PS256 JWT inside an RSA-OAEP JWE) decrypts and verifies", {
  enc_key <- as_jose_key(rfc7520_key(84))
  sig_key <- jose_public(as_jose_key(rfc7520_key(224)))
  for (figure in 236:238) {
    out <- jose_decrypt(rfc7520_token(figure), enc_key, "RSA-OAEP", "A128GCM")
    expect_identical(
      rawToChar(out$plaintext),
      rfc7520_token(228),
      info = figure
    )
  }
  # A JWT is compact, so only Figure 236 is one.
  claims <- jose_jwt_decode(
    rfc7520_token(236),
    sig_key,
    "PS256",
    now = as_posixct(1300819000),
    decrypt = jose_decryption(enc_key, "RSA-OAEP", "A128GCM")
  )
  expect_identical(claims$iss, "hobbiton.example")
})

# Round trips -------------------------------------------------------------

test_that("every RS* and PS* algorithm signs and verifies", {
  key <- jose_key_generate("RSA")
  pub <- jose_public(key)
  for (alg in c("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")) {
    token <- jose_sign("hello", key, alg)
    expect_identical(
      jose_verify(token, pub, alg)$payload,
      charToRaw("hello"),
      info = alg
    )
    other <- setdiff(
      c("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"),
      alg
    )
    expect_error(
      jose_verify(token, pub, other),
      class = "zujose_policy_error",
      info = alg
    )
  }
  # RS* is deterministic, PS* is not.
  expect_identical(jose_sign("x", key, "RS256"), jose_sign("x", key, "RS256"))
  expect_false(identical(
    jose_sign("x", key, "PS256"),
    jose_sign("x", key, "PS256")
  ))
})

test_that("a tampered or foreign RSA signature does not verify", {
  key <- jose_key_generate("RSA")
  token <- jose_sign("hello", key, "PS256")
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  sig <- b64url_decode(parts[[3]], "signature")
  sig[[1]] <- xor(sig[[1]], as.raw(1))
  bad <- paste(parts[[1]], parts[[2]], b64url_encode(sig), sep = ".")
  expect_error(jose_verify(bad, key, "PS256"), class = "zujose_signature_error")
  expect_error(
    jose_verify(token, jose_key_generate("RSA"), "PS256"),
    class = "zujose_signature_error"
  )
})

test_that("RSA-OAEP and RSA-OAEP-256 round-trip, to a public key", {
  key <- jose_key_generate("RSA")
  pub <- jose_public(key)
  for (alg in c("RSA-OAEP", "RSA-OAEP-256")) {
    for (enc in c("A128CBC-HS256", "A256GCM")) {
      token <- jose_encrypt("secret", pub, alg, enc)
      out <- jose_decrypt(token, key, alg, enc)
      expect_identical(
        rawToChar(out$plaintext),
        "secret",
        info = paste(alg, enc)
      )
    }
  }
  # Decryption needs the private key.
  token <- jose_encrypt("secret", pub, "RSA-OAEP-256")
  expect_error(
    jose_decrypt(token, pub, "RSA-OAEP-256", "A128CBC-HS256"),
    class = "zujose_key_error"
  )
})

test_that("RSA1_5 never encrypts and decrypts only when named", {
  key <- as_jose_key(rfc7520_key(73))
  expect_error(
    jose_encrypt("x", jose_public(key), "RSA1_5"),
    class = "zujose_policy_error"
  )
  expect_error(
    jose_decrypt(rfc7520_token(81), key, "RSA-OAEP", "A128CBC-HS256"),
    class = "zujose_policy_error"
  )
})

test_that("a wrong RSA key or a tampered key gives the one decrypt error", {
  key <- jose_key_generate("RSA")
  token <- jose_encrypt("secret", key, "RSA-OAEP")
  other <- jose_key_generate("RSA")
  e1 <- expect_error(
    jose_decrypt(token, other, "RSA-OAEP", "A128CBC-HS256"),
    class = "zujose_decrypt_error"
  )
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  ek <- b64url_decode(parts[[2]], "key")
  ek[[5]] <- xor(ek[[5]], as.raw(1))
  parts[[2]] <- b64url_encode(ek)
  e2 <- expect_error(
    jose_decrypt(
      paste(parts, collapse = "."),
      key,
      "RSA-OAEP",
      "A128CBC-HS256"
    ),
    class = "zujose_decrypt_error"
  )
  # RSA1_5, whose padding failures must look like every other failure.
  v15 <- as_jose_key(rfc7520_key(73))
  parts <- strsplit(rfc7520_token(81), ".", fixed = TRUE)[[1]]
  ek <- b64url_decode(parts[[2]], "key")
  ek[[5]] <- xor(ek[[5]], as.raw(1))
  parts[[2]] <- b64url_encode(ek)
  e3 <- expect_error(
    jose_decrypt(paste(parts, collapse = "."), v15, "RSA1_5", "A128CBC-HS256"),
    class = "zujose_decrypt_error"
  )
  expect_identical(conditionMessage(e1), conditionMessage(e2))
  expect_identical(conditionMessage(e1), conditionMessage(e3))
})

# Keys ---------------------------------------------------------------------

test_that("RSA moduli under 2048 bits are refused for use", {
  skip_if_not_installed("openssl")
  small <- as_jose_key(openssl::write_pem(openssl::rsa_keygen(1024)))
  expect_error(jose_sign("x", small, "RS256"), class = "zujose_key_error")
  expect_error(
    jose_encrypt("x", jose_public(small), "RSA-OAEP"),
    class = "zujose_key_error"
  )
  # Still readable and writable: a JWKS may hold one.
  expect_s3_class(small, "jose_key")
})

test_that("PEM keys are read, and written back as PEM", {
  skip_if_not_installed("openssl")
  theirs <- openssl::rsa_keygen(2048)
  key <- as_jose_key(openssl::write_pem(theirs))
  expect_identical(key$kty, "RSA")
  expect_identical(jose_pem(key, private = TRUE), openssl::write_pem(theirs))
  expect_identical(jose_pem(key), openssl::write_pem(theirs$pubkey))
  pub <- as_jose_key(openssl::write_pem(theirs$pubkey))
  expect_false("d" %in% names(pub$members))
  expect_identical(jose_pem(pub), openssl::write_pem(theirs$pubkey))
  expect_error(jose_pem(pub, private = TRUE), class = "zujose_key_error")
  expect_error(jose_pem(jose_key_oct(as.raw(1:32))), class = "zujose_key_error")
})

test_that("a JWK and its PEM describe the same key", {
  jwk <- as_jose_key(rfc7520_key(4))
  again <- as_jose_key(jose_pem(jwk, private = TRUE))
  expect_identical(jose_thumbprint(again), jose_thumbprint(jwk))
  expect_identical(
    again$members[c("n", "e", "d", "p", "q", "dp", "dq", "qi")],
    jwk$members[c("n", "e", "d", "p", "q", "dp", "dq", "qi")]
  )
})

test_that("jose_key_generate('RSA') makes a usable key of the size asked", {
  key <- jose_key_generate("RSA", size = 3072, alg = "PS512")
  expect_identical(key$kty, "RSA")
  expect_identical(key$alg, "PS512")
  expect_true(key$supported)
  n <- b64url_decode(key$members$n, "n")
  expect_length(n, 384L)
  for (bad in list(1024, 2047, 5000, 8192)) {
    expect_error(
      jose_key_generate("RSA", size = bad),
      class = "zujose_key_error"
    )
  }
  expect_error(
    jose_key_generate("RSA", alg = "HS256"),
    class = "zujose_key_error"
  )
})

test_that("malformed RSA JWKs are key errors", {
  jwk <- zujson::json_parse(rfc7520_key(4), simplify = "none")
  no_crt <- jwk[c("kty", "n", "e", "d")]
  expect_error(as_jose_key(no_crt), class = "zujose_key_error")
  bad <- jwk
  bad$n <- "AQAB"
  expect_error(as_jose_key(bad), class = "zujose_key_error")
  expect_error(as_jose_key(jwk["kty"]), class = "zujose_key_error")
})

test_that("printing an RSA key shows its size, never its private members", {
  key <- as_jose_key(rfc7520_key(4))
  out <- capture.output(print(key))
  expect_match(out[[1]], "RSA, 2048 bits", fixed = TRUE)
  expect_false(any(grepl(key$members$d, out, fixed = TRUE)))
  expect_true(any(grepl("private: yes", out, fixed = TRUE)))
})

test_that("zujose_info() reports RS*, PS* and RSA key management available", {
  info <- zujose_info()
  rsa <- c(
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "RSA1_5"
  )
  expect_true(all(info$available[info$algorithm %in% rsa]))
})
