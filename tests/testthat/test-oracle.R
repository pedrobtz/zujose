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
