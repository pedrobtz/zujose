test_that("a signed-then-encrypted JWT decodes with decrypt", {
  signer <- jose_key_oct(as.raw(1:32))
  kek <- jose_key_oct(as.raw(1:16))
  inner <- jose_jwt_encode(list(sub = "u", exp = 2e9), signer, "HS256")
  outer <- encrypt_fixed(inner, kek, "A128KW", header = list(cty = "JWT"))
  claims <- jose_jwt_decode(
    outer,
    signer,
    "HS256",
    decrypt = jose_decryption(kek, "A128KW", "A128CBC-HS256")
  )
  expect_identical(claims$sub, "u")
  expect_identical(attr(claims, "header")$alg, "HS256")
})

test_that("a JWE is refused where no decrypt is given (D12)", {
  signer <- jose_key_oct(as.raw(1:32))
  kek <- jose_key_oct(as.raw(1:16))
  inner <- jose_jwt_encode(list(exp = 2e9), signer, "HS256")
  outer <- encrypt_fixed(inner, kek, "A128KW", header = list(cty = "JWT"))
  expect_error(
    jose_jwt_decode(outer, signer, "HS256"),
    class = "zujose_policy_error"
  )
  expect_error(
    jose_jwt_decode(outer, signer, "HS256", decrypt = list(key = kek)),
    "jose_decryption"
  )
})

test_that("an encrypted-only JWT carries its claims directly", {
  kek <- jose_key_oct(as.raw(1:16))
  outer <- encrypt_fixed(
    '{"sub":"u","exp":2000000000}',
    kek,
    "A128KW",
    header = list(typ = "JWT")
  )
  claims <- jose_jwt_decode(
    outer,
    jose_key_oct(as.raw(1:32)),
    "HS256",
    decrypt = jose_decryption(kek, "A128KW", "A128CBC-HS256")
  )
  expect_identical(claims$sub, "u")
  expect_identical(attr(claims, "header")$enc, "A128CBC-HS256")
  # typ is checked on the JWE header.
  expect_error(
    jose_jwt_decode(
      outer,
      jose_key_oct(as.raw(1:32)),
      "HS256",
      type = "at+jwt",
      decrypt = jose_decryption(kek, "A128KW", "A128CBC-HS256")
    ),
    class = "zujose_policy_error"
  )
})

test_that("the inner JWT is held to the signature rules", {
  signer <- jose_key_oct(as.raw(1:32))
  kek <- jose_key_oct(as.raw(1:16))
  decrypt <- jose_decryption(kek, "A128KW", "A128CBC-HS256")
  forged <- jose_jwt_encode(
    list(exp = 2e9),
    jose_key_oct(as.raw(2:33)),
    "HS256"
  )
  outer <- encrypt_fixed(forged, kek, "A128KW", header = list(cty = "JWT"))
  expect_error(
    jose_jwt_decode(outer, signer, "HS256", decrypt = decrypt),
    class = "zujose_signature_error"
  )
  # A JWE inside a JWE is refused.
  inner <- encrypt_fixed('{"exp":2000000000}', kek, "A128KW")
  outer <- encrypt_fixed(inner, kek, "A128KW", header = list(cty = "JWT"))
  expect_error(
    jose_jwt_decode(outer, signer, "HS256", decrypt = decrypt),
    class = "zujose_policy_error"
  )
})

test_that("a decoder can carry decrypt", {
  signer <- jose_key_oct(as.raw(1:32))
  kek <- jose_key_oct(as.raw(1:16))
  check_token <- jose_jwt_decoder(
    signer,
    "HS256",
    decrypt = jose_decryption(kek, "A128KW", "A128CBC-HS256")
  )
  inner <- jose_jwt_encode(list(sub = "u", exp = 2e9), signer, "HS256")
  outer <- encrypt_fixed(inner, kek, "A128KW", header = list(cty = "JWT"))
  expect_identical(check_token(outer)$sub, "u")
  expect_identical(check_token(inner)$sub, "u")
})
