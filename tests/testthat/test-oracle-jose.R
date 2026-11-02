# The jose package as an oracle (design §10): each package verifies what
# the other signs, for the algorithms both support.

test_that("jose verifies the HMAC JWTs zujwt signs", {
  skip_if_not_installed("jose")
  secret <- as.raw(1:64)
  key <- jose_key_oct(secret)
  for (size in c(256, 384, 512)) {
    alg <- paste0("HS", size)
    jwt <- jose_jwt_encode(
      list(sub = "u1", aud = "api", n = 42L),
      key,
      alg,
      expires_in = 600
    )
    claims <- jose::jwt_decode_hmac(jwt, secret)
    expect_identical(claims$sub, "u1", info = alg)
    expect_identical(claims$n, 42L, info = alg)
  }
})

test_that("zujwt verifies the HMAC JWTs jose signs", {
  skip_if_not_installed("jose")
  secret <- as.raw(1:64)
  key <- jose_key_oct(secret)
  for (size in c(256, 384, 512)) {
    alg <- paste0("HS", size)
    jwt <- jose::jwt_encode_hmac(
      jose::jwt_claim(sub = "u2", aud = "api", exp = Sys.time() + 600),
      secret = secret,
      size = size
    )
    claims <- jose_jwt_decode(jwt, key, alg, audience = "api")
    expect_identical(claims$sub, "u2", info = alg)
    # jose cannot make zujwt accept an algorithm it was not given.
    other <- setdiff(c("HS256", "HS384", "HS512"), alg)
    expect_error(
      jose_jwt_decode(jwt, key, other, audience = "api"),
      class = "zujwt_policy_error"
    )
  }
})

test_that("a jose token signed with the wrong secret is refused", {
  skip_if_not_installed("jose")
  jwt <- jose::jwt_encode_hmac(
    jose::jwt_claim(exp = Sys.time() + 600),
    secret = as.raw(64:1)
  )
  expect_error(
    jose_jwt_decode(jwt, jose_key_oct(as.raw(1:64)), "HS256"),
    class = "zujwt_signature_error"
  )
})
