test_that("a JWK Set of every RFC 7520 key reads", {
  set <- as_jose_keyset(rfc7520_jwks())
  expect_s3_class(set, "jose_keyset")
  expect_length(set, 10L)
  expect_identical(
    set[["018c0ae5-4d9b-471b-bfd6-eef314bc7037"]],
    as_jose_key(rfc7520_key(5))
  )
  expect_snapshot(print(set))
})

test_that("[[ selects by kid or position; [ keeps a set", {
  set <- jose_keyset(
    jose_key_oct(as.raw(1), kid = "a"),
    jose_key_oct(as.raw(2), kid = "b"),
    jose_key_oct(as.raw(3))
  )
  expect_identical(set[["b"]]$k, as.raw(2))
  expect_identical(set[[3]]$k, as.raw(3))
  expect_s3_class(set["a"], "jose_keyset")
  expect_length(set[c("a", "b")], 2L)
  expect_length(set[2:3], 2L)
  expect_error(set[["z"]], class = "zujwt_key_error")
  expect_error(set[[c("a", "b")]], class = "zujwt_key_error")

  twice <- jose_keyset(set, jose_key_oct(as.raw(4), kid = "a"))
  expect_error(twice[["a"]], class = "zujwt_key_error")
})

test_that("c() and jose_keyset() combine keys and sets in order", {
  a <- jose_key_oct(as.raw(1), kid = "a")
  b <- jose_key_oct(as.raw(2), kid = "b")
  set <- c(a, b)
  expect_s3_class(set, "jose_keyset")
  expect_identical(c(set, a)[[3]], a)
  expect_identical(jose_keyset(), structure(list(), class = "jose_keyset"))
  expect_error(jose_keyset(a, "b"), class = "zujwt_key_error")
})

test_that("malformed and unknown entries are ignored, per RFC 7517 §5", {
  set <- as_jose_keyset(paste0(
    '{"keys":[',
    '{"kty":"oct","k":"AAAA","kid":"good"},',
    '{"kty":"oct","k":"A=="},',
    '{"kty":"AKP","pub":"AAAA"},',
    '{"no":"kty"},',
    '{"kty":"RSA","n":"AAAA","e":"AQAB","kid":"bad-rsa"},',
    '{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","kid":"later"}',
    "]}"
  ))
  expect_identical(
    vapply(unclass(set), `[[`, "", "kid"),
    c("good", "later")
  )
})

test_that("a JWK Set must be an object with a keys array", {
  for (bad in c("[]", "{}", '{"keys":{}}', '{"keys":1}', "nope")) {
    expect_error(as_jose_keyset(bad), class = "zujwt_key_error", info = bad)
  }
  expect_error(as_jose_keyset(c("a", "b")), class = "zujwt_key_error")
  expect_error(
    as_jose_keyset('{"keys":[],"keys":[]}'),
    class = "zujwt_key_error"
  )
})

test_that("jose_public() and jose_jwk() drop oct keys from a set", {
  set <- as_jose_keyset(rfc7520_jwks())
  public <- jose_public(set)
  expect_false(any(vapply(unclass(public), `[[`, "", "kty") == "oct"))
  written <- zujson::json_parse(jose_jwk(set), simplify = "none")
  expect_length(written$keys, length(public))
  expect_identical(as_jose_keyset(jose_jwk(set, private = TRUE)), set)
})
