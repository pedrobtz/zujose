test_that("a JWK Set of every RFC 7520 key reads", {
  set <- as_jwk_set(rfc7520_jwks())
  expect_s3_class(set, "jwk_set")
  expect_length(set, 10L)
  expect_identical(
    set[["018c0ae5-4d9b-471b-bfd6-eef314bc7037"]],
    as_jwk(rfc7520_key(5))
  )
  expect_snapshot(print(set))
})

test_that("[[ selects by kid or position; [ keeps a set", {
  set <- jwk_set(
    jwk_oct(as.raw(1), kid = "a"),
    jwk_oct(as.raw(2), kid = "b"),
    jwk_oct(as.raw(3))
  )
  expect_identical(set[["b"]]$k, as.raw(2))
  expect_identical(set[[3]]$k, as.raw(3))
  expect_s3_class(set["a"], "jwk_set")
  expect_length(set[c("a", "b")], 2L)
  expect_length(set[2:3], 2L)
  expect_error(set[["z"]], class = "zujose_key_error")
  expect_error(set[[c("a", "b")]], class = "zujose_key_error")

  twice <- jwk_set(set, jwk_oct(as.raw(4), kid = "a"))
  expect_error(twice[["a"]], class = "zujose_key_error")
})

test_that("c() and jwk_set() combine keys and sets in order", {
  a <- jwk_oct(as.raw(1), kid = "a")
  b <- jwk_oct(as.raw(2), kid = "b")
  set <- c(a, b)
  expect_s3_class(set, "jwk_set")
  expect_identical(c(set, a)[[3]], a)
  expect_identical(jwk_set(), structure(list(), class = "jwk_set"))
  expect_error(jwk_set(a, "b"), class = "zujose_key_error")
})

test_that("malformed and unknown entries are ignored, per RFC 7517 §5", {
  set <- as_jwk_set(paste0(
    '{"keys":[',
    '{"kty":"oct","k":"AAAA","kid":"good"},',
    '{"kty":"oct","k":"A=="},',
    '{"kty":"AKP","pub":"AAAA"},',
    '{"no":"kty"},',
    '{"kty":"RSA","n":"AAAA","e":"AQAB","kid":"bad-rsa"},',
    '{"kty":"OKP","crv":"Ed25519","x":"AAAA","kid":"later"}',
    "]}"
  ))
  expect_identical(
    vapply(unclass(set), `[[`, "", "kid"),
    c("good", "later")
  )
})

test_that("a JWK Set must be an object with a keys array", {
  for (bad in c("[]", "{}", '{"keys":{}}', '{"keys":1}', "nope")) {
    expect_error(as_jwk_set(bad), class = "zujose_key_error", info = bad)
  }
  expect_error(as_jwk_set(c("a", "b")), class = "zujose_key_error")
  expect_error(
    as_jwk_set('{"keys":[],"keys":[]}'),
    class = "zujose_key_error"
  )
})

test_that("jwk_public() and jwk_json() drop oct keys from a set", {
  set <- as_jwk_set(rfc7520_jwks())
  public <- jwk_public(set)
  expect_false(any(vapply(unclass(public), `[[`, "", "kty") == "oct"))
  written <- zujson::json_parse(jwk_json(set), simplify = "none")
  expect_length(written$keys, length(public))
  expect_identical(as_jwk_set(jwk_json(set, private = TRUE)), set)
})

test_that("`[` refuses NA and out-of-range indices", {
  # #135: a jwk_set holds keys only, never NULL.
  set <- jwk_set(jwk_oct(as.raw(1), kid = "a"), jwk_oct(as.raw(2), kid = "b"))
  for (i in list(NA, NA_integer_, 10, c(1, NA), c(TRUE, TRUE, TRUE))) {
    expect_error(set[i], class = "zujose_argument_error")
  }
  expect_length(set[-1], 1L)
  expect_length(set[], 2L)
  expect_length(set["z"], 0L)
  expect_output(print(set[0]), "0 keys")
})
