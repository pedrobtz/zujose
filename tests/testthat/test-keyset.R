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

test_that("RFC 7517 A.1's public keys read member by member", {
  # The RFC's own example sets, with mixed key types and `use` (#104).
  set <- as_jwk_set(rfc7517_jwks("a1"))
  expect_set_members(set, rfc7517_jwks("a1"))
  expect_identical(vapply(unclass(set), `[[`, "", "kty"), c("EC", "RSA"))
  expect_identical(set[["1"]]$use, "enc")
  expect_identical(set[["1"]]$members$crv, "P-256")
  expect_identical(set[["2011-04-29"]]$alg, "RS256")
  expect_true(all(vapply(unclass(set), `[[`, TRUE, "supported")))
  expect_identical(jwk_thumbprint(set[["2011-04-29"]]), rfc7638_thumbprint())
})

test_that("RFC 7517 A.2's private keys read, and their public halves are A.1", {
  set <- as_jwk_set(rfc7517_jwks("a2"))
  expect_set_members(set, rfc7517_jwks("a2"))
  expect_true(all(
    c("d", "p", "q", "dp", "dq", "qi") %in% names(set[[2]]$members)
  ))
  expect_identical(
    set[[1]]$members$d,
    "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
  )
  expect_same_json(
    jwk_json(jwk_public(set)),
    jwk_json(as_jwk_set(rfc7517_jwks("a1")))
  )
})

test_that("RFC 7517 A.3's symmetric keys read member by member", {
  set <- as_jwk_set(rfc7517_jwks("a3"))
  expect_set_members(set, rfc7517_jwks("a3"))
  expect_identical(set[[1]]$alg, "A128KW")
  expect_null(set[[1]]$kid)
  expect_length(set[[1]]$k, 16L)
  hmac <- set[["HMAC key used in JWS spec Appendix A.1 example"]]
  expect_length(hmac$k, 64L)
  # A.3's HMAC key is RFC 7515 A.1's.
  expect_identical(hmac$k, rfc7515_key()$k)
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
  expect_error(set[[c("a", "b")]], class = "zujose_argument_error")

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
  expect_error(jwk_set(a, "b"), class = "zujose_argument_error")
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
  expect_error(as_jwk_set(c("a", "b")), class = "zujose_argument_error")
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

test_that("[[ on a jwk_set refuses a bad index with a zujose error (#123)", {
  set <- jwk_set(jwk_oct(as.raw(1:32), kid = "a"))
  for (i in list(9, 0, -1, NA, 1.5, c(1, 1), TRUE, list(1))) {
    expect_error(set[[i]], class = "zujose_argument_error")
  }
  expect_identical(set[[1]]$kid, "a")
  expect_identical(set[[1L]]$kid, "a")
})

test_that("a parsed JWK Set must be an object without repeated names", {
  expect_error(as_jwk_set(list(1, 2)), class = "zujose_key_error")
  repeated <- zujson::json_parse('{"keys":[],"keys":[]}', simplify = "none")
  expect_error(as_jwk_set(repeated), class = "zujose_key_error")
  set <- jwk_set(jwk_oct(as.raw(1:16)))
  expect_identical(as_jwk_set(set), set)
})

test_that("as_jwk_set() skips members of `keys` that are not JSON objects (#44)", {
  oct <- '{"kty":"oct","k":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}'
  pem <- rfc7520_key(3) |> as_jwk() |> jwk_pem()
  set <- as_jwk_set(list(keys = list(pem, oct, 5)))
  expect_length(set, 0L)
  text <- sprintf('{"keys":[%s,%s,%s]}', encodeString(oct, quote = '"'), oct, 5)
  expect_length(as_jwk_set(text), 1L)
})
