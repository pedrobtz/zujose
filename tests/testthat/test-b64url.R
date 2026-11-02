test_that("canonical unpadded Base64url decodes", {
  expect_identical(b64url_decode("", "x"), raw())
  expect_identical(b64url_decode("YQ", "x"), charToRaw("a"))
  expect_identical(b64url_decode("YWI", "x"), charToRaw("ab"))
  expect_identical(b64url_decode("YWJj", "x"), charToRaw("abc"))
  expect_identical(b64url_decode("-_8", "x"), as.raw(c(0xfb, 0xff)))
})

test_that("encoding and decoding round-trip for every length", {
  for (n in 0:64) {
    bytes <- as.raw(seq_len(n) %% 256)
    text <- b64url_encode(bytes)
    expect_false(grepl("[=+/]", text))
    expect_identical(b64url_decode(text, "x"), bytes)
  }
})

test_that("every non-canonical form is rejected", {
  bad <- c(
    "YQ==", # padding
    "YQ=", # partial padding
    "Y Q", # whitespace
    "YQ\n", # newline
    "+/8", # the standard alphabet
    "Y", # a length that is 1 mod 4
    "YR", # non-zero trailing bits; "YQ" is the canonical form of "a"
    "YWJ", # non-zero trailing bits; "YWI" is canonical
    "YéQ" # non-ASCII
  )
  for (text in bad) {
    expect_error(b64url_decode(text, "x"), class = "zujwt_parse_error")
  }
})

test_that("the message names the part, never the text", {
  err <- expect_error(
    b64url_decode("secret==", "payload"),
    class = "zujwt_parse_error"
  )
  expect_match(conditionMessage(err), "payload")
  expect_no_match(conditionMessage(err), "secret")
})

test_that("b64url_max_chars() bounds the encoded length of n bytes", {
  for (n in 0:30) {
    expect_lte(nchar(b64url_encode(as.raw(seq_len(n)))), b64url_max_chars(n))
  }
  expect_identical(b64url_max_chars(Inf), Inf)
})
