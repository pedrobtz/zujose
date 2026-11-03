# RFC 7520 ----------------------------------------------------------------

test_that("every RFC 7520 token parses with its type and serialization", {
  manifest <- rfc7520_manifest()
  expect_gte(nrow(manifest), 50L)
  for (i in seq_len(nrow(manifest))) {
    row <- manifest[i, ]
    obj <- jose_parse(rfc7520_token(row$figure), jose_limits())
    info <- sprintf("Figure %d (RFC 7520 §%s)", row$figure, row$section)
    expect_s3_class(obj, "jose_object")
    expect_identical(obj$type, row$type, info = info)
    expect_identical(obj$serialization, row$serialization, info = info)
  }
})

test_that("RFC 7520 §4.1 parses to its header, payload and signature", {
  obj <- jose_parse(rfc7520_token(13), jose_limits())
  sig <- obj$signatures[[1]]
  expect_identical(sig$protected$alg, "RS256")
  expect_identical(sig$protected$kid, "bilbo.baggins@hobbiton.example")
  expect_match(rawToChar(obj$payload), "^It’s a dangerous business, Frodo")
  expect_length(sig$signature, 256L)
  expect_true(obj$b64)
})

test_that("the three serializations of one JWS agree", {
  compact <- jose_parse(rfc7520_token(13), jose_limits())
  general <- jose_parse(rfc7520_token(14), jose_limits())
  flattened <- jose_parse(rfc7520_token(15), jose_limits())
  expect_identical(general$payload, compact$payload)
  expect_identical(flattened$payload, compact$payload)
  expect_identical(general$signatures, compact$signatures)
  expect_identical(flattened$signatures, compact$signatures)
})

test_that("a detached payload parses as empty, or as absent in JSON", {
  compact <- jose_parse(rfc7520_token(41), jose_limits())
  expect_identical(compact$payload_b64, "")
  expect_identical(compact$payload, raw())

  general <- jose_parse(rfc7520_token(42), jose_limits())
  expect_null(general$payload_b64)
  expect_null(general$payload)
})

test_that("several signatures and recipients are all kept", {
  jws <- jose_parse(rfc7520_token(71), jose_limits())
  expect_length(jws$signatures, 3L)
  jwe <- jose_parse(rfc7520_token(221), jose_limits())
  expect_length(jwe$recipients, 3L)
})

test_that("a JWE keeps the received protected header and AAD text", {
  obj <- jose_parse(rfc7520_token(182), jose_limits())
  expect_identical(obj$type, "JWE")
  expect_true(nzchar(obj$protected_b64))
  expect_type(obj$aad, "raw")
  expect_identical(b64url_encode(obj$aad), obj$aad_b64)
})

# RFC 7797 ----------------------------------------------------------------

test_that("RFC 7797 §4.2 unencoded payloads parse", {
  flattened <- sprintf(
    '{"protected":"%s","payload":"$.02","signature":"%s"}',
    rfc7797_header(),
    rfc7797_signature()
  )
  obj <- jose_parse(flattened, jose_limits())
  expect_false(obj$b64)
  expect_identical(obj$payload, charToRaw("$.02"))

  detached <- paste0(rfc7797_header(), "..", rfc7797_signature())
  obj <- jose_parse(detached, jose_limits())
  expect_false(obj$b64)
  expect_identical(obj$payload, raw())
})

# Header rules (design §8.1) ----------------------------------------------

test_that("crit and b64 follow RFC 7515 §4.1.11 and RFC 7797 §6", {
  ok <- list(alg = "HS256", b64 = FALSE, crit = list("b64"))
  expect_no_error(jose_parse(compact_jws(ok, "x"), jose_limits()))

  bad <- list(
    unknown = list(alg = "HS256", crit = list("exp"), exp = 1),
    registered = list(alg = "HS256", crit = list("alg")),
    empty = list(alg = "HS256", crit = list()),
    not_array = list(alg = "HS256", crit = "b64"),
    not_strings = list(alg = "HS256", crit = list(1)),
    repeated = list(alg = "HS256", b64 = FALSE, crit = list("b64", "b64")),
    absent = list(alg = "HS256", crit = list("b64")),
    b64_without_crit = list(alg = "HS256", b64 = FALSE),
    b64_not_boolean = list(alg = "HS256", b64 = "false", crit = list("b64"))
  )
  for (name in names(bad)) {
    expect_error(
      jose_parse(compact_jws(bad[[name]]), jose_limits()),
      class = "zujose_parse_error",
      info = name
    )
  }
})

test_that("crit and b64 are refused outside the protected header", {
  token <- sprintf(
    '{"protected":"%s","header":{"crit":["b64"]},"payload":"","signature":"c2ln"}',
    b64_json(list(alg = "HS256"))
  )
  expect_error(jose_parse(token, jose_limits()), class = "zujose_parse_error")
})

test_that("b64 in a JWE is refused", {
  header <- list(alg = "dir", enc = "A128GCM", b64 = FALSE, crit = list("b64"))
  token <- paste(b64_json(header), "", "aXY", "Y3Q", "dGFn", sep = ".")
  expect_error(jose_parse(token, jose_limits()), class = "zujose_parse_error")
})

test_that("repeated member names are refused, however deep", {
  for (json in c(
    '{"alg":"HS256","alg":"none"}',
    '{"alg":"HS256","jwk":{"k":"a","k":"b"}}'
  )) {
    expect_error(
      jose_parse(compact_jws(json), jose_limits()),
      class = "zujose_parse_error",
      info = json
    )
  }
})

test_that("a member in both the protected and unprotected header is refused", {
  token <- sprintf(
    '{"protected":"%s","header":{"alg":"none"},"payload":"","signature":"c2ln"}',
    b64_json(list(alg = "HS256"))
  )
  expect_error(jose_parse(token, jose_limits()), class = "zujose_parse_error")
})

test_that("required header members must be present strings", {
  expect_error(
    jose_parse(compact_jws(list(typ = "JWT")), jose_limits()),
    class = "zujose_parse_error"
  )
  expect_error(
    jose_parse(compact_jws(list(alg = 1)), jose_limits()),
    class = "zujose_parse_error"
  )
  expect_error(
    jose_parse(compact_jws(list(alg = "HS256", kid = list())), jose_limits()),
    class = "zujose_parse_error"
  )
  no_enc <- paste(
    b64_json(list(alg = "dir")),
    "",
    "aXY",
    "Y3Q",
    "dGFn",
    sep = "."
  )
  expect_error(jose_parse(no_enc, jose_limits()), class = "zujose_parse_error")
})

test_that("recipients must agree on enc", {
  token <- sprintf(
    paste0(
      '{"recipients":[{"header":{"alg":"dir","enc":"A128GCM"}},',
      '{"header":{"alg":"dir","enc":"A256GCM"}}],',
      '"iv":"aXY","ciphertext":"Y3Q","tag":"dGFn"}'
    )
  )
  expect_error(jose_parse(token, jose_limits()), class = "zujose_parse_error")
})

# The malformed corpus (design §10) ---------------------------------------

test_that("the malformed corpus fails with zujose_parse_error", {
  manifest <- rfc7520_manifest()
  compact <- manifest$figure[manifest$serialization == "compact"]
  n <- 0L
  for (figure in compact) {
    for (bad in Filter(
      Negate(is.null),
      malformed_corpus(rfc7520_token(figure))
    )) {
      n <- n + 1L
      expect_error(
        jose_parse(bad, jose_limits()),
        class = "zujose_parse_error",
        info = sprintf("Figure %d, mutation %d", figure, n)
      )
    }
  }
  expect_gt(n, 500L)
})

test_that("malformed JSON serializations fail with zujose_parse_error", {
  general <- zujson::json_parse(rfc7520_token(14), simplify = "none")
  jwe <- zujson::json_parse(rfc7520_token(82), simplify = "none")
  edit <- function(obj, ...) {
    changes <- list(...)
    for (name in names(changes)) {
      obj[name] <- list(changes[[name]])
    }
    zujson::json_write(Filter(Negate(is.null), obj))
  }

  bad <- list(
    "[1, 2]",
    "{}",
    '{"payload":"","signature":"c2ln","signature":"c2ln"}',
    edit(general, signatures = list()),
    edit(general, signatures = "x"),
    edit(general, signatures = list("x")),
    edit(general, signature = "c2ln"),
    edit(general, payload = 1),
    edit(general, payload = "a="),
    edit(jwe, iv = NULL),
    edit(jwe, tag = NULL),
    edit(jwe, ciphertext = 1),
    edit(jwe, unprotected = "x"),
    edit(jwe, recipients = list()),
    edit(jwe, header = list(alg = "dir")),
    edit(jwe, aad = "a=")
  )
  for (i in seq_along(bad)) {
    expect_error(
      jose_parse(bad[[i]], jose_limits()),
      class = "zujose_parse_error",
      info = i
    )
  }
})

test_that("a token that is not a single string is a parse error", {
  for (bad in list(NULL, NA_character_, c("a", "b"), 1, list("a.b.c"))) {
    expect_error(jose_parse(bad, jose_limits()), class = "zujose_parse_error")
  }
})

# Limits are checked before decoding (design §9) --------------------------

test_that("an oversized token fails before any decoding", {
  local_no_decoding()
  token <- rfc7520_token(13)
  expect_error(
    jose_parse(token, jose_limits(token = nchar(token) - 1)),
    class = "zujose_parse_error"
  )
})

test_that("an oversized protected header fails before it is decoded", {
  local_no_decoding("protected header")
  expect_error(
    jose_parse(rfc7520_token(13), jose_limits(header = 16)),
    class = "zujose_parse_error"
  )
})

test_that("an oversized payload or ciphertext fails before it is decoded", {
  local_no_decoding(c("payload", "ciphertext"))
  expect_error(
    jose_parse(rfc7520_token(13), jose_limits(payload = 16)),
    class = "zujose_parse_error"
  )
  expect_error(
    jose_parse(rfc7520_token(81), jose_limits(payload = 16)),
    class = "zujose_parse_error"
  )
})

test_that("an unencoded payload is held to the same limit", {
  flattened <- sprintf(
    '{"protected":"%s","payload":"%s","signature":"%s"}',
    rfc7797_header(),
    strrep("x", 100),
    rfc7797_signature()
  )
  expect_error(
    jose_parse(flattened, jose_limits(payload = 99)),
    class = "zujose_parse_error"
  )
  expect_no_error(jose_parse(flattened, jose_limits(payload = 100)))
})

test_that("too many signatures or recipients fail before any decoding", {
  local_no_decoding()
  expect_error(
    jose_parse(rfc7520_token(71), jose_limits(signatures = 2)),
    class = "zujose_parse_error"
  )
  expect_error(
    jose_parse(rfc7520_token(221), jose_limits(recipients = 2)),
    class = "zujose_parse_error"
  )
})

test_that("a token that is not valid UTF-8 is refused without warnings", {
  # Base R warns, quoting the bytes, when a regular expression meets them;
  # the token is refused before that (#71).
  token <- rawToChar(as.raw(c(0xff, 0x2e, 0x61, 0x2e, 0x62)))
  Encoding(token) <- "UTF-8"
  key <- jwk_oct(as.raw(1:32))
  calls <- list(
    function() jwt_decode(token, key, "HS256"),
    function() jws_verify(token, key, "HS256"),
    function() jwe_decrypt(token, key, "A128KW", "A128GCM"),
    function() jose_peek(token)
  )
  for (f in calls) {
    expect_no_warning(
      expect_error(f(), class = "zujose_parse_error")
    )
  }
  expect_snapshot(jose_peek(token), error = TRUE)
})
