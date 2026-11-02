# RFC vectors -------------------------------------------------------------

test_that("RFC 7515 A.1 verifies", {
  out <- jose_verify(rfc7519_jwt(), rfc7515_key(), algorithms = "HS256")
  expect_s3_class(out, "jose_verified")
  expect_identical(out$alg, "HS256")
  expect_match(rawToChar(out$payload), '"iss":"joe"')
})

test_that("RFC 7520 §4.4 verifies and is reproduced in every serialization", {
  key <- as_jose_key(rfc7520_key(5))
  payload <- jose_parse(rfc7520_token(34), jose_limits())$payload
  for (figure in 34:36) {
    out <- jose_verify(rfc7520_token(figure), key, algorithms = "HS256")
    expect_identical(out$payload, payload, info = figure)
    expect_identical(out$kid, key$kid)
  }
  expect_identical(jose_sign(payload, key), rfc7520_token(34))
  expect_same_json(
    jose_sign(payload, key, format = "general"),
    rfc7520_token(35)
  )
  expect_same_json(
    jose_sign(payload, key, format = "flattened"),
    rfc7520_token(36)
  )
})

test_that("RFC 7520 §4.5 detached content verifies and is reproduced", {
  key <- as_jose_key(rfc7520_key(5))
  payload <- jose_parse(rfc7520_token(34), jose_limits())$payload
  for (figure in 41:43) {
    out <- jose_verify(
      rfc7520_token(figure),
      key,
      algorithms = "HS256",
      payload = payload
    )
    expect_identical(out$payload, payload, info = figure)
  }
  expect_identical(jose_sign(payload, key, detached = TRUE), rfc7520_token(41))
  expect_same_json(
    jose_sign(payload, key, format = "general", detached = TRUE),
    rfc7520_token(42)
  )
  # Without the payload, the empty payload does not verify.
  expect_error(
    jose_verify(rfc7520_token(41), key, algorithms = "HS256"),
    class = "zujwt_signature_error"
  )
})

test_that("RFC 7520 §4.6 protects only some header members", {
  key <- as_jose_key(rfc7520_key(5))
  payload <- jose_parse(rfc7520_token(34), jose_limits())$payload
  for (figure in 49:50) {
    out <- jose_verify(rfc7520_token(figure), key, algorithms = "HS256")
    expect_identical(out$protected, list(alg = "HS256"), info = figure)
    expect_identical(out$header$kid, key$kid)
  }
  unprotected <- list(kid = key$kid)
  expect_same_json(
    jose_sign(payload, key, unprotected = unprotected, format = "general"),
    rfc7520_token(49)
  )
  expect_same_json(
    jose_sign(payload, key, unprotected = unprotected, format = "flattened"),
    rfc7520_token(50)
  )
})

test_that("RFC 7520 §4.7, with no protected header, verifies", {
  key <- as_jose_key(rfc7520_key(5))
  for (figure in 54:55) {
    out <- jose_verify(rfc7520_token(figure), key, algorithms = "HS256")
    expect_identical(out$protected, structure(list(), names = character()))
    expect_identical(out$alg, "HS256")
  }
})

test_that("RFC 7520 §4.8: the HS256 signature verifies with require = 'any'", {
  set <- as_jose_keyset(rfc7520_jwks())
  out <- jose_verify(
    rfc7520_token(71),
    set,
    algorithms = "HS256",
    require = "any"
  )
  expect_identical(out$alg, "HS256")
  expect_length(out$signatures, 1L)
  # With require = "all", the RS256 signature is not allowed.
  expect_error(
    jose_verify(rfc7520_token(71), set, algorithms = "HS256"),
    class = "zujwt_policy_error"
  )
  # Allowing RS256 cannot help until zujwt supports it.
  expect_error(
    jose_verify(rfc7520_token(71), set, algorithms = c("HS256", "RS256")),
    class = "zujwt_unsupported_error"
  )
})

test_that("RFC 7797 §4.1 and §4.2 verify and are reproduced", {
  key <- rfc7515_key()
  control <- "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ"
  expect_identical(
    jose_verify(control, key, algorithms = "HS256")$payload,
    charToRaw("$.02")
  )
  expect_identical(jose_sign("$.02", key, alg = "HS256"), control)

  flattened <- sprintf(
    '{"protected":"%s","payload":"$.02","signature":"%s"}',
    rfc7797_header(),
    rfc7797_signature()
  )
  out <- jose_verify(flattened, key, algorithms = "HS256")
  expect_identical(out$payload, charToRaw("$.02"))
  expect_false(out$protected$b64)
  expect_same_json(
    jose_sign("$.02", key, alg = "HS256", b64 = FALSE, format = "flattened"),
    flattened
  )

  detached <- paste0(rfc7797_header(), "..", rfc7797_signature())
  expect_identical(
    jose_sign("$.02", key, alg = "HS256", b64 = FALSE, detached = TRUE),
    detached
  )
  expect_identical(
    jose_verify(detached, key, algorithms = "HS256", payload = "$.02")$payload,
    charToRaw("$.02")
  )
})

# Round trips -------------------------------------------------------------

test_that("every HMAC algorithm and serialization round-trips", {
  key <- jose_key_oct(as.raw(seq_len(64)), kid = "k")
  for (alg in c("HS256", "HS384", "HS512")) {
    for (format in c("compact", "flattened", "general")) {
      token <- jose_sign(as.raw(0:255), key, alg = alg, format = format)
      out <- jose_verify(token, key, algorithms = alg)
      expect_identical(out$payload, as.raw(0:255), info = paste(alg, format))
      expect_identical(out$header$kid, "k")
    }
  }
})

test_that("several signers make a general JWS that all must verify", {
  a <- jose_key_oct(as.raw(1:32), kid = "a")
  b <- jose_key_oct(as.raw(33:96), kid = "b")
  token <- jose_sign(
    "hello",
    list(jose_signer(a, "HS256"), jose_signer(b, "HS512")),
    format = "general"
  )
  out <- jose_verify(token, c(a, b), algorithms = c("HS256", "HS512"))
  expect_identical(vapply(out$signatures, `[[`, "", "kid"), c("a", "b"))

  # Without b's key, "all" fails and "any" succeeds.
  expect_error(
    jose_verify(token, jose_keyset(a), algorithms = c("HS256", "HS512")),
    class = "zujwt_key_error"
  )
  expect_identical(
    jose_verify(
      token,
      jose_keyset(a),
      c("HS256", "HS512"),
      require = "any"
    )$kid,
    "a"
  )
})

test_that("tampering is a signature error", {
  key <- jose_key_oct(as.raw(1:32))
  token <- jose_sign("hello", key, alg = "HS256")
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  forged <- paste(
    parts[1],
    b64url_encode(charToRaw("hellO")),
    parts[3],
    sep = "."
  )
  expect_error(
    jose_verify(forged, key, algorithms = "HS256"),
    class = "zujwt_signature_error"
  )
  wrong_key <- jose_key_oct(as.raw(2:33))
  expect_error(
    jose_verify(token, wrong_key, algorithms = "HS256"),
    class = "zujwt_signature_error"
  )
  truncated <- paste(parts[1], parts[2], substr(parts[3], 1, 20), sep = ".")
  expect_error(
    jose_verify(truncated, key, algorithms = "HS256"),
    class = "zujwt_signature_error"
  )
})

# The RFC 8725 attacks (design §10) ---------------------------------------

test_that("alg none is refused in every form", {
  key <- jose_key_oct(as.raw(1:32))
  token <- paste0(
    b64_json(list(alg = "none")),
    ".",
    b64url_encode(charToRaw("{}")),
    "."
  )
  expect_error(
    jose_verify(token, key, algorithms = "HS256"),
    class = "zujwt_policy_error"
  )
  expect_error(
    jose_verify(token, key, algorithms = "none"),
    class = "zujwt_policy_error"
  )
  expect_error(jose_sign("x", key, alg = "none"), class = "zujwt_policy_error")
})

test_that("an HS256 token signed with an RSA public key's bytes is refused", {
  rsa <- as_jose_key(rfc7520_key(3))
  secret <- charToRaw(jose_jwk(rsa))
  forged <- jose_sign("{}", jose_key_oct(secret), alg = "HS256")
  # The RSA key does not fit HS256, whatever `algorithms` allows.
  expect_error(
    jose_verify(forged, rsa, algorithms = c("RS256", "HS256")),
    class = "zujwt_policy_error"
  )
  expect_error(
    jose_verify(forged, jose_keyset(rsa), algorithms = c("RS256", "HS256")),
    class = "zujwt_key_error"
  )
})

test_that("an algorithm swapped within the family is refused", {
  key <- jose_key_oct(as.raw(1:64), alg = "HS256")
  token <- jose_sign("x", jose_key_oct(as.raw(1:64)), alg = "HS512")
  expect_error(
    jose_verify(token, key, algorithms = "HS256"),
    class = "zujwt_policy_error"
  )
  expect_error(
    jose_verify(token, key, algorithms = c("HS256", "HS512")),
    class = "zujwt_policy_error"
  )
})

test_that("kid injection selects nothing", {
  set <- jose_keyset(jose_key_oct(as.raw(1:32), kid = "real"))
  for (kid in c("../../dev/null", "' OR 1=1 --", "real ", "Real", "")) {
    token <- jose_sign(
      "x",
      jose_key_oct(as.raw(1:32)),
      alg = "HS256",
      header = list(kid = kid)
    )
    expect_error(
      jose_verify(token, set, algorithms = "HS256"),
      class = "zujwt_key_error",
      info = kid
    )
  }
})

test_that("unknown crit and repeated header members are refused", {
  key <- jose_key_oct(as.raw(1:32))
  crit <- compact_jws(list(alg = "HS256", crit = list("exp"), exp = 1))
  expect_error(
    jose_verify(crit, key, algorithms = "HS256"),
    class = "zujwt_parse_error"
  )
  repeated <- compact_jws('{"alg":"HS256","alg":"HS256"}')
  expect_error(
    jose_verify(repeated, key, algorithms = "HS256"),
    class = "zujwt_parse_error"
  )
})

test_that("keys named inside the token are never used", {
  key <- jose_key_oct(as.raw(1:32))
  attacker <- jose_key_oct(as.raw(101:132))
  token <- jose_sign(
    "x",
    attacker,
    alg = "HS256",
    header = list(jwk = list(kty = "oct", k = b64url_encode(attacker$k)))
  )
  expect_error(
    jose_verify(token, key, algorithms = "HS256"),
    class = "zujwt_signature_error"
  )
})

# Policy and arguments ----------------------------------------------------

test_that("algorithms has no default and names known signature algorithms", {
  key <- jose_key_oct(as.raw(1:32))
  token <- jose_sign("x", key, alg = "HS256")
  expect_error(jose_verify(token, key), "algorithms")
  for (bad in list(character(), NA_character_, "HS1", "A128KW", 256)) {
    expect_error(
      jose_verify(token, key, algorithms = bad),
      class = "zujwt_policy_error"
    )
  }
})

test_that("HMAC keys shorter than the hash are refused", {
  short <- jose_key_oct(as.raw(1:31))
  expect_error(jose_sign("x", short, alg = "HS256"), class = "zujwt_key_error")
  token <- jose_sign("x", jose_key_oct(as.raw(1:48)), alg = "HS256")
  expect_error(
    jose_verify(token, jose_key_oct(as.raw(1:47)), algorithms = "HS256"),
    class = "zujwt_signature_error"
  )
  expect_error(
    jose_sign("x", jose_key_oct(as.raw(1:47)), alg = "HS384"),
    class = "zujwt_key_error"
  )
})

test_that("a JWE is not a JWS", {
  expect_error(
    jose_verify(
      rfc7520_token(81),
      jose_key_oct(as.raw(1:32)),
      algorithms = "HS256"
    ),
    class = "zujwt_policy_error"
  )
})

test_that("a payload argument is only for detached payloads", {
  key <- jose_key_oct(as.raw(1:32))
  token <- jose_sign("x", key, alg = "HS256")
  expect_error(
    jose_verify(token, key, algorithms = "HS256", payload = "x"),
    class = "zujwt_policy_error"
  )
  detached <- jose_sign("x", key, alg = "HS256", detached = TRUE)
  expect_error(
    jose_verify(
      detached,
      key,
      "HS256",
      payload = "xy",
      limits = jose_limits(payload = 1)
    ),
    class = "zujwt_parse_error"
  )
})

test_that("jose_sign() refuses inconsistent requests", {
  key <- jose_key_oct(as.raw(1:32))
  signers <- list(jose_signer(key, "HS256"), jose_signer(key, "HS256"))
  expect_error(jose_sign("x", key), class = "zujwt_policy_error")
  expect_error(jose_sign("x", signers), "general")
  expect_error(
    jose_sign("x", signers, alg = "HS256", format = "general"),
    "signer"
  )
  expect_error(
    jose_sign("x", key, "HS256", unprotected = list(a = 1)),
    "unprotected"
  )
  expect_error(
    jose_sign("x", key, "HS256", header = list(alg = "HS512")),
    "disagrees"
  )
  expect_error(jose_sign("x", key, "HS256", header = list(1)), "named list")
  expect_error(jose_sign("x.y", key, "HS256", b64 = FALSE), "detached")
  expect_type(jose_sign("x", key, "HS256", b64 = FALSE), "character")
  expect_error(jose_sign(1, key, "HS256"), "payload")
  expect_error(jose_sign("x", "key", "HS256"), class = "zujwt_key_error")
  expect_error(
    jose_sign("x", jose_key_oct(as.raw(1:32), alg = "HS512"), "HS256"),
    class = "zujwt_policy_error"
  )
  expect_error(jose_sign("x", key, "RS256"), class = "zujwt_unsupported_error")
})

test_that("the key's kid goes into the protected header unless one is given", {
  key <- jose_key_oct(as.raw(1:32), kid = "k")
  peek <- jose_peek(jose_sign("x", key, "HS256"))
  expect_identical(peek$headers[[1]], list(alg = "HS256", kid = "k"))
  peek <- jose_peek(jose_sign(
    "x",
    key,
    "HS256",
    header = list(kid = "other", typ = "JWT")
  ))
  expect_identical(
    peek$headers[[1]],
    list(alg = "HS256", kid = "other", typ = "JWT")
  )
})

test_that("a resolver sees the header and picks the key", {
  key <- jose_key_oct(as.raw(1:32), kid = "k")
  token <- jose_sign("x", key, "HS256")
  seen <- NULL
  resolver <- function(header) {
    seen <<- header
    key
  }
  expect_identical(jose_verify(token, resolver, "HS256")$kid, "k")
  expect_identical(seen, list(alg = "HS256", kid = "k"))
})

test_that("zujwt_info() reports what this installation can do", {
  info <- zujwt_info()
  expect_named(info, c("algorithm", "kind", "available", "zucrypt"))
  expect_true(all(info$available[
    info$algorithm %in% c("HS256", "HS384", "HS512")
  ]))
  expect_false(info$available[info$algorithm == "RS256"])
  expect_identical(info$zucrypt[info$algorithm == "RS256"], "0.4.0")
  expect_false("none" %in% info$algorithm)
})

test_that("printing a verified JWS shows the header, not the payload", {
  key <- jose_key_oct(as.raw(1:32), kid = "k")
  expect_snapshot(print(jose_verify(
    jose_sign("secret text", key, "HS256"),
    key,
    "HS256"
  )))
})
