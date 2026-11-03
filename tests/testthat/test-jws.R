# RFC vectors -------------------------------------------------------------

test_that("RFC 7515 A.1 verifies", {
  out <- jws_verify(rfc7519_jwt(), rfc7515_key(), algorithms = "HS256")
  expect_s3_class(out, "jws_verified")
  expect_identical(out$alg, "HS256")
  expect_match(rawToChar(out$payload), '"iss":"joe"')
})

test_that("RFC 7520 §4.4 verifies and is reproduced in every serialization", {
  key <- as_jwk(rfc7520_key(5))
  payload <- jose_parse(rfc7520_token(34), jose_limits())$payload
  for (figure in 34:36) {
    out <- jws_verify(rfc7520_token(figure), key, algorithms = "HS256")
    expect_identical(out$payload, payload, info = figure)
    expect_identical(out$kid, key$kid)
  }
  expect_identical(jws_sign(payload, key), rfc7520_token(34))
  expect_same_json(
    jws_sign(payload, key, format = "general"),
    rfc7520_token(35)
  )
  expect_same_json(
    jws_sign(payload, key, format = "flattened"),
    rfc7520_token(36)
  )
})

test_that("RFC 7520 §4.5 detached content verifies and is reproduced", {
  key <- as_jwk(rfc7520_key(5))
  payload <- jose_parse(rfc7520_token(34), jose_limits())$payload
  for (figure in 41:43) {
    out <- jws_verify(
      rfc7520_token(figure),
      key,
      algorithms = "HS256",
      payload = payload
    )
    expect_identical(out$payload, payload, info = figure)
  }
  expect_identical(jws_sign(payload, key, detached = TRUE), rfc7520_token(41))
  expect_same_json(
    jws_sign(payload, key, format = "general", detached = TRUE),
    rfc7520_token(42)
  )
  # Without the payload, the empty payload does not verify.
  expect_error(
    jws_verify(rfc7520_token(41), key, algorithms = "HS256"),
    class = "zujose_signature_error"
  )
})

test_that("RFC 7520 §4.6 protects only some header members", {
  key <- as_jwk(rfc7520_key(5))
  payload <- jose_parse(rfc7520_token(34), jose_limits())$payload
  for (figure in 49:50) {
    out <- jws_verify(rfc7520_token(figure), key, algorithms = "HS256")
    expect_identical(out$protected, list(alg = "HS256"), info = figure)
    expect_identical(out$header$kid, key$kid)
  }
  unprotected <- list(kid = key$kid)
  expect_same_json(
    jws_sign(payload, key, unprotected = unprotected, format = "general"),
    rfc7520_token(49)
  )
  expect_same_json(
    jws_sign(payload, key, unprotected = unprotected, format = "flattened"),
    rfc7520_token(50)
  )
})

test_that("RFC 7520 §4.7, with no protected header, verifies", {
  key <- as_jwk(rfc7520_key(5))
  for (figure in 54:55) {
    out <- jws_verify(rfc7520_token(figure), key, algorithms = "HS256")
    expect_identical(out$protected, structure(list(), names = character()))
    expect_identical(out$alg, "HS256")
  }
})

test_that("RFC 7520 §4.8: the HS256 signature verifies with require = 'any'", {
  set <- as_jwk_set(rfc7520_jwks())
  out <- jws_verify(
    rfc7520_token(71),
    set,
    algorithms = "HS256",
    require = "any"
  )
  expect_identical(out$alg, "HS256")
  expect_length(out$signatures, 1L)
  # With require = "all", the RS256 signature is not allowed.
  expect_error(
    jws_verify(rfc7520_token(71), set, algorithms = "HS256"),
    class = "zujose_policy_error"
  )
  # Allowing RS256 too is not enough: with require = "all", the ES512
  # signature is not allowed either.
  expect_error(
    jws_verify(rfc7520_token(71), set, algorithms = c("HS256", "RS256")),
    class = "zujose_policy_error"
  )
})

test_that("RFC 7797 §4.1 and §4.2 verify and are reproduced", {
  key <- rfc7515_key()
  control <- "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ"
  expect_identical(
    jws_verify(control, key, algorithms = "HS256")$payload,
    charToRaw("$.02")
  )
  expect_identical(jws_sign("$.02", key, alg = "HS256"), control)

  flattened <- sprintf(
    '{"protected":"%s","payload":"$.02","signature":"%s"}',
    rfc7797_header(),
    rfc7797_signature()
  )
  out <- jws_verify(flattened, key, algorithms = "HS256")
  expect_identical(out$payload, charToRaw("$.02"))
  expect_false(out$protected$b64)
  expect_same_json(
    jws_sign("$.02", key, alg = "HS256", b64 = FALSE, format = "flattened"),
    flattened
  )

  detached <- paste0(rfc7797_header(), "..", rfc7797_signature())
  expect_identical(
    jws_sign("$.02", key, alg = "HS256", b64 = FALSE, detached = TRUE),
    detached
  )
  expect_identical(
    jws_verify(detached, key, algorithms = "HS256", payload = "$.02")$payload,
    charToRaw("$.02")
  )
})

# Round trips -------------------------------------------------------------

test_that("every HMAC algorithm and serialization round-trips", {
  key <- jwk_oct(as.raw(seq_len(64)), kid = "k")
  for (alg in c("HS256", "HS384", "HS512")) {
    for (format in c("compact", "flattened", "general")) {
      token <- jws_sign(as.raw(0:255), key, alg = alg, format = format)
      out <- jws_verify(token, key, algorithms = alg)
      expect_identical(out$payload, as.raw(0:255), info = paste(alg, format))
      expect_identical(out$header$kid, "k")
    }
  }
})

test_that("several signers make a general JWS that all must verify", {
  a <- jwk_oct(as.raw(1:32), kid = "a")
  b <- jwk_oct(as.raw(33:96), kid = "b")
  token <- jws_sign(
    "hello",
    list(jws_signer(a, "HS256"), jws_signer(b, "HS512")),
    format = "general"
  )
  out <- jws_verify(token, c(a, b), algorithms = c("HS256", "HS512"))
  expect_identical(vapply(out$signatures, `[[`, "", "kid"), c("a", "b"))

  # Without b's key, "all" fails and "any" succeeds.
  expect_error(
    jws_verify(token, jwk_set(a), algorithms = c("HS256", "HS512")),
    class = "zujose_key_error"
  )
  expect_identical(
    jws_verify(
      token,
      jwk_set(a),
      c("HS256", "HS512"),
      require = "any"
    )$kid,
    "a"
  )
})

test_that("tampering is a signature error", {
  key <- jwk_oct(as.raw(1:32))
  token <- jws_sign("hello", key, alg = "HS256")
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  forged <- paste(
    parts[1],
    b64url_encode(charToRaw("hellO")),
    parts[3],
    sep = "."
  )
  expect_error(
    jws_verify(forged, key, algorithms = "HS256"),
    class = "zujose_signature_error"
  )
  wrong_key <- jwk_oct(as.raw(2:33))
  expect_error(
    jws_verify(token, wrong_key, algorithms = "HS256"),
    class = "zujose_signature_error"
  )
  truncated <- paste(parts[1], parts[2], substr(parts[3], 1, 20), sep = ".")
  expect_error(
    jws_verify(truncated, key, algorithms = "HS256"),
    class = "zujose_signature_error"
  )
})

# The RFC 8725 attacks (design §10) ---------------------------------------

test_that("alg none is refused in every form", {
  key <- jwk_oct(as.raw(1:32))
  token <- paste0(
    b64_json(list(alg = "none")),
    ".",
    b64url_encode(charToRaw("{}")),
    "."
  )
  expect_error(
    jws_verify(token, key, algorithms = "HS256"),
    class = "zujose_policy_error"
  )
  expect_error(
    jws_verify(token, key, algorithms = "none"),
    class = "zujose_policy_error"
  )
  expect_error(jws_sign("x", key, alg = "none"), class = "zujose_policy_error")
})

test_that("an HS256 token signed with an RSA public key's bytes is refused", {
  rsa <- as_jwk(rfc7520_key(3))
  secret <- charToRaw(jwk_json(rsa))
  forged <- jws_sign("{}", jwk_oct(secret), alg = "HS256")
  # The RSA key does not fit HS256, whatever `algorithms` allows.
  expect_error(
    jws_verify(forged, rsa, algorithms = c("RS256", "HS256")),
    class = "zujose_policy_error"
  )
  expect_error(
    jws_verify(forged, jwk_set(rsa), algorithms = c("RS256", "HS256")),
    class = "zujose_key_error"
  )
})

test_that("an algorithm swapped within the family is refused", {
  key <- jwk_oct(as.raw(1:64), alg = "HS256")
  token <- jws_sign("x", jwk_oct(as.raw(1:64)), alg = "HS512")
  expect_error(
    jws_verify(token, key, algorithms = "HS256"),
    class = "zujose_policy_error"
  )
  expect_error(
    jws_verify(token, key, algorithms = c("HS256", "HS512")),
    class = "zujose_policy_error"
  )
})

test_that("kid injection selects nothing", {
  set <- jwk_set(jwk_oct(as.raw(1:32), kid = "real"))
  for (kid in c("../../dev/null", "' OR 1=1 --", "real ", "Real", "")) {
    token <- jws_sign(
      "x",
      jwk_oct(as.raw(1:32)),
      alg = "HS256",
      header = list(kid = kid)
    )
    expect_error(
      jws_verify(token, set, algorithms = "HS256"),
      class = "zujose_key_error",
      info = kid
    )
  }
})

test_that("unknown crit and repeated header members are refused", {
  key <- jwk_oct(as.raw(1:32))
  crit <- compact_jws(list(alg = "HS256", crit = list("exp"), exp = 1))
  expect_error(
    jws_verify(crit, key, algorithms = "HS256"),
    class = "zujose_parse_error"
  )
  repeated <- compact_jws('{"alg":"HS256","alg":"HS256"}')
  expect_error(
    jws_verify(repeated, key, algorithms = "HS256"),
    class = "zujose_parse_error"
  )
})

test_that("keys named inside the token are never used", {
  key <- jwk_oct(as.raw(1:32))
  attacker <- jwk_oct(as.raw(101:132))
  token <- jws_sign(
    "x",
    attacker,
    alg = "HS256",
    header = list(jwk = list(kty = "oct", k = b64url_encode(attacker$k)))
  )
  expect_error(
    jws_verify(token, key, algorithms = "HS256"),
    class = "zujose_signature_error"
  )
})

# Policy and arguments ----------------------------------------------------

test_that("algorithms has no default and names known signature algorithms", {
  key <- jwk_oct(as.raw(1:32))
  token <- jws_sign("x", key, alg = "HS256")
  expect_error(jws_verify(token, key), "algorithms")
  for (bad in list(character(), NA_character_, "HS1", "A128KW", 256)) {
    expect_error(
      jws_verify(token, key, algorithms = bad),
      class = "zujose_policy_error"
    )
  }
})

test_that("HMAC keys shorter than the hash are refused", {
  short <- jwk_oct(as.raw(1:31))
  expect_error(jws_sign("x", short, alg = "HS256"), class = "zujose_key_error")
  token <- jws_sign("x", jwk_oct(as.raw(1:48)), alg = "HS256")
  expect_error(
    jws_verify(token, jwk_oct(as.raw(1:47)), algorithms = "HS256"),
    class = "zujose_signature_error"
  )
  expect_error(
    jws_sign("x", jwk_oct(as.raw(1:47)), alg = "HS384"),
    class = "zujose_key_error"
  )
})

test_that("a JWE is not a JWS", {
  expect_error(
    jws_verify(
      rfc7520_token(81),
      jwk_oct(as.raw(1:32)),
      algorithms = "HS256"
    ),
    class = "zujose_policy_error"
  )
})

test_that("a payload argument is only for detached payloads", {
  key <- jwk_oct(as.raw(1:32))
  token <- jws_sign("x", key, alg = "HS256")
  expect_error(
    jws_verify(token, key, algorithms = "HS256", payload = "x"),
    class = "zujose_policy_error"
  )
  detached <- jws_sign("x", key, alg = "HS256", detached = TRUE)
  expect_error(
    jws_verify(
      detached,
      key,
      "HS256",
      payload = "xy",
      limits = jose_limits(payload = 1)
    ),
    class = "zujose_parse_error"
  )
})

test_that("jws_sign() refuses inconsistent requests", {
  key <- jwk_oct(as.raw(1:32))
  signers <- list(jws_signer(key, "HS256"), jws_signer(key, "HS256"))
  expect_error(jws_sign("x", key), class = "zujose_policy_error")
  expect_error(jws_sign("x", signers), class = "zujose_argument_error")
  expect_error(
    jws_sign("x", signers, alg = "HS256", format = "general"),
    class = "zujose_argument_error"
  )
  expect_error(
    jws_sign("x", key, "HS256", unprotected = list(a = 1)),
    class = "zujose_argument_error"
  )
  expect_error(
    jws_sign("x", key, "HS256", header = list(alg = "HS512")),
    class = "zujose_argument_error"
  )
  expect_error(
    jws_sign("x", key, "HS256", header = list(1)),
    class = "zujose_argument_error"
  )
  expect_error(
    jws_sign("x.y", key, "HS256", b64 = FALSE),
    class = "zujose_argument_error"
  )
  expect_type(jws_sign("x", key, "HS256", b64 = FALSE), "character")
  expect_error(jws_sign(1, key, "HS256"), class = "zujose_argument_error")
  expect_error(jws_sign("x", "key", "HS256"), class = "zujose_key_error")
  expect_error(
    jws_sign("x", jwk_oct(as.raw(1:32), alg = "HS512"), "HS256"),
    class = "zujose_policy_error"
  )
  # ES256 needs a P-256 key, not a symmetric one.
  expect_error(jws_sign("x", key, "ES256"), class = "zujose_policy_error")
})

test_that("the key's kid goes into the protected header unless one is given", {
  key <- jwk_oct(as.raw(1:32), kid = "k")
  peek <- jose_peek(jws_sign("x", key, "HS256"))
  expect_identical(peek$headers[[1]], list(alg = "HS256", kid = "k"))
  peek <- jose_peek(jws_sign(
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
  key <- jwk_oct(as.raw(1:32), kid = "k")
  token <- jws_sign("x", key, "HS256")
  seen <- NULL
  resolver <- function(header) {
    seen <<- header
    key
  }
  expect_identical(jws_verify(token, resolver, "HS256")$kid, "k")
  expect_identical(seen, list(alg = "HS256", kid = "k"))
})

test_that("zujose_info() reports what this installation can do", {
  info <- zujose_info()
  expect_named(info, c("algorithm", "kind", "available", "zucrypt"))
  expect_true(all(info$available[
    info$algorithm %in% c("HS256", "HS384", "HS512")
  ]))
  # Every algorithm zujose knows is available with the zucrypt it requires.
  expect_true(all(info$available))
  expect_identical(info$zucrypt[info$algorithm == "ES256"], "0.5.0")
  expect_false("none" %in% info$algorithm)
})

test_that("printing a verified JWS shows the header, not the payload", {
  key <- jwk_oct(as.raw(1:32), kid = "k")
  expect_snapshot(print(jws_verify(
    jws_sign("secret text", key, "HS256"),
    key,
    "HS256"
  )))
})
