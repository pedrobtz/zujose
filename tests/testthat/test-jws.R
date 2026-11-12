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
  # A JSON token without its `payload` member needs the payload (#147).
  for (figure in 42:43) {
    expect_error(
      jws_verify(rfc7520_token(figure), key, algorithms = "HS256"),
      class = "zujose_parse_error"
    )
  }
})

test_that("a JSON JWS without a payload member is not an empty payload (#147)", {
  key <- jwk_oct(as.raw(1:32))
  for (format in c("flattened", "general")) {
    absent <- jws_sign("", key, "HS256", format = format, detached = TRUE)
    expect_error(
      jws_verify(absent, key, algorithms = "HS256"),
      class = "zujose_parse_error"
    )
    out <- jws_verify(absent, key, algorithms = "HS256", payload = "")
    expect_identical(out$payload, raw())
    empty <- jws_sign("", key, "HS256", format = format)
    expect_identical(jws_verify(empty, key, "HS256")$payload, raw())
  }
  # In the compact serialization an empty part is the detached payload.
  compact <- jws_sign("", key, "HS256", detached = TRUE)
  expect_identical(jws_verify(compact, key, "HS256")$payload, raw())
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
  local_no_crypto()
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
  local_no_crypto()
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
  local_no_crypto()
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
  local_no_crypto()
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
  local_no_crypto()
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
  # zucrypt 0.1.1 adds every primitive beyond HMAC and AES-CBC, randomness
  # and SHA-2 included, so every algorithm needs it.
  expect_true(all(info$zucrypt == "0.1.1"))
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

test_that("the algorithm allow-list is checked before any signature check", {
  # The key fits the token's algorithm, so only the allow-list can refuse
  # it, and it must do so before the signature is computed (#36).
  key <- jwk_oct(as.raw(1:64))
  token <- jws_sign("x", key, alg = "HS512")
  jwt <- jwt_encode(list(sub = "u"), key, alg = "HS512", expires_in = 60)
  local_no_crypto()
  expect_error(
    jws_verify(token, key, algorithms = "HS256"),
    class = "zujose_policy_error"
  )
  expect_error(
    jwt_decode(jwt, key, algorithms = "HS256"),
    class = "zujose_policy_error"
  )
  general <- jws_sign("x", list(jws_signer(key, "HS512")), format = "general")
  expect_error(
    jws_verify(general, key, algorithms = "HS384"),
    class = "zujose_policy_error"
  )
})

test_that("jwk, x5c, jku and x5u in a header are never used as keys", {
  # The attacker signs with their own key and names it in the header in
  # each of the four ways RFC 7515 allows; verifying with the caller's key
  # must fail (#43).
  attacker <- jwk_generate("RSA")
  caller <- jwk_public(jwk_generate("RSA"))
  named <- list(
    jwk = zujson::json_parse_raw(
      charToRaw(jwk_json(attacker)),
      simplify = "none"
    ),
    x5c = list("MIIBszCCAVmgAwIBAgIU"),
    jku = "https://attacker.example/jwks.json",
    x5u = "https://attacker.example/cert.pem"
  )
  for (member in names(named)) {
    token <- jws_sign(
      "x",
      attacker,
      alg = "RS256",
      header = stats::setNames(list(named[[member]]), member)
    )
    expect_error(
      jws_verify(token, caller, algorithms = "RS256"),
      class = "zujose_signature_error",
      info = member
    )
  }
})

test_that("b64 and crit are set through the b64 argument, not a header", {
  # A b64 member the payload encoding does not follow would verify as the
  # wrong bytes (#72).
  key <- jwk_oct(as.raw(1:32), alg = "HS256")
  for (header in list(
    list(b64 = FALSE, crit = list("b64")),
    list(b64 = FALSE),
    list(b64 = TRUE),
    list(crit = list("b64")),
    list(crit = list("exp"), exp = 1)
  )) {
    expect_error(
      jws_sign("x", key, header = header),
      class = "zujose_argument_error"
    )
    expect_error(
      jws_sign("x", key, unprotected = header, format = "flattened"),
      class = "zujose_argument_error"
    )
  }
  # The b64 argument still writes RFC 7797 correctly.
  token <- jws_sign("{\"a\":1}", key, b64 = FALSE, detached = TRUE)
  expect_identical(
    rawToChar(jws_verify(token, key, "HS256", payload = "{\"a\":1}")$payload),
    "{\"a\":1}"
  )
})

test_that("`limits$keys` counts the keys tried across all signatures", {
  signers <- lapply(1:3, function(i) {
    jws_signer(jwk_oct(as.raw(i + 0:31)), "HS256")
  })
  token <- jws_sign("x", signers, format = "general")
  wrong <- jwk_set(
    jwk_oct(as.raw(101:132)),
    jwk_oct(as.raw(102:133)),
    jwk_oct(as.raw(103:134))
  )
  verifies <- 0L
  local_mocked_bindings(jws_verify_bytes = function(...) {
    verifies <<- verifies + 1L
    FALSE
  })
  expect_error(
    jws_verify(
      token,
      wrong,
      "HS256",
      require = "any",
      limits = jose_limits(keys = 3)
    ),
    class = "zujose_key_error"
  )
  expect_identical(verifies, 0L)
  expect_error(
    jws_verify(
      token,
      wrong,
      "HS256",
      require = "any",
      limits = jose_limits(keys = 9)
    ),
    class = "zujose_signature_error"
  )
  expect_identical(verifies, 9L)
})

test_that("a general JWS verifies with keys within `limits$keys`", {
  a <- jwk_oct(as.raw(1:32))
  b <- jwk_oct(as.raw(2:33))
  token <- jws_sign(
    "x",
    list(jws_signer(a, "HS256"), jws_signer(b, "HS256")),
    format = "general"
  )
  set <- jwk_set(jwk_oct(as.raw(1:32)), jwk_oct(as.raw(2:33)))
  expect_no_error(jws_verify(
    token,
    set,
    "HS256",
    limits = jose_limits(keys = 4)
  ))
  expect_error(
    jws_verify(token, set, "HS256", limits = jose_limits(keys = 3)),
    class = "zujose_key_error"
  )
})

test_that("headers with repeated, NA or empty names are refused (#119)", {
  key <- jwk_oct(as.raw(1:32))
  bad <- list(
    list(a = 1, a = 2),
    list(typ = "JWT", typ = "at+jwt"),
    list(x = list(a = 1, a = 2)),
    list(x = c(a = 1, a = 2)),
    list(x = list(list(a = 1, a = 2))),
    stats::setNames(list(1), NA),
    list(x = stats::setNames(list(1), NA)),
    list(x = list(a = 1, 2)),
    data.frame(a = 1:2)
  )
  for (header in bad) {
    expect_error(
      jws_sign("p", key, "HS256", header = header),
      class = "zujose_argument_error"
    )
    expect_error(
      jws_sign(
        "p",
        key,
        "HS256",
        unprotected = header,
        format = "flattened"
      ),
      class = "zujose_argument_error"
    )
  }
  expect_error(
    jws_sign(
      "p",
      key,
      "HS256",
      header = list(a = 1),
      unprotected = list(a = 2),
      format = "flattened"
    ),
    class = "zujose_argument_error"
  )
  # An array of objects, and an object, are still written.
  token <- jws_sign(
    "p",
    key,
    "HS256",
    header = list(x = list(list(a = 1), list(a = 2)), y = list(b = 1))
  )
  expect_identical(
    jose_peek(token)$headers[[1]]$x,
    list(list(a = 1L), list(a = 2L))
  )
})

test_that("a header value JSON cannot represent is an argument error (#123)", {
  key <- jwk_oct(as.raw(1:32))
  for (value in list(as.raw(1), 1i, quote(x), function() 1)) {
    expect_error(
      jws_sign("p", key, "HS256", header = list(a = value)),
      class = "zujose_argument_error"
    )
    expect_error(
      jws_sign("p", key, "HS256", header = list(a = list(b = value))),
      class = "zujose_argument_error"
    )
  }
})

test_that("a named list of signers writes `signatures` as an array (#120)", {
  key <- jwk_oct(as.raw(1:32))
  token <- jws_sign(
    "x",
    list(a = jws_signer(key, c(n = "HS256"))),
    format = "general"
  )
  expect_true(startsWith(
    token,
    "{\"payload\":\"eA\",\"signatures\":[{"
  ))
  expect_identical(jws_verify(token, key, "HS256")$alg, "HS256")
})

test_that("an unencoded payload with a NUL byte is an argument error (#123)", {
  key <- jwk_oct(as.raw(1:32))
  for (format in c("compact", "flattened")) {
    expect_error(
      jws_sign(
        as.raw(c(0x61, 0, 0x62)),
        key,
        "HS256",
        b64 = FALSE,
        detached = TRUE,
        format = format
      ),
      class = "zujose_argument_error"
    )
  }
})
