test_that("jose_limits() has the documented defaults", {
  limits <- jose_limits()
  expect_s3_class(limits, "jose_limits")
  expect_identical(
    unclass(limits),
    list(
      token = 2^21,
      header = 2^14,
      payload = 2^20,
      signatures = 16,
      recipients = 16,
      keys = 16,
      p2c = 600000
    )
  )
})

test_that("limits must be whole numbers of at least 1, or Inf", {
  expect_no_error(jose_limits(token = Inf, keys = 1))
  for (bad in list(0, -1, 1.5, NA_real_, "10", c(1, 2), NULL)) {
    expect_error(jose_limits(token = bad), class = "zujose_argument_error")
  }
})

test_that("jose_limits() prints every limit", {
  expect_snapshot(print(jose_limits(signatures = 2)))
})

test_that("a token is checked against `limits` that are not jose_limits", {
  expect_error(
    jose_peek("a.b.c", limits = list(token = 10)),
    class = "zujose_argument_error"
  )
})

test_that("the header and payload limits are exact in bytes", {
  key <- jwk_oct(as.raw(1:32))
  token <- jws_sign("abcdef", key, alg = "HS256")
  header <- nchar('{"alg":"HS256"}')
  expect_no_error(
    jws_verify(token, key, "HS256", limits = jose_limits(header = header))
  )
  expect_error(
    jws_verify(token, key, "HS256", limits = jose_limits(header = header - 1)),
    class = "zujose_parse_error"
  )
  expect_no_error(
    jws_verify(token, key, "HS256", limits = jose_limits(payload = 6))
  )
  expect_error(
    jws_verify(token, key, "HS256", limits = jose_limits(payload = 5)),
    class = "zujose_parse_error"
  )
  json <- jws_sign("abcdef", key, alg = "HS256", format = "flattened")
  expect_error(
    jws_verify(json, key, "HS256", limits = jose_limits(payload = 4)),
    class = "zujose_parse_error"
  )
  part <- strsplit(token, ".", fixed = TRUE)[[1]][[1]]
  header <- length(b64url_decode(part, "header"))
  expect_error(
    jwe_decrypt(
      token,
      key,
      "A128KW",
      "A128GCM",
      limits = jose_limits(header = header - 1)
    ),
    class = "zujose_parse_error"
  )
})

test_that("the payload limit bounds a JWE ciphertext exactly", {
  key <- jwk_oct(as.raw(1:16))
  token <- jwe_encrypt("abcdef", key, alg = "A128KW", enc = "A128GCM")
  expect_no_error(
    jwe_decrypt(
      token,
      key,
      "A128KW",
      "A128GCM",
      limits = jose_limits(payload = 6)
    )
  )
  expect_error(
    jwe_decrypt(
      token,
      key,
      "A128KW",
      "A128GCM",
      limits = jose_limits(payload = 4)
    ),
    class = "zujose_parse_error"
  )
  part <- strsplit(token, ".", fixed = TRUE)[[1]][[1]]
  header <- length(b64url_decode(part, "header"))
  expect_error(
    jwe_decrypt(
      token,
      key,
      "A128KW",
      "A128GCM",
      limits = jose_limits(header = header - 1)
    ),
    class = "zujose_parse_error"
  )
})

test_that("a payload at the default limit fits the default token limit", {
  key <- jwk_oct(as.raw(1:32))
  payload <- as.raw(rep_len(0:255, 2^20))
  token <- jws_sign(payload, key, alg = "HS256")
  expect_identical(jws_verify(token, key, "HS256")$payload, payload)
  token <- jwe_encrypt(payload, key, alg = "dir", enc = "A256GCM")
  expect_identical(jwe_decrypt(token, key, "dir", "A256GCM")$plaintext, payload)
})

test_that("jose_limits() prints the same under a comma decimal mark", {
  withr::local_options(OutDec = ",", warn = 2)
  expect_snapshot(print(jose_limits(token = Inf)))
})

# Straddles (design §9): each limit at `limit - 1`, `limit` and
# `limit + 1`, on every path that reaches it.

test_that("token straddles in bytes on every serialization and entry (#107)", {
  key <- jwk_oct(as.raw(1:32))
  kek <- jwk_oct(as.raw(1:16))
  # Non-ASCII JSON, so counting characters instead of bytes is caught.
  note <- list(note = "été été")
  verify <- function(token) {
    function(limits) jws_verify(token, key, "HS256", limits = limits)
  }
  decrypt <- function(token) {
    function(limits) jwe_decrypt(token, kek, "A128KW", "A128GCM", limits)
  }
  jws <- list(
    compact = jws_sign("abc", key, "HS256"),
    flattened = jws_sign(
      "abc",
      key,
      "HS256",
      unprotected = note,
      format = "flattened"
    ),
    general = jws_sign(
      "abc",
      key,
      "HS256",
      unprotected = note,
      format = "general"
    )
  )
  jwe <- lapply(
    c(compact = "compact", flattened = "flattened", general = "general"),
    function(format) {
      jwe_encrypt(
        "abc",
        kek,
        "A128KW",
        "A128GCM",
        unprotected = if (format != "compact") note,
        format = format
      )
    }
  )
  expect_gt(nchar(jws$general, "bytes"), nchar(jws$general, "chars"))
  expect_gt(nchar(jwe$general, "bytes"), nchar(jwe$general, "chars"))
  runs <- c(
    lapply(jws, verify),
    lapply(jwe, decrypt),
    lapply(c(jws, jwe), function(token) {
      function(limits) jose_peek(token, limits)
    })
  )
  tokens <- c(jws, jwe, jws, jwe)
  for (i in seq_along(runs)) {
    expect_limit_straddle(
      runs[[i]],
      "token",
      nchar(tokens[[i]], "bytes"),
      no_decoding = TRUE,
      info = names(tokens)[[i]]
    )
  }

  claims <- list(exp = 4e9, note = note$note)
  jwts <- list(
    signed = jwt_encode(claims, key, "HS256"),
    encrypted = jwe_encrypt(
      zujson::json_write(claims),
      kek,
      "A128KW",
      "A128GCM"
    )
  )
  for (name in names(jwts)) {
    jwt <- jwts[[name]]
    expect_limit_straddle(
      function(limits) {
        jwt_decode(
          jwt,
          key,
          "HS256",
          decrypt = jwe_decryption(kek, "A128KW", "A128GCM"),
          limits = limits
        )
      },
      "token",
      nchar(jwt, "bytes"),
      no_decoding = TRUE,
      info = name
    )
  }
})

test_that("header straddles in decoded bytes on every serialization (#108)", {
  key <- jwk_oct(as.raw(1:32))
  kek <- jwk_oct(as.raw(1:16))
  lengths <- integer()
  for (j in 1:3) {
    kid <- strrep("k", j)
    long <- list(kid = strrep("q", j + 8))
    jws <- list(
      compact = jws_sign("abc", key, "HS256", header = list(kid = kid)),
      flattened = jws_sign(
        "abc",
        key,
        "HS256",
        header = list(kid = kid),
        format = "flattened"
      ),
      # The second signature's header is the longer one.
      general = jws_sign(
        "abc",
        list(
          jws_signer(key, "HS256", header = list(kid = kid)),
          jws_signer(key, "HS256", header = long)
        ),
        format = "general"
      )
    )
    jwe <- lapply(
      c(compact = "compact", flattened = "flattened", general = "general"),
      function(format) {
        jwe_encrypt(
          "abc",
          kek,
          "A128KW",
          "A128GCM",
          header = list(kid = kid),
          format = format
        )
      }
    )
    for (name in names(jws)) {
      token <- jws[[name]]
      n <- max(protected_bytes(token))
      lengths <- c(lengths, n)
      expect_limit_straddle(
        function(limits) jws_verify(token, key, "HS256", limits = limits),
        "header",
        n,
        info = paste("JWS", name, j)
      )
    }
    for (name in names(jwe)) {
      token <- jwe[[name]]
      n <- protected_bytes(token)
      lengths <- c(lengths, n)
      expect_limit_straddle(
        function(limits) jwe_decrypt(token, kek, "A128KW", "A128GCM", limits),
        "header",
        n,
        info = paste("JWE", name, j)
      )
    }
  }
  # Every length modulo 3, so every final Base64url quantum, is covered.
  expect_setequal(lengths %% 3, 0:2)
})

test_that("payload straddles in its documented unit on every path (#109)", {
  key <- jwk_oct(as.raw(1:32))
  kek <- jwk_oct(as.raw(1:16))
  for (n in 10:12) {
    payload <- charToRaw(strrep("p", n))
    verify <- function(token, detached = NULL) {
      function(limits) {
        jws_verify(token, key, "HS256", payload = detached, limits = limits)
      }
    }
    runs <- list(
      compact = verify(jws_sign(payload, key, "HS256")),
      flattened = verify(jws_sign(payload, key, "HS256", format = "flattened")),
      general = verify(jws_sign(payload, key, "HS256", format = "general")),
      detached = verify(
        jws_sign(payload, key, "HS256", detached = TRUE),
        payload
      ),
      unencoded_detached = verify(
        jws_sign(payload, key, "HS256", b64 = FALSE, detached = TRUE),
        payload
      ),
      unencoded_compact = verify(jws_sign(payload, key, "HS256", b64 = FALSE)),
      unencoded_flattened = verify(
        jws_sign(payload, key, "HS256", b64 = FALSE, format = "flattened")
      )
    )
    # A128GCM: the ciphertext is as long as the plaintext.
    for (format in c("compact", "flattened", "general")) {
      token <- jwe_encrypt(payload, kek, "A128KW", "A128GCM", format = format)
      runs[[paste("JWE", format)]] <- local({
        token <- token
        function(limits) jwe_decrypt(token, kek, "A128KW", "A128GCM", limits)
      })
    }
    for (name in names(runs)) {
      expect_limit_straddle(runs[[name]], "payload", n, info = paste(name, n))
    }
  }

  # The JWE unit is ciphertext: 10 bytes of plaintext are 16 of ciphertext
  # under A128CBC-HS256, so 15 is refused and 16 is enough.
  for (format in c("compact", "flattened", "general")) {
    token <- jwe_encrypt(
      strrep("p", 10),
      kek,
      "A128KW",
      "A128CBC-HS256",
      format = format
    )
    expect_limit_straddle(
      function(limits) {
        jwe_decrypt(token, kek, "A128KW", "A128CBC-HS256", limits)
      },
      "payload",
      16,
      info = format
    )
  }
})

test_that("signatures and recipients straddle their counts (#110)", {
  key <- jwk_oct(as.raw(1:32))
  kek <- jwk_oct(as.raw(1:16))
  signers <- lapply(1:3, function(i) jws_signer(key, "HS256"))
  jws <- jws_sign("abc", signers, format = "general")
  expect_limit_straddle(
    function(limits) jws_verify(jws, key, "HS256", limits = limits),
    "signatures",
    3,
    no_decoding = TRUE
  )
  recipients <- lapply(1:3, function(i) jwe_recipient(kek, "A128KW"))
  jwe <- jwe_encrypt("abc", recipients, enc = "A128GCM", format = "general")
  expect_limit_straddle(
    function(limits) jwe_decrypt(jwe, kek, "A128KW", "A128GCM", limits),
    "recipients",
    3,
    no_decoding = TRUE
  )

  # A flattened token, and a general one with one entry, count as one.
  one <- jose_limits(signatures = 1, recipients = 1)
  for (format in c("flattened", "general")) {
    token <- jws_sign("abc", key, "HS256", format = format)
    expect_no_error(jws_verify(token, key, "HS256", limits = one))
    token <- jwe_encrypt("abc", kek, "A128KW", "A128GCM", format = format)
    expect_no_error(jwe_decrypt(token, kek, "A128KW", "A128GCM", one))
  }
})

test_that("keys straddles the keys tried for one token (#111)", {
  hmac <- lapply(1:3, function(i) jwk_oct(as.raw(seq_len(32) + i)))
  set <- do.call(jwk_set, hmac)
  resolver <- function(header) set
  jws <- jws_sign("abc", hmac[[3]], "HS256")
  jwt <- jwt_encode(list(exp = 4e9), hmac[[3]], "HS256")
  for (key in list(set = set, resolver = resolver)) {
    expect_limit_straddle(
      function(limits) jws_verify(jws, key, "HS256", limits = limits),
      "keys",
      3,
      class = "zujose_key_error"
    )
    expect_limit_straddle(
      function(limits) jwt_decode(jwt, key, "HS256", limits = limits),
      "keys",
      3,
      class = "zujose_key_error"
    )
  }
  # Three signatures, each fitting two keys: six attempts for the token.
  general <- jws_sign(
    "abc",
    lapply(1:3, function(i) jws_signer(hmac[[3]], "HS256")),
    format = "general"
  )
  two <- jwk_set(hmac[[1]], hmac[[3]])
  expect_limit_straddle(
    function(limits) jws_verify(general, two, "HS256", limits = limits),
    "keys",
    6,
    class = "zujose_key_error"
  )

  keks <- lapply(1:3, function(i) jwk_oct(as.raw(seq_len(16) + i)))
  kek_set <- do.call(jwk_set, keks)
  one <- jwe_encrypt("abc", keks[[3]], "A128KW", "A128GCM")
  # Two recipients, each fitting three keys: six attempts for the token.
  several <- jwe_encrypt(
    "abc",
    list(
      jwe_recipient(keks[[3]], "A128KW"),
      jwe_recipient(keks[[3]], "A128KW")
    ),
    enc = "A128GCM",
    format = "general"
  )
  for (key in list(kek_set, function(header) kek_set)) {
    expect_limit_straddle(
      function(limits) jwe_decrypt(one, key, "A128KW", "A128GCM", limits),
      "keys",
      3,
      class = "zujose_key_error"
    )
    expect_limit_straddle(
      function(limits) jwe_decrypt(several, key, "A128KW", "A128GCM", limits),
      "keys",
      6,
      class = "zujose_key_error"
    )
  }
})

test_that("p2c and p2s straddle on decrypt, compact and JSON (#112)", {
  local_pbes2_reached()
  password <- jwk_oct(charToRaw("pw"))
  alg <- "PBES2-HS256+A128KW"
  limits <- jose_limits(p2c = 1000)
  general <- function(p2c, p2s = b64url_encode(as.raw(1:16))) {
    zujson::json_write(list(
      protected = b64_json(list(enc = "A128GCM")),
      recipients = list(list(
        header = list(alg = alg, p2c = p2c, p2s = p2s),
        encrypted_key = b64url_encode(as.raw(1:24))
      )),
      iv = b64url_encode(as.raw(1:12)),
      ciphertext = "AAAA",
      tag = b64url_encode(as.raw(1:16))
    ))
  }
  for (make in list(compact = pbes2_token, general = general)) {
    # The limit itself and one under it reach key derivation.
    for (p2c in c(999, 1000)) {
      expect_error(
        jwe_decrypt(make(p2c = p2c), password, alg, "A128GCM", limits),
        class = "pbes2_reached"
      )
    }
    expect_error(
      jwe_decrypt(make(p2c = 1001), password, alg, "A128GCM", limits),
      class = "zujose_parse_error"
    )
    # A salt of 8 bytes is enough; 7 is refused.
    for (n in 8:9) {
      token <- make(p2c = 1000, p2s = b64url_encode(as.raw(seq_len(n))))
      expect_error(
        jwe_decrypt(token, password, alg, "A128GCM", limits),
        class = "pbes2_reached"
      )
    }
    token <- make(p2c = 1000, p2s = b64url_encode(as.raw(1:7)))
    expect_error(
      jwe_decrypt(token, password, alg, "A128GCM", limits),
      class = "zujose_parse_error"
    )
  }
})

test_that("p2c straddles 1000 and 2^32 - 1 on encrypt (#112)", {
  local_mocked_bindings(pbes2_kek = function(...) as.raw(1:16))
  password <- jwk_oct(charToRaw("pw"))
  alg <- "PBES2-HS256+A128KW"
  written <- function(token) jose_peek(token)$headers[[1]][["p2c"]]
  for (p2c in c(1000, 1001, 2^32 - 2, 2^32 - 1)) {
    token <- jwe_encrypt("x", password, alg, header = list(p2c = p2c))
    expect_equal(written(token), p2c)
    token <- jwe_encrypt(
      "x",
      list(jwe_recipient(password, alg, header = list(p2c = p2c))),
      format = "general"
    )
    expect_equal(written(token), p2c)
  }
  for (p2c in c(999, 2^32)) {
    expect_error(
      jwe_encrypt("x", password, alg, header = list(p2c = p2c)),
      class = "zujose_argument_error"
    )
    expect_error(
      jwe_encrypt(
        "x",
        list(jwe_recipient(password, alg, header = list(p2c = p2c))),
        format = "general"
      ),
      class = "zujose_argument_error"
    )
  }
})

test_that("A*GCMKW iv must be 12 bytes and tag 16, exactly (#113)", {
  kek <- jwk_oct(as.raw(1:16))
  token <- jwe_encrypt("abc", kek, "A128GCMKW", "A128GCM")
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  header <- jose_peek(token)$headers[[1]]
  rebuild <- function(iv, tag) {
    header$iv <- b64url_encode(as.raw(seq_len(iv)))
    header$tag <- b64url_encode(as.raw(seq_len(tag)))
    paste(c(b64_json(header), parts[-1]), collapse = ".")
  }
  expect_identical(
    rawToChar(jwe_decrypt(token, kek, "A128GCMKW", "A128GCM")$plaintext),
    "abc"
  )
  # The right lengths pass the checks and fail only in decryption.
  expect_error(
    jwe_decrypt(rebuild(12, 16), kek, "A128GCMKW", "A128GCM"),
    class = "zujose_decrypt_error"
  )
  local_no_crypto()
  for (bad in list(c(11, 16), c(13, 16), c(12, 15), c(12, 17))) {
    expect_error(
      jwe_decrypt(rebuild(bad[[1]], bad[[2]]), kek, "A128GCMKW", "A128GCM"),
      class = "zujose_parse_error",
      info = paste(bad, collapse = "/")
    )
  }
})

test_that("an HMAC key straddles the hash size, sign and verify (#113)", {
  for (alg in c("HS256", "HS384", "HS512")) {
    n <- hmac_min_bytes[[alg]]
    short <- jwk_with_kid(jwk_oct(as.raw(seq_len(n - 1))), "short")
    expect_error(jws_sign("abc", short, alg), class = "zujose_key_error")
    for (size in c(n, n + 1)) {
      key <- jwk_with_kid(jwk_oct(as.raw(seq_len(size))), "long")
      token <- jws_sign("abc", key, alg)
      expect_identical(jws_verify(token, key, alg)$kid, "long")
      expect_error(jws_verify(token, short, alg), class = "zujose_key_error")
      # In a set, the short key is skipped and the long one verifies.
      set <- jwk_set(short, key)
      expect_identical(jws_verify(token, set, alg)$kid, "long")
    }
  }
})

test_that("an RSA modulus straddles 2048 bits (#113)", {
  # zucrypt takes only whole-byte RSA keys, so no 2047- or 2049-bit key can
  # be a jwk: those are straddled through the checks themselves, and the
  # public paths with the nearest importable sizes.
  for (bits in c(2047, 2048, 2049)) {
    key <- list(kty = "RSA", bits = bits)
    strong <- bits >= 2048
    expect_identical(sig_key_strong("RS256", key), strong)
    expect_identical(kek_fits("RSA-OAEP", "A128GCM", key), strong)
    if (strong) {
      expect_no_error(check_rsa_size(key, NULL))
    } else {
      expect_error(check_rsa_size(key, NULL), class = "zujose_key_error")
    }
  }
  small <- rsa_2040_jwk()
  expect_identical(small$bits, 2040L)
  expect_error(
    jws_verify("eyJhbGciOiJSUzI1NiJ9.e30.c2ln", small, "RS256"),
    class = "zujose_key_error"
  )
  expect_error(
    jwe_encrypt("abc", small, "RSA-OAEP", "A128GCM"),
    class = "zujose_key_error"
  )
  key <- oracle_key("rsa-2048")
  expect_identical(key$bits, 2048L)
  expect_no_error(jwe_encrypt("abc", key, "RSA-OAEP", "A128GCM"))
})

test_that("max_age straddles seconds since iat, plus leeway (#114)", {
  # At now = 1000 and max_age = 100: 840 is the oldest iat under the
  # default leeway of 60, and 900 under no leeway.
  for (case in list(
    list(leeway = 60, oldest = 840),
    list(leeway = 0, oldest = 900)
  )) {
    for (iat in case$oldest + 0:1) {
      expect_no_error(decode_at_1000(
        list(iat = iat),
        max_age = 100,
        leeway = case$leeway
      ))
    }
    expect_error(
      decode_at_1000(
        list(iat = case$oldest - 1),
        max_age = 100,
        leeway = case$leeway
      ),
      class = "zujose_expired_error"
    )
  }
})

test_that("a JWE holds one level of nested JWT, not two (#115)", {
  key <- jwk_oct(as.raw(1:32))
  kek <- jwk_oct(as.raw(1:16))
  decrypt <- jwe_decryption(kek, "A128KW", "A128GCM")
  inner <- jwt_encode(list(exp = 4e9, sub = "u"), key, "HS256")
  seal <- function(token) {
    jwe_encrypt(token, kek, "A128KW", "A128GCM", header = list(cty = "JWT"))
  }
  claims <- jwt_decode(seal(inner), key, "HS256", decrypt = decrypt)
  expect_identical(claims$sub, "u")
  middle <- jws_sign(inner, key, "HS256", header = list(cty = "JWT"))
  expect_error(
    jwt_decode(seal(middle), key, "HS256", decrypt = decrypt),
    class = "zujose_policy_error"
  )
})

test_that("JSON nests 1000 levels deep, from zujson, and not 1001 (#115)", {
  key <- jwk_oct(as.raw(1:32))
  for (depth in c(999, 1000, 1001)) {
    ok <- depth <= 1000
    check <- function(expr) {
      if (ok) {
        expect_no_error(expr)
      } else {
        expect_error(expr, class = "zujose_parse_error")
      }
    }
    json <- nested_json(depth)
    # A protected header.
    header <- sub("^\\{", '{"alg":"HS256",', json)
    check(jose_peek(paste(b64_json(header), "e30", "c2ln", sep = ".")))
    # A JWS JSON token, nested through its unprotected header.
    token <- sprintf(
      '{"payload":"e30","protected":"%s","header":%s,"signature":"c2ln"}',
      b64_json(list(alg = "HS256")),
      nested_json(depth - 1)
    )
    check(jose_peek(token))
    # A claims set.
    claims <- sub("^\\{", '{"exp":4000000000,', json)
    jwt <- jws_sign(claims, key, "HS256", header = list(typ = "JWT"))
    check(jwt_decode(jwt, key, "HS256"))
  }
})
