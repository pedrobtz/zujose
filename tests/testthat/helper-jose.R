# Fixtures and token builders shared by the test files.

# The RFC 7520 manifest: one row per figure, with type and serialization.
rfc7520_manifest <- function() {
  utils::read.delim(
    test_path("fixtures", "rfc7520", "MANIFEST.tsv"),
    comment.char = "#",
    stringsAsFactors = FALSE
  )
}

# The token in one RFC 7520 figure, as a single string.
rfc7520_token <- function(figure) {
  path <- test_path("fixtures", "rfc7520", sprintf("fig-%03d.txt", figure))
  readChar(path, file.size(path), useBytes = TRUE)
}

# Base64url of a header list, or of a JSON string as written.
b64_json <- function(x) {
  json <- if (is.character(x)) x else zujson::json_write(x)
  b64url_encode(charToRaw(json))
}

# A compact JWS with the given header (a list, or JSON text) and payload.
# The signature is placeholder bytes: nothing in Stage 1 checks it.
compact_jws <- function(header, payload = "{}", signature = "c2ln") {
  paste(
    b64_json(header),
    b64url_encode(charToRaw(payload)),
    signature,
    sep = "."
  )
}

# RFC 7797 §4.2: the protected header and signature of the unencoded
# payload "$.02".
rfc7797_header <- function() {
  "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"
}
rfc7797_signature <- function() "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"

# RFC 7519 §3.1.
rfc7519_jwt <- function() {
  paste0(
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.",
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxl",
    "LmNvbS9pc19yb290Ijp0cnVlfQ.",
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  )
}

# Every way of breaking a well-formed token, applied to the RFC 7520
# compact tokens. Each mutation returns a token or NULL when it does not
# apply.
malformed_corpus <- function(token) {
  parts <- strsplit(paste0(token, "."), ".", fixed = TRUE)[[1]]
  rebuild <- function(i, value) {
    parts[[i]] <- value
    paste(parts, collapse = ".")
  }
  each_part <- function(f) {
    lapply(seq_along(parts), function(i) {
      if (nzchar(parts[[i]])) rebuild(i, f(parts[[i]]))
    })
  }
  header <- function(bytes) rebuild(1L, b64url_encode(bytes))

  c(
    list(
      paste(parts[-1], collapse = "."),
      paste0(token, ".e30"),
      sub(".", "..", token, fixed = TRUE),
      "",
      "....",
      header(raw()),
      header(charToRaw("not json")),
      header(charToRaw("[1]")),
      header(charToRaw('"alg"')),
      header(as.raw(c(0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d))),
      header(charToRaw('{"alg":"HS256","alg":"HS256"}'))
    ),
    each_part(function(p) paste0(p, "=")),
    each_part(function(p) paste0(p, "==")),
    each_part(function(p) paste0(substr(p, 1, 1), " ", substring(p, 2))),
    each_part(function(p) paste0(p, "\n")),
    each_part(function(p) paste0("+", substring(p, 2))),
    each_part(function(p) paste0("/", substring(p, 2))),
    each_part(function(p) {
      while (nchar(p) %% 4L != 1L) {
        p <- paste0(p, "A")
      }
      p
    }),
    each_part(function(p) paste0(p, "é"))
  )
}

# A b64url_decode() that fails the test if it is ever reached for `what`.
local_no_decoding <- function(what = NULL, env = parent.frame()) {
  real <- b64url_decode
  local_mocked_bindings(
    b64url_decode = function(x, part, call = NULL) {
      if (is.null(what) || part %in% what) {
        stop("decoding started")
      }
      real(x, part, call)
    },
    .env = env
  )
}

# Policy runs before cryptography (CLAUDE.md): a refusal that must come
# from the allow-list, `crit` or the limits fails the test if any
# signature check, key unwrap, key derivation or content decryption starts.
local_no_crypto <- function(env = parent.frame()) {
  reached <- function(...) stop("crypto reached")
  local_mocked_bindings(
    jws_verify_bytes = reached,
    recover_cek = reached,
    content_decrypt = reached,
    pbes2_kek = reached,
    ecdh_secret = reached,
    .env = env
  )
}

# RFC 7515 A.1: the HMAC key, also used by RFC 7797 §4.
rfc7515_key <- function() {
  as_jwk(paste0(
    '{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75',
    'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}'
  ))
}

# Two JSON serializations are the same object, whatever the member order.
expect_same_json <- function(actual, expected) {
  expect_identical(
    zujson::json_parse(actual, simplify = "none") |> sort_members(),
    zujson::json_parse(expected, simplify = "none") |> sort_members()
  )
}

sort_members <- function(x) {
  if (!is.list(x)) {
    return(x)
  }
  x <- lapply(x, sort_members)
  if (!is.null(names(x))) x[order(names(x))] else x
}

# Decode the claims `payload`, signed with a fixed key, at time 1000. The
# argument is not called `claims`, which would capture jwt_decode()'s.
decode_at_1000 <- function(
  payload,
  ...,
  required = character(),
  header = list(typ = "JWT")
) {
  key <- jwk_oct(as.raw(1:32))
  jwt <- jwt_encode(
    payload,
    key,
    "HS256",
    header = header,
    issued_at = FALSE
  )
  jwt_decode(
    jwt,
    key,
    "HS256",
    required = required,
    now = as_posixct(1000),
    ...
  )
}

# Hex text to raw, ignoring spaces.
hex <- function(x) {
  x <- gsub(" ", "", x)
  as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
}

# RFC 7516 A.3: the key, CEK, IV, plaintext and compact JWE.
rfc7516_a3 <- function() {
  list(
    key = as_jwk('{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}'),
    cek = as.raw(c(
      4,
      211,
      31,
      197,
      84,
      157,
      252,
      254,
      11,
      100,
      157,
      250,
      63,
      170,
      106,
      206,
      107,
      124,
      212,
      45,
      111,
      107,
      9,
      219,
      200,
      177,
      0,
      240,
      143,
      156,
      44,
      207
    )),
    iv = as.raw(c(
      3,
      22,
      60,
      12,
      43,
      67,
      104,
      105,
      108,
      108,
      105,
      99,
      111,
      116,
      104,
      101
    )),
    plaintext = "Live long and prosper.",
    token = paste0(
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.",
      "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.",
      "AxY8DCtDaGlsbGljb3RoZQ.",
      "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.",
      "U0m_YmjN04DJvceFICbCVQ"
    )
  )
}

# RFC 7516 A.4: the same message to an RSA1_5 recipient and to A.3's A128KW
# key, with kid "7".
rfc7516_a4 <- function() {
  paste0(
    '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",',
    '"unprotected":{"jku":"https://server.example.com/keys.jwks"},',
    '"recipients":[{"header":{"alg":"RSA1_5","kid":"2011-04-29"},',
    '"encrypted_key":"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltG',
    "RhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deL",
    "KxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZ",
    "IFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXd",
    "s2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2Tbq",
    'mScqXMR4gp_A"},',
    '{"header":{"alg":"A128KW","kid":"7"},',
    '"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],',
    '"iv":"AxY8DCtDaGlsbGljb3RoZQ",',
    '"ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",',
    '"tag":"Mz-VPPyU4RlcuYv1IwIvzw"}'
  )
}

# RFC 7518 Appendix B, one row per AES_CBC_HMAC_SHA2 algorithm.
rfc7518_cbc <- function() {
  utils::read.delim(
    test_path("fixtures", "rfc7518-cbc.tsv"),
    comment.char = "#",
    stringsAsFactors = FALSE
  )
}

# RFC 3394 §4: KEK, key data and wrapped key, in hex.
rfc3394_vectors <- function() {
  k16 <- "000102030405060708090A0B0C0D0E0F"
  k24 <- paste0(k16, "1011121314151617")
  k32 <- paste0(k16, "101112131415161718191A1B1C1D1E1F")
  d16 <- "00112233445566778899AABBCCDDEEFF"
  d24 <- paste0(d16, "0001020304050607")
  d32 <- paste0(d16, "000102030405060708090A0B0C0D0E0F")
  list(
    "4.1" = c(k16, d16, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"),
    "4.2" = c(k24, d16, "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"),
    "4.3" = c(k32, d16, "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"),
    "4.4" = c(
      k24,
      d24,
      "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"
    ),
    "4.5" = c(
      k32,
      d24,
      "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"
    ),
    "4.6" = c(
      k32,
      d32,
      "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    )
  )
}

# Encrypt with a fixed CEK and IV, as the RFC vectors do (design §8.6).
encrypt_fixed <- function(
  plaintext,
  key,
  alg = NULL,
  enc = "A128CBC-HS256",
  ...,
  cek = as.raw(seq_len(cek_bytes(enc))),
  iv = as.raw(seq_len(iv_bytes(enc))),
  format = "compact",
  fixed = list()
) {
  args <- list(...)
  encrypt_jwe(
    plaintext,
    key,
    alg,
    enc,
    header = args$header,
    unprotected = args$unprotected,
    aad = args$aad,
    format = format,
    cek = cek,
    iv = iv,
    call = NULL,
    fixed = fixed
  )
}

# An RFC 7520 plaintext or password (Figures 72, 95, 96), as UTF-8 text.
rfc7520_text <- function(figure) {
  path <- test_path("fixtures", "rfc7520", sprintf("text-%03d.txt", figure))
  x <- readChar(path, file.size(path), useBytes = TRUE)
  Encoding(x) <- "UTF-8"
  x
}

# An RFC 7520 generated factor (a CEK, IV, salt or encrypted key), decoded.
rfc7520_factor <- function(figure) {
  f <- utils::read.delim(
    test_path("fixtures", "rfc7520", "FACTORS.tsv"),
    comment.char = "#",
    stringsAsFactors = FALSE
  )
  b64url_decode(f$value[f$figure == figure], "factor")
}

# A compact PBES2 JWE header with the given `p2c` and `p2s`, and placeholder
# parts: enough to reach the PBES2 header checks, never to decrypt.
pbes2_token <- function(
  p2c = 1000,
  p2s = b64url_encode(as.raw(1:16)),
  alg = "PBES2-HS256+A128KW"
) {
  header <- list(alg = alg, enc = "A128GCM", p2c = p2c, p2s = p2s)
  header <- Filter(Negate(is.null), header)
  paste(
    b64_json(header),
    "AAAA",
    "AAAAAAAAAAAAAAAA",
    "AAAA",
    "AAAAAAAAAAAAAAAAAAAAAA",
    sep = "."
  )
}

# RFC 7515 A.3 (ES256) and A.4 (ES512): keys and compact tokens. The
# signatures are randomized, so these verify; they do not reproduce.
rfc7515_a3 <- function() {
  list(
    key = paste0(
      '{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPH',
      'vRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQ',
      'mL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}'
    ),
    token = paste0(
      "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog",
      "Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqO",
      "yKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
    )
  )
}

rfc7515_a4 <- function() {
  list(
    key = paste0(
      '{"kty":"EC","crv":"P-521","x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06w',
      'TjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk","y":"ADSmRA43Z1DSN',
      'x_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3',
      'kyMj2","d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxe',
      'rEzgdRhajnu0ferB0d53vM9mE15j2C"}'
    ),
    token = paste0(
      "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_Ux",
      "Mi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YB",
      "JZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
    )
  )
}

# RFC 7518 Appendix C: Alice's ephemeral key, Bob's key, the ECDH output Z
# and the Concat KDF's derived key, for ECDH-ES with A128GCM.
rfc7518_c <- function() {
  list(
    alice = paste0(
      '{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHK',
      'W5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps","d":"0_NxaRPU',
      'MQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}'
    ),
    bob = paste0(
      '{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF',
      '_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDX',
      'XK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}'
    ),
    z = as.raw(c(
      158,
      86,
      217,
      29,
      129,
      113,
      53,
      211,
      114,
      131,
      66,
      131,
      191,
      132,
      38,
      156,
      251,
      49,
      110,
      163,
      218,
      128,
      106,
      72,
      246,
      218,
      167,
      121,
      140,
      254,
      144,
      196
    )),
    derived = "VqqN6vgjbSBcIijNcacQGg"
  )
}

# RFC 8037 A.6: ECDH-ES with X25519. Bob's private key is RFC 7748's b.
rfc8037_a6 <- function() {
  list(
    bob = paste0(
      '{"kty":"OKP","crv":"X25519","kid":"Bob","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ',
      '8hbeGdNrfx-FG-IK08","d":"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os"}'
    ),
    ephemeral = '{"kty":"OKP","crv":"X25519","d":"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}',
    z = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
  )
}

# A compact ECDH-ES JWE header with the given `epk`, and placeholder parts:
# enough to reach the ephemeral key checks, never to decrypt.
ecdh_token <- function(epk, alg = "ECDH-ES") {
  header <- list(alg = alg, enc = "A128GCM", epk = epk)
  paste(
    b64_json(header),
    "",
    "AAAAAAAAAAAAAAAA",
    "AAAA",
    "AAAAAAAAAAAAAAAAAAAAAA",
    sep = "."
  )
}

# JWEs whose protected header is not canonical JSON, made by jwcrypto
# (tools/make-jwe-noncanonical.py): the AAD guard of #35.
noncanonical_jwe <- function() {
  utils::read.delim(
    test_path("fixtures", "oracle", "jwe-noncanonical.tsv"),
    colClasses = "character",
    quote = ""
  )
}

# A straddle of `limits[[name]]` around `n` (design §9): `run(limits)` is
# refused with `class` at `n - 1` and passes at `n` and `n + 1`. With
# `no_decoding`, the refusal must come before any part is decoded.
expect_limit_straddle <- function(
  run,
  name,
  n,
  class = "zujose_parse_error",
  no_decoding = FALSE,
  info = NULL
) {
  at <- function(value) {
    run(do.call(jose_limits, stats::setNames(list(value), name)))
  }
  refuse <- function() {
    if (no_decoding) {
      local_no_decoding()
    }
    expect_error(at(n - 1), class = class, info = info)
  }
  refuse()
  for (value in c(n, n + 1)) {
    problem <- tryCatch(
      {
        at(value)
        NULL
      },
      error = function(e) conditionMessage(e)
    )
    expect(
      is.null(problem),
      sprintf("`%s = %s` refused (%s): %s", name, value, info, problem)
    )
  }
  invisible()
}

# The decoded length of each protected header in a token.
protected_bytes <- function(token) {
  if (startsWith(token, "{")) {
    obj <- zujson::json_parse(token, simplify = "none")
    entries <- obj$signatures %||% list(obj)
    vapply(entries, function(e) length(b64url_decode(e$protected, "h")), 1L)
  } else {
    length(b64url_decode(strsplit(token, ".", fixed = TRUE)[[1]][[1]], "h"))
  }
}

# A mocked PBKDF2 that signals, with class `pbes2_reached`, that a token
# passed every PBES2 check and reached key derivation.
local_pbes2_reached <- function(env = parent.frame()) {
  local_mocked_bindings(
    pbes2_kek = function(...) {
      stop(structure(
        class = c("pbes2_reached", "error", "condition"),
        list(message = "PBES2 key derivation reached", call = NULL)
      ))
    },
    .env = env
  )
}

# JSON text nested `depth` levels deep: an object holding arrays.
nested_json <- function(depth) {
  paste0('{"a":', strrep("[", depth - 1), strrep("]", depth - 1), "}")
}

# A value of RFC 7517 Appendix C or RFC 7516 A.1, as
# tools/rfc7516-7517-fixtures.R extracted it: Base64url text for octets, or
# the text of a header or token. `rfc` is 7516 or 7517.
rfc_value <- function(rfc, name) {
  v <- utils::read.delim(
    test_path("fixtures", paste0("rfc", rfc), "VALUES.tsv"),
    colClasses = "character",
    quote = ""
  )
  stopifnot(sum(v$name == name) == 1L)
  v$value[v$name == name]
}

# rfc_value(), decoded from Base64url.
rfc_octets <- function(rfc, name) b64url_decode(rfc_value(rfc, name), name)

# JWEs jwcrypto made with fixed keys and ephemeral keys
# (tools/make-jwe-vectors.py): known answers for A192*, A*GCM and the
# Concat KDF's second round.
oracle_jwe_vectors <- function() {
  utils::read.delim(
    test_path("fixtures", "oracle", "jwe-vectors.tsv"),
    colClasses = "character",
    quote = ""
  )
}

# JWE JSON serializations jwcrypto made (tools/make-jwe-json.py): flattened
# and general, one and three recipients, with and without `aad`.
oracle_jwe_json <- function() {
  utils::read.delim(
    test_path("fixtures", "oracle", "jwe-json.tsv"),
    colClasses = "character",
    quote = ""
  )
}
