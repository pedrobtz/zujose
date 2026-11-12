# Key fixtures shared by the test files.

# The JWK text of an RFC 7520 key figure (see KEYS.tsv).
rfc7520_key <- function(figure) {
  path <- test_path("fixtures", "rfc7520", sprintf("key-%03d.json", figure))
  readChar(path, file.size(path), useBytes = TRUE)
}

# RFC 7638 §3.1: an RSA public key and its SHA-256 thumbprint.
rfc7638_jwk <- function() {
  paste0(
    '{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4',
    "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_",
    "2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMic",
    "AtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhA",
    "I4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awa",
    'pJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}'
  )
}
rfc7638_thumbprint <- function() "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

# A JWK Set holding every RFC 7520 key.
rfc7520_jwks <- function() {
  figures <- c(1:6, 84, 120, 138, 151)
  paste0(
    '{"keys":[',
    paste(vapply(figures, rfc7520_key, ""), collapse = ","),
    "]}"
  )
}

# Keys and JWTs written by PyJWT and `cryptography`
# (tools/make-oracle-fixtures.py): the oracle for JWS and JWT.
oracle_pem <- function(name, public = FALSE) {
  path <- test_path(
    "fixtures",
    "oracle",
    paste0(name, if (public) ".pub.pem" else ".pem")
  )
  readChar(path, file.size(path), useBytes = TRUE)
}

oracle_tokens <- function() {
  utils::read.delim(
    test_path("fixtures", "oracle", "tokens.tsv"),
    colClasses = "character",
    quote = ""
  )
}

oracle_key <- function(name, public = TRUE) {
  switch(
    name,
    hmac = jwk_oct(as.raw(1:64)),
    "hmac-wrong" = jwk_oct(as.raw(64:1)),
    as_jwk(oracle_pem(name, public = public))
  )
}

# Tokens zujose signed, which PyJWT verifies (tools/make-zujose-tokens.R,
# #100): a JWT and a JWS per algorithm.
oracle_zujose_tokens <- function() {
  utils::read.delim(
    test_path("fixtures", "oracle", "zujose-tokens.tsv"),
    colClasses = "character",
    quote = "",
    encoding = "UTF-8"
  )
}

# Before the oracle tokens' `exp`, 2000000000.
oracle_now <- function() as.POSIXct(1e9, origin = "1970-01-01", tz = "UTC")

# A 2040-bit RSA public key, the largest importable size under RFC 7518's
# 2048-bit floor: zucrypt takes only whole bytes, so a 2047-bit modulus
# cannot be a jwk. The modulus was generated once with Python's
# `cryptography`; only the public half exists.
rsa_2040_jwk <- function() {
  n <- paste0(
    "vReHW_omQGM2gsJuN1G93OC17YEbxgkP0U9BM9LR3RAT7uadnG5UxrMV7R7K8FTM",
    "hzKmAeWlKbVr9Z-Wm3a8x452k0f7kDRYF3pP28phsBAhKlho_Kb01ipEvCqigtFb",
    "CquWetfaIRMMrDKEH5NbUf2il32I7_40UymgfuIlASuJMFKbaUMLINBrVZ4m6Njn",
    "jofvfgLXgRc6arqqONPHY9YlZEce36mudQH0P4lEraCBOkAPEGUp2Fl-_GpHbHGn",
    "kgOgxDmawnNoVR6XrZ4SpaoOyQjcj3hjqKpsMyROl3UgPcrxPzJo0lJDJRVT8m2e",
    "l10tni9gogpuln2Y9__x"
  )
  as_jwk(sprintf('{"kty":"RSA","n":"%s","e":"AQAB"}', n))
}

# RFC 7638 thumbprints jwcrypto computed (tools/make-jwk-thumbprints.py):
# one row per key and hash, with the key as jwcrypto wrote it.
oracle_thumbprints <- function() {
  utils::read.delim(
    test_path("fixtures", "oracle", "thumbprints.tsv"),
    colClasses = "character",
    quote = ""
  )
}

# An RFC 7517 Appendix A example JWK Set ("a1", "a2" or "a3"), as text
# (tools/rfc7516-7517-fixtures.R).
rfc7517_jwks <- function(appendix) {
  path <- test_path("fixtures", "rfc7517", sprintf("jwks-%s.json", appendix))
  readChar(path, file.size(path), useBytes = TRUE)
}

# Every member of each key in the JWK Set `json` is in the matching key of
# `set`, with the same value, and `set` holds no other member.
expect_set_members <- function(set, json) {
  entries <- zujson::json_parse(json)$keys
  expect_length(set, length(entries))
  for (i in seq_along(entries)) {
    entry <- entries[[i]]
    key <- set[[i]]
    for (name in c("kty", "kid", "use", "alg")) {
      expect_identical(key[[name]], entry[[name]], info = paste(i, name))
    }
    rest <- entry[setdiff(names(entry), c("kty", "kid", "use", "alg"))]
    if (entry$kty == "oct") {
      expect_identical(b64url_encode(key$k), rest$k, info = i)
      expect_identical(names(rest), "k", info = i)
    } else {
      expect_identical(
        key$members[sort(names(key$members))],
        rest[sort(names(rest))],
        info = i
      )
    }
  }
}
