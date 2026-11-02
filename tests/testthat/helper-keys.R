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
