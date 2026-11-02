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

# RFC 7515 A.1: the HMAC key, also used by RFC 7797 §4.
rfc7515_key <- function() {
  as_jose_key(paste0(
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
