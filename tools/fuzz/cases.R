# Run zujose on the fuzz cases that tools/fuzz/gen.py writes (#96).
# Sourced by replay.R, which compares the verdicts with the references',
# and by reach.R, which measures what the cases reach in R/ (#97).
# The calls are unqualified so that they reach zujose's functions both
# after pkgload::load_all() and inside covr::file_coverage().

# A cases.tsv and the keys.tsv beside it.
read_cases <- function(path) {
  read <- function(file) {
    utils::read.delim(
      file,
      colClasses = "character",
      quote = "",
      na.strings = character(),
      encoding = "UTF-8"
    )
  }
  cases <- read(path)
  keys <- read(file.path(dirname(path), "keys.tsv"))
  cases$source <- rep(path, nrow(cases))
  attr(cases, "keys") <- stats::setNames(keys$jwk, keys$name)
  cases
}

case_key <- function(text) {
  if (startsWith(text, '{"keys"')) as_jwk_set(text) else as_jwk(text)
}

split_list <- function(x) {
  if (nzchar(x)) strsplit(x, ",", fixed = TRUE)[[1]] else character()
}

# zujose on one case, under the key and algorithms the references had:
# `accept` with the payload or plaintext as Base64url, `reject` for a
# zujose_error, and `error` for any other condition, which is always a
# finding.
run_case <- function(case, keys) {
  # zuutf directly, so that the case reads the same whatever zujose's
  # own decoder does.
  token <- rawToChar(zuutf::base64_decode(case$token, url = TRUE))
  Encoding(token) <- "UTF-8"
  key <- case_key(keys[[case$key]])
  algs <- split_list(case$algs)
  out <- tryCatch(
    {
      value <- switch(
        case$kind,
        jws = jws_verify(token, key, algs, require = "any")$payload,
        jwt = {
          jwt_decode(
            token,
            key,
            algs,
            audience = "api",
            type = NULL,
            required = character(),
            leeway = 0
          )
          raw()
        },
        jwe = jwe_decrypt(token, key, algs, split_list(case$encs))$plaintext
      )
      list(verdict = "accept", payload = b64url_encode(value), class = "")
    },
    zujose_error = function(e) {
      list(verdict = "reject", payload = "", class = class(e)[[1]])
    },
    error = function(e) {
      list(
        verdict = "error",
        payload = "",
        class = paste(
          class(e)[[1]],
          gsub("[\t\n]", " ", conditionMessage(e))
        )
      )
    }
  )
  out
}

run_cases <- function(cases) {
  keys <- attr(cases, "keys")
  results <- lapply(seq_len(nrow(cases)), function(i) {
    run_case(cases[i, ], keys)
  })
  cases$zujose <- vapply(results, `[[`, "", "verdict")
  cases$zujose_payload <- vapply(results, `[[`, "", "payload")
  cases$zujose_class <- vapply(results, `[[`, "", "class")
  cases
}
