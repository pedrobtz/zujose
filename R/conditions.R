#' Conditions raised by zujose
#'
#' Every error zujose raises inherits from `zujose_error`, then `error` and
#' `condition`, so a caller can catch all of them, or one kind, with
#' [tryCatch()]. Match on the class, never on the message.
#'
#' One rule divides the classes: a mistake in the caller's own code is a
#' `zujose_argument_error`, and anything wrong with what came off the wire
#' is a token error, from `zujose_parse_error` on. So a key, header or
#' claims argument of the wrong type is an argument error, while a malformed
#' token is a parse error whatever its source. A `token` that is not one
#' string, such as `NULL` from a missing HTTP header, is a token error too:
#' callers handle it like any malformed token. Every argument is checked
#' before the token is read, and an argument error names the function the
#' caller called.
#'
#' | Class | Fields | Raised when |
#' |---|---|---|
#' | `zujose_argument_error` | | an argument is of the wrong type, out of range, or inconsistent with another, such as `format = "compact"` with several recipients, a `key` that is not a `jwk`, or a `header` member of the wrong type |
#' | `zujose_parse_error` | | a token, header or key is not well formed, or is not one string, or is over a limit other than `keys` |
#' | `zujose_policy_error` | | an algorithm is not allowed, a `crit` header is not understood, or a key does not fit the algorithm |
#' | `zujose_key_error` | | a key is missing, malformed or too weak, or more keys fit a token than `jose_limits(keys = )` allows; a key that does not fit the token is a `zujose_policy_error` |
#' | `zujose_signature_error` | | a signature or MAC does not verify |
#' | `zujose_decrypt_error` | | decryption fails, for any reason, after the header has passed the policy checks |
#' | `zujose_claim_error` | `claim` | a JWT claim is missing or does not match what the caller expects |
#' | `zujose_expired_error` | `claim`, `time`, `now` | the token has expired, or is older than `max_age` |
#' | `zujose_not_yet_valid_error` | `claim`, `time`, `now` | the token is not valid yet, or was issued in the future |
#' | `zujose_audience_error` | `claim` | the token is not for this audience |
#' | `zujose_issuer_error` | `claim` | the token is not from this issuer |
#' | `zujose_subject_error` | `claim` | the token is not about this subject |
#' | `zujose_missing_claim_error` | `claim` | a required claim is absent |
#' | `zujose_unsupported_error` | `algorithm`, `needs` | an algorithm needs a newer `zucrypt` than the one installed |
#'
#' The last six inherit from `zujose_claim_error`, so a caller can catch every
#' claim failure at once or one cause.
#'
#' Every decryption failure raises the same class with the same message, so
#' that the error cannot tell an attacker which step failed (RFC 7516
#' section 11.5). Messages never contain key material, decrypted bytes or
#' token text.
#'
#' @name zujose_error
#' @examples
#' key <- jwk_generate("oct", alg = "HS256")
#' jwt <- jwt_encode(list(sub = "user-1"), key, expires_in = -120)
#'
#' # Catch one kind of failure by its class.
#' tryCatch(
#'   jwt_decode(jwt, key, algorithms = "HS256"),
#'   zujose_expired_error = function(e) {
#'     paste("expired at", format(e$time, tz = "UTC"))
#'   }
#' )
NULL

zujose_kinds <- c(
  "argument",
  "parse",
  "policy",
  "key",
  "signature",
  "decrypt",
  "claim"
)

zujose_condition <- function(class, message, ..., call = NULL) {
  structure(
    class = c(class, "zujose_error", "error", "condition"),
    list(message = message, call = call, ...)
  )
}

abort_zujose <- function(kind, message, ..., call = NULL) {
  if (!is.character(kind) || length(kind) != 1L || !kind %in% zujose_kinds) {
    stop("`kind` must be one of the zujose condition kinds.", call. = FALSE)
  }
  stop(zujose_condition(
    paste0("zujose_", kind, "_error"),
    message,
    ...,
    call = call
  ))
}

abort_decrypt <- function(call = NULL) {
  stop(zujose_condition(
    "zujose_decrypt_error",
    "Decryption failed.",
    call = call
  ))
}

abort_unsupported <- function(algorithm, needs, call = NULL) {
  stop(zujose_condition(
    "zujose_unsupported_error",
    sprintf("Algorithm \"%s\" needs zucrypt (>= %s).", algorithm, needs),
    algorithm = algorithm,
    needs = needs,
    call = call
  ))
}

claim_leaves <- c(
  "expired",
  "not_yet_valid",
  "audience",
  "issuer",
  "subject",
  "missing_claim"
)

abort_claim <- function(leaf, message, claim, ..., call = NULL) {
  if (!is.null(leaf) && !leaf %in% claim_leaves) {
    stop("`leaf` must be one of the claim error kinds.", call. = FALSE)
  }
  stop(zujose_condition(
    c(
      if (!is.null(leaf)) paste0("zujose_", leaf, "_error"),
      "zujose_claim_error"
    ),
    message,
    claim = claim,
    ...,
    call = call
  ))
}
