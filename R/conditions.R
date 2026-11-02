#' Conditions raised by zujwt
#'
#' Every error zujwt raises inherits from `zujwt_error`, then `error` and
#' `condition`, so a caller can catch all of them, or one kind, with
#' [tryCatch()]. Match on the class, never on the message.
#'
#' | Class | Fields | Raised when |
#' |---|---|---|
#' | `zujwt_parse_error` | | a token, header or key is not well formed, or is over a limit |
#' | `zujwt_policy_error` | | an algorithm is not allowed, a `crit` header is not understood, or a key does not fit the algorithm |
#' | `zujwt_key_error` | | a key is missing, malformed or too weak |
#' | `zujwt_signature_error` | | a signature or MAC does not verify |
#' | `zujwt_decrypt_error` | | decryption fails, for any reason, after the header has passed the policy checks |
#' | `zujwt_claim_error` | `claim` | a JWT claim is missing or does not match what the caller expects |
#' | `zujwt_expired_error` | `claim`, `time`, `now` | the token has expired, or is older than `max_age` |
#' | `zujwt_not_yet_valid_error` | `claim`, `time`, `now` | the token is not valid yet, or was issued in the future |
#' | `zujwt_audience_error` | `claim` | the token is not for this audience |
#' | `zujwt_issuer_error` | `claim` | the token is not from this issuer |
#' | `zujwt_subject_error` | `claim` | the token is not about this subject |
#' | `zujwt_missing_claim_error` | `claim` | a required claim is absent |
#' | `zujwt_unsupported_error` | `algorithm`, `needs` | an algorithm needs a newer `zucrypt` than the one installed |
#'
#' The last six inherit from `zujwt_claim_error`, so a caller can catch every
#' claim failure at once or one cause.
#'
#' Every decryption failure raises the same class with the same message, so
#' that the error cannot tell an attacker which step failed (RFC 7516
#' section 11.5). Messages never contain key material, decrypted bytes or
#' token text.
#'
#' @name zujwt_error
NULL

zujwt_kinds <- c("parse", "policy", "key", "signature", "decrypt", "claim")

zujwt_condition <- function(class, message, ..., call = NULL) {
  structure(
    class = c(class, "zujwt_error", "error", "condition"),
    list(message = message, call = call, ...)
  )
}

abort_zujwt <- function(kind, message, ..., call = NULL) {
  if (!is.character(kind) || length(kind) != 1L || !kind %in% zujwt_kinds) {
    stop("`kind` must be one of the zujwt condition kinds.", call. = FALSE)
  }
  stop(zujwt_condition(
    paste0("zujwt_", kind, "_error"),
    message,
    ...,
    call = call
  ))
}

abort_decrypt <- function(call = NULL) {
  stop(zujwt_condition(
    "zujwt_decrypt_error",
    "Decryption failed.",
    call = call
  ))
}

abort_unsupported <- function(algorithm, needs, call = NULL) {
  stop(zujwt_condition(
    "zujwt_unsupported_error",
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
  stop(zujwt_condition(
    c(
      if (!is.null(leaf)) paste0("zujwt_", leaf, "_error"),
      "zujwt_claim_error"
    ),
    message,
    claim = claim,
    ...,
    call = call
  ))
}
