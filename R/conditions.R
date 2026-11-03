#' Conditions raised by zujose
#'
#' Every error zujose raises inherits from `zujose_error`, then `error` and
#' `condition`, so a caller can catch all of them, or one kind, with
#' [tryCatch()]. Match on the class, never on the message.
#'
#' | Class | Fields | Raised when |
#' |---|---|---|
#' | `zujose_parse_error` | | a token, header or key is not well formed, or is over a limit |
#' | `zujose_policy_error` | | an algorithm is not allowed, a `crit` header is not understood, or a key does not fit the algorithm |
#' | `zujose_key_error` | | a key is missing, malformed or too weak |
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
NULL

zujose_kinds <- c("parse", "policy", "key", "signature", "decrypt", "claim")

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
