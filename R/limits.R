#' Resource limits for untrusted tokens
#'
#' Every function that reads a token checks it against these limits before
#' decoding anything, so a hostile token cannot make zujose allocate or
#' compute much more than an honest one would. The defaults are far above
#' what real tokens need.
#'
#' A token over a limit fails with `zujose_parse_error`, except for `keys`:
#' more fitting keys than `keys` is a property of the key set as much as of
#' the token, and fails with `zujose_key_error`. Give the keys a `kid`, or
#' narrow the set. Use `Inf` to switch a limit off.
#'
#' @param token Maximum length of a token, in bytes. This bounds the encoded
#'   form, which is about 4/3 of the payload, so the default of 2 MiB leaves
#'   room for a payload at the `payload` limit. Encoding functions do not
#'   check these limits.
#' @param header Maximum length of a decoded protected header, in bytes.
#' @param payload Maximum length of a payload or ciphertext, in bytes. This
#'   applies to detached and unencoded (`b64: false`) payloads too.
#' @param signatures Maximum number of signatures in a JWS JSON
#'   serialization.
#' @param recipients Maximum number of recipients in a JWE JSON
#'   serialization.
#' @param keys Maximum number of keys tried for one token.
#' @param p2c Maximum PBES2 iteration count a token may ask for.
#' @returns A list of class `jose_limits`.
#' @export
#' @examples
#' jose_limits()
#' jose_limits(token = 8192, signatures = 1)
jose_limits <- function(
  token = 2^21,
  header = 2^14,
  payload = 2^20,
  signatures = 16,
  recipients = 16,
  keys = 16,
  p2c = 600000
) {
  limits <- list(
    token = token,
    header = header,
    payload = payload,
    signatures = signatures,
    recipients = recipients,
    keys = keys,
    p2c = p2c
  )
  for (name in names(limits)) {
    value <- limits[[name]]
    ok <- is.numeric(value) &&
      length(value) == 1L &&
      !is.na(value) &&
      value >= 1 &&
      (is.infinite(value) || value == trunc(value))
    if (!ok) {
      abort_zujose(
        "argument",
        sprintf("`%s` must be a whole number of at least 1, or Inf.", name)
      )
    }
  }
  structure(limits, class = "jose_limits")
}

#' @export
print.jose_limits <- function(x, ...) {
  cat("<jose_limits>\n")
  values <- vapply(
    unclass(x),
    function(v) {
      format(v, big.mark = ",", decimal.mark = ".", scientific = FALSE)
    },
    ""
  )
  cat(sprintf("  %-10s %s\n", names(values), values), sep = "")
  invisible(x)
}

check_limits <- function(limits, call = NULL) {
  if (!inherits(limits, "jose_limits")) {
    abort_zujose(
      "argument",
      "`limits` must be made by jose_limits().",
      call = call
    )
  }
}
