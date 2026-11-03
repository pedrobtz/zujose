#' Look inside a token without verifying it
#'
#' `jose_peek()` parses a JWS or JWE, in any serialization, and returns its
#' headers and, for a JWS, its payload. **Nothing is verified.** The result
#' is classed `jose_unverified` and says so when printed. Use it to decide
#' which key or policy to apply, or to debug, never to make a decision that
#' trusts the token. `jws_verify()` and `jwe_decrypt()` are the functions
#' that check a token.
#'
#' The token must still be well formed: strict unpadded Base64url, headers
#' that are JSON objects without repeated members, and the rules on `crit`
#' and `b64` (RFC 7515, RFC 7797). A malformed token raises
#' `zujose_parse_error`.
#'
#' @param token A token: a compact serialization, or the text of a JSON
#'   serialization.
#' @param limits Resource limits, from [jose_limits()].
#' @returns A list of class `jose_unverified` with:
#'   * `type`: `"JWS"` or `"JWE"`.
#'   * `serialization`: `"compact"`, `"flattened"` or `"general"`.
#'   * `headers`: one header per signature or recipient, each the union of
#'     the protected and unprotected headers.
#'   * `payload`: for a JWS, the payload as a raw vector; `NULL` for a JWE or
#'     a detached payload.
#'   * `claims`: the payload parsed as a list when it is a JSON object, as in
#'     a JWT; otherwise `NULL`.
#'
#'   A JWS also has, one element per signature:
#'   * `signatures`: each signature, as a raw vector.
#'   * `signing_input`: the bytes each signature covers, as a raw vector;
#'     `NULL` for a detached payload.
#'
#'   A JWE also has:
#'   * `encrypted_keys`: one encrypted key per recipient, as a raw vector,
#'     empty for `dir` and `ECDH-ES`.
#'   * `iv`, `ciphertext` and `tag`: raw vectors.
#'   * `aad`: the additional authenticated data as a raw vector, or `NULL`.
#' @export
#' @examples
#' token <- paste0(
#'   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
#'   "eyJzdWIiOiJ1MSIsImV4cCI6MTMwMDgxOTM4MH0.",
#'   "c2lnbmF0dXJl"
#' )
#' jose_peek(token)
jose_peek <- function(token, limits = jose_limits()) {
  obj <- jose_parse(token, limits, call = sys.call())

  if (obj$type == "JWS") {
    headers <- lapply(obj$signatures, function(s) c(s$protected, s$header))
    payload <- obj$payload
    signed_payload <- if (obj$b64) {
      if (!is.null(obj$payload_b64)) charToRaw(obj$payload_b64)
    } else {
      obj$payload
    }
    parts <- list(
      signatures = lapply(obj$signatures, `[[`, "signature"),
      signing_input = lapply(obj$signatures, function(s) {
        if (!is.null(signed_payload)) {
          c(charToRaw(s$protected_b64), charToRaw("."), signed_payload)
        }
      })
    )
  } else {
    headers <- lapply(obj$recipients, function(r) {
      c(obj$protected, obj$unprotected, r$header)
    })
    payload <- NULL
    parts <- list(
      encrypted_keys = lapply(obj$recipients, `[[`, "encrypted_key"),
      iv = obj$iv,
      ciphertext = obj$ciphertext,
      tag = obj$tag,
      aad = obj$aad
    )
  }

  structure(
    c(
      list(
        type = obj$type,
        serialization = obj$serialization,
        headers = headers,
        payload = payload,
        claims = peek_claims(payload)
      ),
      parts
    ),
    class = "jose_unverified"
  )
}

peek_claims <- function(payload) {
  if (is.null(payload) || length(payload) == 0L) {
    return(NULL)
  }
  claims <- tryCatch(
    zujson::json_parse_raw(payload, simplify = "none"),
    zujson_error = function(e) NULL
  )
  if (!is_json_object(claims) || has_repeated_names(claims)) {
    return(NULL)
  }
  claims
}

#' @export
print.jose_unverified <- function(x, ...) {
  cat(sprintf(
    "<jose_unverified> %s, %s serialization\n",
    x$type,
    x$serialization
  ))
  cat("! Not verified: nothing here can be trusted.\n")
  for (i in seq_along(x$headers)) {
    label <- if (length(x$headers) > 1L) sprintf("Header %d", i) else "Header"
    cat(label, ":\n", sep = "")
    print_members(x$headers[[i]])
  }
  if (!is.null(x$claims)) {
    cat("Claims:\n")
    print_members(x$claims)
  } else if (!is.null(x$payload)) {
    cat(sprintf("Payload: %d bytes\n", length(x$payload)))
  }
  if (x$type == "JWS") {
    print_sizes("Signature", x$signatures)
  } else {
    print_sizes("Encrypted key", x$encrypted_keys)
    print_sizes("IV", list(x$iv))
    print_sizes("Ciphertext", list(x$ciphertext))
    print_sizes("Tag", list(x$tag))
    if (!is.null(x$aad)) print_sizes("AAD", list(x$aad))
  }
  invisible(x)
}

print_sizes <- function(label, parts) {
  for (i in seq_along(parts)) {
    name <- if (length(parts) > 1L) sprintf("%s %d", label, i) else label
    cat(sprintf("%s: %d bytes\n", name, length(parts[[i]])))
  }
}

print_members <- function(x) {
  values <- vapply(
    x,
    function(v) {
      text <- zujson::json_write(v)
      if (nchar(text) > 60L) paste0(substr(text, 1L, 57L), "...") else text
    },
    ""
  )
  cat(sprintf("  %s: %s\n", names(x), values), sep = "")
}
