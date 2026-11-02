# JWS: signing and verification (design §7.3, §8.2, §8.4).

#' Sign a payload as a JWS
#'
#' `jose_sign()` signs `payload` with one key, or with several through
#' [jose_signer()], and returns the JWS in the compact, flattened JSON or
#' general JSON serialization (RFC 7515).
#'
#' The protected header holds `alg`, the key's `kid` unless `header` or
#' `unprotected` sets one, and the members of `header`. With
#' `b64 = FALSE`, the payload is signed and carried unencoded (RFC 7797),
#' and the header gains `b64: false` and `crit: ["b64"]`.
#'
#' @param payload The payload: a raw vector, or a single string taken as
#'   UTF-8 text.
#' @param key A `jose_key`, or a list of [jose_signer()] objects for several
#'   signatures.
#' @param alg The signature algorithm, such as `"HS256"`. `NULL` takes the
#'   key's own `alg`.
#' @param header Further protected header members, as a named list.
#' @param unprotected Unprotected header members, as a named list. Only the
#'   JSON serializations carry them.
#' @param format `"compact"`, `"flattened"` or `"general"`. Several
#'   signatures need `"general"`.
#' @param b64 Whether the payload is Base64url-encoded in the signing input
#'   and the token. `FALSE` follows RFC 7797.
#' @param detached Whether to leave the payload out of the token. The
#'   verifier then supplies it to [jose_verify()].
#' @returns The JWS, as a single string.
#' @export
#' @examples
#' key <- jose_key_oct(as.raw(1:32), kid = "k1")
#' token <- jose_sign("hello", key, alg = "HS256")
#' token
#' rawToChar(jose_verify(token, key, algorithms = "HS256")$payload)
jose_sign <- function(
  payload,
  key,
  alg = NULL,
  header = NULL,
  unprotected = NULL,
  format = c("compact", "flattened", "general"),
  b64 = TRUE,
  detached = FALSE
) {
  call <- sys.call()
  format <- match.arg(format)
  bytes <- as_payload_bytes(payload, call)
  check_flag(b64, "b64", call)
  check_flag(detached, "detached", call)

  signers <- if (inherits(key, "jose_key")) {
    list(jose_signer(key, alg, header, unprotected))
  } else if (
    is.list(key) &&
      length(key) > 0L &&
      all(vapply(key, inherits, logical(1), "jose_signer"))
  ) {
    if (!is.null(alg) || !is.null(header) || !is.null(unprotected)) {
      stop(
        "With several signers, give `alg` and headers to each jose_signer().",
        call. = FALSE
      )
    }
    key
  } else {
    abort_zujwt(
      "key",
      "`key` must be a jose_key or a list of jose_signer() objects.",
      call = call
    )
  }
  if (length(signers) > 1L && format != "general") {
    stop("Several signatures need `format = \"general\"`.", call. = FALSE)
  }
  if (
    format == "compact" &&
      any(vapply(signers, function(s) length(s$unprotected) > 0L, logical(1)))
  ) {
    stop(
      "The compact serialization has no unprotected header.",
      call. = FALSE
    )
  }

  payload_text <- if (b64) {
    b64url_encode(bytes)
  } else {
    if (!isTRUE(zuutf::utf_valid(bytes))) {
      stop("An unencoded payload must be valid UTF-8.", call. = FALSE)
    }
    text <- rawToChar(bytes)
    Encoding(text) <- "UTF-8"
    text
  }
  if (
    !b64 &&
      format == "compact" &&
      !detached &&
      grepl(".", payload_text, fixed = TRUE)
  ) {
    stop(
      "An unencoded payload containing \".\" must be detached in the compact serialization.",
      call. = FALSE
    )
  }
  signed_payload <- if (b64) charToRaw(payload_text) else bytes

  signatures <- lapply(signers, function(signer) {
    protected <- protected_header(signer, b64, call)
    check_headers(protected, list(signer$unprotected), "JWS", call)
    protected_b64 <- b64url_encode(charToRaw(enc2utf8(
      zujson::json_write(protected)
    )))
    input <- c(charToRaw(protected_b64), charToRaw("."), signed_payload)
    list(
      protected = protected_b64,
      header = signer$unprotected,
      signature = b64url_encode(
        jws_sign(protected$alg, signer$key, input, call)
      )
    )
  })

  if (format == "compact") {
    s <- signatures[[1]]
    return(paste(
      s$protected,
      if (detached) "" else payload_text,
      s$signature,
      sep = "."
    ))
  }
  entries <- lapply(signatures, function(s) {
    Filter(
      length,
      list(
        protected = s$protected,
        header = if (length(s$header)) s$header,
        signature = s$signature
      )
    )
  })
  out <- if (format == "flattened") entries[[1]] else list(signatures = entries)
  if (!detached) {
    out <- c(list(payload = payload_text), out)
  }
  zujson::json_write(out)
}

#' One signer of a multi-signature JWS
#'
#' `jose_signer()` pairs a key with its algorithm and headers, for
#' [jose_sign()] to produce a general JSON serialization with several
#' signatures.
#'
#' @inheritParams jose_sign
#' @param key A `jose_key`.
#' @returns A `jose_signer`.
#' @export
#' @examples
#' k1 <- jose_key_oct(as.raw(1:32), kid = "a")
#' k2 <- jose_key_oct(as.raw(33:96), kid = "b")
#' jose_sign(
#'   "hello",
#'   list(jose_signer(k1, "HS256"), jose_signer(k2, "HS512")),
#'   format = "general"
#' )
jose_signer <- function(key, alg = NULL, header = NULL, unprotected = NULL) {
  call <- sys.call()
  key <- check_key(key, call)
  if (!is.null(alg) && !is_string(alg)) {
    stop("`alg` must be a single string.", call. = FALSE)
  }
  structure(
    list(
      key = key,
      alg = alg,
      header = check_header_arg(header, "header"),
      unprotected = check_header_arg(unprotected, "unprotected")
    ),
    class = "jose_signer"
  )
}

protected_header <- function(signer, b64, call) {
  alg <- signer$alg %||% signer$key$alg
  if (is.null(alg)) {
    abort_zujwt(
      "policy",
      "Give `alg`, or a key whose own `alg` is set.",
      call = call
    )
  }
  check_algorithms(alg, "signature", "alg", call)
  check_available(alg, call)
  if (!key_fits(signer$key, alg, "sign")) {
    abort_zujwt(
      "policy",
      "The key does not fit the algorithm or its intended use.",
      call = call
    )
  }
  header <- signer$header
  if ("alg" %in% names(header) && !identical(header$alg, alg)) {
    stop("`header$alg` disagrees with `alg`.", call. = FALSE)
  }
  header <- header[setdiff(names(header), "alg")]
  kid <- if (
    !is.null(signer$key$kid) &&
      !"kid" %in% c(names(header), names(signer$unprotected))
  ) {
    list(kid = signer$key$kid)
  }
  c(
    list(alg = alg),
    kid,
    header,
    if (!b64) list(b64 = FALSE, crit = list("b64"))
  )
}

#' Verify a JWS
#'
#' `jose_verify()` checks a JWS in any serialization and returns its
#' payload. The caller names the algorithms it accepts: a token whose `alg`
#' is not in `algorithms` is refused before any key is used, and the key
#' must fit the algorithm (RFC 8725). There is no default and no way to
#' accept `"none"`.
#'
#' `key` may be a single key, a key set, from which the token's `kid`
#' selects, or a function that receives the token's header (a named list)
#' and returns either. Keys or URLs inside the token (`jwk`, `jku`, `x5c`,
#' `x5u`) are never used.
#'
#' @param token The JWS: a compact serialization, or JSON text.
#' @param key A `jose_key`, a `jose_keyset`, or a function of the header
#'   returning one.
#' @param algorithms The signature algorithms to accept, such as `"HS256"`.
#' @param payload For a detached payload (RFC 7515 Appendix F), the payload:
#'   a raw vector or a single string.
#' @param require With several signatures, whether `"all"` must verify (the
#'   default) or `"any"` one is enough. With `"any"`, signatures whose
#'   algorithm is not in `algorithms` are skipped.
#' @param limits Resource limits, from [jose_limits()].
#' @returns A list of class `jose_verified` with `payload` (raw), `header`
#'   (the protected and unprotected header of the first verified signature),
#'   `protected` (its protected part), `kid` and `alg` (of the key and
#'   algorithm that verified it), and `signatures`, one such entry per
#'   verified signature.
#' @export
#' @examples
#' key <- jose_key_oct(as.raw(1:32), kid = "k1")
#' token <- jose_sign("hello", key, alg = "HS256")
#' jose_verify(token, key, algorithms = "HS256")
#'
#' # The token's algorithm must be one you allow.
#' try(jose_verify(token, key, algorithms = "HS512"))
jose_verify <- function(
  token,
  key,
  algorithms,
  payload = NULL,
  require = c("all", "any"),
  limits = jose_limits()
) {
  call <- sys.call()
  check_algorithms(algorithms, "signature", call = call)
  require <- match.arg(require)
  verify_jws(token, key, algorithms, payload, require, limits, call)
}

# The body of jose_verify(), shared with jose_jwt_decode() so that errors
# name the function the caller called.
verify_jws <- function(token, key, algorithms, payload, require, limits, call) {
  obj <- jose_parse(token, limits, call)
  if (obj$type != "JWS") {
    abort_zujwt("policy", "Expected a JWS, not a JWE.", call = call)
  }

  carried <- !is.null(obj$payload_b64) && nzchar(obj$payload_b64)
  if (!is.null(payload)) {
    if (carried) {
      abort_zujwt(
        "policy",
        "The token carries its payload; `payload` is for a detached one.",
        call = call
      )
    }
    bytes <- as_payload_bytes(payload, call)
    if (length(bytes) > limits$payload) {
      abort_payload_limit(call)
    }
    signed_payload <- if (obj$b64) charToRaw(b64url_encode(bytes)) else bytes
  } else {
    bytes <- obj$payload %||% raw()
    signed_payload <- if (obj$b64) {
      charToRaw(obj$payload_b64 %||% "")
    } else {
      bytes
    }
  }

  verified <- list()
  first_error <- NULL
  for (s in obj$signatures) {
    header <- c(s$protected, s$header)
    attempt <- function() {
      verify_signature(s, header, key, algorithms, signed_payload, limits, call)
    }
    result <- if (require == "all") {
      attempt()
    } else {
      tryCatch(attempt(), zujwt_error = function(e) {
        first_error <<- first_error %||% e
        NULL
      })
    }
    if (!is.null(result)) {
      verified[[length(verified) + 1L]] <- result
    }
  }
  if (length(verified) == 0L) {
    # With require = "any", report why the first signature failed.
    stop(first_error)
  }

  first <- verified[[1]]
  structure(
    list(
      payload = bytes,
      header = first$header,
      protected = first$protected,
      kid = first$kid,
      alg = first$alg,
      signatures = verified
    ),
    class = "jose_verified"
  )
}

verify_signature <- function(
  s,
  header,
  key,
  algorithms,
  signed_payload,
  limits,
  call
) {
  alg <- header[["alg"]]
  if (!alg %in% algorithms) {
    abort_zujwt(
      "policy",
      "The token's algorithm is not in `algorithms`.",
      call = call
    )
  }
  check_available(alg, call)
  keys <- resolve_keys(key, header, "verify", limits, call)
  input <- c(charToRaw(s$protected_b64), charToRaw("."), signed_payload)
  for (k in keys) {
    if (jws_verify(alg, k, input, s$signature, call)) {
      return(list(
        header = header,
        protected = s$protected,
        kid = k$kid,
        alg = alg
      ))
    }
  }
  abort_zujwt("signature", "The signature does not verify.", call = call)
}

# Algorithms --------------------------------------------------------------

hmac_hash <- c(HS256 = "sha256", HS384 = "sha384", HS512 = "sha512")
hmac_min_bytes <- c(HS256 = 32L, HS384 = 48L, HS512 = 64L)

jws_sign <- function(alg, key, input, call) {
  if (alg %in% names(hmac_hash)) {
    check_hmac_key(key, alg, call)
    return(zucrypt::crypt_hmac(input, key$k, hmac_hash[[alg]]))
  }
  check_available(alg, call)
}

jws_verify <- function(alg, key, input, signature, call) {
  if (alg %in% names(hmac_hash)) {
    check_hmac_key(key, alg, call)
    expected <- zucrypt::crypt_hmac(input, key$k, hmac_hash[[alg]])
    return(
      length(signature) == length(expected) &&
        zucrypt::crypt_equal(signature, expected)
    )
  }
  check_available(alg, call)
}

# RFC 7518 §3.2: an HMAC key at least as long as the hash output.
check_hmac_key <- function(key, alg, call) {
  if (length(key$k) < hmac_min_bytes[[alg]]) {
    abort_zujwt(
      "key",
      sprintf(
        "An %s key must be at least %d bytes (RFC 7518 section 3.2).",
        alg,
        hmac_min_bytes[[alg]]
      ),
      call = call
    )
  }
}

# Helpers -----------------------------------------------------------------

as_payload_bytes <- function(x, call) {
  if (is.raw(x)) {
    return(x)
  }
  if (is_string(x)) {
    return(charToRaw(enc2utf8(x)))
  }
  stop("`payload` must be a raw vector or a single string.", call. = FALSE)
}

check_flag <- function(x, name, call) {
  if (!isTRUE(x) && !isFALSE(x)) {
    stop(sprintf("`%s` must be TRUE or FALSE.", name), call. = FALSE)
  }
}

check_header_arg <- function(x, name) {
  if (is.null(x)) {
    return(empty_object())
  }
  if (
    !is.list(x) ||
      (length(x) > 0L && (is.null(names(x)) || any(!nzchar(names(x)))))
  ) {
    stop(sprintf("`%s` must be a named list.", name), call. = FALSE)
  }
  if (length(x) == 0L) empty_object() else x
}

#' @export
print.jose_verified <- function(x, ...) {
  cat(sprintf(
    "<jose_verified> %s%s\n",
    x$alg,
    if (!is.null(x$kid)) {
      paste0(", key ", encodeString(x$kid, quote = '"'))
    } else {
      ""
    }
  ))
  cat("Header:\n")
  print_members(x$header)
  cat(sprintf("Payload: %d bytes\n", length(x$payload)))
  invisible(x)
}
