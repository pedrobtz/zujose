# JWS: signing and verification (design §7.3, §8.2, §8.4).

#' Sign a payload as a JWS
#'
#' `jws_sign()` signs `payload` with one key, or with several through
#' [jws_signer()], and returns the JWS in the compact, flattened JSON or
#' general JSON serialization (RFC 7515).
#'
#' The protected header holds `alg`, the key's `kid` unless `header` or
#' `unprotected` sets one, and the members of `header`. With
#' `b64 = FALSE`, the payload is signed and carried unencoded (RFC 7797),
#' and the header gains `b64: false` and `crit: ["b64"]`.
#'
#' A header's names must be unique and not empty at every depth, a member
#' may appear in only one header, and values must be of a type JSON can
#' represent. Anything else is a `zujose_argument_error`.
#'
#' The algorithms are `HS256`, `HS384` and `HS512` with an `oct` key, and
#' `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` with a private
#' RSA key of at least 2048 bits, and `ES256`, `ES384` and `ES512` with a
#' private EC key on P-256, P-384 and P-521 respectively. `RS*` signatures
#' are deterministic; `PS*` and `ES*` ones are randomized. An `ES*`
#' signature is `r` followed by `s`, each of fixed length, as RFC 7518
#' section 3.4 specifies.
#'
#' @param payload The payload: a raw vector, or a single string taken as
#'   UTF-8 text.
#' @param key A `jwk`, or a list of [jws_signer()] objects for several
#'   signatures.
#' @param alg The signature algorithm, such as `"HS256"` or `"RS256"`.
#'   `NULL` takes the key's own `alg`.
#' @param header Further protected header members, as a named list.
#' @param unprotected Unprotected header members, as a named list. Only the
#'   JSON serializations carry them.
#' @param format `"compact"`, `"flattened"` or `"general"`. Several
#'   signatures need `"general"`.
#' @param b64 Whether the payload is Base64url-encoded in the signing input
#'   and the token. `FALSE` follows RFC 7797.
#' @param detached Whether to leave the payload out of the token. The
#'   verifier then supplies it to [jws_verify()].
#' @returns The JWS, as a single string.
#' @export
#' @examples
#' key <- jwk_oct(as.raw(1:32), kid = "k1")
#' token <- jws_sign("hello", key, alg = "HS256")
#' token
#' rawToChar(jws_verify(token, key, algorithms = "HS256")$payload)
jws_sign <- function(
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
  format <- arg_choice(format, "format", call)
  sign_jws(payload, key, alg, header, unprotected, format, b64, detached, call)
}

# The body of jws_sign(), shared with jwt_encode() so that errors name the
# function the caller called.
sign_jws <- function(
  payload,
  key,
  alg,
  header,
  unprotected,
  format,
  b64,
  detached,
  call
) {
  bytes <- as_payload_bytes(payload, call)
  check_flag(b64, "b64", call)
  check_flag(detached, "detached", call)

  signers <- if (inherits(key, "jwk")) {
    list(new_signer(key, alg, header, unprotected, call))
  } else if (
    is.list(key) &&
      length(key) > 0L &&
      all(vapply(key, inherits, logical(1), "jws_signer"))
  ) {
    if (!is.null(alg) || !is.null(header) || !is.null(unprotected)) {
      abort_zujose(
        "argument",
        "With several signers, give `alg` and headers to each jws_signer().",
        call = call
      )
    }
    unname(key)
  } else {
    abort_zujose(
      "argument",
      "`key` must be a jwk or a list of jws_signer() objects.",
      call = call
    )
  }
  if (length(signers) > 1L && format != "general") {
    abort_zujose(
      "argument",
      "Several signatures need `format = \"general\"`.",
      call = call
    )
  }
  if (
    format == "compact" &&
      any(vapply(signers, function(s) length(s$unprotected) > 0L, logical(1)))
  ) {
    abort_zujose(
      "argument",
      "The compact serialization has no unprotected header.",
      call = call
    )
  }

  payload_text <- if (b64) {
    b64url_encode(bytes)
  } else {
    # An R string cannot hold a NUL byte (#123).
    if (!isTRUE(zuutf::utf_valid(bytes)) || any(bytes == as.raw(0))) {
      abort_zujose(
        "argument",
        "An unencoded payload must be valid UTF-8 without NUL bytes.",
        call = call
      )
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
    abort_zujose(
      "argument",
      "An unencoded payload containing \".\" must be detached in the compact serialization.",
      call = call
    )
  }
  signed_payload <- if (b64) charToRaw(payload_text) else bytes

  signatures <- lapply(signers, function(signer) {
    protected <- protected_header(signer, b64, call)
    check_headers(
      protected,
      list(signer$unprotected),
      "JWS",
      call,
      kind = "argument"
    )
    protected_b64 <- b64url_encode(charToRaw(enc2utf8(
      zujson::json_write(protected)
    )))
    input <- c(charToRaw(protected_b64), charToRaw("."), signed_payload)
    list(
      protected = protected_b64,
      header = signer$unprotected,
      signature = b64url_encode(
        jws_sign_bytes(protected$alg, signer$key, input, call)
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
#' `jws_signer()` pairs a key with its algorithm and headers, for
#' [jws_sign()] to produce a general JSON serialization with several
#' signatures.
#'
#' @inheritParams jws_sign
#' @param key A `jwk`.
#' @returns A `jws_signer`.
#' @export
#' @examples
#' k1 <- jwk_oct(as.raw(1:32), kid = "a")
#' k2 <- jwk_oct(as.raw(33:96), kid = "b")
#' jws_sign(
#'   "hello",
#'   list(jws_signer(k1, "HS256"), jws_signer(k2, "HS512")),
#'   format = "general"
#' )
jws_signer <- function(key, alg = NULL, header = NULL, unprotected = NULL) {
  new_signer(key, alg, header, unprotected, sys.call())
}

new_signer <- function(key, alg, header, unprotected, call) {
  key <- check_key(key, call)
  if (!is.null(alg) && !is_string(alg)) {
    abort_zujose("argument", "`alg` must be a single string.", call = call)
  }
  alg <- if (!is.null(alg)) unname(alg)
  header <- check_header_arg(header, "header", call = call)
  unprotected <- check_header_arg(unprotected, "unprotected", call = call)
  check_disjoint_headers(header, unprotected, call = call)
  structure(
    list(key = key, alg = alg, header = header, unprotected = unprotected),
    class = "jws_signer"
  )
}

protected_header <- function(signer, b64, call) {
  alg <- signer$alg %||% signer$key$alg
  if (is.null(alg)) {
    abort_zujose(
      "policy",
      "Give `alg`, or a key whose own `alg` is set.",
      call = call
    )
  }
  check_algorithms(alg, "signature", "alg", call)
  check_available(alg, call)
  if (!key_fits(signer$key, alg, "sign")) {
    abort_zujose(
      "policy",
      "The key does not fit the algorithm or its intended use.",
      call = call
    )
  }
  header <- signer$header
  # `b64` and `crit` describe how the payload is encoded, which the `b64`
  # argument decides; zujose writes them itself (RFC 7797).
  for (name in c("b64", "crit")) {
    if (name %in% c(names(header), names(signer$unprotected))) {
      abort_zujose(
        "argument",
        sprintf("Set `%s` through the `b64` argument, not a header.", name),
        call = call
      )
    }
  }
  if ("alg" %in% names(header) && !identical(header[["alg"]], alg)) {
    abort_zujose(
      "argument",
      "`header$alg` disagrees with `alg`.",
      call = call
    )
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
#' `jws_verify()` checks a JWS in any serialization and returns its
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
#' @param key A `jwk`, a `jwk_set`, or a function of the header
#'   returning one.
#' @param algorithms The signature algorithms to accept, such as `"HS256"`.
#' @param payload For a detached payload (RFC 7515 Appendix F), the payload:
#'   a raw vector or a single string. A JSON serialization without a
#'   `payload` member needs it; a compact one with an empty payload part is
#'   checked over the empty payload when it is not given.
#' @param require With several signatures, whether `"all"` must verify (the
#'   default) or `"any"` one is enough. With `"any"`, signatures whose
#'   algorithm is not in `algorithms` are skipped.
#' @param limits Resource limits, from [jose_limits()].
#' @returns A list of class `jws_verified` with `payload` (raw), `header`
#'   (the protected and unprotected header of the first verified signature),
#'   `protected` (its protected part), `kid` and `alg` (of the key and
#'   algorithm that verified it), and `signatures`, one such entry per
#'   verified signature.
#' @export
#' @examples
#' key <- jwk_oct(as.raw(1:32), kid = "k1")
#' token <- jws_sign("hello", key, alg = "HS256")
#' jws_verify(token, key, algorithms = "HS256")
#'
#' # The token's algorithm must be one you allow.
#' try(jws_verify(token, key, algorithms = "HS512"))
jws_verify <- function(
  token,
  key,
  algorithms,
  payload = NULL,
  require = c("all", "any"),
  limits = jose_limits()
) {
  call <- sys.call()
  check_algorithms(algorithms, "signature", call = call)
  check_key_arg(key, call)
  require <- arg_choice(require, "require", call)
  if (!is.null(payload)) {
    as_payload_bytes(payload, call)
  }
  check_limits(limits, call)
  verify_jws(token, key, algorithms, payload, require, limits, call)
}

# The body of jws_verify(), shared with jwt_decode() so that errors
# name the function the caller called.
verify_jws <- function(token, key, algorithms, payload, require, limits, call) {
  obj <- jose_parse(token, limits, call)
  if (obj$type != "JWS") {
    abort_zujose("policy", "Expected a JWS, not a JWE.", call = call)
  }

  carried <- !is.null(obj$payload_b64) && nzchar(obj$payload_b64)
  if (!is.null(payload)) {
    if (carried) {
      abort_zujose(
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
    # RFC 7515 Appendix F: a JSON token without its `payload` member is
    # detached, and the caller supplies the payload. A missing payload is
    # not an empty one. In the compact serialization an empty part is
    # both, so it verifies as the empty payload (#131, #147).
    if (is.null(obj$payload_b64) && obj$serialization != "compact") {
      abort_zujose(
        "parse",
        "The token has no `payload` member; pass the detached `payload`.",
        call = call
      )
    }
    bytes <- obj$payload %||% raw()
    signed_payload <- if (obj$b64) {
      charToRaw(obj$payload_b64 %||% "")
    } else {
      bytes
    }
  }

  # Policy and key selection run for every signature before any
  # cryptography, and `limits$keys` bounds the keys tried for the whole
  # token, not per signature, as in jwe_decrypt() (#37, #92).
  first_error <- NULL
  guard <- function(f) {
    if (require == "all") {
      return(f())
    }
    tryCatch(f(), zujose_error = function(e) {
      first_error <<- first_error %||% e
      NULL
    })
  }
  headers <- lapply(obj$signatures, function(s) c(s$protected, s$header))
  keys <- lapply(seq_along(obj$signatures), function(i) {
    guard(function() {
      signature_keys(headers[[i]], key, algorithms, limits, call)
    })
  })
  if (sum(lengths(keys)) > limits$keys) {
    abort_zujose(
      "key",
      "More keys fit the token's signatures than `limits$keys` allows.",
      call = call
    )
  }

  verified <- list()
  for (i in seq_along(obj$signatures)) {
    if (length(keys[[i]]) == 0L) {
      next
    }
    result <- guard(function() {
      verify_signature(
        obj$signatures[[i]],
        headers[[i]],
        keys[[i]],
        signed_payload,
        call
      )
    })
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
    class = "jws_verified"
  )
}

# The keys to try for one signature, after its algorithm passes the policy.
signature_keys <- function(header, key, algorithms, limits, call) {
  alg <- header[["alg"]]
  if (!alg %in% algorithms) {
    abort_zujose(
      "policy",
      "The token's algorithm is not in `algorithms`.",
      call = call
    )
  }
  check_available(alg, call)
  keys <- resolve_keys(key, header, "verify", limits, call)
  # A key too weak for `alg` is skipped, so a legacy key in a set does not
  # stop the search (#39). With none strong enough, the first is used, so
  # its check raises the key error.
  strong <- Filter(function(k) sig_key_strong(alg, k), keys)
  if (length(strong) > 0L) strong else keys[1]
}

verify_signature <- function(s, header, keys, signed_payload, call) {
  alg <- header[["alg"]]
  input <- c(charToRaw(s$protected_b64), charToRaw("."), signed_payload)
  for (k in keys) {
    if (jws_verify_bytes(alg, k, input, s$signature, call)) {
      return(list(
        header = header,
        protected = s$protected,
        kid = k$kid,
        alg = alg
      ))
    }
  }
  abort_zujose("signature", "The signature does not verify.", call = call)
}

# Algorithms --------------------------------------------------------------

hmac_hash <- c(HS256 = "sha256", HS384 = "sha384", HS512 = "sha512")
hmac_min_bytes <- c(HS256 = 32L, HS384 = 48L, HS512 = 64L)

# RS* and PS* (RFC 7518 §3.3, §3.5): the digest, and whether it is PSS.
# PSS uses MGF1 with the same digest and a salt as long as the digest, which
# is what zucrypt's pss = TRUE does.
rsa_sig_hash <- c(
  RS256 = "sha256",
  RS384 = "sha384",
  RS512 = "sha512",
  PS256 = "sha256",
  PS384 = "sha384",
  PS512 = "sha512"
)

# ES* (RFC 7518 §3.4): the digest, and the curve's coordinate size. The
# signature is r || s, each left-padded to that size.
ec_sig_hash <- c(ES256 = "sha256", ES384 = "sha384", ES512 = "sha512")
ec_sig_bytes <- c(ES256 = 32L, ES384 = 48L, ES512 = 66L)

pad_left <- function(x, n) {
  x <- x[cumsum(x != as.raw(0)) > 0]
  c(raw(n - length(x)), x)
}

digest_fun <- function(name) {
  switch(
    name,
    sha256 = zucrypt::crypt_sha256,
    sha384 = zucrypt::crypt_sha384,
    sha512 = zucrypt::crypt_sha512
  )
}

jws_sign_bytes <- function(alg, key, input, call) {
  if (alg %in% names(hmac_hash)) {
    check_hmac_key(key, alg, call)
    return(zucrypt::crypt_hmac(input, key$k, hmac_hash[[alg]]))
  }
  check_available(alg, call)
  if (alg %in% names(rsa_sig_hash)) {
    check_rsa_size(key, call)
    if (!has_private(key)) {
      abort_zujose("key", "Signing needs the private key.", call = call)
    }
    return(zucrypt::crypt_signature_create(
      input,
      digest_fun(rsa_sig_hash[[alg]]),
      rsa_crypt_key(key, TRUE),
      pss = startsWith(alg, "PS")
    ))
  }
  if (!has_private(key)) {
    abort_zujose("key", "Signing needs the private key.", call = call)
  }
  der <- zucrypt::crypt_signature_create(
    input,
    digest_fun(ec_sig_hash[[alg]]),
    ec_crypt_key(key, TRUE)
  )
  rs <- zucrypt::crypt_ecdsa_parse(der)
  n <- ec_sig_bytes[[alg]]
  c(pad_left(rs$r, n), pad_left(rs$s, n))
}

jws_verify_bytes <- function(alg, key, input, signature, call) {
  if (alg %in% names(hmac_hash)) {
    check_hmac_key(key, alg, call)
    expected <- zucrypt::crypt_hmac(input, key$k, hmac_hash[[alg]])
    return(
      length(signature) == length(expected) &&
        zucrypt::crypt_equal(signature, expected)
    )
  }
  check_available(alg, call)
  if (alg %in% names(rsa_sig_hash)) {
    check_rsa_size(key, call)
    return(tryCatch(
      zucrypt::crypt_signature_verify(
        input,
        signature,
        digest_fun(rsa_sig_hash[[alg]]),
        rsa_crypt_key(key, FALSE),
        pss = startsWith(alg, "PS")
      ),
      zucrypt_auth_error = function(e) FALSE
    ))
  }
  n <- ec_sig_bytes[[alg]]
  if (length(signature) != 2L * n) {
    return(FALSE)
  }
  der <- zucrypt::crypt_ecdsa_write(
    signature[seq_len(n)],
    signature[n + seq_len(n)]
  )
  tryCatch(
    zucrypt::crypt_signature_verify(
      input,
      der,
      digest_fun(ec_sig_hash[[alg]]),
      ec_crypt_key(key, FALSE)
    ),
    zucrypt_auth_error = function(e) FALSE
  )
}

# Whether `key` meets the minimum strength for signature algorithm `alg`:
# the hash size for HMAC (RFC 7518 section 3.2), `rsa_min_bits` for RSA
# (3.3).
sig_key_strong <- function(alg, key) {
  if (alg %in% names(hmac_min_bytes)) {
    return(length(key$k) >= hmac_min_bytes[[alg]])
  }
  if (alg %in% names(rsa_sig_hash)) {
    return(rsa_key_strong(key))
  }
  TRUE
}

# RFC 7518 §3.2: an HMAC key at least as long as the hash output.
check_hmac_key <- function(key, alg, call) {
  if (!sig_key_strong(alg, key)) {
    abort_zujose(
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

as_payload_bytes <- function(x, call, arg = "payload") {
  if (is.raw(x)) {
    return(x)
  }
  if (is_string(x)) {
    return(charToRaw(enc2utf8(x)))
  }
  abort_zujose(
    "argument",
    sprintf("`%s` must be a raw vector or a single string.", arg),
    call = call
  )
}

# match.arg() for a user argument, raising zujose_argument_error: the
# default vector means its first element; anything else must be one choice.
arg_choice <- function(x, name, call) {
  choices <- eval(formals(sys.function(sys.parent()))[[name]])
  if (identical(x, choices)) {
    return(choices[[1]])
  }
  if (!is_string(x) || !x %in% choices) {
    abort_zujose(
      "argument",
      sprintf(
        "`%s` must be one of %s.",
        name,
        paste0("\"", choices, "\"", collapse = ", ")
      ),
      call = call
    )
  }
  x
}

check_flag <- function(x, name, call) {
  if (!isTRUE(x) && !isFALSE(x)) {
    abort_zujose(
      "argument",
      sprintf("`%s` must be TRUE or FALSE.", name),
      call = call
    )
  }
}

# A header or claims argument, checked; the members in `scalars`, which
# JSON gives one type, lose any names, which zujson would write as an
# object (#120). The members in `strings` must be strings, as
# check_headers() requires of a token's, but a wrong one is the caller's
# mistake (#148).
check_header_arg <- function(
  x,
  name,
  scalars = c("alg", "enc", "kid", "typ", "cty", "p2c"),
  strings = c("alg", "enc", "kid", "typ", "cty"),
  call
) {
  if (is.null(x)) {
    return(empty_object())
  }
  if (
    !is.list(x) ||
      is.data.frame(x) ||
      (length(x) > 0L && is.null(names(x)))
  ) {
    abort_zujose(
      "argument",
      sprintf("`%s` must be a named list.", name),
      call = call
    )
  }
  check_json_arg(x, name, call)
  for (member in intersect(strings, names(x))) {
    if (!is_string(x[[member]])) {
      abort_zujose(
        "argument",
        sprintf("`%s$%s` must be a single string.", name, member),
        call = call
      )
    }
  }
  for (member in intersect(scalars, names(x))) {
    if (is.atomic(x[[member]])) {
      x[[member]] <- unname(x[[member]])
    }
  }
  if (length(x) == 0L) empty_object() else x
}

# Why zujson would not write `x` as the JSON the caller means: names that
# are repeated, NA or empty, at any depth, which RFC 8725 section 3.4 asks
# readers to reject, or a type JSON has no form for (#119, #123). NULL when
# there is none.
json_arg_problem <- function(x) {
  if (is.null(x)) {
    return(NULL)
  }
  nms <- names(x)
  if (
    !is.null(nms) && (anyNA(nms) || !all(nzchar(nms)) || anyDuplicated(nms))
  ) {
    return("names")
  }
  if (is.list(x)) {
    for (value in x) {
      problem <- json_arg_problem(value)
      if (!is.null(problem)) {
        return(problem)
      }
    }
    return(NULL)
  }
  if (
    is.atomic(x) &&
      typeof(x) %in% c("logical", "integer", "double", "character")
  ) {
    return(NULL)
  }
  "type"
}

# Refuse an argument zujose would write as JSON, as json_arg_problem()
# describes, with zujose_argument_error.
check_json_arg <- function(x, name, call) {
  problem <- json_arg_problem(x)
  if (identical(problem, "names")) {
    abort_zujose(
      "argument",
      sprintf(
        "`%s` must have names that are unique and not empty, at every depth.",
        name
      ),
      call = call
    )
  }
  if (identical(problem, "type")) {
    abort_zujose(
      "argument",
      sprintf(
        "`%s` holds a value JSON cannot represent, such as a raw vector.",
        name
      ),
      call = call
    )
  }
  invisible(x)
}

# Refuse a member given in more than one of the caller's headers, which
# check_headers() would report as a malformed token (#119).
check_disjoint_headers <- function(..., call) {
  if (anyDuplicated(unlist(lapply(list(...), names)))) {
    abort_zujose(
      "argument",
      "A header member is given in more than one header.",
      call = call
    )
  }
}

#' @export
print.jws_verified <- function(x, ...) {
  cat(sprintf(
    "<jws_verified> %s%s\n",
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
