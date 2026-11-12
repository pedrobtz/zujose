# JWT (design §7.5, §8.5).

#' Encode a JWT
#'
#' `jwt_encode()` signs a claims set as a JSON Web Token (RFC 7519),
#' in the compact serialization.
#'
#' Times may be given as `POSIXct` for `exp`, `nbf` and `iat`, and are
#' written as NumericDate, whole seconds since 1970. `expires_in` and
#' `not_before` count from now.
#'
#' @param key A `jwk`. A JWT is in the compact serialization, which carries
#'   one signature, so a list of [jws_signer()]s is refused.
#' @param claims The claims, as a named list. It may be empty. Names must
#'   be unique and not empty at every depth, and values must be of a type
#'   JSON can represent.
#' @inheritParams jws_sign
#' @param header Protected header members. The default declares
#'   `typ: "JWT"`.
#' @param expires_in Seconds, or a `difftime`, until the token expires. Sets
#'   `exp`.
#' @param not_before Seconds, or a `difftime`, before the token becomes
#'   valid. Sets `nbf`.
#' @param issued_at Whether to set `iat` to now, unless `claims` sets it.
#' @param jti Whether to add a random `jti`, 128 bits from the operating
#'   system's random source as Base64url, unless `claims` sets it.
#' @returns The JWT, as a single string.
#' @seealso [jwt_decode()] to check one.
#' @export
#' @examples
#' key <- jwk_oct(as.raw(1:32), kid = "k1")
#' jwt <- jwt_encode(list(sub = "u1", aud = "api"), key, "HS256",
#'                        expires_in = 3600)
#' jwt_decode(jwt, key, algorithms = "HS256", audience = "api")
jwt_encode <- function(
  claims,
  key,
  alg = NULL,
  header = list(typ = "JWT"),
  expires_in = NULL,
  not_before = NULL,
  issued_at = TRUE,
  jti = FALSE
) {
  call <- sys.call()
  # A JWT is a compact JWS, which carries one signature (#130).
  if (
    inherits(key, "jws_signer") ||
      (is.list(key) &&
        !inherits(key, "jwk") &&
        any(vapply(key, inherits, logical(1), "jws_signer")))
  ) {
    abort_zujose(
      "argument",
      "A JWT has one signature: give `key` as one jwk, not jws_signer()s.",
      call = call
    )
  }
  check_key(key, call)
  claims <- check_header_arg(
    claims,
    "claims",
    c("iss", "sub", "aud", "exp", "nbf", "iat", "jti")
  )
  check_flag(issued_at, "issued_at", call)
  check_flag(jti, "jti", call)
  now <- jwt_now()
  for (name in intersect(c("exp", "nbf", "iat"), names(claims))) {
    claims[[name]] <- as_numeric_date(claims[[name]], name)
  }
  if (!is.null(expires_in)) {
    claims[["exp"]] <- as_numeric_date(
      now + as_seconds(expires_in, "expires_in"),
      "expires_in"
    )
  }
  if (!is.null(not_before)) {
    claims[["nbf"]] <- as_numeric_date(
      now + as_seconds(not_before, "not_before"),
      "not_before"
    )
  }
  if (issued_at && !"iat" %in% names(claims)) {
    claims[["iat"]] <- now
  }
  if (jti && !"jti" %in% names(claims)) {
    claims[["jti"]] <- b64url_encode(zucrypt::crypt_rand_bytes(16L))
  }

  jws_sign(zujson::json_write(claims), key, alg = alg, header = header)
}

#' Check a JWT and return its claims
#'
#' `jwt_decode()` verifies a JWT's signature with [jws_verify()]'s
#' rules and then checks its claims (RFC 7519, RFC 8725). The checks happen
#' here, in one call, so none can be forgotten.
#'
#' * `exp`, `nbf` and `iat` must be numbers that `POSIXct` can hold as a
#'   time, within about two billion years of 1970. The token must not have
#'   expired, must already be valid, and must not be issued in the future,
#'   each allowing `leeway` seconds. `max_age` bounds how long ago `iat`
#'   was.
#' * `required` names claims that must be present. The default requires
#'   `exp`: a token that never expires has to be accepted on purpose.
#' * `issuer` and `subject` must equal `iss` and `sub` exactly. An `iss` or
#'   `sub` that is not a single string is refused.
#' * `aud` must contain one of `audience`. A token that names an audience is
#'   refused when `audience` is `NULL` (RFC 7519 section 4.1.3), and one
#'   without `aud` is refused when `audience` is given.
#' * `type` must match the `typ` header, ignoring case and an
#'   `application/` prefix. A token without `typ` passes only when `type`
#'   is `"JWT"`.
#' * `claims` holds further expectations, one per claim: a value the claim
#'   must equal, or a function of the claim that must return `TRUE`.
#'   `validate` is a function of the whole claims list, for checks across
#'   claims.
#'
#' A value in `claims` is compared with the claim as JSON values, the value
#' taken as [jwt_encode()] would write it. Object members may come in any
#' order, and `3L` equals `3`. A vector of length one is a scalar and a
#' longer one an array, so `"a"` does not match `["a"]`; write `list("a")`
#' for an array of one. `NULL` matches a JSON `null`. `NA` and non-finite
#' numbers have no JSON form and are refused. `exp`, `nbf` and `iat` are
#' compared, and passed to a function, as the `POSIXct` times
#' `jwt_decode()` returns; a number expects the same NumericDate.
#'
#' A JWT must not use the unencoded payload option, `b64: false` (RFC 7797
#' section 7), and one that does is refused with `zujose_policy_error`.
#'
#' A JWT whose header has `cty: "JWT"` carries another JWT as its payload.
#' That inner JWT is verified with the same `key` and `algorithms`, and its
#' claims are checked. Deeper nesting is refused.
#'
#' A JWT sent as a JWE is accepted only when `decrypt` says how to decrypt
#' it, so a check meant for signed tokens never silently accepts encrypted
#' ones. The JWE carries a signed JWT (`cty: "JWT"`), verified as above,
#' or, when its key management is symmetric (`dir`, `A*KW`, `A*GCMKW` or
#' `PBES2-*`), the claims themselves. With RSA or ECDH key management anyone
#' holding the recipient's public key can encrypt a token, so the claims must
#' be signed: an encrypted-only JWT is refused with `zujose_policy_error`.
#'
#' Each failed check raises a subclass of `zujose_claim_error` carrying the
#' claim name: `zujose_expired_error`, `zujose_not_yet_valid_error`,
#' `zujose_audience_error`, `zujose_issuer_error`, `zujose_subject_error` or
#' `zujose_missing_claim_error`. Time errors also carry `time` and `now`.
#'
#' @param token The JWT, in the compact serialization.
#' @inheritParams jws_verify
#' @param audience The audiences this caller accepts, or `NULL`.
#' @param issuer The issuer this caller accepts, or `NULL`.
#' @param subject The subject this caller accepts, or `NULL`.
#' @param type The expected `typ`, or `NULL` to skip the check.
#' @param required Names of claims that must be present.
#' @param claims Further expectations, as a list of values or functions
#'   with unique names.
#' @param validate A function of the claims list that must return `TRUE`, or
#'   `NULL`.
#' @param max_age The greatest age, in seconds, of `iat`, or `NULL`.
#' @param leeway Seconds of clock skew to allow.
#' @param now The current time, as `POSIXct`.
#' @param decrypt For a JWT sent as a JWE, the key and algorithms to decrypt
#'   it, from [jwe_decryption()]; `NULL` refuses a JWE.
#' @returns The claims, as a named list of class `jwt_claims`, with `exp`,
#'   `nbf` and `iat` as `POSIXct` and the verified header as the `header`
#'   attribute.
#' @seealso [jwt_decoder()] to fix these arguments once.
#' @export
#' @examples
#' key <- jwk_oct(as.raw(1:32))
#' jwt <- jwt_encode(list(iss = "me", aud = "api"), key, "HS256",
#'                        expires_in = 60)
#' claims <- jwt_decode(jwt, key, "HS256", audience = "api",
#'                           issuer = "me")
#' claims$iss
#'
#' # Claim failures have classes of their own.
#' tryCatch(
#'   jwt_decode(jwt, key, "HS256", audience = "other"),
#'   zujose_audience_error = function(e) "wrong audience"
#' )
jwt_decode <- function(
  token,
  key,
  algorithms,
  audience = NULL,
  issuer = NULL,
  subject = NULL,
  type = "JWT",
  required = "exp",
  claims = list(),
  validate = NULL,
  max_age = NULL,
  leeway = 60,
  now = Sys.time(),
  decrypt = NULL,
  limits = jose_limits()
) {
  call <- sys.call()
  check_algorithms(algorithms, "signature", call = call)
  check_decode_args(
    audience,
    issuer,
    subject,
    type,
    required,
    claims,
    validate,
    max_age,
    leeway,
    now
  )
  # identical() would compare names too (#120).
  issuer <- if (!is.null(issuer)) unname(issuer)
  subject <- if (!is.null(subject)) unname(subject)
  if (!is_string(token)) {
    abort_zujose("parse", "`token` must be a single string.", call = call)
  }
  check_utf8_token(token, call)
  if (grepl("^[[:space:]]*\\{", token)) {
    abort_zujose(
      "parse",
      "A JWT uses the compact serialization.",
      call = call
    )
  }

  if (!is.null(decrypt) && !inherits(decrypt, "jwe_decryption")) {
    abort_zujose("argument", "`decrypt` must be made by jwe_decryption().")
  }

  if (compact_parts(token) == 5L) {
    if (is.null(decrypt)) {
      abort_zujose(
        "policy",
        "The token is a JWE; pass `decrypt = jwe_decryption()` to accept one.",
        call = call
      )
    }
    # An encrypted-only JWT is authentic only when the key management is
    # symmetric: with RSA or ECDH, anyone holding the recipient's public key
    # can make one. Its claims must then come inside a signed JWT (#34).
    # Decided on the header, before any decryption.
    outer <- jose_parse(token, limits, call)$protected
    if (!is_nested(outer) && !identical(alg_key_types(outer[["alg"]]), "oct")) {
      abort_zujose(
        "policy",
        paste0(
          "A JWT encrypted with public-key key management must carry a ",
          "signed JWT (`cty: \"JWT\"`)."
        ),
        call = call
      )
    }
    opened <- decrypt_jwe(
      token,
      decrypt$key,
      decrypt$algorithms,
      decrypt$encryptions,
      limits,
      call
    )
    verified <- if (is_nested(opened$header)) {
      verify_inner(opened$plaintext, key, algorithms, limits, call)
    } else {
      list(header = opened$header, payload = opened$plaintext)
    }
  } else {
    refuse_unencoded(token, limits, call)
    verified <- verify_jws(token, key, algorithms, NULL, "all", limits, call)
    if (is_nested(verified$header)) {
      verified <- verify_inner(verified$payload, key, algorithms, limits, call)
    }
  }
  header <- verified$header
  check_type(header, type, call)

  payload <- tryCatch(
    json_object(verified$payload, "claims set", call),
    zujose_parse_error = function(e) {
      abort_zujose("parse", "The claims set is not a JSON object.", call = call)
    }
  )
  now <- as.numeric(now)
  check_claims(
    payload,
    audience,
    issuer,
    subject,
    required,
    claims,
    validate,
    max_age,
    leeway,
    now,
    call
  )

  for (name in intersect(c("exp", "nbf", "iat"), names(payload))) {
    payload[[name]] <- as_posixct(payload[[name]])
  }
  structure(payload, header = header, class = "jwt_claims")
}

#' A reusable JWT check
#'
#' `jwt_decoder()` fixes the key and every check of
#' [jwt_decode()] once, and returns a function of the token that
#' applies them. Use it where the same policy guards many requests.
#'
#' @inheritParams jwt_decode
#' @returns A function `function(token, now = Sys.time())` returning the
#'   claims, as [jwt_decode()] does.
#' @export
#' @examples
#' key <- jwk_oct(as.raw(1:32))
#' check <- jwt_decoder(key, "HS256", audience = "api", issuer = "me")
#' jwt <- jwt_encode(list(iss = "me", aud = "api"), key, "HS256",
#'                        expires_in = 60)
#' check(jwt)$iss
jwt_decoder <- function(
  key,
  algorithms,
  audience = NULL,
  issuer = NULL,
  subject = NULL,
  type = "JWT",
  required = "exp",
  claims = list(),
  validate = NULL,
  max_age = NULL,
  leeway = 60,
  decrypt = NULL,
  limits = jose_limits()
) {
  check_algorithms(algorithms, "signature", call = sys.call())
  if (!is.null(decrypt) && !inherits(decrypt, "jwe_decryption")) {
    abort_zujose("argument", "`decrypt` must be made by jwe_decryption().")
  }
  check_decode_args(
    audience,
    issuer,
    subject,
    type,
    required,
    claims,
    validate,
    max_age,
    leeway,
    Sys.time()
  )
  check_limits(limits)
  force(key)
  function(token, now = Sys.time()) {
    jwt_decode(
      token,
      key,
      algorithms,
      audience = audience,
      issuer = issuer,
      subject = subject,
      type = type,
      required = required,
      claims = claims,
      validate = validate,
      max_age = max_age,
      leeway = leeway,
      now = now,
      decrypt = decrypt,
      limits = limits
    )
  }
}

# Checks ------------------------------------------------------------------

check_claims <- function(
  cl,
  audience,
  issuer,
  subject,
  required,
  spec,
  validate,
  max_age,
  leeway,
  now,
  call
) {
  present <- names(cl)

  # RFC 7519 §4.1.4–§4.1.6: NumericDate, so a finite number. A string or a
  # null is a malformed token, never a skipped check.
  for (name in intersect(c("exp", "nbf", "iat"), present)) {
    value <- cl[[name]]
    if (!is.numeric(value) || length(value) != 1L || !is.finite(value)) {
      abort_zujose(
        "parse",
        sprintf("The `%s` claim must be a number.", name),
        call = call
      )
    }
    # Returned as POSIXct, which has no calendar time for a NumericDate
    # beyond about two billion years either side of 1970 (#127).
    if (is.na(as.POSIXlt(as_posixct(value)))) {
      abort_zujose(
        "parse",
        sprintf("The `%s` claim is beyond any time R can represent.", name),
        call = call
      )
    }
  }
  for (name in intersect(c("iss", "sub"), present)) {
    if (!is_string(cl[[name]])) {
      abort_claim(
        if (name == "iss") "issuer" else "subject",
        sprintf("The `%s` claim must be a single string.", name),
        claim = name,
        call = call
      )
    }
  }
  aud <- NULL
  if ("aud" %in% present) {
    aud <- cl[["aud"]]
    if (
      is.list(aud) &&
        is.null(names(aud)) &&
        length(aud) > 0L &&
        all(vapply(aud, is_string, logical(1)))
    ) {
      aud <- unlist(aud)
    }
    if (!is.character(aud) || length(aud) == 0L || anyNA(aud)) {
      abort_claim(
        "audience",
        "The `aud` claim must be a string or an array of strings.",
        claim = "aud",
        call = call
      )
    }
  }

  for (name in required) {
    if (!name %in% present) {
      abort_missing(name, call)
    }
  }

  exp <- member(cl, "exp")
  if (!is.null(exp) && now >= exp + leeway) {
    abort_time("expired", "The token has expired.", "exp", exp, now, call)
  }
  nbf <- member(cl, "nbf")
  if (!is.null(nbf) && now + leeway < nbf) {
    abort_time(
      "not_yet_valid",
      "The token is not valid yet.",
      "nbf",
      nbf,
      now,
      call
    )
  }
  iat <- member(cl, "iat")
  if (!is.null(iat) && iat > now + leeway) {
    abort_time(
      "not_yet_valid",
      "The token was issued in the future.",
      "iat",
      iat,
      now,
      call
    )
  }
  if (!is.null(max_age)) {
    if (is.null(iat)) {
      abort_missing("iat", call)
    }
    if (now - iat > max_age + leeway) {
      abort_time(
        "expired",
        "The token is older than `max_age`.",
        "iat",
        iat,
        now,
        call
      )
    }
  }

  if (!is.null(issuer)) {
    if (!"iss" %in% present) {
      abort_missing("iss", call)
    }
    if (!identical(cl[["iss"]], issuer)) {
      abort_claim(
        "issuer",
        "The token's issuer is not `issuer`.",
        claim = "iss",
        call = call
      )
    }
  }
  if (!is.null(subject)) {
    if (!"sub" %in% present) {
      abort_missing("sub", call)
    }
    if (!identical(cl[["sub"]], subject)) {
      abort_claim(
        "subject",
        "The token's subject is not `subject`.",
        claim = "sub",
        call = call
      )
    }
  }
  if (is.null(audience)) {
    if (!is.null(aud)) {
      abort_claim(
        "audience",
        "The token names an audience; pass `audience` to accept it.",
        claim = "aud",
        call = call
      )
    }
  } else {
    if (is.null(aud)) {
      abort_missing("aud", call)
    }
    if (!any(aud %in% audience)) {
      abort_claim(
        "audience",
        "The token is not for this `audience`.",
        claim = "aud",
        call = call
      )
    }
  }

  for (name in names(spec)) {
    if (!name %in% present) {
      abort_missing(name, call)
    }
    expected <- spec[[name]]
    ok <- claim_matches(name, cl[[name]], expected)
    if (!ok) {
      abort_claim(
        NULL,
        sprintf("The `%s` claim is not what `claims` expects.", name),
        claim = name,
        call = call
      )
    }
  }
  if (!is.null(validate) && !isTRUE(validate(cl))) {
    abort_claim(
      NULL,
      "`validate` refused the claims.",
      claim = NA_character_,
      call = call
    )
  }
  invisible()
}

# Whether a claim meets its expectation in `claims` (#128). Time claims
# are compared, and passed to a function, as the POSIXct jwt_decode()
# returns. Other values are compared as parsed JSON, the expectation as
# jwt_encode() would write it: object members in any order, and integers
# equal to the same doubles.
claim_matches <- function(name, value, expected) {
  time <- name %in% c("exp", "nbf", "iat")
  if (time) {
    value <- as_posixct(value)
  }
  if (is.function(expected)) {
    return(isTRUE(expected(value)))
  }
  if (time) {
    return(
      (is.numeric(expected) || inherits(expected, "POSIXct")) &&
        length(expected) == 1L &&
        identical(as.numeric(expected), as.numeric(value))
    )
  }
  expected <- zujson::json_parse(
    zujson::json_write(expected),
    simplify = "none"
  )
  json_equal(value, expected)
}

# Whether two parsed JSON values are equal: object members in any order,
# and numbers by value. Level by level, not by recursion, so a claim
# nested as deep as zujson parses cannot exhaust the C stack.
json_equal <- function(a, b) {
  as <- list(a)
  bs <- list(b)
  while (length(as) > 0L) {
    if (length(as) != length(bs)) {
      return(FALSE)
    }
    next_a <- vector("list", length(as))
    next_b <- vector("list", length(as))
    for (i in seq_along(as)) {
      x <- as[[i]]
      y <- bs[[i]]
      if (is.list(x) != is.list(y)) {
        return(FALSE)
      }
      if (!is.list(x)) {
        same <- if (is.numeric(x) && is.numeric(y)) {
          identical(as.double(x), as.double(y))
        } else {
          identical(x, y)
        }
        if (!same) {
          return(FALSE)
        }
        next
      }
      if (length(x) != length(y) || is.null(names(x)) != is.null(names(y))) {
        return(FALSE)
      }
      if (!is.null(names(x))) {
        x <- x[order(names(x), method = "radix")]
        y <- y[order(names(y), method = "radix")]
        if (!identical(names(x), names(y))) {
          return(FALSE)
        }
      }
      next_a[i] <- list(unname(x))
      next_b[i] <- list(unname(y))
    }
    as <- unlist(next_a, recursive = FALSE)
    bs <- unlist(next_b, recursive = FALSE)
  }
  length(bs) == 0L
}

# RFC 7515 §4.1.9: compare media types without case and without an
# "application/" prefix. RFC 7519 §5.1: `typ` is optional, and its absence
# means a plain JWT.
check_type <- function(header, type, call) {
  if (is.null(type)) {
    return(invisible())
  }
  norm <- function(x) tolower(sub("^application/", "", x, ignore.case = TRUE))
  typ <- member(header, "typ")
  ok <- if (is.null(typ)) norm(type) == "jwt" else norm(typ) == norm(type)
  if (!ok) {
    abort_zujose(
      "policy",
      "The token's `typ` header is not `type`.",
      call = call
    )
  }
  invisible()
}

# The JWT nested inside a JWS or JWE: a compact JWS, one level only.
verify_inner <- function(bytes, key, algorithms, limits, call) {
  inner <- if (!any(bytes == as.raw(0))) rawToChar(bytes) else ""
  Encoding(inner) <- "UTF-8"
  if (compact_parts(inner) != 3L) {
    abort_zujose(
      "policy",
      "A nested JWT must be a signed JWT in the compact serialization.",
      call = call
    )
  }
  refuse_unencoded(inner, limits, call)
  verified <- verify_jws(inner, key, algorithms, NULL, "all", limits, call)
  if (is_nested(verified$header)) {
    abort_zujose(
      "policy",
      "A JWT nested more than one level deep is refused.",
      call = call
    )
  }
  verified
}

# RFC 7797 §7: JWTs must not use the unencoded payload option. Decided on
# the parsed header, before any key is tried (#126).
refuse_unencoded <- function(token, limits, call) {
  obj <- jose_parse(token, limits, call)
  if (identical(obj$type, "JWS") && !obj$b64) {
    abort_zujose(
      "policy",
      "A JWT must not use an unencoded payload (`b64: false`).",
      call = call
    )
  }
  invisible()
}

compact_parts <- function(token) {
  if (!is_string(token)) {
    return(NA_integer_)
  }
  lengths(regmatches(token, gregexpr(".", token, fixed = TRUE))) + 1L
}

is_nested <- function(header) {
  cty <- member(header, "cty")
  is_string(cty) &&
    toupper(sub("^application/", "", cty, ignore.case = TRUE)) == "JWT"
}

check_decode_args <- function(
  audience,
  issuer,
  subject,
  type,
  required,
  claims,
  validate,
  max_age,
  leeway,
  now
) {
  bad <- function(what) abort_zujose("argument", what)
  if (
    !is.null(audience) &&
      (!is.character(audience) || length(audience) == 0L || anyNA(audience))
  ) {
    bad("`audience` must be NULL or a character vector.")
  }
  for (arg in list(
    list(issuer, "issuer"),
    list(subject, "subject"),
    list(type, "type")
  )) {
    if (!is.null(arg[[1]]) && !is_string(arg[[1]])) {
      bad(sprintf("`%s` must be NULL or a single string.", arg[[2]]))
    }
  }
  if (!is.character(required) || anyNA(required)) {
    bad("`required` must be a character vector.")
  }
  # One expectation per claim: a repeated name would go unchecked (#118).
  nms <- names(claims)
  if (
    !is.list(claims) ||
      (length(claims) > 0L &&
        (is.null(nms) || anyNA(nms) || !all(nzchar(nms)) || anyDuplicated(nms)))
  ) {
    bad("`claims` must be a list with unique, non-empty names.")
  }
  # NA and non-finite numbers would be written as JSON null (#128).
  for (expected in claims) {
    if (is.function(expected)) {
      next
    }
    values <- unlist(expected)
    if (
      !is.null(json_arg_problem(expected)) ||
        anyNA(values) ||
        (is.numeric(values) && !all(is.finite(values)))
    ) {
      bad(
        "Each expectation in `claims` must be a function or a JSON value."
      )
    }
  }
  if (!is.null(validate) && !is.function(validate)) {
    bad("`validate` must be NULL or a function.")
  }
  for (arg in list(
    list(max_age, "max_age", TRUE),
    list(leeway, "leeway", FALSE)
  )) {
    value <- arg[[1]]
    if (is.null(value) && arg[[3]]) {
      next
    }
    if (
      !is.numeric(value) ||
        length(value) != 1L ||
        !is.finite(value) ||
        value < 0
    ) {
      bad(sprintf("`%s` must be a number of seconds, at least 0.", arg[[2]]))
    }
  }
  if (!inherits(now, "POSIXct") || length(now) != 1L || is.na(now)) {
    bad("`now` must be a single POSIXct time.")
  }
}

# Helpers -----------------------------------------------------------------

jwt_now <- function() {
  floor(as.numeric(Sys.time()))
}

as_numeric_date <- function(x, name) {
  if (inherits(x, "POSIXct")) {
    x <- floor(as.numeric(x))
  }
  if (!is.numeric(x) || length(x) != 1L || !is.finite(x)) {
    abort_zujose(
      "argument",
      sprintf("`%s` must be a time or a number of seconds.", name)
    )
  }
  # jwt_decode() refuses a NumericDate POSIXct cannot hold (#127), so a
  # token that carries one is not written either.
  if (is.na(as.POSIXlt(as_posixct(x)))) {
    abort_zujose(
      "argument",
      sprintf("`%s` is beyond any time R can represent.", name)
    )
  }
  unname(x)
}

as_seconds <- function(x, name) {
  if (inherits(x, "difftime")) {
    x <- as.numeric(x, units = "secs")
  }
  if (!is.numeric(x) || length(x) != 1L || !is.finite(x)) {
    abort_zujose(
      "argument",
      sprintf("`%s` must be a number of seconds or a difftime.", name)
    )
  }
  round(unname(x))
}

as_posixct <- function(x) {
  as.POSIXct(x, origin = "1970-01-01", tz = "UTC")
}

abort_missing <- function(name, call) {
  abort_claim(
    "missing_claim",
    sprintf("The token has no `%s` claim.", name),
    claim = name,
    call = call
  )
}

abort_time <- function(leaf, message, claim, time, now, call) {
  abort_claim(
    leaf,
    message,
    claim = claim,
    time = as_posixct(time),
    now = as_posixct(now),
    call = call
  )
}

#' @export
print.jwt_claims <- function(x, ...) {
  header <- attr(x, "header")
  cat(sprintf(
    "<jwt_claims> verified %s%s\n",
    member(header, "alg"),
    if (!is.null(member(header, "kid"))) {
      paste0(", key ", encodeString(member(header, "kid"), quote = '"'))
    } else {
      ""
    }
  ))
  claims <- unclass(x)
  attr(claims, "header") <- NULL
  values <- vapply(
    claims,
    function(v) {
      if (inherits(v, "POSIXct")) {
        format(v, "%Y-%m-%d %H:%M:%S UTC", tz = "UTC")
      } else {
        text <- zujson::json_write(v)
        if (nchar(text) > 60L) paste0(substr(text, 1L, 57L), "...") else text
      }
    },
    ""
  )
  cat(sprintf("  %s: %s\n", names(claims), values), sep = "")
  invisible(x)
}
