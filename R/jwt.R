# JWT (design §7.5, §8.5).

#' Encode a JWT
#'
#' `jose_jwt_encode()` signs a claims set as a JSON Web Token (RFC 7519),
#' in the compact serialization.
#'
#' Times may be given as `POSIXct` for `exp`, `nbf` and `iat`, and are
#' written as NumericDate, whole seconds since 1970. `expires_in` and
#' `not_before` count from now.
#'
#' @param claims The claims, as a named list. It may be empty.
#' @inheritParams jose_sign
#' @param header Protected header members. The default declares
#'   `typ: "JWT"`.
#' @param expires_in Seconds, or a `difftime`, until the token expires. Sets
#'   `exp`.
#' @param not_before Seconds, or a `difftime`, before the token becomes
#'   valid. Sets `nbf`.
#' @param issued_at Whether to set `iat` to now, unless `claims` sets it.
#' @param jti Whether to add a random `jti`. Needs zucrypt's randomness.
#' @returns The JWT, as a single string.
#' @seealso [jose_jwt_decode()] to check one.
#' @export
#' @examples
#' key <- jose_key_oct(as.raw(1:32), kid = "k1")
#' jwt <- jose_jwt_encode(list(sub = "u1", aud = "api"), key, "HS256",
#'                        expires_in = 3600)
#' jose_jwt_decode(jwt, key, algorithms = "HS256", audience = "api")
jose_jwt_encode <- function(
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
  if (
    !is.list(claims) ||
      (length(claims) > 0L &&
        (is.null(names(claims)) ||
          !all(nzchar(names(claims))) ||
          anyDuplicated(names(claims))))
  ) {
    stop("`claims` must be a named list without repeated names.", call. = FALSE)
  }
  check_flag(issued_at, "issued_at", call)
  check_flag(jti, "jti", call)
  if (jti) {
    stop(zujwt_condition(
      "zujwt_unsupported_error",
      "A random `jti` needs zucrypt (>= 0.2.0), for its randomness.",
      algorithm = "jti",
      needs = "0.2.0",
      call = call
    ))
  }
  if (length(claims) == 0L) {
    claims <- empty_object()
  }

  now <- jwt_now()
  for (name in intersect(c("exp", "nbf", "iat"), names(claims))) {
    claims[[name]] <- as_numeric_date(claims[[name]], name)
  }
  if (!is.null(expires_in)) {
    claims[["exp"]] <- now + as_seconds(expires_in, "expires_in")
  }
  if (!is.null(not_before)) {
    claims[["nbf"]] <- now + as_seconds(not_before, "not_before")
  }
  if (issued_at && !"iat" %in% names(claims)) {
    claims[["iat"]] <- now
  }

  jose_sign(zujson::json_write(claims), key, alg = alg, header = header)
}

#' Check a JWT and return its claims
#'
#' `jose_jwt_decode()` verifies a JWT's signature with [jose_verify()]'s
#' rules and then checks its claims (RFC 7519, RFC 8725). The checks happen
#' here, in one call, so none can be forgotten.
#'
#' * `exp`, `nbf` and `iat` must be numbers. The token must not have
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
#' A JWT whose header has `cty: "JWT"` carries another JWT as its payload.
#' That inner JWT is verified with the same `key` and `algorithms`, and its
#' claims are checked. Deeper nesting is refused.
#'
#' Each failed check raises a subclass of `zujwt_claim_error` carrying the
#' claim name: `zujwt_expired_error`, `zujwt_not_yet_valid_error`,
#' `zujwt_audience_error`, `zujwt_issuer_error`, `zujwt_subject_error` or
#' `zujwt_missing_claim_error`. Time errors also carry `time` and `now`.
#'
#' @param token The JWT, in the compact serialization.
#' @inheritParams jose_verify
#' @param audience The audiences this caller accepts, or `NULL`.
#' @param issuer The issuer this caller accepts, or `NULL`.
#' @param subject The subject this caller accepts, or `NULL`.
#' @param type The expected `typ`, or `NULL` to skip the check.
#' @param required Names of claims that must be present.
#' @param claims Further expectations, as a named list of values or
#'   functions.
#' @param validate A function of the claims list that must return `TRUE`, or
#'   `NULL`.
#' @param max_age The greatest age, in seconds, of `iat`, or `NULL`.
#' @param leeway Seconds of clock skew to allow.
#' @param now The current time, as `POSIXct`.
#' @returns The claims, as a named list of class `jose_claims`, with `exp`,
#'   `nbf` and `iat` as `POSIXct` and the verified header as the `header`
#'   attribute.
#' @seealso [jose_jwt_decoder()] to fix these arguments once.
#' @export
#' @examples
#' key <- jose_key_oct(as.raw(1:32))
#' jwt <- jose_jwt_encode(list(iss = "me", aud = "api"), key, "HS256",
#'                        expires_in = 60)
#' claims <- jose_jwt_decode(jwt, key, "HS256", audience = "api",
#'                           issuer = "me")
#' claims$iss
#'
#' # Claim failures have classes of their own.
#' tryCatch(
#'   jose_jwt_decode(jwt, key, "HS256", audience = "other"),
#'   zujwt_audience_error = function(e) "wrong audience"
#' )
jose_jwt_decode <- function(
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
  if (is_string(token) && grepl("^[[:space:]]*\\{", token)) {
    abort_zujwt(
      "parse",
      "A JWT uses the compact serialization.",
      call = call
    )
  }

  verified <- verify_jws(token, key, algorithms, NULL, "all", limits, call)
  if (is_nested(verified$header)) {
    inner <- rawToChar(verified$payload)
    if (grepl("^[[:space:]]*\\{", inner)) {
      abort_zujwt("parse", "A JWT uses the compact serialization.", call = call)
    }
    verified <- verify_jws(inner, key, algorithms, NULL, "all", limits, call)
    if (is_nested(verified$header)) {
      abort_zujwt(
        "policy",
        "A JWT nested more than one level deep is refused.",
        call = call
      )
    }
  }
  header <- verified$header
  check_type(header, type, call)

  payload <- tryCatch(
    json_object(verified$payload, "claims set", call),
    zujwt_parse_error = function(e) {
      abort_zujwt("parse", "The claims set is not a JSON object.", call = call)
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
  structure(payload, header = header, class = "jose_claims")
}

#' A reusable JWT check
#'
#' `jose_jwt_decoder()` fixes the key and every check of
#' [jose_jwt_decode()] once, and returns a function of the token that
#' applies them. Use it where the same policy guards many requests.
#'
#' @inheritParams jose_jwt_decode
#' @returns A function `function(token, now = Sys.time())` returning the
#'   claims, as [jose_jwt_decode()] does.
#' @export
#' @examples
#' key <- jose_key_oct(as.raw(1:32))
#' check <- jose_jwt_decoder(key, "HS256", audience = "api", issuer = "me")
#' jwt <- jose_jwt_encode(list(iss = "me", aud = "api"), key, "HS256",
#'                        expires_in = 60)
#' check(jwt)$iss
jose_jwt_decoder <- function(
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
  limits = jose_limits()
) {
  check_algorithms(algorithms, "signature", call = sys.call())
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
    jose_jwt_decode(
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
      abort_zujwt(
        "parse",
        sprintf("The `%s` claim must be a number.", name),
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
    ok <- if (is.function(expected)) {
      isTRUE(expected(cl[[name]]))
    } else {
      identical(zujson::json_write(cl[[name]]), zujson::json_write(expected))
    }
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
    abort_zujwt(
      "policy",
      "The token's `typ` header is not `type`.",
      call = call
    )
  }
  invisible()
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
  bad <- function(what) stop(what, call. = FALSE)
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
  if (
    !is.list(claims) ||
      (length(claims) > 0L &&
        (is.null(names(claims)) || !all(nzchar(names(claims)))))
  ) {
    bad("`claims` must be a named list.")
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
    stop(
      sprintf("`%s` must be a time or a number of seconds.", name),
      call. = FALSE
    )
  }
  x
}

as_seconds <- function(x, name) {
  if (inherits(x, "difftime")) {
    x <- as.numeric(x, units = "secs")
  }
  if (!is.numeric(x) || length(x) != 1L || !is.finite(x)) {
    stop(
      sprintf("`%s` must be a number of seconds or a difftime.", name),
      call. = FALSE
    )
  }
  round(x)
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
print.jose_claims <- function(x, ...) {
  header <- attr(x, "header")
  cat(sprintf(
    "<jose_claims> verified %s%s\n",
    header$alg,
    if (!is.null(header$kid)) {
      paste0(", key ", encodeString(header$kid, quote = '"'))
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
