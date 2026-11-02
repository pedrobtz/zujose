# The codec layer (design §6): split, decode and parse a compact or JSON
# serialization into a `jose_object`, applying the header rules of §8.1 and
# the limits of §9. No key is touched here, and nothing is trusted: the
# result only says the token is well formed.
#
# A jose_object is a list:
#
# * JWS: `type`, `serialization`, `payload_b64` (as received, or NULL when
#   detached), `payload` (raw, or NULL), `b64`, and `signatures`, a list of
#   `protected_b64` (as received), `protected`, `header` and `signature`.
# * JWE: `type`, `serialization`, `protected_b64`, `protected`,
#   `unprotected`, `aad_b64` and `aad` (NULL when absent), `iv`,
#   `ciphertext`, `tag`, and `recipients`, a list of `header` and
#   `encrypted_key`.
#
# Signing input and AAD are always rebuilt from the `*_b64` fields, never
# from a re-serialized header.

# RFC 7515 §4.1, RFC 7516 §4.1 and RFC 7518 §4.6.1, §4.7.1, §4.8.1.
registered_headers <- c(
  "alg",
  "jku",
  "jwk",
  "kid",
  "x5u",
  "x5c",
  "x5t",
  "x5t#S256",
  "typ",
  "cty",
  "crit",
  "enc",
  "zip",
  "epk",
  "apu",
  "apv",
  "iv",
  "tag",
  "p2s",
  "p2c"
)

# Extensions zujwt implements, and so may appear in `crit`.
understood_crit <- "b64"

jose_parse <- function(token, limits, call = NULL) {
  check_limits(limits)
  if (!is.character(token) || length(token) != 1L || is.na(token)) {
    abort_zujwt("parse", "`token` must be a single string.", call = call)
  }
  if (nchar(token, type = "bytes") > limits$token) {
    abort_zujwt(
      "parse",
      "The token is longer than `limits$token` allows.",
      call = call
    )
  }

  if (grepl("^[[:space:]]*\\{", token)) {
    obj <- json_object(token, "token", call)
    if ("ciphertext" %in% names(obj)) {
      parse_jwe_json(obj, limits, call)
    } else {
      parse_jws_json(obj, limits, call)
    }
  } else {
    parts <- strsplit(paste0(token, "."), ".", fixed = TRUE)[[1]]
    switch(
      as.character(length(parts)),
      "3" = parse_jws_compact(parts, limits, call),
      "5" = parse_jwe_compact(parts, limits, call),
      abort_zujwt(
        "parse",
        sprintf(
          "A compact token has 3 parts (JWS) or 5 (JWE), not %d.",
          length(parts)
        ),
        call = call
      )
    )
  }
}

# JWS ---------------------------------------------------------------------

parse_jws_compact <- function(parts, limits, call) {
  protected <- parse_protected(parts[[1]], limits, call)
  check_headers(protected, list(), "JWS", call)
  require_member(protected, "alg", "header", call)
  b64 <- !identical(member(protected, "b64"), FALSE)

  new_jose_object(
    type = "JWS",
    serialization = "compact",
    payload_b64 = parts[[2]],
    payload = decode_payload(parts[[2]], b64, limits, call),
    b64 = b64,
    signatures = list(list(
      protected_b64 = parts[[1]],
      protected = protected,
      header = empty_object(),
      signature = b64url_decode(parts[[3]], "signature", call)
    ))
  )
}

parse_jws_json <- function(obj, limits, call) {
  flattened_members <- c("protected", "header", "signature")
  general <- "signatures" %in% names(obj)
  if (general && any(flattened_members %in% names(obj))) {
    abort_zujwt(
      "parse",
      "The token mixes the general and flattened JSON serializations.",
      call = call
    )
  }

  entries <- if (general) {
    json_array(obj[["signatures"]], "`signatures`", limits$signatures, call)
  } else {
    list(obj[intersect(flattened_members, names(obj))])
  }

  signatures <- lapply(entries, function(entry) {
    if (!is_json_object(entry)) {
      abort_zujwt(
        "parse",
        "A signature entry is not a JSON object.",
        call = call
      )
    }
    protected_b64 <- json_string(entry, "protected", call, optional = TRUE)
    protected <- if (nzchar(protected_b64)) {
      parse_protected(protected_b64, limits, call)
    } else {
      empty_object()
    }
    header <- json_header(entry, "header", call)
    check_headers(protected, list(header), "JWS", call)
    require_member(c(protected, header), "alg", "header", call)
    list(
      protected_b64 = protected_b64,
      protected = protected,
      header = header,
      signature = b64url_decode(
        json_string(entry, "signature", call),
        "signature",
        call
      )
    )
  })

  b64 <- unique(vapply(
    signatures,
    function(s) !identical(member(s$protected, "b64"), FALSE),
    logical(1)
  ))
  if (length(b64) != 1L) {
    abort_zujwt(
      "parse",
      "The signatures disagree on `b64`.",
      call = call
    )
  }

  payload_b64 <- if ("payload" %in% names(obj)) {
    json_string(obj, "payload", call)
  }
  new_jose_object(
    type = "JWS",
    serialization = if (general) "general" else "flattened",
    payload_b64 = payload_b64,
    payload = if (!is.null(payload_b64)) {
      decode_payload(payload_b64, b64, limits, call)
    },
    b64 = b64,
    signatures = signatures
  )
}

decode_payload <- function(text, b64, limits, call) {
  if (b64) {
    if (nchar(text, type = "bytes") > b64url_max_chars(limits$payload)) {
      abort_payload_limit(call)
    }
    return(b64url_decode(text, "payload", call))
  }
  bytes <- charToRaw(enc2utf8(text))
  if (length(bytes) > limits$payload) {
    abort_payload_limit(call)
  }
  bytes
}

abort_payload_limit <- function(call) {
  abort_zujwt(
    "parse",
    "The payload is longer than `limits$payload` allows.",
    call = call
  )
}

# JWE ---------------------------------------------------------------------

parse_jwe_compact <- function(parts, limits, call) {
  protected <- parse_protected(parts[[1]], limits, call)
  check_headers(protected, list(), "JWE", call)
  require_member(protected, "alg", "header", call)
  require_member(protected, "enc", "header", call)

  new_jose_object(
    type = "JWE",
    serialization = "compact",
    protected_b64 = parts[[1]],
    protected = protected,
    unprotected = empty_object(),
    aad_b64 = NULL,
    aad = NULL,
    iv = b64url_decode(parts[[3]], "initialization vector", call),
    ciphertext = decode_ciphertext(parts[[4]], limits, call),
    tag = b64url_decode(parts[[5]], "authentication tag", call),
    recipients = list(list(
      header = empty_object(),
      encrypted_key = b64url_decode(parts[[2]], "encrypted key", call)
    ))
  )
}

parse_jwe_json <- function(obj, limits, call) {
  flattened_members <- c("header", "encrypted_key")
  general <- "recipients" %in% names(obj)
  if (general && any(flattened_members %in% names(obj))) {
    abort_zujwt(
      "parse",
      "The token mixes the general and flattened JSON serializations.",
      call = call
    )
  }

  # Counted before anything is decoded.
  entries <- if (general) {
    json_array(obj[["recipients"]], "`recipients`", limits$recipients, call)
  } else {
    list(obj[intersect(flattened_members, names(obj))])
  }

  protected_b64 <- json_string(obj, "protected", call, optional = TRUE)
  protected <- if (nzchar(protected_b64)) {
    parse_protected(protected_b64, limits, call)
  } else {
    empty_object()
  }
  unprotected <- json_header(obj, "unprotected", call)

  recipients <- lapply(entries, function(entry) {
    if (!is_json_object(entry)) {
      abort_zujwt(
        "parse",
        "A recipient entry is not a JSON object.",
        call = call
      )
    }
    header <- json_header(entry, "header", call)
    check_headers(protected, list(unprotected, header), "JWE", call)
    merged <- c(protected, unprotected, header)
    require_member(merged, "alg", "header", call)
    require_member(merged, "enc", "header", call)
    list(
      header = header,
      encrypted_key = b64url_decode(
        json_string(entry, "encrypted_key", call, optional = TRUE),
        "encrypted key",
        call
      ),
      enc = merged[["enc"]]
    )
  })

  if (length(unique(vapply(recipients, `[[`, "", "enc"))) != 1L) {
    abort_zujwt(
      "parse",
      "The recipients disagree on `enc`.",
      call = call
    )
  }
  recipients <- lapply(recipients, `[`, c("header", "encrypted_key"))

  aad_b64 <- if ("aad" %in% names(obj)) json_string(obj, "aad", call)
  new_jose_object(
    type = "JWE",
    serialization = if (general) "general" else "flattened",
    protected_b64 = protected_b64,
    protected = protected,
    unprotected = unprotected,
    aad_b64 = aad_b64,
    aad = if (!is.null(aad_b64)) {
      b64url_decode(aad_b64, "additional authenticated data", call)
    },
    iv = b64url_decode(
      json_string(obj, "iv", call),
      "initialization vector",
      call
    ),
    ciphertext = decode_ciphertext(
      json_string(obj, "ciphertext", call),
      limits,
      call
    ),
    tag = b64url_decode(
      json_string(obj, "tag", call),
      "authentication tag",
      call
    ),
    recipients = recipients
  )
}

decode_ciphertext <- function(text, limits, call) {
  if (nchar(text, type = "bytes") > b64url_max_chars(limits$payload)) {
    abort_payload_limit(call)
  }
  b64url_decode(text, "ciphertext", call)
}

# Headers -----------------------------------------------------------------

parse_protected <- function(text, limits, call) {
  if (nchar(text, type = "bytes") > b64url_max_chars(limits$header)) {
    abort_zujwt(
      "parse",
      "The protected header is longer than `limits$header` allows.",
      call = call
    )
  }
  bytes <- b64url_decode(text, "protected header", call)
  if (length(bytes) == 0L) {
    abort_zujwt("parse", "The protected header is empty.", call = call)
  }
  if (!isTRUE(zuutf::utf_valid(bytes))) {
    abort_zujwt(
      "parse",
      "The protected header is not valid UTF-8.",
      call = call
    )
  }
  json_object(bytes, "protected header", call)
}

# RFC 7515 §4.1.11 and §7.2.1, RFC 7516 §7.2.1, RFC 7797 §3 and §6.
check_headers <- function(protected, unprotected, type, call) {
  all_names <- c(names(protected), unlist(lapply(unprotected, names)))
  if (anyDuplicated(all_names)) {
    abort_zujwt(
      "parse",
      "A header member appears in more than one header.",
      call = call
    )
  }
  for (header in unprotected) {
    if (any(c("crit", "b64") %in% names(header))) {
      abort_zujwt(
        "parse",
        "`crit` and `b64` must be in the protected header.",
        call = call
      )
    }
  }

  for (name in c("alg", "enc", "kid", "typ", "cty")) {
    for (header in c(list(protected), unprotected)) {
      value <- member(header, name)
      if (!is.null(value) && !is_string(value)) {
        abort_zujwt(
          "parse",
          sprintf("The `%s` header must be a string.", name),
          call = call
        )
      }
    }
  }

  if ("b64" %in% names(protected)) {
    if (type != "JWS") {
      abort_zujwt("parse", "`b64` applies only to a JWS.", call = call)
    }
    b64 <- protected[["b64"]]
    if (!is.logical(b64) || length(b64) != 1L || is.na(b64)) {
      abort_zujwt("parse", "The `b64` header must be a boolean.", call = call)
    }
  }

  crit <- member(protected, "crit")
  if ("crit" %in% names(protected)) {
    names_ok <- is.list(crit) &&
      is.null(names(crit)) &&
      length(crit) > 0L &&
      all(vapply(crit, is_string, logical(1)))
    if (!names_ok) {
      abort_zujwt(
        "parse",
        "`crit` must be a non-empty array of strings.",
        call = call
      )
    }
    crit <- unlist(crit)
    if (anyDuplicated(crit) || any(crit %in% registered_headers)) {
      abort_zujwt(
        "parse",
        "`crit` repeats a name or lists a registered header.",
        call = call
      )
    }
    if (!all(crit %in% understood_crit)) {
      abort_zujwt(
        "parse",
        "`crit` lists an extension zujwt does not implement.",
        call = call
      )
    }
    if (!all(crit %in% all_names)) {
      abort_zujwt(
        "parse",
        "`crit` lists a header that is not present.",
        call = call
      )
    }
  }
  if ("b64" %in% names(protected) && !"b64" %in% crit) {
    abort_zujwt("parse", "`b64` must be listed in `crit`.", call = call)
  }
  invisible()
}

require_member <- function(header, name, what, call) {
  if (!is_string(member(header, name))) {
    abort_zujwt(
      "parse",
      sprintf("The %s has no `%s`.", what, name),
      call = call
    )
  }
}

# JSON helpers ------------------------------------------------------------

json_object <- function(x, what, call) {
  parsed <- tryCatch(
    if (is.raw(x)) {
      zujson::json_parse_raw(x, simplify = "none")
    } else {
      zujson::json_parse(x, simplify = "none")
    },
    zujson_error = function(e) {
      abort_zujwt(
        "parse",
        sprintf("The %s is not valid JSON.", what),
        call = call
      )
    }
  )
  if (!is_json_object(parsed)) {
    abort_zujwt(
      "parse",
      sprintf("The %s is not a JSON object.", what),
      call = call
    )
  }
  if (has_repeated_names(parsed)) {
    abort_zujwt(
      "parse",
      sprintf("The %s repeats a member name.", what),
      call = call
    )
  }
  parsed
}

json_array <- function(x, what, limit, call) {
  if (!is.list(x) || !is.null(names(x)) || length(x) == 0L) {
    abort_zujwt(
      "parse",
      sprintf("%s must be a non-empty JSON array.", what),
      call = call
    )
  }
  if (length(x) > limit) {
    abort_zujwt(
      "parse",
      sprintf("%s has more entries than the limits allow.", what),
      call = call
    )
  }
  x
}

json_string <- function(obj, name, call, optional = FALSE) {
  value <- member(obj, name)
  if (is.null(value) && optional) {
    return("")
  }
  if (!is_string(value)) {
    abort_zujwt(
      "parse",
      sprintf("`%s` must be a string.", name),
      call = call
    )
  }
  value
}

json_header <- function(obj, name, call) {
  value <- member(obj, name)
  if (is.null(value)) {
    return(empty_object())
  }
  if (!is_json_object(value)) {
    abort_zujwt(
      "parse",
      sprintf("`%s` must be a JSON object.", name),
      call = call
    )
  }
  value
}

# Exact member lookup: `$` would partially match.
member <- function(x, name) {
  if (name %in% names(x)) x[[name]] else NULL
}

is_json_object <- function(x) {
  is.list(x) && !is.null(names(x))
}

is_string <- function(x) {
  is.character(x) && length(x) == 1L && !is.na(x)
}

has_repeated_names <- function(x) {
  if (!is.list(x)) {
    return(FALSE)
  }
  if (!is.null(names(x)) && anyDuplicated(names(x))) {
    return(TRUE)
  }
  any(vapply(x, has_repeated_names, logical(1)))
}

empty_object <- function() {
  stats::setNames(list(), character())
}

new_jose_object <- function(...) {
  structure(list(...), class = "jose_object")
}
