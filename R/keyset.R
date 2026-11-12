#' Key sets
#'
#' A `jwk_set` holds several keys, as a JWK Set does (RFC 7517 section
#' 5). Select one by `kid` with `[[`, or several with `[`; combine with
#' `c()` or `jwk_set()`.
#'
#' `as_jwk_set()` reads a JWK Set from its JSON text or from a parsed
#' list. Following RFC 7517 section 5, a member of `keys` that is not a
#' well-formed JWK object is ignored rather than failing the whole set, as
#' is a key of a type zujose does not know. A string member is not read as
#' JWK text or PEM. A key of a known type that zujose cannot
#' use, such as an Ed25519 `OKP` key, is kept: it can be listed, selected
#' and thumbprinted, and using it raises `zujose_unsupported_error`.
#'
#' @param ... `jwk` and `jwk_set` objects, combined in order.
#' @param x JWK Set text, a parsed JWK Set, or a `jwk_set`.
#' @returns A `jwk_set`.
#' @export
#' @examples
#' set <- jwk_set(
#'   jwk_oct(as.raw(1:32), kid = "a"),
#'   jwk_oct(as.raw(33:64), kid = "b")
#' )
#' set[["b"]]
#' length(set)
jwk_set <- function(...) {
  combine_keys(list(...), sys.call())
}

# The body of jwk_set(), shared with its c() methods.
combine_keys <- function(items, call) {
  keys <- list()
  for (item in items) {
    if (inherits(item, "jwk_set")) {
      keys <- c(keys, unclass(item))
    } else if (inherits(item, "jwk")) {
      keys <- c(keys, list(item))
    } else {
      abort_zujose(
        "argument",
        "`...` must hold jwk or jwk_set objects.",
        call = call
      )
    }
  }
  new_jwk_set(keys)
}

new_jwk_set <- function(keys) {
  structure(unname(keys), class = "jwk_set")
}

#' @rdname jwk_set
#' @export
as_jwk_set <- function(x) {
  call <- sys.call()
  if (inherits(x, "jwk_set")) {
    return(x)
  }
  json <- is.character(x)
  if (json) {
    if (!is_string(x)) {
      abort_zujose(
        "argument",
        "A JWK Set must be a single string.",
        call = call
      )
    }
    x <- json_key_object(x, "JWK Set", call)
  } else if (!is.list(x)) {
    abort_zujose(
      "argument",
      "`x` must be JWK Set text, a parsed JWK Set or a jwk_set.",
      call = call
    )
  }
  if (!is_json_object(x) || has_repeated_names(x)) {
    abort_zujose(
      "key",
      "A JWK Set must be a JSON object without repeated names.",
      call = call
    )
  }
  entries <- member(x, "keys")
  if (!is.list(entries) || !is.null(names(entries))) {
    abort_zujose("key", "A JWK Set must have a `keys` array.", call = call)
  }
  known <- c("oct", names(pending_key_types))
  # RFC 7517 §5: each member of `keys` is a JWK object. A string is not
  # read as PEM or JWK text; it is skipped like any other bad entry (#44).
  keys <- lapply(entries, function(entry) {
    if (!is_json_object(entry)) {
      return(NULL)
    }
    key <- tryCatch(
      list_to_key(entry, call, json),
      zujose_key_error = function(e) NULL
    )
    if (!is.null(key) && key$kty %in% known) key
  })
  new_jwk_set(Filter(Negate(is.null), keys))
}

#' @export
`[[.jwk_set` <- function(x, i) {
  keys <- unclass(x)
  if (!is.character(i)) {
    ok <- is.numeric(i) &&
      length(i) == 1L &&
      !is.na(i) &&
      i == trunc(i) &&
      i >= 1 &&
      i <= length(keys)
    if (!ok) {
      abort_zujose(
        "argument",
        "Select a key with one index in the set, or a `kid`.",
        call = sys.call()
      )
    }
    return(keys[[i]])
  }
  if (!is_string(i)) {
    abort_zujose(
      "argument",
      "Select a key with a single `kid`.",
      call = sys.call()
    )
  }
  kids <- vapply(keys, function(key) key$kid %||% NA_character_, "")
  found <- which(kids == i)
  if (length(found) != 1L) {
    abort_zujose(
      "key",
      if (length(found) == 0L) {
        "No key in the set has this `kid`."
      } else {
        "Several keys in the set have this `kid`."
      },
      call = sys.call()
    )
  }
  keys[[found]]
}

#' @export
`[.jwk_set` <- function(x, i) {
  keys <- unclass(x)
  if (missing(i)) {
    return(x)
  }
  if (is.character(i)) {
    kids <- vapply(keys, function(key) key$kid %||% NA_character_, "")
    i <- which(kids %in% i)
  }
  # An NA or out-of-range index would put NULL in the set (#135).
  out <- if (!anyNA(i)) keys[i]
  if (anyNA(i) || any(vapply(out, is.null, logical(1)))) {
    abort_zujose(
      "argument",
      "Select keys with indices or `kid`s in the set, without NA.",
      call = sys.call()
    )
  }
  new_jwk_set(out)
}

#' @export
c.jwk_set <- function(...) {
  combine_keys(list(...), sys.call())
}

#' @export
c.jwk <- function(...) {
  combine_keys(list(...), sys.call())
}

#' @export
format.jwk_set <- function(x, ...) {
  keys <- unclass(x)
  head <- sprintf(
    "<jwk_set> %d key%s",
    length(keys),
    if (length(keys) == 1L) "" else "s"
  )
  rows <- vapply(
    keys,
    function(key) {
      paste0(
        "  ",
        key$kty,
        if (!is.null(key$kid)) {
          paste0(" ", encodeString(key$kid, quote = '"'))
        },
        if (!is.null(key$alg)) paste0(" ", key$alg),
        if (!key$supported) " (not usable yet)"
      )
    },
    ""
  )
  c(head, rows)
}

#' @export
print.jwk_set <- function(x, ...) {
  cat(format(x), sep = "\n")
  invisible(x)
}
