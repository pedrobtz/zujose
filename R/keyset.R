#' Key sets
#'
#' A `jwk_set` holds several keys, as a JWK Set does (RFC 7517 section
#' 5). Select one by `kid` with `[[`, or several with `[`; combine with
#' `c()` or `jwk_set()`.
#'
#' `as_jwk_set()` reads a JWK Set from its JSON text or from a parsed
#' list. Following RFC 7517 section 5, a member of `keys` that is not a
#' well-formed JWK is ignored rather than failing the whole set, as is a key
#' of a type zujose does not know. A key of a known type that zujose cannot
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
  items <- list(...)
  keys <- list()
  for (item in items) {
    if (inherits(item, "jwk_set")) {
      keys <- c(keys, unclass(item))
    } else if (inherits(item, "jwk")) {
      keys <- c(keys, list(item))
    } else {
      abort_zujose(
        "key",
        "`...` must hold jwk or jwk_set objects.",
        call = sys.call()
      )
    }
  }
  new_jose_keyset(keys)
}

new_jose_keyset <- function(keys) {
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
      abort_zujose("key", "A JWK Set must be a single string.", call = call)
    }
    x <- json_key_object(x, "JWK Set", call)
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
  keys <- lapply(entries, function(entry) {
    key <- tryCatch(
      if (is.list(entry)) list_to_key(entry, call, json) else as_jwk(entry),
      zujose_key_error = function(e) NULL
    )
    if (!is.null(key) && key$kty %in% known) key
  })
  new_jose_keyset(Filter(Negate(is.null), keys))
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
    abort_zujose("key", "Select a key with a single `kid`.", call = sys.call())
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
  new_jose_keyset(out)
}

#' @export
c.jwk_set <- function(...) {
  jwk_set(...)
}

#' @export
c.jwk <- function(...) {
  jwk_set(...)
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
