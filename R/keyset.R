#' Key sets
#'
#' A `jose_keyset` holds several keys, as a JWK Set does (RFC 7517 section
#' 5). Select one by `kid` with `[[`, or several with `[`; combine with
#' `c()` or `jose_keyset()`.
#'
#' `as_jose_keyset()` reads a JWK Set from its JSON text or from a parsed
#' list. Following RFC 7517 section 5, a member of `keys` that is not a
#' well-formed JWK is ignored rather than failing the whole set, as is a key
#' of a type zujose does not know. A key of a known type that zujose cannot
#' use, such as an Ed25519 `OKP` key, is kept: it can be listed, selected
#' and thumbprinted, and using it raises `zujose_unsupported_error`.
#'
#' @param ... `jose_key` and `jose_keyset` objects, combined in order.
#' @param x JWK Set text, a parsed JWK Set, or a `jose_keyset`.
#' @returns A `jose_keyset`.
#' @export
#' @examples
#' set <- jose_keyset(
#'   jose_key_oct(as.raw(1:32), kid = "a"),
#'   jose_key_oct(as.raw(33:64), kid = "b")
#' )
#' set[["b"]]
#' length(set)
jose_keyset <- function(...) {
  items <- list(...)
  keys <- list()
  for (item in items) {
    if (inherits(item, "jose_keyset")) {
      keys <- c(keys, unclass(item))
    } else if (inherits(item, "jose_key")) {
      keys <- c(keys, list(item))
    } else {
      abort_zujose(
        "key",
        "`...` must hold jose_key or jose_keyset objects.",
        call = sys.call()
      )
    }
  }
  new_jose_keyset(keys)
}

new_jose_keyset <- function(keys) {
  structure(unname(keys), class = "jose_keyset")
}

#' @rdname jose_keyset
#' @export
as_jose_keyset <- function(x) {
  call <- sys.call()
  if (inherits(x, "jose_keyset")) {
    return(x)
  }
  if (is.character(x)) {
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
    key <- tryCatch(as_jose_key(entry), zujose_key_error = function(e) NULL)
    if (!is.null(key) && key$kty %in% known) key
  })
  new_jose_keyset(Filter(Negate(is.null), keys))
}

#' @export
`[[.jose_keyset` <- function(x, i) {
  keys <- unclass(x)
  if (!is.character(i)) {
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
`[.jose_keyset` <- function(x, i) {
  keys <- unclass(x)
  if (is.character(i)) {
    kids <- vapply(keys, function(key) key$kid %||% NA_character_, "")
    i <- which(kids %in% i)
  }
  new_jose_keyset(keys[i])
}

#' @export
c.jose_keyset <- function(...) {
  jose_keyset(...)
}

#' @export
c.jose_key <- function(...) {
  jose_keyset(...)
}

#' @export
format.jose_keyset <- function(x, ...) {
  keys <- unclass(x)
  head <- sprintf(
    "<jose_keyset> %d key%s",
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
print.jose_keyset <- function(x, ...) {
  cat(format(x), sep = "\n")
  invisible(x)
}
