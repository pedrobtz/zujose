# Keys (design §7.2, §8.3).
#
# A jose_key is a list of class "jose_key" with:
#
# * `kty`, `kid`, `alg`, `use`, `key_ops`: the JWK's common members, NULL
#   when absent;
# * `k`: for an oct key, the secret as a raw vector;
# * `members`: every other member as read, so that a key zujwt cannot use
#   yet (RSA, EC, OKP before their stages) can still be listed, selected,
#   written and thumbprinted;
# * `supported`: whether the installed zujwt can use the key, and `needs`,
#   the zucrypt version that would make it usable.

# RFC 7517 §4.3.
key_operations <- c(
  "sign",
  "verify",
  "encrypt",
  "decrypt",
  "wrapKey",
  "unwrapKey",
  "deriveKey",
  "deriveBits"
)

# Members that hold secrets (RFC 7518 §6.2.2, §6.3.2, §6.4; RFC 8037 §2).
private_members <- c("d", "p", "q", "dp", "dq", "qi", "oth", "k")

# Key types zujwt reads but cannot use yet, and the zucrypt that adds them.
pending_key_types <- c(RSA = "0.4.0", EC = "0.5.0", OKP = "0.5.0")

#' Make a symmetric key
#'
#' `jose_key_oct()` wraps a secret as a JSON Web Key of type `oct` (RFC 7518
#' section 6.4), the key type of the `HS*`, `A*KW`, `A*GCMKW` and `dir`
#' algorithms.
#'
#' The secret is a raw vector, never a string: a key is bytes, and a
#' password is not a key. Secrets live in ordinary R memory, which R can
#' copy and cannot reliably wipe; keep long-lived secrets out of saved
#' workspaces.
#'
#' @param secret The key, as a raw vector of at least one byte.
#' @param alg The one algorithm the key is meant for, such as `"HS256"`, or
#'   `NULL`. When set, a token whose `alg` differs is refused.
#' @param kid A key identifier, or `NULL`. See [jose_with_kid()].
#' @param use `"sig"` or `"enc"`, or `NULL`.
#' @param key_ops The operations the key may be used for, from `"sign"`,
#'   `"verify"`, `"encrypt"`, `"decrypt"`, `"wrapKey"`, `"unwrapKey"`,
#'   `"deriveKey"` and `"deriveBits"`, or `NULL`.
#' @returns A `jose_key`.
#' @seealso [as_jose_key()] to read a JWK, [jose_jwk()] to write one.
#' @export
#' @examples
#' key <- jose_key_oct(as.raw(1:32), alg = "HS256", kid = "k1")
#' key
jose_key_oct <- function(
  secret,
  alg = NULL,
  kid = NULL,
  use = NULL,
  key_ops = NULL
) {
  call <- sys.call()
  if (!is.raw(secret) || length(secret) == 0L) {
    abort_zujwt(
      "key",
      "`secret` must be a raw vector of at least one byte.",
      call = call
    )
  }
  new_jose_key(
    kty = "oct",
    k = secret,
    kid = kid,
    alg = alg,
    use = use,
    key_ops = key_ops,
    call = call
  )
}

new_jose_key <- function(
  kty,
  k = NULL,
  kid = NULL,
  alg = NULL,
  use = NULL,
  key_ops = NULL,
  members = empty_object(),
  call = NULL
) {
  for (name in c("kid", "alg", "use")) {
    value <- get(name)
    if (!is.null(value) && !is_string(value)) {
      abort_zujwt(
        "key",
        sprintf("`%s` must be a single string.", name),
        call = call
      )
    }
  }
  if (!is.null(key_ops)) {
    ok <- is.character(key_ops) &&
      !anyNA(key_ops) &&
      !anyDuplicated(key_ops) &&
      all(key_ops %in% key_operations)
    if (!ok) {
      abort_zujwt(
        "key",
        "`key_ops` must name distinct operations from RFC 7517 section 4.3.",
        call = call
      )
    }
  }
  needs <- unname(pending_key_types[kty])
  structure(
    list(
      kty = kty,
      kid = kid,
      alg = alg,
      use = use,
      key_ops = key_ops,
      k = k,
      members = members,
      supported = kty == "oct",
      needs = if (kty != "oct") needs
    ),
    class = "jose_key"
  )
}

#' Read a JSON Web Key
#'
#' `as_jose_key()` reads a JWK (RFC 7517) from its JSON text or from a list
#' already parsed. A raw vector is taken as an `oct` secret, as by
#' [jose_key_oct()].
#'
#' Keys of type `RSA`, `EC` and `OKP` are read and kept, so they can be
#' listed, selected, written and thumbprinted, but using one before zujwt
#' supports it raises `zujwt_unsupported_error`.
#'
#' @param x JWK text, a parsed JWK as a named list, a raw secret, or a
#'   `jose_key`.
#' @param ... Not used.
#' @returns A `jose_key`.
#' @export
#' @examples
#' key <- as_jose_key(
#'   '{"kty":"oct","kid":"k1","alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}'
#' )
#' key
as_jose_key <- function(x, ...) {
  UseMethod("as_jose_key")
}

#' @export
as_jose_key.jose_key <- function(x, ...) {
  x
}

#' @export
as_jose_key.raw <- function(x, ...) {
  jose_key_oct(x)
}

#' @export
as_jose_key.character <- function(x, ...) {
  call <- sys.call(-1)
  if (!is_string(x)) {
    abort_zujwt("key", "A JWK must be a single string.", call = call)
  }
  if (grepl("^[[:space:]]*-----BEGIN", x)) {
    abort_unsupported("PEM", pending_key_types[["RSA"]], call = call)
  }
  jwk_to_key(json_key_object(x, "JWK", call), call)
}

#' @export
as_jose_key.list <- function(x, ...) {
  call <- sys.call(-1)
  if (!is_json_object(x) || has_repeated_names(x)) {
    abort_zujwt(
      "key",
      "A JWK must be a named list without repeated names.",
      call = call
    )
  }
  jwk_to_key(x, call)
}

#' @export
as_jose_key.default <- function(x, ...) {
  abort_zujwt(
    "key",
    "Can't read a key from this object.",
    call = sys.call(-1)
  )
}

json_key_object <- function(text, what, call) {
  tryCatch(
    json_object(text, what, call),
    zujwt_parse_error = function(e) {
      abort_zujwt("key", conditionMessage(e), call = call)
    }
  )
}

jwk_to_key <- function(jwk, call) {
  kty <- member(jwk, "kty")
  if (!is_string(kty)) {
    abort_zujwt("key", "A JWK must have a string `kty`.", call = call)
  }
  key_ops <- member(jwk, "key_ops")
  if (!is.null(key_ops)) {
    if (!is.list(key_ops) || !all(vapply(key_ops, is_string, logical(1)))) {
      abort_zujwt("key", "`key_ops` must be an array of strings.", call = call)
    }
    key_ops <- unlist(key_ops)
  }
  common <- c("kty", "kid", "alg", "use", "key_ops")
  members <- jwk[setdiff(names(jwk), common)]

  k <- NULL
  if (kty == "oct") {
    k_text <- member(jwk, "k")
    if (!is_string(k_text) || !nzchar(k_text)) {
      abort_zujwt("key", "An oct JWK must have a non-empty `k`.", call = call)
    }
    k <- tryCatch(
      b64url_decode(k_text, "key value", call),
      zujwt_parse_error = function(e) {
        abort_zujwt("key", conditionMessage(e), call = call)
      }
    )
    members <- members[setdiff(names(members), "k")]
  } else {
    strings <- vapply(
      members[intersect(names(members), c("n", "e", "crv", "x", "y", "d"))],
      is_string,
      logical(1)
    )
    if (!all(strings)) {
      abort_zujwt(
        "key",
        "The key members of a JWK must be strings.",
        call = call
      )
    }
  }

  new_jose_key(
    kty = kty,
    k = k,
    kid = member(jwk, "kid"),
    alg = member(jwk, "alg"),
    use = member(jwk, "use"),
    key_ops = key_ops,
    members = members,
    call = call
  )
}

#' Set a key's identifier
#'
#' `jose_with_kid()` sets `kid`, by default to the key's RFC 7638
#' thumbprint, which is stable and needs no registry.
#'
#' @param key A `jose_key`.
#' @param kid The identifier.
#' @returns The key, with `kid` set.
#' @export
#' @examples
#' key <- jose_with_kid(jose_key_oct(as.raw(1:32)))
#' key$kid
jose_with_kid <- function(key, kid = jose_thumbprint(key)) {
  key <- check_key(key, sys.call())
  if (!is_string(kid)) {
    abort_zujwt("key", "`kid` must be a single string.", call = sys.call())
  }
  key$kid <- kid
  key
}

#' Write a key or key set as JSON
#'
#' `jose_jwk()` writes a `jose_key` as a JWK, or a `jose_keyset` as a JWK
#' Set, in compact JSON. By default only public members are written, so the
#' result is safe to publish; a symmetric (`oct`) key has no public part,
#' and is refused alone or dropped from a set.
#'
#' @param x A `jose_key` or `jose_keyset`.
#' @param private Whether to write private members, including the secrets
#'   of `oct` keys.
#' @returns A single string.
#' @export
#' @examples
#' key <- jose_key_oct(as.raw(1:32), alg = "HS256", kid = "k1")
#' jose_jwk(key, private = TRUE)
jose_jwk <- function(x, private = FALSE) {
  call <- sys.call()
  if (!isTRUE(private) && !isFALSE(private)) {
    abort_zujwt("key", "`private` must be TRUE or FALSE.", call = call)
  }
  if (!private) {
    x <- jose_public(x)
  }
  if (inherits(x, "jose_keyset")) {
    zujson::json_write(list(keys = lapply(unclass(x), key_to_jwk)))
  } else {
    zujson::json_write(key_to_jwk(check_key(x, call)))
  }
}

key_to_jwk <- function(key) {
  jwk <- list(kty = key$kty)
  if (!is.null(key$k)) {
    jwk$k <- b64url_encode(key$k)
  }
  jwk <- c(jwk, key$members)
  for (name in c("kid", "alg", "use")) {
    if (!is.null(key[[name]])) jwk[[name]] <- key[[name]]
  }
  if (!is.null(key$key_ops)) {
    jwk$key_ops <- as.list(key$key_ops)
  }
  jwk
}

#' The public part of a key or key set
#'
#' `jose_public()` removes private members: `d`, `p`, `q`, `dp`, `dq`,
#' `qi` and `oth`. A symmetric (`oct`) key is entirely secret, so it is an
#' error alone and dropped from a key set.
#'
#' @param x A `jose_key` or `jose_keyset`.
#' @returns An object of the same class.
#' @export
#' @examples
#' set <- as_jose_keyset('{"keys":[{"kty":"oct","k":"AAAA"}]}')
#' length(jose_public(set))
jose_public <- function(x) {
  call <- sys.call()
  if (inherits(x, "jose_keyset")) {
    keys <- Filter(function(key) key$kty != "oct", unclass(x))
    return(new_jose_keyset(lapply(keys, public_key)))
  }
  key <- check_key(x, call)
  if (key$kty == "oct") {
    abort_zujwt(
      "key",
      "A symmetric (oct) key has no public part.",
      call = call
    )
  }
  public_key(key)
}

public_key <- function(key) {
  key$members <- key$members[setdiff(names(key$members), private_members)]
  key
}

check_key <- function(key, call) {
  if (!inherits(key, "jose_key")) {
    abort_zujwt("key", "`key` must be a jose_key.", call = call)
  }
  key
}

#' @export
format.jose_key <- function(x, ...) {
  bits <- if (!is.null(x$k)) sprintf(", %d bits", 8L * length(x$k)) else ""
  fields <- c(
    if (!is.null(x$kid)) sprintf("kid %s", encodeString(x$kid, quote = '"')),
    if (!is.null(x$alg)) sprintf("alg %s", x$alg),
    if (!is.null(x$use)) sprintf("use %s", x$use),
    if (!is.null(x$key_ops)) {
      sprintf("key_ops %s", paste(x$key_ops, collapse = ", "))
    }
  )
  lines <- sprintf("<jose_key> %s%s", x$kty, bits)
  if (length(fields)) {
    lines <- c(lines, paste0("  ", fields))
  }
  secret <- !is.null(x$k) || any(names(x$members) %in% private_members)
  if (secret) {
    lines <- c(lines, "  private: yes (not shown)")
  }
  if (!x$supported) {
    lines <- c(
      lines,
      sprintf("  ! not usable yet: needs zucrypt (>= %s)", x$needs %||% "?")
    )
  }
  lines
}

#' @export
print.jose_key <- function(x, ...) {
  cat(format(x), sep = "\n")
  invisible(x)
}

`%||%` <- function(x, y) if (is.null(x)) y else x
