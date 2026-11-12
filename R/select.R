# Key resolution, shared by every function that checks a token (D9).
#
# `key` is a jwk, a jwk_set, or a resolver function(header) that
# returns either. A single key is used as given and must fit the token's
# algorithm; a key set is narrowed by the header's `kid`, when it has one,
# and then to the keys that fit (design §8.2, §8.3). Keys named in the
# token itself (`jwk`, `jku`, `x5c`, `x5u`) are never consulted (D3).

# The key types each JWA algorithm takes (RFC 7518 §3.1, §4.1).
alg_key_types <- function(alg) {
  if (
    grepl("^HS(256|384|512)$", alg) ||
      grepl("^A(128|192|256)(GCM)?KW$", alg) ||
      grepl("^PBES2-HS(256|384|512)\\+A(128|192|256)KW$", alg) ||
      identical(alg, "dir")
  ) {
    "oct"
  } else if (
    grepl("^(RS|PS)(256|384|512)$", alg) ||
      alg %in% c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5")
  ) {
    "RSA"
  } else if (grepl("^ES(256|384|512)$", alg)) {
    "EC"
  } else if (grepl("^ECDH-ES(\\+A(128|192|256)KW)?$", alg)) {
    c("EC", "OKP")
  } else {
    character()
  }
}

# The `use` value each operation belongs to (RFC 7517 §4.2, §4.3).
operation_use <- c(
  sign = "sig",
  verify = "sig",
  encrypt = "enc",
  decrypt = "enc",
  wrapKey = "enc",
  unwrapKey = "enc",
  deriveKey = "enc",
  deriveBits = "enc"
)

resolve_keys <- function(key, header, operation, limits, call = NULL) {
  if (is.function(key)) {
    key <- key(header)
    if (!inherits(key, c("jwk", "jwk_set"))) {
      abort_zujose(
        "key",
        "The key resolver must return a jwk or jwk_set.",
        call = call
      )
    }
  }
  alg <- header[["alg"]]

  if (inherits(key, "jwk")) {
    if (!key_fits(key, alg, operation, header[["enc"]])) {
      abort_zujose(
        "policy",
        "The key does not fit the token's algorithm or intended use.",
        call = call
      )
    }
    candidates <- list(key)
  } else if (inherits(key, "jwk_set")) {
    candidates <- unclass(key)
    kid <- member(header, "kid")
    if (!is.null(kid)) {
      candidates <- Filter(function(k) identical(k$kid, kid), candidates)
    }
    candidates <- Filter(
      function(k) key_fits(k, alg, operation, header[["enc"]]),
      candidates
    )
    if (length(candidates) == 0L) {
      abort_zujose(
        "key",
        "No key in the set fits the token's `kid` and algorithm.",
        call = call
      )
    }
  } else {
    check_key_arg(key, call)
  }

  usable <- Filter(function(k) k$supported, candidates)
  if (length(usable) == 0L) {
    abort_unsupported(alg, candidates[[1]]$needs, call = call)
  }
  if (length(usable) > limits$keys) {
    abort_zujose(
      "key",
      "More keys fit the token than `limits$keys` allows.",
      call = call
    )
  }
  usable
}

# A verifying or decrypting `key` argument: a jwk, a jwk_set or a resolver.
# Its type is the caller's code, so a wrong one is an argument error (#78).
check_key_arg <- function(key, call) {
  if (!is.function(key) && !inherits(key, c("jwk", "jwk_set"))) {
    abort_zujose(
      "argument",
      "`key` must be a jwk, a jwk_set or a resolver function.",
      call = call
    )
  }
  invisible(key)
}

# Design §8.2: ES256 only with P-256, ES384 with P-384, ES512 with P-521;
# ECDH-ES with a NIST curve or X25519.
curve_fits <- function(key, alg) {
  crv <- key$members[["crv"]]
  if (grepl("^ES(256|384|512)$", alg)) {
    want <- c(ES256 = "P-256", ES384 = "P-384", ES512 = "P-521")[[alg]]
    return(identical(crv, want))
  }
  if (grepl("^ECDH-ES", alg)) {
    return(isTRUE(crv %in% c(names(ec_curves), "X25519")))
  }
  TRUE
}

# A `dir` key is the content encryption key itself, so its `alg` may name
# the content encryption instead, as RFC 7520 section 5.6's key does
# ("alg": "A128GCM" for a `dir` token). `enc` is the token's.
key_fits <- function(key, alg, operation, enc = NULL) {
  key$kty %in%
    alg_key_types(alg) &&
    curve_fits(key, alg) &&
    (is.null(key$alg) ||
      identical(key$alg, alg) ||
      (alg == "dir" && !is.null(enc) && identical(key$alg, enc))) &&
    (is.null(key$use) || identical(key$use, operation_use[[operation]])) &&
    (is.null(key$key_ops) || operation %in% key$key_ops)
}
