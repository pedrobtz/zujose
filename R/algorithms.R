# The algorithm table (design §6): every JWA identifier zujwt knows, with
# the zucrypt version it needs and whether this version of zujwt implements
# it. An identifier is usable only when both hold; otherwise it is reported
# as unsupported, never silently skipped.

jwa_table <- function() {
  rows <- list(
    # JWS (RFC 7518 §3.1).
    c("HS256", "signature", "0.1.0"),
    c("HS384", "signature", "0.1.0"),
    c("HS512", "signature", "0.1.0"),
    c("RS256", "signature", "0.4.0"),
    c("RS384", "signature", "0.4.0"),
    c("RS512", "signature", "0.4.0"),
    c("PS256", "signature", "0.4.0"),
    c("PS384", "signature", "0.4.0"),
    c("PS512", "signature", "0.4.0"),
    c("ES256", "signature", "0.5.0"),
    c("ES384", "signature", "0.5.0"),
    c("ES512", "signature", "0.5.0"),
    # JWE key management (RFC 7518 §4.1).
    c("dir", "key management", "0.1.0"),
    c("A128KW", "key management", "0.1.0"),
    c("A192KW", "key management", "0.1.0"),
    c("A256KW", "key management", "0.1.0"),
    c("A128GCMKW", "key management", "0.3.0"),
    c("A192GCMKW", "key management", "0.3.0"),
    c("A256GCMKW", "key management", "0.3.0"),
    c("PBES2-HS256+A128KW", "key management", "0.3.0"),
    c("PBES2-HS384+A192KW", "key management", "0.3.0"),
    c("PBES2-HS512+A256KW", "key management", "0.3.0"),
    c("RSA-OAEP", "key management", "0.4.0"),
    c("RSA-OAEP-256", "key management", "0.4.0"),
    c("RSA1_5", "key management", "0.4.0"),
    c("ECDH-ES", "key management", "0.5.0"),
    c("ECDH-ES+A128KW", "key management", "0.5.0"),
    c("ECDH-ES+A192KW", "key management", "0.5.0"),
    c("ECDH-ES+A256KW", "key management", "0.5.0"),
    # JWE content encryption (RFC 7518 §5.1).
    c("A128CBC-HS256", "content encryption", "0.1.0"),
    c("A192CBC-HS384", "content encryption", "0.1.0"),
    c("A256CBC-HS512", "content encryption", "0.1.0"),
    c("A128GCM", "content encryption", "0.3.0"),
    c("A192GCM", "content encryption", "0.3.0"),
    c("A256GCM", "content encryption", "0.3.0")
  )
  data.frame(
    algorithm = vapply(rows, `[[`, "", 1L),
    kind = vapply(rows, `[[`, "", 2L),
    zucrypt = vapply(rows, `[[`, "", 3L)
  )
}

# The identifiers this version of zujwt has code for. Each stage adds its
# own.
implemented_algorithms <- c(
  "HS256",
  "HS384",
  "HS512",
  "dir",
  "A128KW",
  "A192KW",
  "A256KW",
  "A128CBC-HS256",
  "A192CBC-HS384",
  "A256CBC-HS512"
)

#' Algorithms available in this installation
#'
#' `zujwt_info()` lists every JOSE algorithm zujwt knows and whether it can
#' be used here. An algorithm is available when this version of zujwt
#' implements it and the installed zucrypt is recent enough. Using one that
#' is not raises `zujwt_unsupported_error`.
#'
#' @returns A data frame with columns `algorithm`, `kind` (`"signature"`,
#'   `"key management"` or `"content encryption"`), `available`, and
#'   `zucrypt`, the zucrypt version the algorithm needs.
#' @export
#' @examples
#' info <- zujwt_info()
#' info[info$available, ]
zujwt_info <- function() {
  table <- jwa_table()
  installed <- utils::packageVersion("zucrypt")
  table$available <- table$algorithm %in%
    implemented_algorithms &
    vapply(
      table$zucrypt,
      function(v) installed >= package_version(v),
      logical(1),
      USE.NAMES = FALSE
    )
  table[c("algorithm", "kind", "available", "zucrypt")]
}

# Validate the caller's allow-list (design §8.2, D2). It has no default,
# names only algorithms of the expected kind, and never "none".
check_algorithms <- function(algorithms, kind, arg = "algorithms", call) {
  table <- jwa_table()
  known <- table$algorithm[table$kind %in% kind]
  ok <- is.character(algorithms) &&
    length(algorithms) > 0L &&
    !anyNA(algorithms) &&
    all(algorithms %in% known)
  if (!ok) {
    abort_zujwt(
      "policy",
      sprintf(
        "`%s` must name %s algorithms from RFC 7518; \"none\" is never allowed.",
        arg,
        paste(kind, collapse = " or ")
      ),
      call = call
    )
  }
  invisible(algorithms)
}

# Refuse an algorithm this installation cannot run, naming what it needs.
check_available <- function(alg, call) {
  info <- zujwt_info()
  row <- info[info$algorithm == alg, ]
  if (nrow(row) == 0L) {
    abort_zujwt(
      "policy",
      "The token's algorithm is not a JOSE algorithm zujwt knows.",
      call = call
    )
  }
  if (!alg %in% implemented_algorithms) {
    stop(zujwt_condition(
      "zujwt_unsupported_error",
      sprintf(
        "Algorithm \"%s\" is not implemented in this version of zujwt.",
        alg
      ),
      algorithm = alg,
      needs = row$zucrypt,
      call = call
    ))
  }
  if (!row$available) {
    abort_unsupported(alg, row$zucrypt, call = call)
  }
  invisible(alg)
}
