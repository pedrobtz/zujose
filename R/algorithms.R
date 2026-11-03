# The algorithm table (design §6): every JWA identifier zujose knows, with
# the zucrypt version it needs and whether this version of zujose implements
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

# The identifiers this version of zujose has code for. Each stage adds its
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
  "A256CBC-HS512",
  "A128GCM",
  "A192GCM",
  "A256GCM",
  "A128GCMKW",
  "A192GCMKW",
  "A256GCMKW",
  "PBES2-HS256+A128KW",
  "PBES2-HS384+A192KW",
  "PBES2-HS512+A256KW",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "RSA-OAEP",
  "RSA-OAEP-256",
  "RSA1_5",
  "ES256",
  "ES384",
  "ES512",
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW"
)

# The zucrypt functions each release adds that zujose uses. An algorithm is
# available when the installed zucrypt is that release or later, or when it
# already exports those functions: a development zucrypt (0.1.0.9000) can
# carry a later release's functions before it is numbered.
zucrypt_functions <- list(
  "0.3.0" = c("crypt_aes_gcm_encrypt", "crypt_aes_gcm_decrypt", "crypt_pbkdf2"),
  "0.4.0" = c("crypt_rsa_key", "crypt_signature_create", "crypt_rsa_encrypt"),
  "0.5.0" = c("crypt_ec_key", "crypt_ec_dh", "crypt_x25519_diffie_hellman")
)

zucrypt_provides <- function(version, installed) {
  if (installed >= package_version(version)) {
    return(TRUE)
  }
  fns <- zucrypt_functions[[version]]
  !is.null(fns) &&
    all(vapply(
      fns,
      exists,
      logical(1),
      envir = asNamespace("zucrypt"),
      inherits = FALSE
    ))
}

#' Algorithms available in this installation
#'
#' `zujose_info()` lists every JOSE algorithm zujose knows and whether it can
#' be used here. An algorithm is available when this version of zujose
#' implements it and the installed zucrypt provides what it needs: zucrypt is
#' the version in the `zucrypt` column or later, or already exports the
#' functions that version adds. Using one that
#' is not raises `zujose_unsupported_error`.
#'
#' @returns A data frame with columns `algorithm`, `kind` (`"signature"`,
#'   `"key management"` or `"content encryption"`), `available`, and
#'   `zucrypt`, the zucrypt version the algorithm needs.
#' @export
#' @examples
#' info <- zujose_info()
#' info[info$available, ]
zujose_info <- function() {
  table <- jwa_table()
  installed <- utils::packageVersion("zucrypt")
  table$available <- table$algorithm %in%
    implemented_algorithms &
    vapply(
      table$zucrypt,
      zucrypt_provides,
      logical(1),
      installed = installed,
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
    abort_zujose(
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
  info <- zujose_info()
  row <- info[info$algorithm == alg, ]
  if (nrow(row) == 0L) {
    abort_zujose(
      "policy",
      "The token's algorithm is not a JOSE algorithm zujose knows.",
      call = call
    )
  }
  if (!alg %in% implemented_algorithms) {
    stop(zujose_condition(
      "zujose_unsupported_error",
      sprintf(
        "Algorithm \"%s\" is not implemented in this version of zujose.",
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
