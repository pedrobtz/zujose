# JWE: encryption and decryption (design §7.4, §8.6).

# Key sizes, in bytes, that each key management algorithm needs.
kw_key_bytes <- c(A128KW = 16L, A192KW = 24L, A256KW = 32L)

#' Encrypt a payload as a JWE
#'
#' `jose_encrypt()` encrypts `plaintext` to one recipient, or to several
#' through [jose_recipient()], and returns the JWE in the compact,
#' flattened JSON or general JSON serialization (RFC 7516).
#'
#' Every message gets a fresh content encryption key and initialization
#' vector, drawn from the operating system's cryptographic random source
#' through zucrypt. They cannot be supplied: a reused IV or CEK breaks the
#' encryption. If the random source fails, the error is zucrypt's
#' `zucrypt_entropy_error`, and nothing is returned.
#'
#' Key management is `dir`, `A128KW`, `A192KW`, `A256KW`, `A128GCMKW`,
#' `A192GCMKW`, `A256GCMKW`, one of the `PBES2-*` algorithms, or
#' `RSA-OAEP` or `RSA-OAEP-256` to an RSA public key of at least 2048 bits,
#' or `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW` or `ECDH-ES+A256KW` to
#' an EC key on P-256, P-384 or P-521 or an X25519 key. ECDH-ES generates a
#' fresh ephemeral key, written as `epk`, and takes `apu` and `apv` from
#' `header`; in direct mode (`ECDH-ES`) it encrypts to one recipient.
#' `RSA1_5` is refused: it is accepted by [jose_decrypt()] only, when
#' `algorithms` names it, and it never encrypts. Content
#' encryption is `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`,
#' `A128GCM`, `A192GCM` or `A256GCM`. `A*GCMKW` writes the key wrapping `iv`
#' and `tag` into the header, and `PBES2-*` writes a random 16-byte `p2s`;
#' none of the three can be given.
#'
#' For `PBES2-*` the key is the password, as an `oct` key:
#' `jose_key_oct(charToRaw(enc2utf8(password)))`. The iteration count is
#' `p2c` in `header`, a whole number of at least 1000, and defaults to
#' 600 000. A recipient decrypting with [jose_decrypt()] accepts at most
#' `jose_limits()$p2c` iterations, by default also 600 000.
#'
#' @param plaintext The plaintext: a raw vector, or a single string taken
#'   as UTF-8 text.
#' @param key A `jose_key`, or a list of [jose_recipient()] objects for
#'   several recipients.
#' @param alg The key management algorithm, such as `"A256KW"`,
#'   `"A256GCMKW"`, `"PBES2-HS256+A128KW"` or `"dir"`. `NULL` takes the key's
#'   own `alg`.
#' @param enc The content encryption algorithm. `"A128CBC-HS256"` is the one
#'   RFC 7518 requires every implementation to support.
#' @param header Further protected header members, as a named list. For
#'   `PBES2-*`, `p2c` sets the iteration count.
#' @param unprotected Shared unprotected header members, as a named list.
#'   Only the JSON serializations carry them.
#' @param aad Additional authenticated data, as a raw vector or a string.
#'   Only the JSON serializations carry it.
#' @param format `"compact"`, `"flattened"` or `"general"`. Several
#'   recipients need `"general"`.
#' @returns The JWE, as a single string.
#' @seealso [jose_decrypt()].
#' @export
#' @examples
#' key <- jose_key_generate("oct", alg = "A128KW", kid = "kek")
#' token <- jose_encrypt("secret", key)
#' token
#' jose_decrypt(token, key, algorithms = "A128KW",
#'              encryptions = "A128CBC-HS256")
#'
#' # AES-GCM content encryption, under a password.
#' password <- jose_key_oct(charToRaw("correct horse battery staple"))
#' token <- jose_encrypt("secret", password, alg = "PBES2-HS256+A128KW",
#'                       enc = "A256GCM", header = list(p2c = 10000))
#' jose_decrypt(token, password, algorithms = "PBES2-HS256+A128KW",
#'              encryptions = "A256GCM")$plaintext
jose_encrypt <- function(
  plaintext,
  key,
  alg = NULL,
  enc = "A128CBC-HS256",
  header = NULL,
  unprotected = NULL,
  aad = NULL,
  format = c("compact", "flattened", "general")
) {
  call <- sys.call()
  format <- match.arg(format)
  encrypt_jwe(
    plaintext,
    key,
    alg,
    enc,
    header,
    unprotected,
    aad,
    format,
    cek = NULL,
    iv = NULL,
    call = call
  )
}

#' One recipient of a multi-recipient JWE
#'
#' `jose_recipient()` pairs a key with its key management algorithm and
#' per-recipient header, for [jose_encrypt()] to produce a general JSON
#' serialization with several recipients.
#'
#' @param key A `jose_key`.
#' @param alg The key management algorithm, or `NULL` for the key's own.
#' @param header Per-recipient unprotected header members, as a named list.
#' @returns A `jose_recipient`.
#' @export
#' @examples
#' jose_recipient(jose_key_oct(as.raw(1:16)), "A128KW")
jose_recipient <- function(key, alg = NULL, header = NULL) {
  key <- check_key(key, sys.call())
  if (!is.null(alg) && !is_string(alg)) {
    stop("`alg` must be a single string.", call. = FALSE)
  }
  structure(
    list(key = key, alg = alg, header = check_header_arg(header, "header")),
    class = "jose_recipient"
  )
}

encrypt_jwe <- function(
  plaintext,
  key,
  alg,
  enc,
  header,
  unprotected,
  aad,
  format,
  cek,
  iv,
  call,
  fixed = list()
) {
  bytes <- as_payload_bytes(plaintext, call)
  check_algorithms(enc, "content encryption", "enc", call)
  check_available(enc, call)
  header <- check_header_arg(header, "header")
  unprotected <- check_header_arg(unprotected, "unprotected")
  if (!is.null(aad)) {
    aad <- as_payload_bytes(aad, call)
  }

  recipients <- if (inherits(key, "jose_key")) {
    list(jose_recipient(key, alg))
  } else if (
    is.list(key) &&
      length(key) > 0L &&
      all(vapply(key, inherits, logical(1), "jose_recipient"))
  ) {
    if (!is.null(alg)) {
      stop(
        "With several recipients, give `alg` to each jose_recipient().",
        call. = FALSE
      )
    }
    key
  } else {
    abort_zujose(
      "key",
      "`key` must be a jose_key or a list of jose_recipient() objects.",
      call = call
    )
  }
  general <- format == "general"
  if (length(recipients) > 1L && !general) {
    stop("Several recipients need `format = \"general\"`.", call. = FALSE)
  }
  if (
    format == "compact" &&
      (length(unprotected) > 0L ||
        !is.null(aad) ||
        length(recipients[[1]]$header) > 0L)
  ) {
    stop(
      "The compact serialization has no unprotected header and no `aad`.",
      call. = FALSE
    )
  }
  for (name in c("alg", "enc", "zip")) {
    if (name %in% names(header)) {
      stop(
        sprintf("Set `%s` through its argument, not `header`.", name),
        call. = FALSE
      )
    }
  }
  given <- c(
    names(header),
    names(unprotected),
    unlist(lapply(recipients, function(r) names(r$header)))
  )
  for (name in intersect(c("iv", "tag", "p2s", "epk"), given)) {
    stop(
      sprintf("`%s` is generated for each message; it cannot be given.", name),
      call. = FALSE
    )
  }

  algs <- vapply(
    recipients,
    function(r) {
      alg <- r$alg %||% r$key$alg
      if (is.null(alg)) {
        abort_zujose(
          "policy",
          "Give `alg`, or a key whose own `alg` is set.",
          call = call
        )
      }
      check_algorithms(alg, "key management", "alg", call)
      check_available(alg, call)
      if (alg == "RSA1_5") {
        abort_zujose(
          "policy",
          paste0(
            "RSA1_5 is accepted for decryption only; it never ",
            "encrypts (RFC 8725 section 3.2). Use RSA-OAEP-256."
          ),
          call = call
        )
      }
      operation <- if (alg == "dir") {
        "encrypt"
      } else if (is_ecdh(alg)) {
        "deriveKey"
      } else {
        "wrapKey"
      }
      if (!key_fits(r$key, alg, operation, enc)) {
        abort_zujose(
          "policy",
          "The key does not fit the algorithm or its intended use.",
          call = call
        )
      }
      check_kek(alg, enc, r$key, call)
      alg
    },
    ""
  )
  if (any(algs %in% c("dir", "ECDH-ES")) && length(recipients) > 1L) {
    stop(
      "`dir` and `ECDH-ES` encrypt to exactly one recipient.",
      call. = FALSE
    )
  }
  # ECDH-ES's PartyUInfo and PartyVInfo (RFC 7518 §4.6.1.2), from whichever
  # header gives them.
  party <- function(i, name) {
    value <- recipients[[i]]$header[[name]] %||%
      header[[name]] %||%
      unprotected[[name]]
    if (is.null(value)) {
      return(raw())
    }
    if (!is_string(value)) {
      stop(sprintf("`%s` must be a Base64url string.", name), call. = FALSE)
    }
    b64url_decode(value, name, call)
  }
  p2cs <- lapply(seq_along(recipients), function(i) {
    p2c <- recipients[[i]]$header$p2c %||% header$p2c %||% unprotected$p2c
    if (!is_pbes2(algs[[i]])) {
      if (!is.null(p2c)) {
        stop("`p2c` applies only to PBES2 key management.", call. = FALSE)
      }
      return(NULL)
    }
    check_p2c(p2c %||% pbes2_default_p2c)
  })

  cek <- if (algs[[1]] == "dir") {
    recipients[[1]]$key$k
  } else {
    cek %||% zucrypt::crypt_rand_bytes(cek_bytes(enc))
  }
  iv <- iv %||% zucrypt::crypt_rand_bytes(iv_bytes(enc))

  # Key management first: A*GCMKW and PBES2 generate header members (`iv`
  # and `tag`, `p2s` and `p2c`), which must be in place before the
  # protected header becomes the content's associated data.
  wrapped <- lapply(seq_along(recipients), function(i) {
    wrap_cek(
      algs[[i]],
      recipients[[i]]$key,
      cek,
      p2cs[[i]],
      fixed,
      enc = enc,
      apu = party(i, "apu"),
      apv = party(i, "apv")
    )
  })
  # ECDH-ES in direct mode derives the CEK rather than wrapping one.
  if (algs[[1]] == "ECDH-ES") {
    cek <- wrapped[[1]]$cek
  }
  # A generated member joins a header only if no header holds it already,
  # as a `p2c` given in `header` does.
  fresh <- function(params, ...) {
    params[setdiff(names(params), unlist(lapply(list(...), names)))]
  }

  recipient_headers <- lapply(seq_along(recipients), function(i) {
    r <- recipients[[i]]
    own <- r$header
    if (general) {
      own <- c(
        list(alg = algs[[i]]),
        if (
          !is.null(r$key$kid) &&
            !"kid" %in% c(names(own), names(header), names(unprotected))
        ) {
          list(kid = r$key$kid)
        },
        own[setdiff(names(own), "alg")]
      )
      own <- c(own, fresh(wrapped[[i]]$header, own, header, unprotected))
    }
    own
  })
  protected <- if (general) {
    c(list(enc = enc), header)
  } else {
    r <- recipients[[1]]
    kid <- if (
      !is.null(r$key$kid) &&
        !"kid" %in% c(names(header), names(unprotected), names(r$header))
    ) {
      list(kid = r$key$kid)
    }
    c(
      list(alg = algs[[1]], enc = enc),
      kid,
      fresh(wrapped[[1]]$header, header, unprotected, r$header),
      header
    )
  }
  for (h in recipient_headers) {
    check_headers(protected, list(unprotected, h), "JWE", call)
  }

  protected_b64 <- b64url_encode(charToRaw(enc2utf8(zujson::json_write(
    protected
  ))))
  aad_b64 <- if (!is.null(aad)) b64url_encode(aad)
  aad_input <- charToRaw(protected_b64)
  if (!is.null(aad_b64)) {
    aad_input <- c(aad_input, charToRaw("."), charToRaw(aad_b64))
  }
  sealed <- content_encrypt(enc, cek, iv, bytes, aad_input)
  encrypted_keys <- lapply(wrapped, `[[`, "encrypted_key")

  if (format == "compact") {
    return(paste(
      protected_b64,
      b64url_encode(encrypted_keys[[1]]),
      b64url_encode(iv),
      b64url_encode(sealed$ciphertext),
      b64url_encode(sealed$tag),
      sep = "."
    ))
  }
  entries <- lapply(seq_along(recipients), function(i) {
    Filter(
      length,
      list(
        header = if (length(recipient_headers[[i]])) recipient_headers[[i]],
        encrypted_key = if (length(encrypted_keys[[i]])) {
          b64url_encode(encrypted_keys[[i]])
        }
      )
    )
  })
  out <- list(
    protected = protected_b64,
    unprotected = if (length(unprotected)) unprotected
  )
  out <- if (general) {
    c(
      out,
      list(
        recipients = lapply(entries, function(e) {
          if (length(e)) e else empty_object()
        })
      )
    )
  } else {
    c(out, entries[[1]])
  }
  out <- c(
    out,
    list(
      aad = aad_b64,
      iv = b64url_encode(iv),
      ciphertext = b64url_encode(sealed$ciphertext),
      tag = b64url_encode(sealed$tag)
    )
  )
  zujson::json_write(Filter(Negate(is.null), out))
}

#' Decrypt a JWE
#'
#' `jose_decrypt()` decrypts a JWE in any serialization. The caller names
#' the key management algorithms and the content encryption algorithms it
#' accepts; neither has a default. A token with `zip` is refused (RFC 8725
#' section 3.6).
#'
#' `RSA1_5` is decrypted only when `algorithms` names it. It is exposed to
#' Bleichenbacher-style attacks (RFC 8725 section 3.2); a padding failure is
#' replaced by a random content key, as RFC 7516 section 11.5 asks, so that
#' it fails exactly as a wrong key does. Prefer `RSA-OAEP-256`.
#'
#' Every failure after the header checks (a wrong key, a bad tag, bad
#' padding, a failed key unwrap, a wrong length) raises the same
#' `zujose_decrypt_error` with the same message, so that the error cannot
#' tell an attacker which step failed (RFC 7516 section 11.5).
#'
#' With several recipients, those whose algorithm is not in `algorithms`,
#' or for whom `key` holds no key, are skipped; decryption succeeds with the
#' first recipient it can decrypt for.
#'
#' @param token The JWE: a compact serialization, or JSON text.
#' @param key A `jose_key`, a `jose_keyset`, or a function of the header
#'   returning one.
#' @param algorithms The key management algorithms to accept, such as
#'   `"A256KW"`.
#' @param encryptions The content encryption algorithms to accept, such as
#'   `"A256CBC-HS512"`.
#' @param limits Resource limits, from [jose_limits()].
#' @returns A list of class `jose_decrypted` with `plaintext` (raw),
#'   `header` (the protected, shared and per-recipient headers merged),
#'   `protected`, and the `kid`, `alg` and `enc` that decrypted it.
#' @export
#' @examples
#' # RFC 7516 Appendix A.3.
#' token <- paste0(
#'   "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.",
#'   "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.",
#'   "AxY8DCtDaGlsbGljb3RoZQ.",
#'   "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.",
#'   "U0m_YmjN04DJvceFICbCVQ"
#' )
#' key <- as_jose_key('{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}')
#' out <- jose_decrypt(token, key, "A128KW", "A128CBC-HS256")
#' rawToChar(out$plaintext)
jose_decrypt <- function(
  token,
  key,
  algorithms,
  encryptions,
  limits = jose_limits()
) {
  call <- sys.call()
  check_algorithms(algorithms, "key management", call = call)
  check_algorithms(encryptions, "content encryption", "encryptions", call)
  decrypt_jwe(token, key, algorithms, encryptions, limits, call)
}

#' Accept an encrypted JWT
#'
#' `jose_decryption()` bundles the key and algorithms that
#' [jose_jwt_decode()] uses to decrypt a JWT sent as a JWE. Without it, a
#' JWE is refused where a JWT is expected, which keeps a signed-token check
#' from silently accepting encrypted tokens (jwcrypto's CVE-2022-3102).
#'
#' @inheritParams jose_decrypt
#' @returns A `jose_decryption`.
#' @export
#' @examples
#' jose_decryption(jose_key_oct(as.raw(1:16)), "A128KW", "A128CBC-HS256")
jose_decryption <- function(key, algorithms, encryptions) {
  call <- sys.call()
  check_algorithms(algorithms, "key management", call = call)
  check_algorithms(encryptions, "content encryption", "encryptions", call)
  if (!is.function(key) && !inherits(key, c("jose_key", "jose_keyset"))) {
    abort_zujose(
      "key",
      "`key` must be a jose_key, a jose_keyset or a resolver function.",
      call = call
    )
  }
  structure(
    list(key = key, algorithms = algorithms, encryptions = encryptions),
    class = "jose_decryption"
  )
}

#' @export
print.jose_decryption <- function(x, ...) {
  cat(sprintf(
    "<jose_decryption> %s with %s\n",
    paste(x$algorithms, collapse = ", "),
    paste(x$encryptions, collapse = ", ")
  ))
  invisible(x)
}

decrypt_jwe <- function(token, key, algorithms, encryptions, limits, call) {
  obj <- jose_parse(token, limits, call)
  if (obj$type != "JWE") {
    abort_zujose("policy", "Expected a JWE, not a JWS.", call = call)
  }
  headers <- lapply(obj$recipients, function(r) {
    c(obj$protected, obj$unprotected, r$header)
  })
  if (any(vapply(headers, function(h) "zip" %in% names(h), logical(1)))) {
    abort_zujose(
      "policy",
      "Compressed content (`zip`) is refused (RFC 8725 section 3.6).",
      call = call
    )
  }
  enc <- headers[[1]][["enc"]]
  if (!enc %in% encryptions) {
    abort_zujose(
      "policy",
      "The token's content encryption is not in `encryptions`.",
      call = call
    )
  }
  check_available(enc, call)

  candidates <- which(vapply(
    headers,
    function(h) h[["alg"]] %in% algorithms,
    logical(1)
  ))
  if (length(candidates) == 0L) {
    abort_zujose(
      "policy",
      "No recipient uses an algorithm in `algorithms`.",
      call = call
    )
  }

  aad_input <- charToRaw(obj$protected_b64)
  if (!is.null(obj$aad_b64)) {
    aad_input <- c(aad_input, charToRaw("."), charToRaw(obj$aad_b64))
  }

  # Key selection depends only on the headers, so its errors reveal nothing
  # about the ciphertext. With several recipients, one whose keys cannot be
  # found is skipped; the first such error is reported if none remain.
  single <- length(obj$recipients) == 1L
  first_error <- NULL
  attempts <- list()
  for (i in candidates) {
    header <- headers[[i]]
    alg <- header[["alg"]]
    params <- NULL
    keys <- tryCatch(
      {
        check_available(alg, call)
        # Header-only: the A*GCMKW and PBES2 members are checked against
        # their formats and limits before any key is looked up or derived.
        params <- kek_params(alg, header, limits, call)
        found <- resolve_keys(
          key,
          header,
          if (alg == "dir") {
            "decrypt"
          } else if (is_ecdh(alg)) {
            "deriveKey"
          } else {
            "unwrapKey"
          },
          limits,
          call
        )
        # A key of the wrong size for this recipient is ruled out, as one of
        # the wrong type is; only when none is left is that an error.
        sized <- Filter(function(k) kek_fits(alg, enc, k, TRUE, params), found)
        if (length(sized) == 0L) {
          check_kek(alg, enc, found[[1]], call, decrypt = TRUE, params = params)
        }
        sized
      },
      zujose_error = function(e) {
        if (single) {
          stop(e)
        }
        first_error <<- first_error %||% e
        NULL
      }
    )
    for (k in keys) {
      attempts[[length(attempts) + 1L]] <- list(i = i, key = k, params = params)
    }
  }
  if (length(attempts) == 0L) {
    stop(first_error)
  }

  for (attempt in attempts) {
    header <- headers[[attempt$i]]
    alg <- header[["alg"]]
    encrypted_key <- obj$recipients[[attempt$i]]$encrypted_key
    cek <- recover_cek(alg, enc, attempt$key, encrypted_key, attempt$params)
    if (is.null(cek)) {
      next
    }
    plaintext <- content_decrypt(
      enc,
      cek,
      obj$iv,
      obj$ciphertext,
      obj$tag,
      aad_input
    )
    if (is.null(plaintext)) {
      next
    }
    return(structure(
      list(
        plaintext = plaintext,
        header = header,
        protected = obj$protected,
        kid = attempt$key$kid,
        alg = alg,
        enc = enc
      ),
      class = "jose_decrypted"
    ))
  }
  abort_decrypt(call = call)
}

# Key management (RFC 7518 §4) -----------------------------------------

gcmkw_key_bytes <- c(A128GCMKW = 16L, A192GCMKW = 24L, A256GCMKW = 32L)

# PBES2 (RFC 7518 §4.8): the HMAC digest of the PBKDF2 and the AES key wrap
# the derived key feeds.
pbes2 <- list(
  "PBES2-HS256+A128KW" = list(hash = "sha256", bytes = 16L),
  "PBES2-HS384+A192KW" = list(hash = "sha384", bytes = 24L),
  "PBES2-HS512+A256KW" = list(hash = "sha512", bytes = 32L)
)

# The iteration count encryption writes when `header` gives none: OWASP's
# 2023 figure for PBKDF2-HMAC-SHA256, and the default limit decryption
# accepts.
pbes2_default_p2c <- 600000L

is_pbes2 <- function(alg) alg %in% names(pbes2)

# RFC 7518 §4.8.1.2 recommends at least 1000; zucrypt's PBKDF2 counts to
# 2^32 - 1.
check_p2c <- function(p2c) {
  ok <- is.numeric(p2c) &&
    length(p2c) == 1L &&
    !is.na(p2c) &&
    p2c == trunc(p2c) &&
    p2c >= 1000 &&
    p2c <= 4294967295
  if (!ok) {
    stop(
      "`p2c` must be a whole number of PBKDF2 iterations, at least 1000.",
      call. = FALSE
    )
  }
  p2c
}

# The PBES2 key encryption key: PBKDF2 over the password, salted with
# UTF8(alg) || 0x00 || p2s.
pbes2_kek <- function(alg, password, p2s, p2c) {
  spec <- pbes2[[alg]]
  zucrypt::crypt_pbkdf2(
    password,
    c(charToRaw(alg), as.raw(0L), p2s),
    iterations = p2c,
    length = spec$bytes,
    algorithm = spec$hash
  )
}

# Encrypt the CEK for one recipient: the encrypted key, and the header
# members the algorithm generates. `fixed` injects the key-wrap IV and the
# salt, for the RFC vectors; callers never pass it.
wrap_cek <- function(
  alg,
  key,
  cek,
  p2c = NULL,
  fixed = list(),
  enc = NULL,
  apu = raw(),
  apv = raw()
) {
  if (alg == "dir") {
    list(encrypted_key = raw(), header = list())
  } else if (is_ecdh(alg)) {
    # A fresh ephemeral key on the recipient's curve (RFC 7518 §4.6);
    # `fixed$epk` injects RFC 7518 Appendix C's.
    eph <- fixed$epk %||%
      jose_key_generate(key$kty, crv = key$members$crv)
    z <- ecdh_secret(eph, key)
    out <- list(header = list(epk = epk_jwk(eph)))
    if (alg == "ECDH-ES") {
      out$cek <- concat_kdf(z, 8L * cek_bytes(enc), enc, apu, apv)
      out$encrypted_key <- raw()
    } else {
      kek <- concat_kdf(z, 8L * ecdh_kw[[alg]], alg, apu, apv)
      out$encrypted_key <- aes_key_wrap(kek, cek)
    }
    out
  } else if (alg %in% names(kw_key_bytes)) {
    list(encrypted_key = aes_key_wrap(key$k, cek), header = list())
  } else if (is_rsa_kem(alg)) {
    list(
      encrypted_key = zucrypt::crypt_rsa_encrypt(
        cek,
        rsa_crypt_key(key, FALSE),
        oaep = TRUE,
        oaep_hash = rsa_kem[[alg]]
      ),
      header = list()
    )
  } else if (alg %in% names(gcmkw_key_bytes)) {
    kw_iv <- fixed$kw_iv %||% zucrypt::crypt_rand_bytes(12L)
    sealed <- gcm_encrypt(key$k, kw_iv, cek, NULL)
    list(
      encrypted_key = sealed$ciphertext,
      header = list(iv = b64url_encode(kw_iv), tag = b64url_encode(sealed$tag))
    )
  } else {
    p2c <- p2c %||% pbes2_default_p2c
    p2s <- fixed$p2s %||% zucrypt::crypt_rand_bytes(16L)
    kek <- pbes2_kek(alg, key$k, p2s, p2c)
    list(
      encrypted_key = aes_key_wrap(kek, cek),
      header = list(p2s = b64url_encode(p2s), p2c = p2c)
    )
  }
}

# The header members key management needs, checked and decoded. Runs on the
# header alone, before any key is looked up or derived (design §8.6): a
# malformed member, a `p2c` over the limit or a `p2s` under 8 bytes is a
# parse error that no cryptography is spent on.
kek_params <- function(alg, header, limits, call) {
  member_b64 <- function(name, what) {
    value <- header[[name]]
    if (!is_string(value)) {
      abort_zujose(
        "parse",
        sprintf("`%s` needs a `%s` header member.", alg, name),
        call = call
      )
    }
    b64url_decode(value, what, call)
  }
  if (alg %in% names(gcmkw_key_bytes)) {
    kw_iv <- member_b64("iv", "key wrapping IV")
    tag <- member_b64("tag", "key wrapping tag")
    if (length(kw_iv) != 12L || length(tag) != 16L) {
      abort_zujose(
        "parse",
        "An A*GCMKW `iv` must be 12 bytes and its `tag` 16.",
        call = call
      )
    }
    return(list(kw_iv = kw_iv, tag = tag))
  }
  if (is_ecdh(alg)) {
    return(ecdh_params(header, call))
  }
  if (is_pbes2(alg)) {
    p2c <- header[["p2c"]]
    if (
      !is.numeric(p2c) ||
        length(p2c) != 1L ||
        is.na(p2c) ||
        p2c != trunc(p2c) ||
        p2c < 1
    ) {
      abort_zujose(
        "parse",
        "A PBES2 token needs a positive whole `p2c`.",
        call = call
      )
    }
    if (p2c > limits$p2c) {
      abort_zujose(
        "parse",
        sprintf(
          "The token's `p2c` is over the limit of %s PBES2 iterations.",
          format(limits$p2c, scientific = FALSE)
        ),
        call = call
      )
    }
    p2s <- member_b64("p2s", "PBES2 salt")
    if (length(p2s) < 8L) {
      abort_zujose(
        "parse",
        "A PBES2 `p2s` must be at least 8 bytes (RFC 7518 section 4.8.1.1).",
        call = call
      )
    }
    return(list(p2s = p2s, p2c = p2c))
  }
  list()
}

# The CEK, or NULL on any failure (D5).
recover_cek <- function(alg, enc, key, encrypted_key, params = list()) {
  cek <- if (alg == "dir") {
    if (length(encrypted_key) != 0L) {
      return(NULL)
    }
    key$k
  } else if (alg %in% names(kw_key_bytes)) {
    aes_key_unwrap(key$k, encrypted_key)
  } else if (is_ecdh(alg)) {
    z <- tryCatch(
      ecdh_secret(key, params$epk),
      zujose_error = function(e) NULL,
      zucrypt_error = function(e) NULL
    )
    if (is.null(z)) {
      return(NULL)
    }
    if (alg == "ECDH-ES") {
      if (length(encrypted_key) != 0L) {
        return(NULL)
      }
      concat_kdf(z, 8L * cek_bytes(enc), enc, params$apu, params$apv)
    } else {
      kek <- concat_kdf(z, 8L * ecdh_kw[[alg]], alg, params$apu, params$apv)
      aes_key_unwrap(kek, encrypted_key)
    }
  } else if (alg == "RSA1_5") {
    # RFC 7516 section 11.5 and RFC 3218: a padding failure must not be
    # distinguishable from any later one, so it is replaced by a random CEK
    # of the right length and decryption goes on, to fail at the tag like
    # any other wrong key.
    cek <- tryCatch(
      zucrypt::crypt_rsa_decrypt(encrypted_key, rsa_crypt_key(key, TRUE)),
      zucrypt_error = function(e) NULL
    )
    if (is.null(cek) || length(cek) != cek_bytes(enc)) {
      cek <- zucrypt::crypt_rand_bytes(cek_bytes(enc))
    }
    cek
  } else if (is_rsa_kem(alg)) {
    tryCatch(
      zucrypt::crypt_rsa_decrypt(
        encrypted_key,
        rsa_crypt_key(key, TRUE),
        oaep = TRUE,
        oaep_hash = rsa_kem[[alg]]
      ),
      zucrypt_error = function(e) NULL
    )
  } else if (alg %in% names(gcmkw_key_bytes)) {
    gcm_decrypt(key$k, params$kw_iv, encrypted_key, params$tag, NULL)
  } else {
    kek <- pbes2_kek(alg, key$k, params$p2s, params$p2c)
    aes_key_unwrap(kek, encrypted_key)
  }
  if (is.null(cek) || length(cek) != cek_bytes(enc)) {
    return(NULL)
  }
  cek
}

# Design §8.2: AES-KW, A*GCMKW and dir keys of exactly the size the
# identifier names. A PBES2 key is a password, of any length.
kek_bytes <- function(alg, enc) {
  if (alg == "dir") {
    cek_bytes(enc)
  } else if (alg %in% names(gcmkw_key_bytes)) {
    gcmkw_key_bytes[[alg]]
  } else if (is_pbes2(alg)) {
    NA_integer_
  } else {
    kw_key_bytes[[alg]]
  }
}

# RSA key management (RFC 7518 §4.2, §4.3): the OAEP digest, or NA for
# RSA1_5, which only decrypts.
rsa_kem <- c("RSA-OAEP" = "sha1", "RSA-OAEP-256" = "sha256", "RSA1_5" = NA)

is_rsa_kem <- function(alg) alg %in% names(rsa_kem)

# Whether `key` can manage the CEK for `alg`. For RSA: at least 2048 bits,
# and for decryption the private key.
kek_fits <- function(alg, enc, key, decrypt = FALSE, params = NULL) {
  if (is_ecdh(alg)) {
    return(
      (!decrypt || has_private(key)) &&
        (is.null(params) || identical(key$members$crv, params$epk$members$crv))
    )
  }
  if (is_rsa_kem(alg)) {
    return((key$bits %||% 0) >= 2048 && (!decrypt || has_private(key)))
  }
  need <- kek_bytes(alg, enc)
  if (is.na(need)) length(key$k) >= 1L else length(key$k) == need
}

check_kek <- function(alg, enc, key, call, decrypt = FALSE, params = NULL) {
  if (is_ecdh(alg)) {
    if (decrypt && !has_private(key)) {
      abort_zujose("key", "Key agreement needs the private key.", call = call)
    }
    if (
      !is.null(params) &&
        !identical(key$members$crv, params$epk$members$crv)
    ) {
      abort_zujose(
        "key",
        "The token's ephemeral key is not on the key's curve.",
        call = call
      )
    }
    return(invisible())
  }
  if (is_rsa_kem(alg)) {
    check_rsa_size(key, call)
    if (decrypt && !has_private(key)) {
      abort_zujose("key", "Decrypting needs the private RSA key.", call = call)
    }
    return(invisible())
  }
  if (!kek_fits(alg, enc, key)) {
    abort_zujose(
      "key",
      sprintf(
        "An `%s` key must be exactly %d bytes here.",
        alg,
        kek_bytes(alg, enc)
      ),
      call = call
    )
  }
}

#' @export
print.jose_decrypted <- function(x, ...) {
  cat(sprintf(
    "<jose_decrypted> %s with %s%s\n",
    x$alg,
    x$enc,
    if (!is.null(x$kid)) {
      paste0(", key ", encodeString(x$kid, quote = '"'))
    } else {
      ""
    }
  ))
  cat("Header:\n")
  print_members(x$header)
  cat(sprintf("Plaintext: %d bytes\n", length(x$plaintext)))
  invisible(x)
}

# ECDH-ES (RFC 7518 §4.6) --------------------------------------------------

# The key-wrap size of each ECDH-ES variant, NA for direct key agreement.
ecdh_kw <- c(
  "ECDH-ES" = NA_integer_,
  "ECDH-ES+A128KW" = 16L,
  "ECDH-ES+A192KW" = 24L,
  "ECDH-ES+A256KW" = 32L
)

is_ecdh <- function(alg) alg %in% names(ecdh_kw)

# The shared secret Z of a private and a public jose_key on one curve.
ecdh_secret <- function(private, public) {
  if (private$kty == "OKP") {
    zucrypt::crypt_x25519_diffie_hellman(
      ec_crypt_key(private, TRUE),
      ec_crypt_key(public, FALSE)
    )
  } else {
    zucrypt::crypt_ec_dh(
      ec_crypt_key(private, TRUE),
      ec_crypt_key(public, FALSE)
    )
  }
}

# The public JWK of an ephemeral key, as the header's `epk`.
epk_jwk <- function(key) {
  c(
    list(kty = key$kty),
    key$members[intersect(c("crv", "x", "y"), names(key$members))]
  )
}

# The Concat KDF of NIST SP 800-56A, as RFC 7518 §4.6.2 specifies it:
# SHA-256 rounds over counter || Z || OtherInfo, where OtherInfo is the
# length-prefixed AlgorithmID, PartyUInfo and PartyVInfo, then keydatalen.
concat_kdf <- function(z, bits, alg_id, apu, apv) {
  be32 <- function(n) {
    as.raw(c(
      n %/% 16777216,
      (n %/% 65536) %% 256,
      (n %/% 256) %% 256,
      n %% 256
    ))
  }
  with_length <- function(x) c(be32(length(x)), x)
  other <- c(
    with_length(charToRaw(alg_id)),
    with_length(apu),
    with_length(apv),
    be32(bits)
  )
  rounds <- ceiling(bits / 256)
  out <- unlist(lapply(seq_len(rounds), function(i) {
    zucrypt::crypt_hash(c(be32(i), z, other), "sha256")
  }))
  out[seq_len(bits %/% 8L)]
}

# The ECDH-ES header members, checked on the header alone: `epk` must be a
# public key on a supported curve, and on it (the point is validated), and
# `apu` and `apv` must be Base64url when present.
ecdh_params <- function(header, call) {
  epk <- header[["epk"]]
  bad <- function() {
    abort_zujose(
      "parse",
      "The `epk` header is not a public key on a supported curve.",
      call = call
    )
  }
  if (!is.list(epk) || !is_string(epk$kty) || !epk$kty %in% c("EC", "OKP")) {
    bad()
  }
  key <- tryCatch(
    as_jose_key(epk[intersect(c("kty", "crv", "x", "y"), names(epk))]),
    zujose_error = function(e) NULL
  )
  if (is.null(key) || !key$supported) {
    bad()
  }
  party <- function(name) {
    value <- header[[name]]
    if (is.null(value)) {
      return(raw())
    }
    if (!is_string(value)) {
      abort_zujose(
        "parse",
        sprintf("`%s` must be a string.", name),
        call = call
      )
    }
    b64url_decode(value, name, call)
  }
  list(epk = key, apu = party("apu"), apv = party("apv"))
}
