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
#' @param plaintext The plaintext: a raw vector, or a single string taken
#'   as UTF-8 text.
#' @param key A `jose_key`, or a list of [jose_recipient()] objects for
#'   several recipients.
#' @param alg The key management algorithm, such as `"A256KW"` or `"dir"`.
#'   `NULL` takes the key's own `alg`.
#' @param enc The content encryption algorithm. `"A128CBC-HS256"` is the one
#'   RFC 7518 requires every implementation to support.
#' @param header Further protected header members, as a named list.
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
  call
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
    abort_zujwt(
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

  algs <- vapply(
    recipients,
    function(r) {
      alg <- r$alg %||% r$key$alg
      if (is.null(alg)) {
        abort_zujwt(
          "policy",
          "Give `alg`, or a key whose own `alg` is set.",
          call = call
        )
      }
      check_algorithms(alg, "key management", "alg", call)
      check_available(alg, call)
      if (!key_fits(r$key, alg, if (alg == "dir") "encrypt" else "wrapKey")) {
        abort_zujwt(
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
  if ("dir" %in% algs && length(recipients) > 1L) {
    stop("`dir` encrypts to exactly one recipient.", call. = FALSE)
  }

  cek <- if (algs[[1]] == "dir") {
    recipients[[1]]$key$k
  } else {
    cek %||% zucrypt::crypt_rand_bytes(cbc_hs[[enc]]$key)
  }
  iv <- iv %||% zucrypt::crypt_rand_bytes(16L)

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
    c(list(alg = algs[[1]], enc = enc), kid, header)
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
  sealed <- cbc_hs_encrypt(enc, cek, iv, bytes, aad_input)

  encrypted_keys <- lapply(seq_along(recipients), function(i) {
    if (algs[[i]] == "dir") raw() else aes_key_wrap(recipients[[i]]$key$k, cek)
  })

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
#' Every failure after the header checks (a wrong key, a bad tag, bad
#' padding, a failed key unwrap, a wrong length) raises the same
#' `zujwt_decrypt_error` with the same message, so that the error cannot
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
    abort_zujwt(
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
    abort_zujwt("policy", "Expected a JWE, not a JWS.", call = call)
  }
  headers <- lapply(obj$recipients, function(r) {
    c(obj$protected, obj$unprotected, r$header)
  })
  if (any(vapply(headers, function(h) "zip" %in% names(h), logical(1)))) {
    abort_zujwt(
      "policy",
      "Compressed content (`zip`) is refused (RFC 8725 section 3.6).",
      call = call
    )
  }
  enc <- headers[[1]][["enc"]]
  if (!enc %in% encryptions) {
    abort_zujwt(
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
    abort_zujwt(
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
    keys <- tryCatch(
      {
        check_available(alg, call)
        found <- resolve_keys(
          key,
          header,
          if (alg == "dir") "decrypt" else "unwrapKey",
          limits,
          call
        )
        # A key of the wrong size for this recipient is ruled out, as one of
        # the wrong type is; only when none is left is that an error.
        sized <- Filter(function(k) kek_fits(alg, enc, k), found)
        if (length(sized) == 0L) {
          check_kek(alg, enc, found[[1]], call)
        }
        sized
      },
      zujwt_error = function(e) {
        if (single) {
          stop(e)
        }
        first_error <<- first_error %||% e
        NULL
      }
    )
    for (k in keys) {
      attempts[[length(attempts) + 1L]] <- list(i = i, key = k)
    }
  }
  if (length(attempts) == 0L) {
    stop(first_error)
  }

  for (attempt in attempts) {
    header <- headers[[attempt$i]]
    alg <- header[["alg"]]
    encrypted_key <- obj$recipients[[attempt$i]]$encrypted_key
    cek <- recover_cek(alg, enc, attempt$key, encrypted_key)
    if (is.null(cek)) {
      next
    }
    plaintext <- cbc_hs_decrypt(
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

# The CEK, or NULL on any failure (D5).
recover_cek <- function(alg, enc, key, encrypted_key) {
  cek <- if (alg == "dir") {
    if (length(encrypted_key) != 0L) {
      return(NULL)
    }
    key$k
  } else {
    aes_key_unwrap(key$k, encrypted_key)
  }
  if (is.null(cek) || length(cek) != cbc_hs[[enc]]$key) {
    return(NULL)
  }
  cek
}

# Design §8.2: AES-KW and dir keys of exactly the size the identifier names.
kek_bytes <- function(alg, enc) {
  if (alg == "dir") cbc_hs[[enc]]$key else kw_key_bytes[[alg]]
}

kek_fits <- function(alg, enc, key) {
  length(key$k) == kek_bytes(alg, enc)
}

check_kek <- function(alg, enc, key, call) {
  need <- kek_bytes(alg, enc)
  if (length(key$k) != need) {
    abort_zujwt(
      "key",
      sprintf("An `%s` key must be exactly %d bytes here.", alg, need),
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
