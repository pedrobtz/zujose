# The JWE oracle (design section 10): zujose and jwcrypto (Python) exchange
# JWE tokens both ways. Development only, never run at check time; the
# jwe-oracle workflow runs it.
#
#   Rscript tools/jwe-oracle/oracle.R keys    <dir>   write keys.jwks
#   Rscript tools/jwe-oracle/oracle.R encrypt <dir>   write r-tokens.tsv
#                                                     and r-json.tsv
#   Rscript tools/jwe-oracle/oracle.R decrypt <dir>   check py-tokens.tsv
#                                                     and py-json.tsv
#
# Between `encrypt` and `decrypt`, tools/jwe-oracle/oracle.py decrypts
# r-tokens.tsv and r-json.tsv and writes py-tokens.tsv and py-json.tsv.
# Every token has the same plaintext; `decrypt` fails unless each token
# decrypts to it. The *-json.tsv files hold the JSON serializations
# (#101): flattened and general, one and three recipients, with and
# without `aad`, with a shared unprotected header and a per-recipient
# header on every recipient, each JSON token decrypted for each of its
# recipients alone.

pkgload::load_all(quiet = TRUE)

plaintext <- "zujose JWE oracle: été, 日本, \U0001f511."
encs <- c(
  "A128CBC-HS256",
  "A192CBC-HS384",
  "A256CBC-HS512",
  "A128GCM",
  "A192GCM",
  "A256GCM"
)
oct_algs <- c(
  "A128KW",
  "A192KW",
  "A256KW",
  "A128GCMKW",
  "A192GCMKW",
  "A256GCMKW",
  "PBES2-HS256+A128KW",
  "PBES2-HS384+A192KW",
  "PBES2-HS512+A256KW"
)
ecdh_algs <- c("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")
curves <- c("ec-p256" = "P-256", "ec-p384" = "P-384", "ec-p521" = "P-521")

# One row per token R writes: alg, enc and the kid of the recipient's key.
cases <- function() {
  rows <- list()
  add <- function(alg, enc, kid) {
    rows[[length(rows) + 1L]] <<- data.frame(alg = alg, enc = enc, kid = kid)
  }
  for (enc in encs) {
    add("dir", enc, paste0("dir-", enc))
    for (alg in oct_algs) {
      add(alg, enc, alg)
    }
    for (alg in c("RSA-OAEP", "RSA-OAEP-256")) {
      add(alg, enc, "rsa")
    }
    for (alg in ecdh_algs) {
      for (kid in c(names(curves), "x25519")) {
        add(alg, enc, kid)
      }
    }
  }
  do.call(rbind, rows)
}

write_keys <- function(dir) {
  keys <- c(
    lapply(encs, function(enc) {
      size <- c(
        "A128CBC-HS256" = 256,
        "A192CBC-HS384" = 384,
        "A256CBC-HS512" = 512,
        A128GCM = 128,
        A192GCM = 192,
        A256GCM = 256
      )[[enc]]
      jwk_generate("oct", size = size, kid = paste0("dir-", enc))
    }),
    # No `alg` on the keys: one A*KW key serves every `enc`.
    lapply(oct_algs, function(alg) {
      size <- if (startsWith(alg, "PBES2")) {
        256
      } else {
        as.numeric(sub("^A([0-9]+).*", "\\1", alg))
      }
      jwk_generate("oct", size = size, kid = alg)
    }),
    list(jwk_generate("RSA", kid = "rsa")),
    lapply(names(curves), function(kid) {
      jwk_generate("EC", crv = curves[[kid]], kid = kid)
    }),
    list(jwk_generate("OKP", crv = "X25519", kid = "x25519"))
  )
  writeLines(
    jwk_json(do.call(jwk_set, keys), private = TRUE),
    file.path(dir, "keys.jwks")
  )
  cat(sprintf("oracle.R: wrote %d keys\n", length(keys)))
}

read_keys <- function(dir) {
  as_jwk_set(paste(readLines(file.path(dir, "keys.jwks")), collapse = ""))
}

# Encrypt to the public half, as a sender would; an oct key has none.
recipient_key <- function(key) {
  if (key$kty == "oct") key else jwk_public(key)
}

encrypt_all <- function(dir) {
  keys <- read_keys(dir)
  rows <- cases()
  rows$token <- vapply(
    seq_len(nrow(rows)),
    function(i) {
      header <- list(kid = rows$kid[[i]])
      if (startsWith(rows$alg[[i]], "PBES2")) {
        # jwcrypto refuses more than 16384 iterations, and so zujose's
        # default of 600 000; ?jwe_encrypt gives 10 000 as the interoperable
        # count, which oracle.py checks jwcrypto reads at its default cap
        # (#140).
        header$p2c <- 10000L
      }
      jwe_encrypt(
        plaintext,
        recipient_key(keys[[rows$kid[[i]]]]),
        alg = rows$alg[[i]],
        enc = rows$enc[[i]],
        header = header
      )
    },
    ""
  )
  utils::write.table(
    rows,
    file.path(dir, "r-tokens.tsv"),
    sep = "\t",
    quote = FALSE,
    row.names = FALSE
  )
  cat(sprintf("oracle.R: zujose encrypted %d tokens\n", nrow(rows)))
}

# The JSON serializations, for every `enc`: id, format, whether there is
# `aad`, and each recipient's alg and kid. Each kid is a key of keys.jwks.
json_cases <- list(
  list(
    id = "flattened-aad",
    format = "flattened",
    aad = TRUE,
    recipients = list(c("A128KW", "A128KW"))
  ),
  list(
    id = "flattened",
    format = "flattened",
    aad = FALSE,
    recipients = list(c("ECDH-ES", "x25519"))
  ),
  list(
    id = "general-one-aad",
    format = "general",
    aad = TRUE,
    recipients = list(c("RSA-OAEP-256", "rsa"))
  ),
  list(
    id = "general-three-aad",
    format = "general",
    aad = TRUE,
    recipients = list(
      c("A256GCMKW", "A256GCMKW"),
      c("RSA-OAEP", "rsa"),
      c("ECDH-ES+A192KW", "ec-p384")
    )
  ),
  list(
    id = "general-three",
    format = "general",
    aad = FALSE,
    recipients = list(
      c("PBES2-HS256+A128KW", "PBES2-HS256+A128KW"),
      c("A192KW", "A192KW"),
      c("ECDH-ES+A128KW", "ec-p521")
    )
  )
)
json_aad <- "zujose JWE oracle aad: été"

encrypt_json <- function(dir) {
  keys <- read_keys(dir)
  rows <- list()
  for (enc in encs) {
    for (case in json_cases) {
      recipients <- lapply(case$recipients, function(r) {
        header <- list(`x-recipient` = r[[2]])
        if (startsWith(r[[1]], "PBES2")) {
          header$p2c <- 10000L
        }
        jwe_recipient(recipient_key(keys[[r[[2]]]]), r[[1]], header = header)
      })
      token <- jwe_encrypt(
        plaintext,
        recipients,
        enc = enc,
        header = list(cty = "text/plain"),
        unprotected = list(`x-shared` = "unprotected"),
        aad = if (case$aad) json_aad,
        format = case$format
      )
      rows[[length(rows) + 1L]] <- data.frame(
        id = case$id,
        enc = enc,
        algs = paste(vapply(case$recipients, `[[`, "", 1L), collapse = ","),
        kids = paste(vapply(case$recipients, `[[`, "", 2L), collapse = ","),
        aad = if (case$aad) json_aad else "",
        token = token
      )
    }
  }
  rows <- do.call(rbind, rows)
  utils::write.table(
    rows,
    file.path(dir, "r-json.tsv"),
    sep = "\t",
    quote = FALSE,
    row.names = FALSE,
    fileEncoding = "UTF-8"
  )
  cat(sprintf("oracle.R: zujose encrypted %d JSON tokens\n", nrow(rows)))
}

decrypt_json <- function(dir) {
  keys <- read_keys(dir)
  rows <- utils::read.delim(
    file.path(dir, "py-json.tsv"),
    colClasses = "character",
    quote = "",
    encoding = "UTF-8"
  )
  n <- 0L
  for (i in seq_len(nrow(rows))) {
    algs <- strsplit(rows$algs[[i]], ",", fixed = TRUE)[[1]]
    kids <- strsplit(rows$kids[[i]], ",", fixed = TRUE)[[1]]
    for (j in seq_along(kids)) {
      out <- jwe_decrypt(
        rows$token[[i]],
        keys[[kids[[j]]]],
        algorithms = algs,
        encryptions = rows$enc[[i]]
      )
      if (
        !identical(out$plaintext, charToRaw(enc2utf8(plaintext))) ||
          !identical(out$alg, algs[[j]]) ||
          !identical(out$header[["x-shared"]], "unprotected") ||
          !identical(out$header[["x-recipient"]], kids[[j]]) ||
          !identical(out$header$cty, "text/plain")
      ) {
        stop(sprintf(
          "oracle.R: FAILED %s %s %s",
          rows$id[[i]],
          rows$enc[[i]],
          kids[[j]]
        ))
      }
      n <- n + 1L
    }
  }
  cat(sprintf(
    "oracle.R: zujose decrypted %d jwcrypto JSON tokens for %d recipients\n",
    nrow(rows),
    n
  ))
}

decrypt_all <- function(dir) {
  keys <- read_keys(dir)
  rows <- utils::read.delim(
    file.path(dir, "py-tokens.tsv"),
    colClasses = "character",
    quote = ""
  )
  for (i in seq_len(nrow(rows))) {
    out <- jwe_decrypt(
      rows$token[[i]],
      keys,
      algorithms = rows$alg[[i]],
      encryptions = rows$enc[[i]]
    )
    if (!identical(out$plaintext, charToRaw(enc2utf8(plaintext)))) {
      stop(sprintf("oracle.R: FAILED %s %s", rows$alg[[i]], rows$enc[[i]]))
    }
  }
  combos <- unique(rows[c("alg", "enc")])
  cat(sprintf(
    "oracle.R: zujose decrypted %d jwcrypto tokens (%d alg/enc pairs)\n",
    nrow(rows),
    nrow(combos)
  ))
}

args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 2L) {
  stop("usage: oracle.R keys|encrypt|decrypt <dir>")
}
switch(
  args[[1]],
  keys = write_keys(args[[2]]),
  encrypt = {
    encrypt_all(args[[2]])
    encrypt_json(args[[2]])
  },
  decrypt = {
    decrypt_all(args[[2]])
    decrypt_json(args[[2]])
  },
  stop("usage: oracle.R keys|encrypt|decrypt <dir>")
)
