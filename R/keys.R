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

# The zucrypt release each asymmetric key type needs. A type is usable when
# this version of zujwt implements it and the installed zucrypt provides it
# (zucrypt_provides(), algorithms.R); until then it is read and kept, but
# not used.
pending_key_types <- c(RSA = "0.4.0", EC = "0.5.0", OKP = "0.5.0")
implemented_key_types <- c("oct", "RSA", "EC", "OKP")

# The curves zujwt uses: EC on the three NIST curves, OKP for X25519 only
# (there is no Ed25519 in zucrypt), with their sizes in bits.
ec_curves <- c("P-256" = 256L, "P-384" = 384L, "P-521" = 521L)

key_type_usable <- function(kty, crv = NULL) {
  if (kty == "oct") {
    return(TRUE)
  }
  if (kty == "OKP" && !identical(crv, "X25519")) {
    return(FALSE)
  }
  kty %in%
    implemented_key_types &&
    zucrypt_provides(pending_key_types[[kty]], utils::packageVersion("zucrypt"))
}

# RSA (Stage 8). The JWK members hold the key; a zucrypt key object is
# built from them for each operation, so that a jose_key stays an ordinary
# R object that survives saveRDS().
rsa_private_members <- c("d", "p", "q", "dp", "dq", "qi")

rsa_member_raw <- function(key, name) {
  b64url_decode(key$members[[name]], "RSA key member")
}

has_private <- function(key) {
  if (key$kty == "RSA") {
    all(rsa_private_members %in% names(key$members))
  } else {
    key$kty %in% c("EC", "OKP") && "d" %in% names(key$members)
  }
}

# EC and X25519 (Stage 9): the zucrypt key from the JWK members, private
# when asked and present.
ec_crypt_key <- function(key, private) {
  m <- function(name) b64url_decode(key$members[[name]], "EC key member")
  if (key$kty == "OKP") {
    return(
      if (private) {
        zucrypt::crypt_read_x25519_key(m("d"))
      } else {
        zucrypt::crypt_read_x25519_pubkey(m("x"))
      }
    )
  }
  zucrypt::crypt_ec_key(key$members$crv, m("x"), m("y"), if (private) m("d"))
}

# JWK members from a zucrypt EC or X25519 key.
ec_members <- function(ck) {
  data <- as.list(ck)$data
  if (inherits(ck, "crypt_x25519")) {
    out <- list(crv = "X25519", x = b64url_encode(data$x))
    if (!is.null(data$d)) out$d <- b64url_encode(data$d)
  } else {
    out <- list(
      crv = data$curve,
      x = b64url_encode(data$x),
      y = b64url_encode(data$y)
    )
    if (!is.null(data$secret)) out$d <- b64url_encode(data$secret)
  }
  out
}

# A jose_key's type, members and size, from any zucrypt key.
crypt_key_members <- function(ck) {
  if (inherits(ck, "crypt_rsa")) {
    list(
      kty = "RSA",
      members = rsa_members(ck),
      bits = as.integer(as.list(ck)$size)
    )
  } else if (inherits(ck, "crypt_x25519")) {
    list(kty = "OKP", members = ec_members(ck), bits = 255L)
  } else {
    m <- ec_members(ck)
    list(kty = "EC", members = m, bits = unname(ec_curves[[m$crv]]))
  }
}

# The zucrypt key for `key`: the private key when asked and present,
# otherwise the public one.
rsa_crypt_key <- function(key, private) {
  parts <- lapply(c("n", "e"), function(n) rsa_member_raw(key, n))
  if (private) {
    parts <- c(
      parts,
      lapply(rsa_private_members, function(n) rsa_member_raw(key, n))
    )
  }
  do.call(zucrypt::crypt_rsa_key, parts)
}

# JWK members (Base64url strings) from a zucrypt RSA key.
rsa_members <- function(ck) {
  data <- as.list(ck)$data
  names <- intersect(c("n", "e", rsa_private_members), names(data))
  stats::setNames(lapply(data[names], b64url_encode), names)
}

# RFC 7518 §3.3: at least 2048 bits, for any use.
check_rsa_size <- function(key, call) {
  if ((key$bits %||% 0) < 2048) {
    abort_zujwt(
      "key",
      "An RSA key must be at least 2048 bits (RFC 7518 section 3.3).",
      call = call
    )
  }
}

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

#' Generate a random key
#'
#' `jose_key_generate()` makes a new key from the operating system's
#' cryptographic random source, through zucrypt: `oct`, `RSA`, `EC` (on
#' P-256, P-384 or P-521) and `OKP` (X25519) keys. There is no Ed25519.
#'
#' Without `size`, an `oct` key is as long as `alg` needs: the hash size for
#' `HS256`, `HS384` and `HS512` (RFC 7518 section 3.2), the key size for
#' `A*KW` and `A*GCMKW`, and 256 bits otherwise. A `dir` key must match the
#' content encryption: 256 bits for `A128CBC-HS256`, 384 for
#' `A192CBC-HS384` and 512 for `A256CBC-HS512`.
#'
#' An `RSA` key's `size` is its modulus, 2048 bits by default and at most
#' 4096, with public exponent 65537. Generating one takes a moment.
#'
#' @param kty The key type: `"oct"`, `"RSA"`, `"EC"` or `"OKP"`.
#' @param size The key size in bits. For an `oct` key, a multiple of 8 and at
#'   least 128, and `NULL` takes the size `alg` needs; for an `RSA` key, 2048
#'   to 4096, and `NULL` is 2048.
#' @param crv The curve: `"P-256"` (the default), `"P-384"` or `"P-521"`
#'   for an `EC` key, `"X25519"` for an `OKP` key. Not used otherwise.
#' @inheritParams jose_key_oct
#' @returns A `jose_key`.
#' @seealso [jose_key_oct()] to wrap a secret you already have,
#'   [jose_with_kid()] to name the new key by its thumbprint.
#' @export
#' @examples
#' key <- jose_key_generate("oct", alg = "HS256")
#' key
#'
#' # A key encryption key, named by its thumbprint.
#' jose_with_kid(jose_key_generate("oct", alg = "A256KW"))
jose_key_generate <- function(
  kty,
  size = NULL,
  crv = NULL,
  alg = NULL,
  kid = NULL,
  use = NULL,
  key_ops = NULL
) {
  call <- sys.call()
  if (!is_string(kty) || !kty %in% c("oct", names(pending_key_types))) {
    abort_zujwt(
      "key",
      "`kty` must be \"oct\", \"RSA\", \"EC\" or \"OKP\".",
      call = call
    )
  }
  if (kty == "RSA" && key_type_usable("RSA")) {
    return(generate_rsa(size, crv, alg, kid, use, key_ops, call))
  }
  # The curve is checked by generate_ec(); here only whether zucrypt has
  # the key type at all.
  if (kty %in% c("EC", "OKP") && key_type_usable(kty, "X25519")) {
    return(generate_ec(kty, size, crv, alg, kid, use, key_ops, call))
  }
  if (kty != "oct") {
    abort_unsupported(kty, pending_key_types[[kty]], call = call)
  }
  if (!is.null(crv)) {
    abort_zujwt("key", "An `oct` key has no `crv`.", call = call)
  }
  if (!is.null(alg) && !is_string(alg)) {
    abort_zujwt("key", "`alg` must be a single string.", call = call)
  }
  need <- oct_key_bits(alg, call)
  if (is.null(size)) {
    size <- need$bits
  }
  ok <- is.numeric(size) &&
    length(size) == 1L &&
    is.finite(size) &&
    size >= 128 &&
    size %% 8 == 0
  if (!ok) {
    abort_zujwt(
      "key",
      "`size` must be a whole number of bytes, in bits, of at least 128.",
      call = call
    )
  }
  if (size < need$bits || (need$exact && size != need$bits)) {
    abort_zujwt(
      "key",
      sprintf(
        "An %s key must be %s %d bits.",
        alg,
        if (need$exact) "exactly" else "at least",
        need$bits
      ),
      call = call
    )
  }
  new_jose_key(
    kty = "oct",
    k = zucrypt::crypt_rand_bytes(size / 8),
    kid = kid,
    alg = alg,
    use = use,
    key_ops = key_ops,
    call = call
  )
}

generate_rsa <- function(size, crv, alg, kid, use, key_ops, call) {
  if (!is.null(crv)) {
    abort_zujwt("key", "An `RSA` key has no `crv`.", call = call)
  }
  if (!is.null(alg) && (!is_string(alg) || !"RSA" %in% alg_key_types(alg))) {
    abort_zujwt(
      "key",
      "`alg` must be an RSA algorithm such as \"RS256\" or \"RSA-OAEP\".",
      call = call
    )
  }
  size <- size %||% 2048
  ok <- is.numeric(size) &&
    length(size) == 1L &&
    is.finite(size) &&
    size == trunc(size) &&
    size >= 2048 &&
    size <= 4096
  if (!ok) {
    abort_zujwt(
      "key",
      "`size` must be a whole number of bits from 2048 to 4096.",
      call = call
    )
  }
  ck <- zucrypt::crypt_rsa_keygen(size)
  new_jose_key(
    kty = "RSA",
    kid = kid,
    alg = alg,
    use = use,
    key_ops = key_ops,
    members = rsa_members(ck),
    bits = as.integer(size),
    call = call
  )
}

generate_ec <- function(kty, size, crv, alg, kid, use, key_ops, call) {
  crv <- crv %||% if (kty == "EC") "P-256" else "X25519"
  curves <- if (kty == "EC") names(ec_curves) else "X25519"
  if (!is_string(crv) || !crv %in% curves) {
    abort_zujwt(
      "key",
      sprintf(
        "`crv` must be %s for an `%s` key.",
        paste0('"', curves, '"', collapse = ", "),
        kty
      ),
      call = call
    )
  }
  if (!is.null(size)) {
    abort_zujwt(
      "key",
      "The curve sets an EC key's size; omit `size`.",
      call = call
    )
  }
  probe <- list(kty = kty, members = list(crv = crv))
  if (
    !is.null(alg) &&
      (!is_string(alg) ||
        !curve_fits(probe, alg) ||
        !kty %in% alg_key_types(alg))
  ) {
    abort_zujwt(
      "key",
      sprintf("`alg` does not fit a %s key.", crv),
      call = call
    )
  }
  ck <- if (kty == "OKP") {
    zucrypt::crypt_x25519_keygen()
  } else {
    zucrypt::crypt_ec_keygen(crv)
  }
  parts <- crypt_key_members(ck)
  new_jose_key(
    kty = kty,
    kid = kid,
    alg = alg,
    use = use,
    key_ops = key_ops,
    members = parts$members,
    bits = parts$bits,
    call = call
  )
}

# The size an oct key for `alg` needs, in bits, and whether it is exact.
oct_key_bits <- function(alg, call) {
  if (is.null(alg) || alg == "dir") {
    return(list(bits = 256, exact = FALSE))
  }
  if (alg %in% names(hmac_min_bytes)) {
    return(list(bits = 8 * hmac_min_bytes[[alg]], exact = FALSE))
  }
  if (grepl("^A(128|192|256)(GCM)?KW$", alg)) {
    return(list(bits = as.numeric(substr(alg, 2L, 4L)), exact = TRUE))
  }
  abort_zujwt(
    "key",
    sprintf("\"%s\" is not an algorithm for an `oct` key.", alg),
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
  bits = NULL,
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
  supported <- key_type_usable(kty, members$crv)
  # An OKP curve other than X25519 (Ed25519, X448) waits on no zucrypt
  # version: the bundled library has none of them.
  needs <- if (!(kty == "OKP" && !identical(members$crv, "X25519"))) {
    unname(pending_key_types[kty])
  }
  structure(
    list(
      kty = kty,
      kid = kid,
      alg = alg,
      use = use,
      key_ops = key_ops,
      k = k,
      members = members,
      bits = bits,
      supported = supported,
      needs = if (!supported) needs
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
#' `RSA` keys need `n` and `e`, and for a private key all of `d`, `p`, `q`,
#' `dp`, `dq` and `qi`; they are checked when read. A PEM string holding an
#' RSA key, in PKCS#1, PKCS#8 or SubjectPublicKeyInfo, is read too.
#'
#' `EC` keys on P-256, P-384 and P-521 and `OKP` keys on X25519 are checked
#' when read: the point must be on its curve. PEM holding an EC or X25519 key
#' is read too. Other `OKP` keys, such as Ed25519, are read and kept so that
#' they can be listed, selected and thumbprinted, but cannot be used.
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
    return(pem_to_key(x, call))
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

  bits <- if (kty == "RSA" && key_type_usable("RSA")) {
    check_rsa_jwk(members, call)
  } else if (kty %in% c("EC", "OKP") && key_type_usable(kty, members$crv)) {
    check_ec_jwk(kty, members, call)
  }

  new_jose_key(
    kty = kty,
    k = k,
    kid = member(jwk, "kid"),
    alg = member(jwk, "alg"),
    use = member(jwk, "use"),
    key_ops = key_ops,
    members = members,
    bits = bits,
    call = call
  )
}

# An RSA JWK's members must make a key: n and e, and for a private key all
# of the CRT parameters, consistent with each other. Returns the modulus
# size in bits.
check_rsa_jwk <- function(members, call) {
  if (!all(c("n", "e") %in% names(members))) {
    abort_zujwt("key", "An RSA JWK needs `n` and `e`.", call = call)
  }
  given <- rsa_private_members %in% names(members)
  if (any(given) && !all(given)) {
    abort_zujwt(
      "key",
      paste0(
        "A private RSA JWK needs all of `d`, `p`, `q`, `dp`, `dq` and ",
        "`qi`; zujwt does not reconstruct the primes."
      ),
      call = call
    )
  }
  key <- list(kty = "RSA", members = members)
  ck <- tryCatch(
    rsa_crypt_key(key, all(given)),
    zujwt_error = function(e) e,
    zucrypt_error = function(e) e
  )
  if (inherits(ck, "error")) {
    abort_zujwt(
      "key",
      "The RSA JWK's members do not make a valid key.",
      call = call
    )
  }
  as.integer(as.list(ck)$size)
}

# An EC JWK needs a NIST curve, x and y; an X25519 one, x. Either may carry
# d. The point (and d) must make a key. Returns the size in bits.
check_ec_jwk <- function(kty, members, call) {
  need <- if (kty == "EC") c("crv", "x", "y") else c("crv", "x")
  if (
    !all(need %in% names(members)) ||
      (kty == "EC" && !members$crv %in% names(ec_curves))
  ) {
    abort_zujwt(
      "key",
      sprintf(
        "An %s JWK needs %s on a supported curve.",
        kty,
        paste0("`", need, "`", collapse = ", ")
      ),
      call = call
    )
  }
  key <- list(kty = kty, members = members)
  ck <- tryCatch(
    ec_crypt_key(key, "d" %in% names(members)),
    zujwt_error = function(e) e,
    zucrypt_error = function(e) e
  )
  if (inherits(ck, "error")) {
    abort_zujwt(
      "key",
      "The JWK's point is not on its curve, or its members are not a key.",
      call = call
    )
  }
  if (kty == "OKP") 255L else unname(ec_curves[[members$crv]])
}

# A PEM key, through zucrypt: private first, then public.
pem_to_key <- function(x, call) {
  if (!key_type_usable("RSA")) {
    abort_unsupported("PEM", pending_key_types[["RSA"]], call = call)
  }
  ck <- tryCatch(zucrypt::crypt_read_key(x), zucrypt_error = function(e) {
    tryCatch(zucrypt::crypt_read_pubkey(x), zucrypt_error = function(e) e)
  })
  if (inherits(ck, "error")) {
    abort_zujwt(
      "key",
      "The PEM is not an unencrypted RSA, EC or X25519 key zujwt can read.",
      call = call
    )
  }
  parts <- crypt_key_members(ck)
  new_jose_key(
    kty = parts$kty,
    members = parts$members,
    bits = parts$bits,
    call = call
  )
}

#' Write a key as PEM
#'
#' `jose_pem()` writes an RSA, EC or X25519 key as PEM: the public key as
#' SubjectPublicKeyInfo (`PUBLIC KEY`), or with `private = TRUE` the private
#' key as PKCS#8 (`PRIVATE KEY`), byte for byte as the openssl package
#' writes them.
#'
#' @param key An RSA, EC or X25519 `jose_key`.
#' @param private Whether to write the private key.
#' @returns A single string.
#' @seealso [as_jose_key()], which reads PEM.
#' @export
#' @examples
#' key <- jose_key_generate("RSA")
#' cat(jose_pem(key))
jose_pem <- function(key, private = FALSE) {
  call <- sys.call()
  key <- check_key(key, call)
  if (!isTRUE(private) && !isFALSE(private)) {
    abort_zujwt("key", "`private` must be TRUE or FALSE.", call = call)
  }
  if (key$kty == "oct" || !key$supported) {
    abort_zujwt(
      "key",
      "Only RSA, EC and X25519 keys are written as PEM.",
      call = call
    )
  }
  if (private && !has_private(key)) {
    abort_zujwt(
      "key",
      "This is a public key; it has no private part.",
      call = call
    )
  }
  ck <- if (key$kty == "RSA") {
    rsa_crypt_key(key, private)
  } else {
    ec_crypt_key(key, private)
  }
  zucrypt::crypt_write_pem(ck)
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
  bits <- if (!is.null(x$k)) {
    sprintf(", %d bits", 8L * length(x$k))
  } else if (!is.null(x$bits)) {
    sprintf(", %d bits", x$bits)
  } else {
    ""
  }
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
      if (is.null(x$needs)) {
        sprintf("  ! not usable: zujwt has no %s", x$members$crv %||% x$kty)
      } else {
        sprintf("  ! not usable yet: needs zucrypt (>= %s)", x$needs)
      }
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
