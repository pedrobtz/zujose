# Keys (design §7.2, §8.3).
#
# A jwk is a list of class "jwk" with:
#
# * `kty`, `kid`, `alg`, `use`, `key_ops`: the JWK's common members, NULL
#   when absent;
# * `k`: for an oct key, the secret as a raw vector;
# * `members`: every other member as read, so that a key zujose cannot use
#   (such as Ed25519, or a key type the installed zucrypt lacks) can still
#   be listed, selected, written and thumbprinted;
# * `supported`: whether the installed zujose can use the key, and `needs`,
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
# this version of zujose implements it and the installed zucrypt provides it
# (zucrypt_provides(), algorithms.R); otherwise it is read and kept, but not
# used.
key_type_zucrypt <- c(RSA = "0.1.1", EC = "0.1.1", OKP = "0.1.1")
implemented_key_types <- c("oct", "RSA", "EC", "OKP")

# The curves zujose uses: EC on the three NIST curves, OKP for X25519 only
# (there is no Ed25519 in zucrypt), with their sizes in bits.
ec_curves <- c("P-256" = 256L, "P-384" = 384L, "P-521" = 521L)

#' Make a symmetric key
#'
#' `jwk_oct()` wraps a secret as a JSON Web Key of type `oct` (RFC 7518
#' section 6.4), the key type of the `HS*`, `A*KW`, `A*GCMKW` and `dir`
#' algorithms.
#'
#' The secret is a raw vector, never a string: a key is bytes, and a
#' password is not a key.
#'
#' @section Secrets in memory:
#' zujose is pure R, and so are its keys: an `oct` secret, and the private
#' members of an RSA, EC or X25519 key, are ordinary R vectors. R copies
#' vectors freely and has no way to wipe one, so a secret may stay in memory
#' after the key is gone, and may reach a saved workspace or a core dump.
#' zujose never prints secret members and never puts them in an error
#' message, but it cannot do more than that. Keep long-lived secrets out of
#' saved workspaces (`.RData`) and load them from a secret store when they
#' are needed.
#'
#' @param secret The key, as a raw vector of at least one byte.
#' @param alg The one algorithm the key is meant for, such as `"HS256"`, or
#'   `NULL`. When set, a token whose `alg` differs is refused.
#' @param kid A key identifier, or `NULL`. See [jwk_with_kid()].
#' @param use `"sig"` or `"enc"`, or `NULL`.
#' @param key_ops The operations the key may be used for, from `"sign"`,
#'   `"verify"`, `"encrypt"`, `"decrypt"`, `"wrapKey"`, `"unwrapKey"`,
#'   `"deriveKey"` and `"deriveBits"`, or `NULL`.
#' @returns A `jwk`.
#' @seealso [as_jwk()] to read a JWK, [jwk_json()] to write one.
#' @export
#' @examples
#' key <- jwk_oct(as.raw(1:32), alg = "HS256", kid = "k1")
#' key
jwk_oct <- function(
  secret,
  alg = NULL,
  kid = NULL,
  use = NULL,
  key_ops = NULL
) {
  oct_key(secret, alg, kid, use, key_ops, sys.call())
}

# The body of jwk_oct(), shared with as_jwk() so that errors name the
# function the caller called.
oct_key <- function(secret, alg, kid, use, key_ops, call) {
  if (!is.raw(secret)) {
    abort_zujose("argument", "`secret` must be a raw vector.", call = call)
  }
  if (length(secret) == 0L) {
    abort_zujose("key", "`secret` must be at least one byte.", call = call)
  }
  new_jwk(
    kty = "oct",
    k = secret,
    kid = kid,
    alg = alg,
    use = use,
    key_ops = key_ops,
    call = call,
    kind = "argument"
  )
}

#' Generate a random key
#'
#' `jwk_generate()` makes a new key from the operating system's
#' cryptographic random source, through zucrypt: `oct`, `RSA`, `EC` (on
#' P-256, P-384 or P-521) and `OKP` (X25519) keys. There is no Ed25519.
#'
#' Without `size`, an `oct` key is as long as `alg` needs: the hash size for
#' `HS256`, `HS384` and `HS512` (RFC 7518 section 3.2), the key size for
#' `A*KW` and `A*GCMKW`, and 256 bits otherwise, as for a `PBES2-*`
#' password. A `dir` key is the content encryption key itself: name it by
#' its content encryption, such as `alg = "A128GCM"`, to get its exact size
#' (256 bits for `A128CBC-HS256`, 384 for `A192CBC-HS384`, 512 for
#' `A256CBC-HS512`, and 128, 192 or 256 for `A128GCM`, `A192GCM` and
#' `A256GCM`), or give `alg = "dir"` and its `size`.
#'
#' An `RSA` key's `size` is its modulus, a multiple of 8 bits, 2048 by
#' default and at most 4096, with public exponent 65537. Generating one takes
#' a moment.
#'
#' @param kty The key type: `"oct"`, `"RSA"`, `"EC"` or `"OKP"`.
#' @param size The key size in bits. For an `oct` key, a multiple of 8 and at
#'   least 128, and `NULL` takes the size `alg` needs; for an `RSA` key, a
#'   multiple of 8 from 2048 to 4096, and `NULL` is 2048.
#' @param crv The curve: `"P-256"` (the default), `"P-384"` or `"P-521"`
#'   for an `EC` key, `"X25519"` for an `OKP` key. Not used otherwise.
#' @inheritParams jwk_oct
#' @returns A `jwk`.
#' @inheritSection jwk_oct Secrets in memory
#' @seealso [jwk_oct()] to wrap a secret you already have,
#'   [jwk_with_kid()] to name the new key by its thumbprint.
#' @export
#' @examples
#' key <- jwk_generate("oct", alg = "HS256")
#' key
#'
#' # A key encryption key, named by its thumbprint.
#' jwk_with_kid(jwk_generate("oct", alg = "A256KW"))
jwk_generate <- function(
  kty,
  size = NULL,
  crv = NULL,
  alg = NULL,
  kid = NULL,
  use = NULL,
  key_ops = NULL
) {
  call <- sys.call()
  if (!is_string(kty) || !kty %in% c("oct", names(key_type_zucrypt))) {
    abort_zujose(
      "argument",
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
    abort_unsupported(kty, key_type_zucrypt[[kty]], call = call)
  }
  if (!is.null(crv)) {
    abort_zujose("argument", "An `oct` key has no `crv`.", call = call)
  }
  if (!is.null(alg) && !is_string(alg)) {
    abort_zujose("argument", "`alg` must be a single string.", call = call)
  }
  need <- oct_key_bits(alg, call)
  if (is.null(size)) {
    size <- need$bits
  }
  check_size_arg(size, call)
  if (size < 128 || size %% 8 != 0) {
    abort_zujose(
      "key",
      "`size` must be a whole number of bytes, in bits, of at least 128.",
      call = call
    )
  }
  if (size < need$min || (need$exact && size != need$bits)) {
    abort_zujose(
      "key",
      sprintf(
        "An %s key must be %s %d bits.",
        alg,
        if (need$exact) "exactly" else "at least",
        need$min
      ),
      call = call
    )
  }
  new_jwk(
    kty = "oct",
    k = zucrypt::crypt_rand_bytes(size / 8),
    kid = kid,
    alg = alg,
    use = use,
    key_ops = key_ops,
    call = call,
    kind = "argument"
  )
}

# A key size argument is one finite number; whether it makes a strong
# enough key is a key error.
check_size_arg <- function(size, call) {
  if (!is.numeric(size) || length(size) != 1L || !is.finite(size)) {
    abort_zujose("argument", "`size` must be a number of bits.", call = call)
  }
}

generate_rsa <- function(size, crv, alg, kid, use, key_ops, call) {
  if (!is.null(crv)) {
    abort_zujose("argument", "An `RSA` key has no `crv`.", call = call)
  }
  if (!is.null(alg) && (!is_string(alg) || !"RSA" %in% alg_key_types(alg))) {
    abort_zujose(
      "argument",
      "`alg` must be an RSA algorithm such as \"RS256\" or \"RSA-OAEP\".",
      call = call
    )
  }
  size <- size %||% rsa_min_bits
  check_size_arg(size, call)
  ok <- size %% 8 == 0 &&
    size >= rsa_min_bits &&
    size <= 4096
  if (!ok) {
    abort_zujose(
      "key",
      "`size` must be a whole number of bytes, in bits, from 2048 to 4096.",
      call = call
    )
  }
  ck <- zucrypt::crypt_rsa_keygen(size)
  new_jwk(
    kty = "RSA",
    kid = kid,
    alg = alg,
    use = use,
    key_ops = key_ops,
    members = rsa_members(ck),
    bits = as.integer(size),
    call = call,
    kind = "argument"
  )
}

generate_ec <- function(kty, size, crv, alg, kid, use, key_ops, call) {
  crv <- crv %||% if (kty == "EC") "P-256" else "X25519"
  curves <- if (kty == "EC") names(ec_curves) else "X25519"
  if (!is_string(crv) || !crv %in% curves) {
    abort_zujose(
      "argument",
      sprintf(
        "`crv` must be %s for an `%s` key.",
        paste0('"', curves, '"', collapse = ", "),
        kty
      ),
      call = call
    )
  }
  if (!is.null(size)) {
    abort_zujose(
      "argument",
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
    abort_zujose(
      "argument",
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
  new_jwk(
    kty = kty,
    kid = kid,
    alg = alg,
    use = use,
    key_ops = key_ops,
    members = parts$members,
    bits = parts$bits,
    call = call,
    kind = "argument"
  )
}

# The default size of an `oct` key for `alg`, the least it may be, and
# whether it must be exactly that.
oct_key_bits <- function(alg, call) {
  if (is.null(alg) || alg == "dir") {
    return(list(bits = 256, min = 128, exact = FALSE))
  }
  if (alg %in% names(hmac_min_bytes)) {
    bits <- 8 * hmac_min_bytes[[alg]]
    return(list(bits = bits, min = bits, exact = FALSE))
  }
  if (grepl("^A(128|192|256)(GCM)?KW$", alg)) {
    bits <- as.numeric(substr(alg, 2L, 4L))
    return(list(bits = bits, min = bits, exact = TRUE))
  }
  # A PBES2 key is a password, of any length (#132).
  if ("oct" %in% alg_key_types(alg)) {
    return(list(bits = 256, min = 128, exact = FALSE))
  }
  # A `dir` key named by its content encryption is that algorithm's CEK.
  if (alg %in% c(names(cbc_hs), names(gcm_key_bytes))) {
    bits <- 8 * cek_bytes(alg)
    return(list(bits = bits, min = bits, exact = TRUE))
  }
  abort_zujose(
    "argument",
    sprintf("\"%s\" is not an algorithm for an `oct` key.", alg),
    call = call
  )
}

new_jwk <- function(
  kty,
  k = NULL,
  kid = NULL,
  alg = NULL,
  use = NULL,
  key_ops = NULL,
  members = empty_object(),
  bits = NULL,
  call = NULL,
  kind = "key"
) {
  # `kind` is "argument" for members the caller passes as arguments, and
  # "key" for members read from a JWK.
  for (name in c("kid", "alg", "use")) {
    value <- get(name)
    if (!is.null(value) && !is_string(value)) {
      abort_zujose(
        kind,
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
      abort_zujose(
        kind,
        "`key_ops` must name distinct operations from RFC 7517 section 4.3.",
        call = call
      )
    }
  }
  supported <- key_type_usable(kty, members[["crv"]])
  # An OKP curve other than X25519 (Ed25519, X448) waits on no zucrypt
  # version: the bundled library has none of them.
  # An unknown key type waits on no zucrypt version either (#136).
  needs <- if (
    (kty %in% names(key_type_zucrypt)) &&
      !(kty == "OKP" && !identical(members[["crv"]], "X25519"))
  ) {
    unname(key_type_zucrypt[[kty]])
  }
  structure(
    list(
      kty = kty,
      # Names would make zujson write a member as an object (#120).
      kid = unname(kid),
      alg = unname(alg),
      use = unname(use),
      key_ops = unname(key_ops),
      k = k,
      members = members,
      bits = bits,
      supported = supported,
      needs = if (!supported) needs
    ),
    class = "jwk"
  )
}

#' Read a JSON Web Key
#'
#' `as_jwk()` reads a JWK (RFC 7517) from its JSON text or from a list
#' already parsed. A raw vector is taken as an `oct` secret, as by
#' [jwk_oct()].
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
#' @inheritSection jwk_oct Secrets in memory
#' @param x JWK text, a parsed JWK as a named list, a raw secret, or a
#'   `jwk`.
#' @param ... Not used.
#' @returns A `jwk`.
#' @export
#' @examples
#' key <- as_jwk(paste0(
#'   '{"kty":"oct","kid":"k1","alg":"HS256",',
#'   '"k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}'
#' ))
#' key
as_jwk <- function(x, ...) {
  UseMethod("as_jwk")
}

#' @export
as_jwk.jwk <- function(x, ...) {
  x
}

#' @export
as_jwk.raw <- function(x, ...) {
  oct_key(x, NULL, NULL, NULL, NULL, sys.call(-1))
}

#' @export
as_jwk.character <- function(x, ...) {
  call <- sys.call(-1)
  if (!is_string(x)) {
    abort_zujose("argument", "A JWK must be a single string.", call = call)
  }
  if (grepl("^[[:space:]]*-----BEGIN", x)) {
    return(pem_to_key(x, call))
  }
  jwk_to_key(json_key_object(x, "JWK", call), call, json = TRUE)
}

#' @export
as_jwk.list <- function(x, ...) {
  list_to_key(x, sys.call(-1))
}

# `json` is whether the list was parsed from JSON text, where an array is
# always a list; a list built in R may hold a character vector instead.
list_to_key <- function(x, call, json = FALSE) {
  if (!is_json_object(x) || has_repeated_names(x)) {
    abort_zujose(
      "key",
      "A JWK must be a named list without repeated names.",
      call = call
    )
  }
  jwk_to_key(x, call, json)
}

#' @export
as_jwk.default <- function(x, ...) {
  abort_zujose(
    "argument",
    "Can't read a key from this object.",
    call = sys.call(-1)
  )
}

json_key_object <- function(text, what, call) {
  tryCatch(
    json_object(text, what, call),
    zujose_parse_error = function(e) {
      abort_zujose("key", conditionMessage(e), call = call)
    }
  )
}

jwk_to_key <- function(jwk, call, json = FALSE) {
  kty <- member(jwk, "kty")
  if (!is_string(kty)) {
    abort_zujose("key", "A JWK must have a string `kty`.", call = call)
  }
  key_ops <- jwk_key_ops(member(jwk, "key_ops"), json, call)
  common <- c("kty", "kid", "alg", "use", "key_ops")
  members <- jwk[setdiff(names(jwk), common)]

  k <- NULL
  if (kty == "oct") {
    k_text <- member(jwk, "k")
    if (!is_string(k_text) || !nzchar(k_text)) {
      abort_zujose("key", "An oct JWK must have a non-empty `k`.", call = call)
    }
    k <- tryCatch(
      b64url_decode(k_text, "key value", call),
      zujose_parse_error = function(e) {
        abort_zujose("key", conditionMessage(e), call = call)
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
      abort_zujose(
        "key",
        "The key members of a JWK must be strings.",
        call = call
      )
    }
  }

  bits <- if (kty == "RSA" && key_type_usable("RSA")) {
    check_rsa_jwk(members, call)
  } else if (
    kty %in% c("EC", "OKP") && key_type_usable(kty, members[["crv"]])
  ) {
    check_ec_jwk(kty, members, call)
  }

  new_jwk(
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

# `key_ops` is an array of strings (RFC 7517 §4.3): a JSON array, or a
# character vector in a list built in R. A present empty array permits no
# operation, so it is kept as character(0), never NULL (#121).
jwk_key_ops <- function(key_ops, json, call) {
  if (is.null(key_ops)) {
    return(NULL)
  }
  if (!json && is.character(key_ops) && is.null(names(key_ops))) {
    return(key_ops)
  }
  ok <- is.list(key_ops) &&
    is.null(names(key_ops)) &&
    all(vapply(key_ops, is_string, logical(1)))
  if (!ok) {
    abort_zujose("key", "`key_ops` must be an array of strings.", call = call)
  }
  as.character(unlist(key_ops))
}

# An RSA JWK's members must make a key: n and e, and for a private key all
# of the CRT parameters, consistent with each other. Returns the modulus
# size in bits.
check_rsa_jwk <- function(members, call) {
  if (!all(c("n", "e") %in% names(members))) {
    abort_zujose("key", "An RSA JWK needs `n` and `e`.", call = call)
  }
  # RFC 7518 §6.3.2.7: an implementation without multi-prime keys must not
  # use a key with `oth`, private or not (#125).
  if ("oth" %in% names(members)) {
    abort_zujose(
      "key",
      "zujose does not support multi-prime RSA keys (`oth`).",
      call = call
    )
  }
  given <- rsa_private_members %in% names(members)
  if (any(given) && !all(given)) {
    abort_zujose(
      "key",
      paste0(
        "A private RSA JWK needs all of `d`, `p`, `q`, `dp`, `dq` and ",
        "`qi`; zujose does not reconstruct the primes."
      ),
      call = call
    )
  }
  # RFC 7518 §2: a Base64urlUInt uses the fewest octets, so a key has one
  # encoding and one thumbprint (#94).
  for (name in c("n", "e", if (all(given)) rsa_private_members)) {
    value <- jwk_member_raw(members, name)
    if (is.null(value) || length(value) == 0L || value[[1]] == as.raw(0)) {
      abort_zujose(
        "key",
        sprintf(
          "The RSA JWK's `%s` is not a minimal Base64urlUInt.",
          name
        ),
        call = call
      )
    }
  }
  key <- list(kty = "RSA", members = members)
  ck <- tryCatch(
    rsa_crypt_key(key, all(given)),
    zujose_error = function(e) e,
    zucrypt_error = function(e) e
  )
  if (inherits(ck, "error")) {
    abort_zujose(
      "key",
      "The RSA JWK's members do not make a valid key.",
      call = call
    )
  }
  as.integer(as.list(ck)$size)
}

# A JWK member's bytes, or NULL when it is not a string of Base64url.
jwk_member_raw <- function(members, name) {
  value <- members[[name]]
  if (!is_string(value)) {
    return(NULL)
  }
  tryCatch(b64url_decode(value, name), zujose_error = function(e) NULL)
}

# An EC JWK needs a NIST curve, x and y; an X25519 one, x. Either may carry
# d. The point (and d) must make a key. Returns the size in bits.
check_ec_jwk <- function(kty, members, call) {
  need <- if (kty == "EC") c("crv", "x", "y") else c("crv", "x")
  if (
    !all(need %in% names(members)) ||
      (kty == "EC" && !members[["crv"]] %in% names(ec_curves))
  ) {
    abort_zujose(
      "key",
      sprintf(
        "An %s JWK needs %s on a supported curve.",
        kty,
        paste0("`", need, "`", collapse = ", ")
      ),
      call = call
    )
  }
  # RFC 7518 §6.2.1.2, §6.2.1.3 and §6.2.2.1 (and RFC 8037 §2): `x`, `y`
  # and `d` are the full coordinate length, never shorter or longer (#94).
  bytes <- if (kty == "OKP") {
    32L
  } else {
    (ec_curves[[members[["crv"]]]] + 7L) %/% 8L
  }
  for (name in intersect(c("x", "y", "d"), names(members))) {
    if (length(jwk_member_raw(members, name)) != bytes) {
      abort_zujose(
        "key",
        sprintf("The JWK's `%s` is not %d bytes long.", name, bytes),
        call = call
      )
    }
  }
  key <- list(kty = kty, members = members)
  private <- "d" %in% names(members)
  ck <- tryCatch(
    ec_crypt_key(key, private),
    zujose_error = function(e) e,
    zucrypt_error = function(e) e
  )
  # An EC private key is built from x, y and d together, so zucrypt checks
  # that they agree; an X25519 one only from d, so `x` is compared with the
  # public key d makes (#124).
  if (
    !inherits(ck, "error") &&
      kty == "OKP" &&
      private &&
      !identical(as.list(ck)$data$x, jwk_member_raw(members, "x"))
  ) {
    ck <- simpleError("x does not match d")
  }
  if (inherits(ck, "error")) {
    abort_zujose(
      "key",
      "The JWK's point is not on its curve, or its members are not a key.",
      call = call
    )
  }
  if (kty == "OKP") 255L else unname(ec_curves[[members[["crv"]]]])
}

# A PEM key, through zucrypt: private first, then public.
pem_to_key <- function(x, call) {
  if (!key_type_usable("RSA")) {
    abort_unsupported("PEM", key_type_zucrypt[["RSA"]], call = call)
  }
  ck <- tryCatch(zucrypt::crypt_read_key(x), zucrypt_error = function(e) {
    tryCatch(zucrypt::crypt_read_pubkey(x), zucrypt_error = function(e) e)
  })
  if (inherits(ck, "error")) {
    abort_zujose(
      "key",
      "The PEM is not an unencrypted RSA, EC or X25519 key zujose can read.",
      call = call
    )
  }
  parts <- crypt_key_members(ck)
  new_jwk(
    kty = parts$kty,
    members = parts$members,
    bits = parts$bits,
    call = call
  )
}

#' Write a key as PEM
#'
#' `jwk_pem()` writes an RSA, EC or X25519 key as PEM: the public key as
#' SubjectPublicKeyInfo (`PUBLIC KEY`), or with `private = TRUE` the private
#' key as PKCS#8 (`PRIVATE KEY`), byte for byte as OpenSSL writes them.
#'
#' @inheritSection jwk_oct Secrets in memory
#' @param key An RSA, EC or X25519 `jwk`.
#' @param private Whether to write the private key.
#' @returns A single string.
#' @seealso [as_jwk()], which reads PEM.
#' @export
#' @examples
#' key <- jwk_generate("RSA")
#' cat(jwk_pem(key))
jwk_pem <- function(key, private = FALSE) {
  call <- sys.call()
  key <- check_key(key, call)
  check_flag(private, "private", call)
  if (key$kty == "oct" || !key$supported) {
    abort_zujose(
      "key",
      "Only RSA, EC and X25519 keys are written as PEM.",
      call = call
    )
  }
  if (private && !has_private(key)) {
    abort_zujose(
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
#' `jwk_with_kid()` sets `kid`, by default to the key's RFC 7638
#' thumbprint, which is stable and needs no registry.
#'
#' @param key A `jwk`.
#' @param kid The identifier.
#' @returns The key, with `kid` set.
#' @export
#' @examples
#' key <- jwk_with_kid(jwk_oct(as.raw(1:32)))
#' key$kid
jwk_with_kid <- function(key, kid = jwk_thumbprint(key)) {
  call <- sys.call()
  key <- check_key(key, call)
  if (!is_string(kid)) {
    abort_zujose("argument", "`kid` must be a single string.", call = call)
  }
  key$kid <- kid
  key
}

#' Write a key or key set as JSON
#'
#' `jwk_json()` writes a `jwk` as a JWK, or a `jwk_set` as a JWK
#' Set, in compact JSON. By default only public members are written, so the
#' result is safe to publish; a symmetric (`oct`) key has no public part,
#' and is refused alone or dropped from a set.
#'
#' @param x A `jwk` or `jwk_set`.
#' @param private Whether to write private members, including the secrets
#'   of `oct` keys.
#' @returns A single string.
#' @export
#' @examples
#' key <- jwk_oct(as.raw(1:32), alg = "HS256", kid = "k1")
#' jwk_json(key, private = TRUE)
jwk_json <- function(x, private = FALSE) {
  call <- sys.call()
  check_flag(private, "private", call)
  if (!private) {
    x <- public_jwk(x, call)
  }
  if (inherits(x, "jwk_set")) {
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
#' `jwk_public()` removes private members: `d`, `p`, `q`, `dp`, `dq`,
#' `qi` and `oth`. A symmetric (`oct`) key is entirely secret, so it is an
#' error alone and dropped from a key set.
#'
#' A private key's `key_ops` become those of its public half: `sign` becomes
#' `verify`, `decrypt` becomes `encrypt` and `unwrapKey` becomes `wrapKey`,
#' and public operations stay. When no public operation is left, as for a
#' key only for `deriveKey`, the public key has no `key_ops`.
#'
#' @param x A `jwk` or `jwk_set`.
#' @returns An object of the same class.
#' @export
#' @examples
#' set <- as_jwk_set('{"keys":[{"kty":"oct","k":"AAAA"}]}')
#' length(jwk_public(set))
jwk_public <- function(x) {
  public_jwk(x, sys.call())
}

# The body of jwk_public(), shared with jwk_json().
public_jwk <- function(x, call) {
  if (inherits(x, "jwk_set")) {
    keys <- Filter(function(key) key$kty != "oct", unclass(x))
    return(new_jwk_set(lapply(keys, public_key)))
  }
  key <- check_key(x, call)
  if (key$kty == "oct") {
    abort_zujose(
      "key",
      "A symmetric (oct) key has no public part.",
      call = call
    )
  }
  public_key(key)
}

public_key <- function(key) {
  private <- names(key$members) %in% private_members
  if (any(private)) {
    key$key_ops <- public_key_ops(key$key_ops)
  }
  key$members <- key$members[!private]
  key
}

# The operations of a key's public half: each private operation becomes its
# public counterpart, and public ones stay. With none left, `key_ops` is
# dropped rather than publishing a key that can do nothing (#133). An empty
# `key_ops` already permits nothing, and stays empty.
public_ops <- c(
  sign = "verify",
  verify = "verify",
  decrypt = "encrypt",
  encrypt = "encrypt",
  unwrapKey = "wrapKey",
  wrapKey = "wrapKey"
)

public_key_ops <- function(key_ops) {
  if (length(key_ops) == 0L) {
    return(key_ops)
  }
  ops <- unique(unname(public_ops[intersect(key_ops, names(public_ops))]))
  if (length(ops) == 0L) NULL else ops
}

check_key <- function(key, call) {
  if (!inherits(key, "jwk")) {
    abort_zujose("argument", "`key` must be a jwk.", call = call)
  }
  key
}

#' @export
format.jwk <- function(x, ...) {
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
  lines <- sprintf("<jwk> %s%s", x$kty, bits)
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
      if (!x$kty %in% c("oct", names(key_type_zucrypt))) {
        "  ! not usable: unknown key type"
      } else if (is.null(x$needs)) {
        sprintf(
          "  ! not usable: zujose has no %s",
          x$members[["crv"]] %||% x$kty
        )
      } else {
        sprintf("  ! not usable yet: needs zucrypt (>= %s)", x$needs)
      }
    )
  }
  lines
}

#' @export
print.jwk <- function(x, ...) {
  cat(format(x), sep = "\n")
  invisible(x)
}

# zucrypt keys ------------------------------------------------------------

key_type_usable <- function(kty, crv = NULL) {
  if (kty == "oct") {
    return(TRUE)
  }
  if (kty == "OKP" && !identical(crv, "X25519")) {
    return(FALSE)
  }
  installed <- utils::packageVersion("zucrypt")
  (kty %in% implemented_key_types) &&
    zucrypt_provides(key_type_zucrypt[[kty]], installed)
}

# RSA. The JWK members hold the key; a zucrypt key object is built from
# them for each operation, so that a jwk stays an ordinary R object that
# survives saveRDS().
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

# EC and X25519: the zucrypt key from the JWK members, private
# when asked and present.
ec_crypt_key <- function(key, private) {
  member_raw <- function(name) {
    b64url_decode(key$members[[name]], "EC key member")
  }
  if (key$kty == "OKP" && private) {
    return(zucrypt::crypt_read_x25519_key(member_raw("d")))
  }
  if (key$kty == "OKP") {
    return(zucrypt::crypt_read_x25519_pubkey(member_raw("x")))
  }
  zucrypt::crypt_ec_key(
    key$members[["crv"]],
    member_raw("x"),
    member_raw("y"),
    if (private) member_raw("d")
  )
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

# A jwk's type, members and size, from any zucrypt key.
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
    list(kty = "EC", members = m, bits = unname(ec_curves[[m[["crv"]]]]))
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
rsa_min_bits <- 2048L

rsa_key_strong <- function(key) {
  (key$bits %||% 0) >= rsa_min_bits
}

check_rsa_size <- function(key, call) {
  if (!rsa_key_strong(key)) {
    abort_zujose(
      "key",
      sprintf(
        "An RSA key must be at least %d bits (RFC 7518 section 3.3).",
        rsa_min_bits
      ),
      call = call
    )
  }
}
