# RFC 7638 §3.2: the required members of each key type.
thumbprint_members <- list(
  oct = c("k", "kty"),
  RSA = c("e", "kty", "n"),
  EC = c("crv", "kty", "x", "y"),
  OKP = c("crv", "kty", "x")
)

# RFC 9278 §3, names from the Named Information Hash Algorithm Registry.
thumbprint_hashes <- c(
  sha256 = "sha-256",
  sha384 = "sha-384",
  sha512 = "sha-512"
)

#' JWK thumbprint
#'
#' `jwk_thumbprint()` computes a key's RFC 7638 thumbprint: the hash of
#' its required members, in lexicographic order, as JSON without
#' whitespace. With `uri = TRUE` it returns the RFC 9278 thumbprint URI.
#'
#' The thumbprint of a private key equals that of its public key, since
#' private members are never part of it. It is a common `kid`; see
#' [jwk_with_kid()].
#'
#' @param key A `jwk`.
#' @param hash `"sha256"`, `"sha384"` or `"sha512"`.
#' @param uri Whether to return a `urn:ietf:params:oauth:jwk-thumbprint`
#'   URI rather than the bare Base64url value.
#' @returns A single string.
#' @export
#' @examples
#' key <- jwk_oct(as.raw(1:32))
#' jwk_thumbprint(key)
#' jwk_thumbprint(key, uri = TRUE)
jwk_thumbprint <- function(key, hash = "sha256", uri = FALSE) {
  call <- sys.call()
  key <- check_key(key, call)
  check_flag(uri, "uri", call)
  if (!is_string(hash) || !hash %in% names(thumbprint_hashes)) {
    abort_zujose(
      "key",
      "`hash` must be \"sha256\", \"sha384\" or \"sha512\".",
      call = call
    )
  }
  required <- thumbprint_members[[key$kty]]
  if (is.null(required)) {
    abort_zujose(
      "key",
      "RFC 7638 defines no thumbprint for this key type.",
      call = call
    )
  }
  jwk <- key_to_jwk(key)
  if (!all(required %in% names(jwk))) {
    abort_zujose(
      "key",
      "The key lacks a member its thumbprint needs.",
      call = call
    )
  }
  json <- zujson::json_write(jwk[required])
  digest <- zucrypt::crypt_hash(charToRaw(enc2utf8(json)), hash)
  value <- b64url_encode(digest)
  if (uri) {
    paste0(
      "urn:ietf:params:oauth:jwk-thumbprint:",
      thumbprint_hashes[[hash]],
      ":",
      value
    )
  } else {
    value
  }
}
