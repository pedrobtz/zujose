#' @details
#' Start with the Get started article, at
#' <https://pedrobtz.github.io/zujose/articles/zujose.html>. The main
#' functions are:
#'
#' * JWT: [jose_jwt_encode()], [jose_jwt_decode()], [jose_jwt_decoder()].
#' * JWS: [jose_sign()], [jose_verify()].
#' * JWE: [jose_encrypt()], [jose_decrypt()].
#' * Keys: [jose_key_oct()], [jose_key_generate()], [as_jose_key()],
#'   [jose_keyset()], [as_jose_keyset()], [jose_jwk()], [jose_pem()].
#' * Inspection: [jose_peek()], [zujose_info()].
#'
#' zujose never fetches anything: keys come only from the caller, as a
#' key, a key set, or a function that returns one (a resolver).
#'
#' @inheritSection jose_key_oct Secrets in memory
#' @keywords internal
#' @examples
#' key <- jose_key_generate("oct", alg = "HS256")
#' jwt <- jose_jwt_encode(list(sub = "user-1"), key, expires_in = 3600)
#' jose_jwt_decode(jwt, key, algorithms = "HS256")$sub
"_PACKAGE"

## usethis namespace: start
## usethis namespace: end
NULL
