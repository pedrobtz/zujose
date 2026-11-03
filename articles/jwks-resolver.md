# Verifying tokens against a JWKS

An OpenID Connect provider signs its tokens with keys it publishes as a
JWK Set (JWKS), and it rotates them: a new key appears in the set before
the first token signed with it, and an old key stays until its tokens
expire. A client has to fetch that set, cache it, and fetch it again
when a token names a key it has not seen.

zujose never fetches anything itself. Every function that checks a token
takes, instead of a key, a **resolver**: a function of the token’s
header that returns a key or a key set. This article writes one with
[httr2](https://httr2.r-lib.org).

``` r

library(zujose)
```

## A resolver is a function of the header

The resolver gets the token’s header, a named list, before anything is
verified. It may read `kid`, `alg` or `iss` from it to choose keys. What
it returns is still checked: the key must fit one of the `algorithms`
you allowed, and the signature must verify with it.

``` r

current <- jwk_generate("EC", crv = "P-256", alg = "ES256", kid = "2026-11")
provider_keys <- jwk_set(current)

resolver <- function(header) {
  message("resolving kid ", header$kid)
  jwk_public(provider_keys)
}

jwt <- jwt_encode(
  list(iss = "https://auth.example", aud = "orders-api"),
  current,
  expires_in = 600
)
jwt_decode(jwt, resolver, algorithms = "ES256", audience = "orders-api")$iss
#> resolving kid 2026-11
#> [1] "https://auth.example"
```

Because the header is untrusted, never let it decide where keys come
from. A `jku` or `x5u` URL in a header is ignored by zujose, and a
resolver should only follow one that is on an allow-list you wrote.

## Fetching and caching the JWKS

The provider’s discovery document, at
`<issuer>/.well-known/openid-configuration`, gives the URL of its JWKS
as `jwks_uri`. The resolver below fetches the set once, keeps it for
`ttl` seconds, and fetches it again early when a token names a `kid` the
cached set does not have, but at most once every `min_refresh` seconds,
so a flood of tokens with made-up `kid`s cannot turn it into a flood of
requests.

``` r

jwks_resolver <- function(issuer, ttl = 3600, min_refresh = 60) {
  cache <- new.env(parent = emptyenv())

  fetch <- function() {
    config <- httr2::request(issuer) |>
      httr2::req_url_path_append(".well-known", "openid-configuration") |>
      httr2::req_perform() |>
      httr2::resp_body_json()
    if (!identical(config$issuer, issuer)) {
      stop("The discovery document is for another issuer.")
    }
    jwks <- httr2::request(config$jwks_uri) |>
      httr2::req_perform() |>
      httr2::resp_body_string()
    cache$keys <- as_jwk_set(jwks)
    cache$fetched <- Sys.time()
  }

  has_kid <- function(kid) {
    tryCatch(
      {
        cache$keys[[kid]]
        TRUE
      },
      zujose_key_error = function(e) FALSE
    )
  }

  function(header) {
    age <- if (is.null(cache$fetched)) {
      Inf
    } else {
      as.numeric(difftime(Sys.time(), cache$fetched, units = "secs"))
    }
    stale <- age > ttl
    unknown <- !is.null(header$kid) && !is.null(cache$keys) &&
      !has_kid(header$kid)
    if (stale || (unknown && age > min_refresh)) {
      fetch()
    }
    cache$keys
  }
}
```

Build the resolver once, when the app starts, and give it to
[`jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jwt_decoder.md)
with the rest of the policy. Every call then shares one cache:

``` r

check <- jwt_decoder(
  key = jwks_resolver("https://accounts.google.com"),
  algorithms = "RS256",
  issuer = "https://accounts.google.com",
  audience = "my-client-id.apps.googleusercontent.com"
)

claims <- check(id_token)
```

The cached keys are public, so the cache holds no secrets. A JWKS can
list keys zujose cannot use, such as Ed25519 keys; they are kept in the
set and skipped when a token does not name them.

## Several issuers

A service that accepts tokens from more than one provider can read `iss`
from the payload with
[`jose_peek()`](https://pedrobtz.github.io/zujose/reference/jose_peek.md),
pick that provider’s resolver, and then check the token against it. The
`issuer` check inside
[`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
makes sure the token really came from the issuer whose keys were used:

``` r

resolvers <- list(
  "https://accounts.google.com" = jwks_resolver("https://accounts.google.com"),
  "https://login.example.org" = jwks_resolver("https://login.example.org")
)

check_token <- function(token) {
  iss <- jose_peek(token)$claims$iss
  if (!is.character(iss) || !iss %in% names(resolvers)) {
    stop("Unknown issuer.")
  }
  jwt_decode(
    token,
    resolvers[[iss]],
    algorithms = c("RS256", "ES256"),
    issuer = iss,
    audience = "orders-api"
  )
}
```
