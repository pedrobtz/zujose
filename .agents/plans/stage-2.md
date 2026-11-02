# Stage 2 plan (scratch)

1. Extend tools/rfc7520-fixtures.R to the keys of RFC 7520 (KEYS.tsv).
2. Tests first: keys, keyset, thumbprint (RFC 7638, RFC 9278), select.
3. R/keys.R, R/keyset.R, R/thumbprint.R, R/select.R (resolver, D9).
4. Imports zucrypt for crypt_hash().
