## Submission

This is a new submission.

<!-- Before submitting (release gate, design §11.2): zuutf and zucrypt
(>= 0.5.0) are on CRAN, `Remotes:` is dropped from DESCRIPTION, and the
version is 0.1.0. Fill in the full-run link below on the release commit. -->

## R CMD check results

0 errors | 0 warnings | 1 note

* This is a new submission.

## Test environments

The checks run on GitHub Actions through the reusable workflows of
<https://github.com/pedrobtz/r-actions>, with `R CMD check --as-cran`:

* macOS (latest), R release
* Windows (latest), R release and R-devel
* Ubuntu (latest), R release and R oldrel-1
* R-devel containers built with clang 23, with clang (Debian), and with
  GCC 16
* Ubuntu, R release, without Suggests (`_R_CHECK_FORCE_SUGGESTS_=false`),
  and with `--no-long-double`

Full run on the release commit: <!-- link -->

## Method references

The package implements Internet standards rather than published methods.
They are cited with their DOIs in the Description field: RFC 7515 to 7519
(JWS, JWE, JWK, JWA and JWT) and RFC 8725 (JWT best current practices).
The tests use the published test vectors of RFC 7515 to 7520, 7638, 7797
and 8037.
