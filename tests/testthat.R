# The standard testthat runner, with one deviation: the run is conditional
# on testthat being installed. The `nosuggests` CI leg is CRAN's NOSUGGESTS
# flavor, where no Suggests are available and an unguarded
# `library(testthat)` is an ERROR. A package must check without its
# suggested packages, not test without them.
#
# Learn more about the roles of the test files in:
# * https://r-pkgs.org/testing-design.html#sec-tests-files-overview
# * https://testthat.r-lib.org/articles/special-files.html

if (requireNamespace("testthat", quietly = TRUE)) {
  library(testthat)
  library(zujwt)

  test_check("zujwt")
}
