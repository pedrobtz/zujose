# Stage 0 plan (scratch)

1. DESCRIPTION identity: Title, Description with RFC DOIs, Authors@R, URL,
   BugReports, Depends R (>= 4.1). LICENSE holder.
2. Tests first: tests/testthat/test-conditions.R, one block per class,
   asserting class chain and fields. Red.
3. R/conditions.R: zujwt_condition() and one abort_*() per class; the
   documented ?zujwt_error topic. Green.
4. CI: Windows R-devel runner row; coverage pinned to r-actions v1.26.0's
   commit; pkgdown stays the usethis workflow (r-actions has none).
5. Replace the placeholder test; NEWS; roadmap Done column and deviation
   (Imports added by the stage that first calls them).
6. document(), test(shuffle = TRUE), check().
