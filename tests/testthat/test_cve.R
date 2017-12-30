context("cve functions")

#### Expected Values -------------------------------------------------------------------------------

expected_cves_names    <- c("cve.id", "affects", "problem.type", "references",
                            "description", "vulnerable.configuration", "cvss3.vector",
                            "cvss3.av", "cvss3.ac", "cvss3.pr", "cvss3.ui", "cvss3.s",
                            "cvss3.c", "cvss3.i", "cvss3.a", "cvss3.score",
                            "cvss3.severity", "cvss3.score.exploit", "cvss3.score.impact",
                            "cvss2.vector", "cvss2.av", "cvss2.ac", "cvss2.au",
                            "cvss2.c", "cvss2.i", "cvss2.a", "cvss2.score",
                            "cvss2.score.exploit", "cvss2.score.impact",
                            "cvss2.getallprivilege", "cvss2.getusrprivilege",
                            "cvss2.getothprivilege", "cvss2.requsrinter",
                            "published.date", "last.modified")
expected_cves_classes  <- c("character", "character", "character", "character",
                            "character", "character", "character", "factor",
                            "factor", "factor", "factor", "factor", "factor",
                            "factor", "factor", "numeric", "factor", "numeric",
                            "numeric", "character", "factor", "factor", "factor",
                            "factor", "factor", "factor", "numeric", "numeric",
                            "numeric", "logical", "logical", "logical", "logical",
                            "POSIXlt", "POSIXlt")


#### CVE data fram generation ----------------------------------------------------------------------

my_cves <- net.security::GetDataFrame("cves")

#### TESTS -----------------------------------------------------------------------------------------

test_that("cves_creation",{
  expect_true(exists("my_cves"))
})

test_that("cves_not_null", {
  expect_false(is.null(my_cves))
})

test_that("cves_is_dataframe", {
  expect_is(my_cves, "data.frame")
})

test_that("cves_structure",{
  expect_true(all.equal(expected_cves_names, names(my_cves)))

  actual.classes  <- sapply(my_cves, class)
  actual.classes  <- sapply(actual.classes, `[[`, 1) # time columns have two clases...
  expect_true(all(mapply(function(x,y) {return(x == y)}, actual.classes, expected_cves_classes )))
})

test_that("cves_content", {
  cve_pattern <- "CVE-[[:digit:]]"
  expect_true(all(grepl(pattern = cve_pattern, x = my_cves$cve.id)))
})

#### Internal functions
x <- LastDownloadCVEDate()

test_that("check LastDownloadCVEDate output",{
  expect_true(exists("x"))
  expect_false(is.null(x))
  expect_is(x, "character")
})
rm(x)

