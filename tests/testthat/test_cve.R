context("cve functions")

#### Expected Values -------------------------------------------------------------------------------

expected_cves_names    <- c("cve", "status", "description", "ref.mitre", "phase",
                            "votes", "comments", "cpe.config", "cpe.software",
                            "discovered.datetime", "disclosure.datetime", "exploit.publish.datetime",
                            "published.datetime", "last.modified.datetime", "cvss",
                            "security.protection", "assessment.check", "cwe", "ref.nist", "fix.action",
                            "scanner", "summary", "technical.description", "attack.scenario")
expected_cves_classes  <- c("character", "factor", "character", "character", "character", "character", "character")


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

  # actual.classes  <- sapply(my_cves, class)
  # actual.classes  <- sapply(actual.classes, `[[`, 1) # time columns have two clases...
  # expect_true(all(mapply(function(x,y) {return(x == y)}, actual.classes, expected_cves_classes )))
})

test_that("cves_content", {
  cve_pattern <- "CVE-[[:digit:]]"
  expect_true(all(grepl(pattern = cve_pattern, x = my_cves$cve)))
})

#### Internal functions
x <- LastDownloadCVEDate()

test_that("check LastDownloadCVEDate output",{
  expect_true(exists("x"))
  expect_false(is.null(x))
  expect_is(x, "character")
})
rm(x)

