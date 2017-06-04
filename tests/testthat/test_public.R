context("public functions")


#### DataSetList -----------------------------------------------------------------------------------------
x <- net.security::DataSetList()

test_that("check DataSetList output",{
  expect_true(exists("x"))
  expect_false(is.null(x))
  expect_is(x, "character")
})
rm(x)

#### DataSetStatus -----------------------------------------------------------------------------------------
# x <- net.security::DataSetStatus()
#
# test_that("check DataSetStatus output",{
#   expect_true(exists("x"))
#   expect_false(is.null(x))
#   expect_is(x, "character")
# })
# rm(x)

#### GetDataFrame -----------------------------------------------------------------------------------------
x <- net.security::GetDataFrame("cves")

test_that("check GetDataFrame output with 'cves'",{
  expect_true(exists("x"))
  expect_false(is.null(x))
  expect_is(x, "data.frame")
})
rm(x)
