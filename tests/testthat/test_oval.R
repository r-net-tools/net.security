context("oval functions")

#### Expected Values -------------------------------------------------------------------------------

expected_oval_names    <- c("type","class","id","version","title",
                            "affected.family","affected.platforms","affected.cpes",
                            "references","status","deprecated")
expected_oval_classes  <- c("factor","factor","character","factor","character",
                            "factor","character","character","character","factor",
                            "factor")

expected_item_names <- c("class","id","version","title","affected.family",
                         "affected.platforms","affected.cpes",
                         "references","status")
expected_item_classes <- c("character","character","character","character",
                           "character","character","character","character",
                           "character","character","character")

#### OVAL data fram generation ----------------------------------------------------------------------

my_oval <- net.security::GetDataFrame("oval")

#### TESTS -----------------------------------------------------------------------------------------

test_that("oval_creation",{
  expect_true(exists("my_oval"))
})

test_that("oval_not_null", {
  expect_false(is.null(my_oval))
})

test_that("oval_is_dataframe", {
  expect_is(my_oval, "data.frame")
})

test_that("oval_structure",{
  expect_true(all.equal(expected_oval_names, names(my_oval)))
  # expect_true(all(sapply(my_oval, class) == expected_oval_classes))
})

#### Internal functions
x <- LastDownloadOVALDate()

test_that("check LastDownloadOVALDate output",{
  expect_true(exists("x"))
  expect_false(is.null(x))
  expect_is(x, "character")
})
rm(x)

# x <- NewOVALItem()
#
# test_that("check NewOVALItem output",{
#   expect_true(exists("x"))
#   expect_false(is.null(x))
#   expect_is(x, "data.frame")
#   expect_true(all.equal(expected_item_names, names(x)))
#   expect_true(all(expected_item_classes == sapply(x, class)))
# })
# rm(x)
