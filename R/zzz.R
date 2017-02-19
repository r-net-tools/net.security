.onLoad <- function(libname, pkgname){
  if (file.exists("inst/extdata/netsec.data.rda")) {
    load(file = "inst/extdata/netsec.data.rda", envir = .GlobalEnv)
  }
}
