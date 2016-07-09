# Data Driven Security Functions -----------------------------------------------

#' GetCVE2CWE
#'
#' @return data frame
#' @export
#'
#' @examples
#' cve2cwe <- GetCVE2CWE()
GetCVE2CWE <- function() {
  x <- cves.nist[,c("cve.id","cwe")]
  x$cwe <- as.factor(x$cwe)
  return(x)
}
