# Data Driven Security Functions -----------------------------------------------

#' Match CVE with CWE
#'
#' @return data frame
#' @export
#'
#' @examples
#' cve2cwe <- GetCVE2CWE()
GetCVE2CWE <- function() {
  x <- cves.nist[, c("cve.id", "cwe")]
  x$cwe <- as.factor(x$cwe)
  return(x)
}

# TODO
GetCVEInfo <- function(cve.id = "CVE-2010-2010") {
  return(cve.id)
}

# TODO
GetCWEInfo <- function(cwe.id) {
  return(cwe.id)
}

# TODO
GetCAPECInfo <- function(capec.id) {
  return(capec.id)
}

# TODO
GetCPEbyName <- function(platform) {
  return(platform)
}

# TODO
GetAffectedPlatform <- function(cve.id) {
  return(cve.id)
}

# TODO
GetWeaknessIntroduced <- function(cve.id) {
  return(cve.id)
}

# TODO
GetPossibleAttacks <- function(cve.id) {
  return(cve.id)
}

# TODO
GetPublicExploits <- function(cve.id = NA, cpe.id = NA) {
  GetPublicExploitsByCVE <- function(cve.id) {
    return(cve.id)
  }
  GetPublicExploitsByCPE <- function(cpe.id) {
    return(cpe.id)
  }

  if (!is.na(cve.id)) {
    exploits <- GetPublicExploitsByCVE(cve.id)
  }
  if (!is.na(cpe.id)) {
    exploits <- GetPublicExploitsByCPE(cpe.id)
  }
  return(exploits)
}

# TODO
GetPlatformVulns <- function(cpe.id) {
  return(cpe.id)
}
