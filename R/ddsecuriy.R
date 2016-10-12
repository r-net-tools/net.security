# Data Driven Security Functions -----------------------------------------------

#' GetCVEInfo
#'
#' @param cve.id
#' @param output "json", "markdown", "html"
#'
#' @return
#'
#* @get /cveinfo
GetCVEInfo <- function(cve.id = "CVE-2010-2010", output = "json") {
  cve.row <- cves[cves$cve == cve.id,]
  if (output == "json") {
    cve.info <- jsonlite::toJSON(cve.row)
  }
  if (output == "html") {
    cve.info <- print(xtable(cve.row), type="html", print.results = T)
  }
  if (output == "markdown") {
    cve.info <- print(xtable(cve.row), type = "latex", print.results = T)
  }
  return(cve.info)
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
