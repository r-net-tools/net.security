# Data Driven Security Functions -----------------------------------------------
# Ref: http://plumber.trestletech.com/docs/routing/

#' GetCVEInfo
#'
#' @param cve.id character
#' @param output character "json", "markdown", "html"
#'
#' @return
#'
#* @get /cveinfo/<cve.id>
GetCVEInfo <- function(cve.id = "CVE-2010-2010", output = "json") {
  cve.row <- cves[cves$cve == cve.id,]
  if (output == "json") {
    cve.info <- cve.row
  }
  # TODO: Implement other output types
  # if (output == "html") {
  #   cve.head <- "<html><body>"
  #   cve.info <- print(xtable::xtable(cve.row), type="html", print.results = T)
  #   cve.tail <- "</body></html>"
  #   cve.info <- paste(cve.head, cve.info, cve.tail, sep = "")
  # }
  # if (output == "markdown") {
  #   cve.info <- print(xtable::xtable(cve.row), type = "latex", print.results = T)
  # }
  return(cve.info)
}


#' GetCWEInfo
#'
#' @param cwe.id
#' @param output
#'
#' @return
#'
#* @get /cweinfo/<cwe.id>
GetCWEInfo <- function(cwe.id = "CWE-250", output = "json") {
  cwe.row <- cwes[cwes$code_standard == cwe.id,]
  if (output == "json") {
    cwe.info <- cwe.row
  }
  # TODO: Implement other output types
  return(cwe.info)
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
