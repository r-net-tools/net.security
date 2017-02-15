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


#' GetCWEInfo search cwe.id and returns its info
#'
#' @param cwe.id character
#' @param output character "json", "markdown", "html"
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

#' GetCAPECInfo
#'
#' @param capec.id character
#' @param vca character
#' @param output character
#'
#' @return data frame
#'
#* @get /capec/<vca>/<capec.id>
GetCAPECInfo <- function(vca = "attack", capec.id, output = "json") {
  if (vca == "attack") df <- capec[["attacks"]]
  if (vca == "categ") df <- capec[["categories"]]
  if (vca == "view") df <- capec[["views"]]

  df.row <- df[df$id == capec.id,]
  if (output == "json") {
    capec.info <- df.row
  }
  # TODO: Implement other output types
  return(capec.info)
}

#' GetCPEbyName
#'
#' @param name character
#'
#' @return
#'
#* @get /cpe
GetCPEbyName <- function(name) {
  # TODO: Investigate plumber funcitionalities, add issue or fork it :(
  #name <- "winamp"
  name <- stringr::str_replace_all(string = name, pattern = "%20", replacement = ".")
  # name <- stringr::str_replace_all(string = name, pattern = ".", replacement = "[.*]")
  # TODO: Improve matching
  matched <- grepl(pattern = name, x = cpes$cpe.23, ignore.case = T)
  if (!any(matched)) matched <- agrepl(pattern = name, x = cpes$cpe.23, ignore.case = T)
  if (!any(matched)) matched <- agrepl(pattern = name, x = cpes$title, ignore.case = T)
  if (!any(matched)) matched <- agrepl(pattern = name, x = cpes$product, ignore.case = T)
  # TODO: Implement other output types
  return(cpes[matched, c("product", "cpe.23", "title")])
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
