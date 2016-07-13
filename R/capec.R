# References: https://capec.mitre.org/data/index.html
#' Download, parse and return a tidy data frame with CAPEC information
#'
#' @return data frame
#' @export
#'
#' @examples
GetCAPECData <- function() {
  DownloadCAPECData(dest = tempdir())
  capec <- data.frame()

  return(capec)
}

#### Private Functions -----------------------------------------------------------------------------

#' Title
#'
#' @param dest. String
DownloadCAPECData <- function(dest) {
  curdir <- setwd(dest)
  if (!dir.exists("capec")) {
    dir.create("capec")
  }
  capec.url  <- "https://capec.mitre.org/data/xml/capec_v2.8.xml"
  destfile <- "capec/capec_v2.8.xml"
  utils::download.file(url = capec.url, destfile = destfile)
  setwd(curdir)
}

#' Title
#'
#' @param cwe.file String
#'
#' @return Data frame
ParseCAPECData <- function(capec.file) {

  doc <- XML::xmlParse(capec.file)
  raw.capec.views <- XML::xpathApply(doc, "//capec:View")
  raw.capec.cates <- XML::xmlToDataFrame(XML::xpathApply(doc, "//capec:Category"))
  raw.capec.atcks <- XML::xmlToDataFrame(XML::xpathApply(doc, "//capec:Attack_Pattern"))
  raw.capec.envrs <- XML::xmlToDataFrame(XML::xpathApply(doc, "//capec:Environment"))

}
