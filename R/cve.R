#' GetCVEData
#'
#' @param path where Standard CVE definitions will be downloaded and unziped (don't finish with /). Default set as inst/tmpdata
#' @param download TRUE if you want to download source files
#' @param cached TRUE if you want to load saved dataframe, it won't download anything
#'
#' @return data frame
#' @export
#'
#' @examples
#' cves <- GetCVEData(cached = TRUE)
GetCVEData <- function(path = "inst/tmpdata", download = FALSE, cached = TRUE) {
  if (cached) {
    return(cves)
  } else {
    path <- ifelse(download, DownloadCVEData(path), path)
    cves <- read.csv(file = "inst/tmpdata/cve/mitre/allitems.csv", skip = 9,
                     col.names = c("cve","status","description","references","phase","votes","comments"),
                     colClasses = c("character","factor","character","character","character","character","character"))
    cves$cwe <- GetNISTvulns(2005)
  }
  return(cves)
}

NewNISTEntry <- function() {
  return(data.frame(osvdb.ext = character(),
                    vulnerable.configuration = character(),
                    vulnerable.software.list = character(),
                    cve.id = character(),
                    discovered.datetime = character(),
                    disclosure.datetime = character(),
                    exploit.publish.datetime = character(),
                    published.datetime = character(),
                    last.modified.datetime = character(),
                    cvss = character(),
                    security.protection = character(),
                    assessment.check = character(),
                    cwe = character(),
                    references = character(),
                    fix.action = character(),
                    scanner = character(),
                    summary = character(),
                    technical.description = character(),
                    attack.scenario = character(),
                    stringsAsFactors = FALSE)
         )
}

GetNISTEntry <- function(node) {
  entry <- NewNISTEntry()
  lnode <- XML::xmlChildren(node)

  # Parse "xsd:*:vulnerabilityType" fields
  osvdb.ext <- NodeToJson(lnode[["osvdb-ext"]])
  vulnerable.configuration <- NodeToJson(lnode[["vulnerable-configuration"]])
  vulnerable.software.list <- NodeToJson(lnode[["vulnerable-software-list"]])
  cve.id <- NodeToChar((lnode[["cve-id"]]))
  discovered.datetime <- NodeToJson(lnode[["discovered-datetime"]])
  disclosure.datetime <- NodeToJson(lnode[["disclosure-datetime"]])
  exploit.publish.datetime <- NodeToJson(lnode[["exploit-publish-datetime"]])
  published.datetime <- NodeToJson(lnode[["published-datetime"]])
  last.modified.datetime <- NodeToJson(lnode[["last-modified-datetime"]])
  cvss <- NodeToJson(lnode[["cvss"]])
  security.protection <- NodeToJson(lnode[["security-protection"]])
  assessment.check <- NodeToJson(lnode[["assessment_check"]])
  cwe <- NodeToJson(lnode[["cwe"]])
  references <- NodeToJson(lnode[["references"]])
  fix.action <- NodeToJson(lnode[["fix_action"]])
  scanner <- NodeToJson(lnode[["scanner"]])
  summary <- NodeToJson(lnode[["summary"]])
  technical.description <- NodeToJson(lnode[["technical_description"]])
  attack.scenario <- NodeToJson(lnode[["attack_scenario"]])

  entry <- rbind(entry,
                 c(osvdb.ext,
                   vulnerable.configuration,
                   vulnerable.software.list,
                   cve.id,
                   discovered.datetime,
                   disclosure.datetime,
                   exploit.publish.datetime,
                   published.datetime,
                   last.modified.datetime,
                   cvss,
                   security.protection,
                   assessment.check,
                   cwe,
                   references,
                   fix.action,
                   scanner,
                   summary,
                   technical.description,
                   attack.scenario)
                 )
  names(entry) <- names(NewNISTEntry())

  return(entry)
}

NodeToJson <- function(x) {
  if (is.null(x)) x <- "<xml></xml>"
  return(jsonlite::toJSON(XML::xmlToList(x)))
}

NodeToChar <- function(x) {
  if (is.null(x)) x <- ""
  return(as.character(unlist(XML::xmlToList(x))))
}

#' GetNISTvulns
#'
#' > system.time({cve.nist <- GetNISTvulns()})
#' user  system elapsed
#' 394.63    8.24  435.69
#'
#' @return data frame
#' @export
#'
#' @examples
#' cve.nist <- GetNISTvulns()
GetNISTvulns <- function() {
  # Reference: https://scap.nist.gov/schema/nvd/vulnerability_0.4.xsd
  # Output: XMLDocument -> "as list"
  doc <- XML::xmlTreeParse(file = "inst/tmpdata/cve/nist/nvdcve-2.0-2005.xml", useInternalNodes = T)
  entries <- XML::xmlChildren(XML::xmlRoot(doc))
  lentries <- lapply(entries, GetNISTEntry)
  df <- plyr::ldply(lentries, data.frame)

  # Tidy Data
  df$.id <- NULL
  df$cve.id <- as.character(df$cve.id)
  df$cwe <- as.character(sapply(as.character(df$cwe), function(x) jsonlite::fromJSON(x)))
  df$cwe <- sub(pattern = "list()",replacement = NA, x = df$cwe)

  return(df)
}

DownloadCVEData <- function(path = "inst/tmpdata") {
  UnzipDataFiles <- function(path = "inst/tmpdata") {
    # Uncompress gzip XML files
    gzs <- list.files(path = paste(path,"cve", sep = "/"), pattern = "*.(xml|csv).gz",
                      full.names = TRUE, recursive = TRUE)
    apply(X = data.frame(gzs = gzs, stringsAsFactors = F), 1, function(x) R.utils::gunzip(x, overwrite = TRUE, remove = TRUE))
  }

  # Create data folders
  dir.create(paste(path, "cve", sep = "/"), showWarnings = FALSE)
  dir.create(paste(path, "cve","mitre", sep = "/"), showWarnings = FALSE)
  dir.create(paste(path, "cve","nist", sep = "/"), showWarnings = FALSE)

  # Download MITRE data
  # Reference: http://cve.mitre.org/data/downloads/index.html#download
  download.file(url = "http://cve.mitre.org/data/downloads/allitems.xml.gz",
                destfile = paste(path, "/cve/mitre/allitems.xml.gz", sep = ""))
  download.file(url = "http://cve.mitre.org/schema/cve/cve_1.0.xsd",
                destfile = paste(path, "/cve/mitre/cve_1.0.xsd", sep = ""))
  download.file(url = "http://cve.mitre.org/data/downloads/allitems.csv.gz",
                destfile = paste(path, "/cve/mitre/allitems.csv.gz", sep = ""))

  # Download NIST data
  # Reference: https://nvd.nist.gov/download.cfm
  cve.years <- 2002:as.integer(format(Sys.Date(), "%Y"))
  for (year in cve.years) {
    url <- paste("http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-", year, ".xml.gz", sep = "")
    destfile <- paste(path, "/cve/nist/nvdcve-2.0-", year, ".xml.gz", sep = "")
    download.file(url, destfile)
    # Spanish translations
    url <- paste("https://nvd.nist.gov/download/nvdcve-", year, "trans.xml.gz", sep = "")
    destfile <- paste(path, "/cve/nist/nvdcve-", year, "trans.xml.gz", sep = "")
    download.file(url, destfile)
  }

  # Download NIST Vendor statements
  download.file(url = "https://nvd.nist.gov/download/vendorstatements.xml.gz",
                destfile = paste(path, "/cve/nist/vendorstatements.xml.gz", sep = ""))

  UnzipDataFiles(path)
  path <- paste(path, "cve/mitre/allitems.csv", sep = "/" )
  return(path)
}

