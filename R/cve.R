#' GetCVEData
#'
#' @param path where Standard CVE definitions will be downloaded and unziped (don't finish with /). Default set as inst/tmpdata
#' @param download
#'
#' @return data frame
#' @export
#'
#' @examples
#' cves <- GetCVEData()
#' cves <- GetCVEData(download = TRUE)
GetCVEData <- function(path = "inst/tmpdata", download = FALSE) {
  path <- ifelse(download, DownloadCVEData(path), path)
  cves <- read.csv(file = "inst/tmpdata/cve/mitre/allitems.csv", skip = 9,
                   col.names = c("cve","status","description","references","phase","votes","comments"),
                   colClasses = c("character","factor","character","character","character","character","character"))
  return(cves)
}

DownloadCVEData <- function(path = "inst/tmpdata") {
  # Create data folders
  dir.create(paste(path, "cve", sep="/"), showWarnings = FALSE)
  dir.create(paste(path, "cve","mitre", sep="/"), showWarnings = FALSE)
  dir.create(paste(path, "cve","nist", sep="/"), showWarnings = FALSE)

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
  for(year in cve.years){
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
  return(path)
}

UnzipDataFiles <- function(path = "inst/tmpdata") {
  # Uncompress gzip XML files
  gzs <- list.files(path = paste(path,"cve", sep="/"), pattern = "*.(xml|csv).gz",
                    full.names = TRUE, recursive = TRUE)
  apply(X = data.frame(gzs = gzs, stringsAsFactors = F), 1, function(x) R.utils::gunzip(x))
}
