#### Exported Functions ----------------------------------------------------------------------------

#' GetCVEData
#'#'
#' @return data frame
#' @export
#'
#' @examples
#' cves <- GetCVEData()
GetCVEData <- function() {
  DownloadCVEData(dest = tempdir())
  UnzipDataFiles(path = tempdir())
  cve.source.file <- paste(tempdir(), "cve/mitre/allitems.csv", sep = "/")
  cves <- ParseCVEData(cve.source.file)
  return(cves)
}

#### Private Functions -----------------------------------------------------------------------------

#' Title
#'
#' @param dest String with directory where to store files to be downloaded.
DownloadCVEData <- function(dest) {
  curdir <- setwd(dir = dest)

  # Group downloaded data
  if (!dir.exists("cve")) {
    dir.create("cve")
    dir.create("cve/mitre")
    dir.create("cve/nist")
  }

  # Download MITRE data (http://cve.mitre.org/data/downloads/index.html#download)
  utils::download.file(url = "http://cve.mitre.org/data/downloads/allitems.xml.gz",
                destfile = "cve/mitre/allitems.xml.gz")
  utils::download.file(url = "http://cve.mitre.org/schema/cve/cve_1.0.xsd",
                destfile = "cve/mitre/cve_1.0.xsd")
  utils::download.file(url = "http://cve.mitre.org/data/downloads/allitems.csv.gz",
                destfile = "cve/mitre/allitems.csv.gz")

  # Download NIST data (https://nvd.nist.gov/download.cfm)
  # cve.years             <- 2002:as.integer(format(Sys.Date(), "%Y"))
  # base.url              <- "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-"
  # base.url.translation  <- "https://nvd.nist.gov/download/nvdcve-"
  # for (year in cve.years) {
  #   url <- paste(base.url, year, ".xml.gz", sep = "")
  #   destfile <- paste("cve/nist/nvdcve-2.0-", year, ".xml.gz", sep = "")
  #   utils::download.file(url, destfile)
  #
  #   # Spanish translations
  #   url.translation <- paste(base.url.translation, year, "trans.xml.gz", sep = "")
  #   destfile <- paste("cve/nist/nvdcve-", year, "trans.xml.gz", sep = "")
  #   utils::download.file(url.translation, destfile)
  # }

  # Download NIST Vendor statements
  utils::download.file(url = "https://nvd.nist.gov/download/vendorstatements.xml.gz",
                destfile = "cve/nist/vendorstatements.xml.gz")

  setwd(curdir)
}


#' Title
#'
#' @param path String, the directory containing the files to be extracted
UnzipDataFiles <- function(path) {
  # Uncompress gzip XML files
  gzs <- list.files(path = paste(path,"cve", sep = "/"), pattern = ".gz",
                    full.names = TRUE, recursive = TRUE)
  apply(X = data.frame(gzs = gzs, stringsAsFactors = F),
        1,
        function(x) {
          R.utils::gunzip(x, overwrite = TRUE, remove = TRUE)
        })

}


#' Title
#'
#' @param cve.file String
#'
#' @return Data frame
ParseCVEData <- function(cve.file) {
  column.names <- c("cve","status","description","references","phase","votes","comments")
  column.classes <- c("character","factor","character","character","character","character","character")
  cves <- utils::read.csv(file = cve.file,
                          skip = 9,
                          col.names = column.names,
                          colClasses = column.classes)
  return(cves)
}
