#### Exported Functions ----------------------------------------------------------------------------

#' GetCWEData
#'
#' @return
#' @export
#'
#' @examples
GetCPEData <- function() {
  # Schema: https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd
  # RawData: http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
  # DownloadCPEData(dest = tempdir())
  # utils::unzip(zipfile = paste(tempdir(),
  #                              "cpe","official-cpe-dictionary_v2.3.xml.zip",
  #                              sep = ifelse (.Platform$OS.type == "windows","\\","/"))
  #              )
  curdir <- setwd(tempdir())
  cpe.downloaded.file <- DownloadCPEData()
  utils::unzip(zipfile = cpe.downloaded.file, exdir = "cpe")
  cpe.source.file <- paste(tempdir(),
                           "cpe", "official-cpe-dictionary_v2.3.xml",
                           sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  cpes <- ParseCPEData(cpe.source.file)
  setwd(curdir)
  return(cpes)
}


#### Private Functions -----------------------------------------------------------------------------

#' Download CPE information from NIST
#'
DownloadCPEData <- function() {
  if (!dir.exists("cpe")) {
    dir.create("cpe")
  }
  cwe.url  <- "http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
  destfile <- "cpe/official-cpe-dictionary_v2.3.xml.zip"
  utils::download.file(url = cwe.url, destfile = destfile)
  return(destfile)
}

#' Title
#'
#' @param cpe.raw
#'
#' @return
#'
#' @examples
GetCPEItem <- function(cpe.raw) {
  cpe <- NewCPEItem()
  cpe.raw <- XML::xmlToList(cpe.raw)

  cpe.22 <- ifelse(is.null(cpe.raw[["title"]]$text),"",cpe.raw[["title"]]$text)
  cpe.23 <- ifelse(is.null(cpe.raw[["cpe23-item"]][["name"]]),"",cpe.raw[["cpe23-item"]][["name"]])
  cpe.ref <- unlist(cpe.raw[["references"]])
  cpe.ref.names <- cpe.ref[names(cpe.ref) == ""]
  cpe.ref <- as.character(cpe.ref[names(cpe.ref) == "href"])
  names(cpe.ref) <- cpe.ref.names
  cpe.ref <- as.character(jsonlite::toJSON(as.list(cpe.ref)))

  cpe <- rbind(cpe, c(cpe.22, cpe.23, cpe.ref))
  names(cpe) <- names(NewCPEItem())

  return(cpe)
}

#' Title
#'
#' @return
#'
#' @examples
NewCPEItem <- function(){
  return(data.frame(cpe.22 = character(),
                    cpe.23 = character(),
                    cpe.ref = character(),
                    stringsAsFactors = FALSE)
  )
}

#' Title
#'
#' @param cpe.file
#'
#' @return
#'
#' @examples
ParseCPEData <- function(cpe.file) {
  doc <- XML::xmlTreeParse(cpe.file)
  cpes.raw <- XML::xmlRoot(doc)
  cpes.raw <- cpes.raw[2:length(cpes.raw)]

  lcpes <- lapply(cpes.raw, GetCPEItem)
  cpes <- plyr::ldply(lcpes, data.frame)

  # TidyData
  cpes$.id <- NULL
  cpes$Title <- as.character(cpes$cpe.22)
  cpes$cpe.23 <- as.character(cpes$cpe.23)
  cpes$cpe.ref <- as.character(cpes$cpe.ref)

  return(cpes)

}


