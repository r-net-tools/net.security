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
  cpe.source.file <- paste(tempdir(),
                           "cpe","official-cpe-dictionary_v2.3.xml",
                           sep = ifelse (.Platform$OS.type == "windows","\\","/"))
  cpes <- ParseCPEData(cpe.source.file)

  return(cpes)
}

#### Private Functions -----------------------------------------------------------------------------
DownloadCPEData <- function(dest) {
  curdir <- setwd(dest)
  if (!dir.exists("cpe")) {
    dir.create("cpe")
  }
  cwe.url  <- "http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
  destfile <- "cpe/official-cpe-dictionary_v2.3.xml.zip"
  utils::download.file(url = cwe.url, destfile = destfile)

  setwd(curdir)
}

ParseCPEData <- function(cpe.file) {
  doc <- XML::xmlTreeParse(cpe.file)
  cpes.raw <- XML::xmlRoot(doc)
  cpes.raw <- cpes.raw[2:length(cpes.raw)]

  lcpes <- lapply(cpes.raw, GetCPEItem)
  cpes <- plyr::ldply(lcpes, data.frame)

  return(cpes)

}

NewCPEItem <- function(){
  return(data.frame(cpe.22 = character(),
                    cpe.23 = character(),
                    cpe.ref = character(),
                    stringsAsFactors = FALSE)
  )
}

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
  if (length(names(cpe)) == length(names(NewCPEItem()))) {
    names(cpe) <- names(NewCPEItem())
  } else {
    k <- cpe
  }

  return(cpe)
}
