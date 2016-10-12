#### Exported Functions ----------------------------------------------------------------------------

#' GetCPEData
#'
#' @return
#'
#' @examples
#' cpes <- GetCPEData()
GetCPEData <- function(savepath = tempdir()) {
  # Schema: https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd
  # RawData: http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
  DownloadCPEData(savepath)
  cpe.source.file <- ExtractCPEFiles(savepath)
  cpes <- ParseCPEData(cpe.source.file)
  return(cpes)
}


#### Private Functions -----------------------------------------------------------------------------

ExtractCPEFiles <- function(savepath) {
  # Uncompress gzip XML files
  cpes.zip <- paste(savepath, "cpe", "official-cpe-dictionary_v2.3.xml.zip", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  cpes.xml <- paste(savepath, "cpe", "official-cpe-dictionary_v2.3.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::unzip(zipfile = cpes.zip, exdir = cpes.xml)
  cpes.xml <- paste(cpes.xml, "official-cpe-dictionary_v2.3.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  return(cpes.xml)
}

#' Download CPE information from NIST
#'
DownloadCPEData <- function(savepath) {
  if (!dir.exists(paste(savepath, "cpe", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "cpe", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }
  cpe.url  <- "http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
  cpes.zip <- paste(savepath, "cpe", "official-cpe-dictionary_v2.3.xml.zip", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::download.file(url = cpe.url, destfile = cpes.zip)
}

#' Title
#'
#' @param cpe.raw
#'
#' @return data.frame
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
#' @return data.frame
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
#' @return data.frame
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


