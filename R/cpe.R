GetCPEData <- function(savepath = tempdir()) {
  # Schema: https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd
  # RawData: http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
  print(paste("Downloading raw data..."))
  DownloadCPEData(savepath)
  print(paste("Extracting data..."))
  cpe.source.file <- ExtractCPEFiles(savepath)
  print(paste("Indexing data..."))
  cpes <- ParseCPEData(cpe.source.file)
  return(cpes)
}

LastDownloadCPEDate <- function(){
  doc.html <- XML::htmlParse(paste(readLines("https://nvd.nist.gov/cpe.cfm")))
  ltxt <- XML::xpathSApply(doc.html, '//li')
  i <- sapply(ltxt, function(x) grepl("official-cpe-dictionary_v2.3.xml", XML::saveXML(x)))
  txt <- XML::xmlValue(ltxt[[which(i)]])
  last <- stringr::str_sub(txt,
                           stringr::str_locate(txt, "Updated")[1,1],
                           stringr::str_locate(txt, "- gz")[1,1]-2)
  last <- strptime(last, "Updated: %m/%d/%Y %I:%M:%S %p", tz="EST")
  last <- as.character.POSIXt(last)
  return(last)
}

ExtractCPEFiles <- function(savepath) {
  # Uncompress gzip XML files
  cpes.zip <- paste(savepath, "cpe", "official-cpe-dictionary_v2.3.xml.zip", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  cpes.xml <- paste(savepath, "cpe", "official-cpe-dictionary_v2.3.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::unzip(zipfile = cpes.zip, exdir = cpes.xml)
  cpes.xml <- paste(cpes.xml, "official-cpe-dictionary_v2.3.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  return(cpes.xml)
}

DownloadCPEData <- function(savepath) {
  if (!dir.exists(paste(savepath, "cpe", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "cpe", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }
  cpe.url  <- "http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
  cpes.zip <- paste(savepath, "cpe", "official-cpe-dictionary_v2.3.xml.zip", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::download.file(url = cpe.url, destfile = cpes.zip)
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
  names(cpe) <- names(NewCPEItem())

  return(cpe)
}

NewCPEItem <- function(){
  return(data.frame(cpe.22 = character(),
                    cpe.23 = character(),
                    cpe.ref = character(),
                    stringsAsFactors = FALSE)
  )
}

ParseCPEData <- function(cpe.file) {
  # TODO: Improve performance
  doc <- XML::xmlTreeParse(cpe.file)
  cpes.raw <- XML::xmlRoot(doc)
  cpes.raw <- cpes.raw[2:length(cpes.raw)]
  cpes <- plyr::ldply(cpes.raw, GetCPEItem)

  # TidyData
  cpes$title <- as.character(cpes$cpe.22)
  cpes$cpe.23 <- as.character(cpes$cpe.23)
  cpes$cpe.ref <- as.character(cpes$cpe.ref)
  cpes <- cpes[,c("cpe.23", "cpe.ref", "title")]

  # Augment CPE2.3
  cpes.23 <- stringr::str_replace_all(string = cpes$cpe.23, pattern = "\\\\:", replacement = "_")
  cpes.23 <- stringr::str_split(string = cpes.23, pattern = ":", simplify = T)
  cpes$part <- as.factor(cpes.23[,3])
  cpes$vendor <- as.factor(cpes.23[,4])
  cpes$product <- as.factor(cpes.23[,5])
  cpes$version <- as.factor(cpes.23[,6])
  cpes$update <- as.factor(cpes.23[,7])
  cpes$edition <- as.factor(cpes.23[,8])
  cpes$language <- as.factor(cpes.23[,9])
  cpes$sw_edition <- as.factor(cpes.23[,10])
  cpes$target_sw <- as.factor(cpes.23[,11])
  cpes$target_hw <- as.factor(cpes.23[,12])
  cpes$other <- as.factor(cpes.23[,13])

  return(cpes)

}
