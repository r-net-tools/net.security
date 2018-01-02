GetCPEData <- function(savepath = tempdir(), verbose = T) {
  # Schema: https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd
  # RawData: http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
  print(paste("Downloading raw data..."))
  DownloadCPEData(savepath)
  print(paste("Extracting data..."))
  cpe.source.file <- ExtractCPEFiles(savepath)
  print(paste("Indexing data..."))
  cpes <- ParseCPEData(cpe.source.file, verbose)
  print(paste("CPES data frame building process finished."))
  return(cpes)
}

LastDownloadCPEDate <- function(){
  doc.html <- XML::htmlParse(paste(readLines("https://nvd.nist.gov/cpe.cfm")))
  last <- as.character(XML::getChildrenStrings(XML::xpathSApply(doc.html, '//span[@data-testid="cpe-feed-23-gz-date"]')[[1]]))
  last <- strptime(last, "%m/%d/%Y %I:%M:%S %p", tz = "EST")
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

ParseCPEData <- function(cpe.file, verbose) {
  doc <- xml2::read_xml(cpe.file)

  if (verbose) print("Parsing product title and cpe codes 2.x...")
  cpes <- data.frame(title = xml2::xml_text(xml2::xml_find_all(doc, "//*[name()='cpe-item']/*[@xml:lang='en-US'][1]")),
                     cpe.22 = xml2::xml_text(xml2::xml_find_all(doc, "//*[name()='cpe-item']/@name")),
                     cpe.23 = xml2::xml_text(xml2::xml_find_all(doc, "//*[name()='cpe-item']/*/@name")),
                     stringsAsFactors = F)

  if (verbose) print("Extracting factors from cpe 2.3 code...")
  new.cols <- c("std", "std.v", "part", "vendor", "product",
                "version", "update", "edition", "language", "sw_edition",
                "target_sw", "target_hw", "other")
  cpes$cpe.23 <- stringr::str_replace_all(cpes$cpe.23, "\\\\:", ";")
  cpes <- tidyr::separate(data = cpes, col = cpe.23, into = new.cols, sep = ":", remove = F)
  cpes <- dplyr::select(.data = cpes, -std, -std.v)
  cpes$vendor <- as.factor(cpes$vendor)
  cpes$product <- as.factor(cpes$product)
  cpes$language <- as.factor(cpes$language)
  cpes$sw_edition <- as.factor(cpes$sw_edition)
  cpes$target_sw <- as.factor(cpes$target_sw)
  cpes$target_hw <- as.factor(cpes$target_hw)

  if (verbose) print("Parsing product links and references...")
  raw.cpes <- rvest::html_nodes(doc, xpath = "//*[name()='cpe-item']")
  cpes$references <- sapply(raw.cpes,
                            function(x) {
                              ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "*[name()='references']")), character(0)),
                                     yes = "{}",
                                     no = {
                                       y2 <- lapply(rvest::html_children(rvest::html_nodes(x, xpath = "*[name()='references']")), xml2::as_list)
                                       y <- sapply(y2, attributes)
                                       names(y) <- unlist(y2)
                                       RJSONIO::toJSON(y, pretty = T)
                                     }
                              )
                            }
  )

  if (verbose) print("Parsing check and OVAL references...")
  cpes$checks <- sapply(raw.cpes,
                            function(x) {
                              ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "*[name()='check']")), character(0)),
                                     yes = "{}",
                                     no = {
                                       y2 <- lapply(rvest::html_nodes(x, xpath = "*[name()='check']"), xml2::as_list)
                                       y <- c(unlist(sapply(y2, attributes)[,1]), check = unlist(y2))
                                       RJSONIO::toJSON(y, pretty = T)
                                     }
                              )
                            }
  )
  return(cpes)
}
