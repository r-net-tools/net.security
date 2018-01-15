GetCPEData <- function(savepath = tempdir(), verbose = T) {
  # Schema: https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd
  # RawData: http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
  print(paste("Downloading raw data..."))
  DownloadCPEData(savepath)
  print(paste("Extracting data..."))
  cpe.file <- ExtractCPEFiles(savepath)
  print(paste("Building data frame..."))
  cpes <- ParseCPEData(cpe.file, verbose)
  print(paste("CPES data frame building process finished."))
  return(cpes)
}

LastDownloadCPEDate <- function(){
  doc <- xml2::read_html("https://nvd.nist.gov/cpe.cfm")
  txt <- rvest::html_text(rvest::html_nodes(doc, "#body-section > div:nth-child(2) > ol:nth-child(7) > li:nth-child(1) > span:nth-child(3)"))
  last <- strptime(txt, "%m/%d/%Y %I:%M:%S %p", tz = "EST")
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
  i <- 1
  if (verbose) pb <- txtProgressBar(min = 0, max = 10, style = 3, title = "CPE data")
  if (verbose) print("Indexing CPE XML and namespace schemas...")
  doc <- xml2::read_xml(cpe.file)
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}

  if (verbose) print("Parsing product title and cpe codes 2.x...")
  cpes <- data.frame(title = xml2::xml_text(xml2::xml_find_all(doc, "//*[cpe-23:cpe23-item]/*[@xml:lang='en-US'][1]")),
                     cpe.22 = xml2::xml_text(xml2::xml_find_all(doc, "//cpe-23:cpe23-item/@name")),
                     cpe.23 = xml2::xml_text(xml2::xml_find_all(doc, "//*[cpe-23:cpe23-item]/*/@name")),
                     stringsAsFactors = F)
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}

  if (verbose) print("Extracting factors from cpe 2.3 code...")
  new.cols <- c("std", "std.v", "part", "vendor", "product",
                "version", "update", "edition", "language", "sw_edition",
                "target_sw", "target_hw", "other")
  cpes$cpe.23 <- stringr::str_replace_all(cpes$cpe.23, "\\\\:", ";")
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  cpes <- tidyr::separate(data = cpes, col = cpe.23, into = new.cols, sep = ":", remove = F)
  cpes <- dplyr::select(.data = cpes, -std, -std.v)
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  cpes$vendor <- as.factor(cpes$vendor)
  cpes$product <- as.factor(cpes$product)
  cpes$language <- as.factor(cpes$language)
  cpes$sw_edition <- as.factor(cpes$sw_edition)
  cpes$target_sw <- as.factor(cpes$target_sw)
  cpes$target_hw <- as.factor(cpes$target_hw)
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}

  if (verbose) print("Parsing product links and references...")
  raw.refs <- xml2::as_list(xml2::xml_find_all(doc, "//*[name()='cpe-item']/*[name()='references']"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  refs <- sapply(raw.refs,
                 function(x) {
                    refs <- as.character(unlist(sapply(x, attributes)))
                    names(refs) <- as.character(unlist(x))
                    RJSONIO::toJSON(refs, pretty = T)
                 })
  if (verbose) print("Adding references to data.frame ...")
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  refs.cpe.23 <- xml2::xml_text(xml2::xml_find_all(doc, "//*[name()='cpe-item']/*[name()='references']/parent::*/cpe-23:cpe23-item/@name"))
  df.refs <- data.frame(cpe.23 = refs.cpe.23, references = refs, stringsAsFactors = F)
  cpes <- dplyr::left_join(cpes, df.refs, by = c("cpe.23"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}

  if (verbose) print("Parsing check and OVAL references...")
  checks <- sapply(xml2::as_list(xml2::xml_find_all(doc, "//*[name()='cpe-item']/*[name()='check']")),
                   function(x) RJSONIO::toJSON(attributes(x)))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  if (verbose) print("Adding checks to data.frame ...")
  checks.cpe.23 <- xml2::xml_text(xml2::xml_find_all(doc, "//*[name()='cpe-item']/*[name()='check']/parent::*/cpe-23:cpe23-item/@name"))
  df.checks <- data.frame(cpe.23 = checks.cpe.23, checks = checks, stringsAsFactors = F)
  cpes <- dplyr::left_join(cpes, df.checks, by = c("cpe.23"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}

  close(pb)
  return(cpes)
}
