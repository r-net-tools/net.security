ExtractSARDFiles <- function(savepath) {
  sep <- ifelse(.Platform$OS.type == "windows", "\\", "/")

  # Uncompress gzip XML files
  sard.zip <- paste(savepath, "sard", "full_manifest.zip", sep = sep)
  sard.xml <- paste(savepath, "sard", "full_manifest.xml", sep = sep)
  utils::unzip(zipfile = sard.zip, exdir = sard.xml)
  sard.xml <- paste(sard.xml, "full_manifest.xml", sep = sep)

  return(sard.xml)
}

DownloadSARDData <- function(savepath) {
  sep <- ifelse(.Platform$OS.type == "windows", "\\", "/")
  if (!dir.exists(paste(savepath, "sard", sep = sep))) {
    dir.create(paste(savepath, "sard", sep = sep))
  }
  sard.url  <- "https://samate.nist.gov/SRD/resources/full_manifest.zip"
  sard.zip <- paste(savepath, "sard", "full_manifest.zip", sep = sep)
  utils::download.file(url = sard.url, destfile = sard.zip)
}

ParseSARDData <- function(sards.file, verbose) {
  i <- 1
  if (verbose) {
    print("Moving data from SARD XML to data.frame ...")
    pb <- txtProgressBar(min = 0, max = 15, style = 3, title = "SARD data")
  }
  doc <- xml2::read_xml(sards.file)
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  sards <- data.frame(id = xml2::xml_text(xml2::xml_find_all(doc, "//testcase/@id")),
                      stringsAsFactors = FALSE)
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  sards$type <- xml2::xml_text(xml2::xml_find_all(doc, "//testcase/@type"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  sards$status <- xml2::xml_text(xml2::xml_find_all(doc, "//testcase/@status"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  sards$submissionDate <- xml2::xml_text(xml2::xml_find_all(doc, "//testcase/@submissionDate"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  instruction <- data.frame(id = xml2::xml_text(xml2::xml_find_all(doc, "//testcase[@instruction]/@id")),
                            instruction = xml2::xml_text(xml2::xml_find_all(doc, "//testcase/@instruction")),
                            stringsAsFactors = FALSE)
  sards <- dplyr::left_join(sards, instruction, by = c("id"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  sards$language <- xml2::xml_text(xml2::xml_find_all(doc, "//testcase/@language"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  author <- data.frame(id = xml2::xml_text(xml2::xml_find_all(doc, "//testcase[@author]/@id")),
                            author = xml2::xml_text(xml2::xml_find_all(doc, "//testcase/@author")),
                            stringsAsFactors = FALSE)
  sards <- dplyr::left_join(sards, author, by = c("id"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  sards$numberOfFiles <- xml2::xml_text(xml2::xml_find_all(doc, "//testcase/@numberOfFiles"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  testsuiteid <- data.frame(id = xml2::xml_text(xml2::xml_find_all(doc, "//testcase[@testsuiteid]/@id")),
                       testsuiteid = xml2::xml_text(xml2::xml_find_all(doc, "//testcase/@testsuiteid")),
                       stringsAsFactors = FALSE)
  sards <- dplyr::left_join(sards, testsuiteid, by = c("id"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  applicationid <- data.frame(id = xml2::xml_text(xml2::xml_find_all(doc, "//testcase[@applicationid]/@id")),
                       applicationid = xml2::xml_text(xml2::xml_find_all(doc, "//testcase/@applicationid")),
                       stringsAsFactors = FALSE)
  sards <- dplyr::left_join(sards, applicationid, by = c("id"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  description <- data.frame(id = xml2::xml_text(xml2::xml_find_all(doc, "//testcase[description]/@id")),
                            description = xml2::xml_text(xml2::xml_find_all(doc, "//testcase/description")),
                            stringsAsFactors = FALSE)
  sards <- dplyr::left_join(sards, description, by = c("id"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  association <- data.frame(id = xml2::xml_text(xml2::xml_find_all(doc, "//testcase[association]/@id")),
                            association = sapply(xml2::xml_find_all(doc, "//testcase/association/parent::*"),
                                                 function(x) RJSONIO::toJSON(xml2::xml_attrs(xml2::xml_find_all(x, "./association")))),
                            stringsAsFactors = FALSE)
  sards <- dplyr::left_join(sards, association, by = c("id"))

  # samples
  doc2 <- XML::xmlParse(file = sards.file)
  samples <- XML::xmlChildren(XML::xmlChildren(doc2)[["container"]])
  samples <- data.frame(id = xml2::xml_text(xml2::xml_find_all(doc, "//testcase[file]/@id")),
                        files = sapply(samples,
                                       function(x) {
                                         notmixed <- lapply(XML::xpathApply(x, "file[not(mixed)][not(flaw)][not(fix)]", XML::xmlAttrs), function(x) list(file = x))
                                         mixed <- lapply(XML::xpathApply(x, "file[mixed|flaw|fix]"),
                                                         function(y)
                                                           list(file = list(c(XML::xmlAttrs(y),
                                                                              XML::xmlApply(y, XML::xmlAttrs)))
                                                                )
                                                         )
                                         RJSONIO::toJSON(c(notmixed, mixed), pretty = T)
                                       }
                                       ),
                        stringsAsFactors = FALSE)
  sards <- dplyr::left_join(sards, samples, by = c("id"))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  sards$related.cwe <- sapply(stringr::str_extract_all(string = sards$files, pattern = "CWE-\\d+"),
                              function(x) RJSONIO::toJSON(unique(x)))
  if (verbose) {setTxtProgressBar(pb, i); i <- i + 1}
  return(sards)
}

GetSARDData <- function(savepath = tempdir(), verbose = T) {
  # Schema: https://samate.nist.gov/SRD/resources/sard_schema.xsd
  # RawData: https://samate.nist.gov/SRD/resources/full_manifest.zip
  if (verbose) print(paste("Downloading raw data..."))
  DownloadSARDData(savepath)
  if (verbose) print(paste("Extracting data..."))
  sards.file <- ExtractSARDFiles(savepath)
  if (verbose) print(paste("Building data frame..."))
  sards <- ParseSARDData(sards.file, verbose)
  if (verbose) print(paste("CPES data frame building process finished."))

  return(sards)
}

