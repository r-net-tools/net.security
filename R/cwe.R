LastDownloadCWEDate <- function(){
  return(Sys.Date())
}

GetCWEData <- function(savepath = tempdir(), verbose = T) {
  print("Downloading raw data from MITRE...")
  DownloadCWEData(savepath)
  print("Unzip, extract, etc...")
  cwes.file <- ExtractCWEFiles(savepath)
  print("Processing CWE raw data...")
  cwes <- ParseCWEData(cwes.file, verbose)
  print(paste("CWES data frame building process finished."))
  return(cwes)
}

DownloadCWEData <- function(savepath) {
  if (!dir.exists(paste(savepath, "cwe", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "cwe", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }
  cwe.url  <- "https://cwe.mitre.org/data/xml/cwec_v3.1.xml.zip"
  destfile <- paste(savepath, "cwe", "cwec_v3.1.xml.zip",sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::download.file(url = cwe.url, destfile = destfile)
}

ExtractCWEFiles <- function(savepath) {
  # Uncompress gzip XML files
  cwes.zip <- paste(savepath, "cwe", "cwec_v3.1.xml.zip", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  cwes.xml <- paste(savepath, "cwe", "cwec_v3.1.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::unzip(zipfile = cwes.zip, exdir = cwes.xml)
  cwes.xml <- paste(cwes.xml, "cwec_v3.1.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  return(cwes.xml)
}

ParseCWEData <- function(cwes.file, verbose) {
  print("Parsing Basic attributes...")
  i <- 1
  if (verbose) pb <- utils::txtProgressBar(min = 0, max = 17, style = 3, title = "CWE data")

  # Load Weakness raw data
  doc <- suppressWarnings(rvest::html(cwes.file))
  raw.cwes <- rvest::html_nodes(doc, "weakness")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  # Extract Weakness node attributes
  cwes <- as.data.frame(t(sapply(raw.cwes, rvest::html_attrs)), stringsAsFactors = F)
  names(cwes) <- c("ID", "Name", "Abstraction", "Structure", "Status")
  # Set factors (improve setting levels according to XSD)
  cwes$Abstraction <- as.factor(cwes$Abstraction)
  cwes$Structure <- as.factor(cwes$Structure)
  cwes$Status <- as.factor(cwes$Status)
  # Add extra field with code standard
  cwes$Code_Standard <- paste("CWE-", cwes$ID, sep = "")

  if (verbose) print("Parsing Description...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}

  cwes$Description <- sapply(rvest::html_nodes(doc, xpath = "//weakness/description"),
                             rvest::html_text)

  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/extended_description/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/extended_description"), xml2::xml_text)
  df <- data.frame(ID = ids, Extended_Description = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Related Weakness...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/related_weaknesses/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/related_weaknesses"),
                   function(x) RJSONIO::toJSON(lapply(rvest::html_children(x),
                                                      rvest::html_attrs),
                                               pretty = T)
                   )
  df <- data.frame(ID = ids, Related_Weakness = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Weakness Ordinality...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/weakness_ordinalities/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/weakness_ordinalities"),
                 function(x) RJSONIO::toJSON(lapply(rvest::html_children(x),
                                                    function(x) rvest::html_text(rvest::html_children(x))),
                                             pretty = T)
  )
  df <- data.frame(ID = ids, Weakness_Ordinality = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Applicable Platforms...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/applicable_platforms/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/applicable_platforms"),
                 function(x) {
                   y <- lapply(rvest::html_children(x), rvest::html_attrs)
                   names(y) <- rvest::html_name(rvest::html_children(x))
                   RJSONIO::toJSON(y, pretty = T)
                 }
  )
  df <- data.frame(ID = ids, Applicable_Platforms = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Background Details...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/background_details/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/background_details"),
                 function(x) RJSONIO::toJSON(xml2::xml_text(x),
                                             pretty = T)
  )
  df <- data.frame(ID = ids, Background_Details = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Alternate Terms...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/alternate_terms/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/alternate_terms"),
                 function(x) RJSONIO::toJSON(lapply(rvest::html_children(x),
                                                    rvest::html_text),
                                             pretty = T)
  )
  df <- data.frame(ID = ids, Alternate_Terms = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Modes Of Introduction...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/modes_of_introduction/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/modes_of_introduction"),
                 function(x) RJSONIO::toJSON(lapply(
                   lapply(rvest::html_children(x),
                          function(x) rvest::html_children(x)),
                   function(y) {
                     z <- rvest::html_text(y)
                     names(z) <- rvest::html_name(y)
                     z
                   }
                 ),
                 pretty = T)
  )
  df <- data.frame(ID = ids, Modes_Of_Introduction = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Likelihood Of Exploit...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/likelihood_of_exploit/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/likelihood_of_exploit"), rvest::html_text)
  df <- data.frame(ID = ids, Likelihood_Of_Exploit = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))
  cwes$Likelihood_Of_Exploit <- as.factor(cwes$Likelihood_Of_Exploit)

  if (verbose) print("Parsing Common Consequences...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/common_consequences/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/common_consequences"),
                 function(x) RJSONIO::toJSON(lapply(
                   lapply(rvest::html_children(x),
                          function(x) rvest::html_children(x)),
                   function(y) {
                     z <- rvest::html_text(y)
                     names(z) <- rvest::html_name(y)
                     z
                   }
                 ),
                 pretty = T)
  )
  df <- data.frame(ID = ids, Common_Consequences = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Detection Methods...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/detection_methods/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/detection_methods"),
                 function(x) RJSONIO::toJSON(lapply(
                   lapply(rvest::html_children(x),
                          function(x) rvest::html_children(x)),
                   function(y) {
                     z <- rvest::html_text(y)
                     names(z) <- rvest::html_name(y)
                     z
                   }
                 ),
                 pretty = T)
  )
  df <- data.frame(ID = ids, Detection_Methods = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Potential Mitigations...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/potential_mitigations/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/potential_mitigations"),
                 function(x) RJSONIO::toJSON(lapply(
                   lapply(rvest::html_children(x),
                          function(x) rvest::html_children(x)),
                   function(y) {
                     z <- rvest::html_text(y)
                     names(z) <- rvest::html_name(y)
                     z
                   }
                 ),
                 pretty = T)
  )
  df <- data.frame(ID = ids, Potential_Mitigations = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Observed Examples...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/observed_examples/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/observed_examples"),
                 function(x) RJSONIO::toJSON(lapply(
                   lapply(rvest::html_children(x),
                          function(x) rvest::html_children(x)),
                   function(y) {
                     z <- rvest::html_text(y)
                     names(z) <- rvest::html_name(y)
                     z
                   }
                 ),
                 pretty = T)
  )
  df <- data.frame(ID = ids, Observed_Examples = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Functional Areas...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/functional_areas/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/functional_areas"),
                 function(x) RJSONIO::toJSON(sapply(rvest::html_children(x), rvest::html_text))
  )
  df <- data.frame(ID = ids, Functional_Areas = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Affected Resources...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/affected_resources/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/affected_resources"),
                 function(x) RJSONIO::toJSON(sapply(rvest::html_children(x), rvest::html_text))
  )
  df <- data.frame(ID = ids, Affected_Resources = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Taxonomy Mappings...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/taxonomy_mappings/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/taxonomy_mappings"),
                 function(x) RJSONIO::toJSON({w <- lapply(
                   lapply(rvest::html_children(x),
                          function(x) rvest::html_children(x)),
                   function(y) {
                     z <- rvest::html_text(y)
                     names(z) <- rvest::html_name(y)
                     z
                   })
                 names(w) <- unlist(rvest::html_attrs(rvest::html_children(x)))
                 w}, pretty = T)
  )
  df <- data.frame(ID = ids, Taxonomy_Mappings = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  if (verbose) print("Parsing Related Attack Patterns...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  ids <- xml2::xml_text(xml2::xml_find_all(doc, "//weakness/related_attack_patterns/parent::*/@id"))
  vals <- sapply(xml2::xml_find_all(doc, "//weakness/related_attack_patterns"),
                 function(x) RJSONIO::toJSON(sapply(rvest::html_children(x), rvest::html_attrs))
  )
  df <- data.frame(ID = ids, Related_Attack_Patterns = vals, stringsAsFactors = F)
  cwes <- dplyr::left_join(cwes, df, by = c("ID"))

  close(pb)
  return(cwes)
}
