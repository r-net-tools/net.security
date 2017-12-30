GetCVEData <- function(savepath = tempdir(), verbose = TRUE,
                       from.year = 2002L,
                       to.year = as.integer(format(Sys.Date(), "%Y"))) {
  if (verbose) print("Downloading raw data from sources...")
  DownloadCVEData(savepath, verbose, from.year, to.year)
  if (verbose) print(paste("Unzip, extract, etc..."))
  ExtractCVEFiles(savepath, verbose)

  # Parse MITRE data
  if (verbose) print("Processing MITRE raw data...")
  cves.mitre <- ParseCVEMITREData(savepath, verbose)

  # Parse NIST data
  if (verbose) print("Processing NIST raw data...")
  cves.nist <- ParseCVENISTData(savepath, from.year, to.year, verbose)

  if (verbose) print("Joining MITRE and NIST data...")
  # cves <- list(cves.mitre, cves.nist)
  cves <- cves.nist

  return(cves)
}

#### MITRE Private Functions ---------------------------------------------------

ParseCVEMITREData <- function(savepath, verbose) {
  # TODO: Parse XML files
  cve.file <-   paste(savepath, "cve", "mitre", "allitems.csv",
                      sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  column.names <- c("cve","mitre.status","mitre.description","mitre.references",
                    "mitre.phase","mitre.votes","mitre.comments")
  column.classes <- c("character","factor","character","character","character",
                      "character","character")
  if (verbose) print("Parsing MITRE cves from CSV source...")
  cves <- utils::read.csv(file = cve.file,
                          skip = 9,
                          col.names = column.names,
                          colClasses = column.classes)
  if (verbose) print("Tidy MITRE data frame...")
  if (verbose) print("Parsing MITRE data finished.")
  return(cves)
}


##### NIST Private Functions ---------------------------------------------------

ParseCVENISTData <- function(savepath, from.year, to.year, verbose) {
  cves <- NewNISTEntry()
  for (year in from.year:to.year) {
    cves <- dplyr::bind_rows(cves, GetNISTvulnsByYear(savepath, year, verbose))
  }
  if (verbose) print("Tidy NIST data frame...")
  cves$cvss3.av <- as.factor(cves$cvss3.av)
  cves$cvss3.ac <- as.factor(cves$cvss3.ac)
  cves$cvss3.pr <- as.factor(cves$cvss3.pr)
  cves$cvss3.ui <- as.factor(cves$cvss3.ui)
  cves$cvss3.s <- as.factor(cves$cvss3.s)
  cves$cvss3.c <- as.factor(cves$cvss3.c)
  cves$cvss3.i <- as.factor(cves$cvss3.i)
  cves$cvss3.a <- as.factor(cves$cvss3.a)
  cves$cvss3.severity <- as.factor(cves$cvss3.severity)
  cves$cvss2.av <- as.factor(cves$cvss2.av)
  cves$cvss2.ac <- as.factor(cves$cvss2.ac)
  cves$cvss2.au <- as.factor(cves$cvss2.au)
  cves$cvss2.c <- as.factor(cves$cvss2.c)
  cves$cvss2.i <- as.factor(cves$cvss2.i)
  cves$cvss2.a <- as.factor(cves$cvss2.a)
  cves$published.date <- strptime(cves$published.date, "%Y-%m-%dT%H:%MZ")
  cves$last.modified <- strptime(cves$last.modified, "%Y-%m-%dT%H:%MZ")

  if (verbose) print("Parsing NIST data finished.")
  return(cves)
}

GetNISTvulnsByYear <- function(savepath, year, verbose) {
  if (verbose) print(paste("Parsing cves (year ", year, ") from json source...", sep = ""))
  nistfile <- paste("nvdcve-1.0-", year, ".json", sep = "")
  nistpath <- paste(savepath, "cve","nist", nistfile,
                    sep = ifelse(.Platform$OS.type == "windows","\\","/"))
  cve.entries <- jsonlite::fromJSON(nistpath)
  cve.entries <- cve.entries$CVE_Items

  cves <- data.frame(cve.id = cve.entries$cve$CVE_data_meta$ID,
                     stringsAsFactors = F)
  cves$affects <- unlist(lapply(cve.entries$cve$affects$vendor$vendor_data, jsonlite::toJSON))
  cves$problem.type <- unlist(lapply(cve.entries$cve$problemtype$problemtype_data, function(x) jsonlite::toJSON(x[[1]][[1]]$value)))
  cves$references <- unlist(lapply(cve.entries$cve$references$reference_data, jsonlite::toJSON))
  cves$description <- unlist(lapply(cve.entries$cve$description$description_data, jsonlite::toJSON))
  cves$vulnerable.configuration <- unlist(lapply(cve.entries$configurations$nodes, jsonlite::toJSON))
  cves$cvss3.vector <- cve.entries$impact$baseMetricV3$cvssV3$vectorString
  cves$cvss3.av <- cve.entries$impact$baseMetricV3$cvssV3$attackVector
  cves$cvss3.ac <- cve.entries$impact$baseMetricV3$cvssV3$attackComplexity
  cves$cvss3.pr <- cve.entries$impact$baseMetricV3$cvssV3$privilegesRequired
  cves$cvss3.ui <- cve.entries$impact$baseMetricV3$cvssV3$userInteraction
  cves$cvss3.s <- cve.entries$impact$baseMetricV3$cvssV3$scope
  cves$cvss3.c <- cve.entries$impact$baseMetricV3$cvssV3$confidentialityImpact
  cves$cvss3.i <- cve.entries$impact$baseMetricV3$cvssV3$integrityImpact
  cves$cvss3.a <- cve.entries$impact$baseMetricV3$cvssV3$availabilityImpact
  cves$cvss3.score <- cve.entries$impact$baseMetricV3$cvssV3$baseScore
  cves$cvss3.severity <- cve.entries$impact$baseMetricV3$cvssV3$baseSeverity
  cves$cvss3.score.exploit <- cve.entries$impact$baseMetricV3$exploitabilityScore
  cves$cvss3.score.impact <- cve.entries$impact$baseMetricV3$impactScore
  cves$cvss2.vector <- cve.entries$impact$baseMetricV2$cvssV2$vectorString
  cves$cvss2.av <- cve.entries$impact$baseMetricV2$cvssV2$accessVector
  cves$cvss2.ac <- cve.entries$impact$baseMetricV2$cvssV2$accessComplexity
  cves$cvss2.au <- cve.entries$impact$baseMetricV2$cvssV2$authentication
  cves$cvss2.c <- cve.entries$impact$baseMetricV2$cvssV2$confidentialityImpact
  cves$cvss2.i <- cve.entries$impact$baseMetricV2$cvssV2$integrityImpact
  cves$cvss2.a <- cve.entries$impact$baseMetricV2$cvssV2$availabilityImpact
  cves$cvss2.score <- cve.entries$impact$baseMetricV2$cvssV2$baseScore
  cves$cvss2.severity <- cve.entries$impact$baseMetricV2$cvssV2$baseSeverity
  cves$cvss2.score.exploit <- cve.entries$impact$baseMetricV2$exploitabilityScore
  cves$cvss2.score.impact <- cve.entries$impact$baseMetricV2$impactScore
  cves$cvss2.getallprivilege <- cve.entries$impact$baseMetricV2$obtainAllPrivilege
  cves$cvss2.getusrprivilege <- cve.entries$impact$baseMetricV2$obtainUserPrivilege
  cves$cvss2.getothprivilege <- cve.entries$impact$baseMetricV2$obtainOtherPrivilege
  cves$cvss2.requsrinter <- cve.entries$impact$baseMetricV2$userInteractionRequired
  cves$published.date <- cve.entries$publishedDate
  cves$last.modified <- cve.entries$lastModifiedDate

  return(cves)
}

NewNISTEntry <- function() {
  return(data.frame(cve.id = character(),
                    affects = character(),
                    problem.type = character(),
                    references = character(),
                    description = character(),
                    vulnerable.configuration = character(),
                    cvss3.vector = character(),
                    cvss3.av = character(),
                    cvss3.ac = character(),
                    cvss3.pr = character(),
                    cvss3.ui = character(),
                    cvss3.s = character(),
                    cvss3.c = character(),
                    cvss3.i = character(),
                    cvss3.a = character(),
                    cvss3.score = numeric(),
                    cvss3.severity = character(),
                    cvss3.score.exploit = numeric(),
                    cvss3.score.impact = numeric(),
                    cvss2.vector = character(),
                    cvss2.av = character(),
                    cvss2.ac = character(),
                    cvss2.au = character(),
                    cvss2.c = character(),
                    cvss2.i = character(),
                    cvss2.a = character(),
                    cvss2.score = numeric(),
                    cvss2.score.exploit = numeric(),
                    cvss2.score.impact = numeric(),
                    cvss2.getallprivilege = logical(),
                    cvss2.getusrprivilege = logical(),
                    cvss2.getothprivilege = logical(),
                    cvss2.requsrinter = logical(),
                    published.date = character(),
                    last.modified = character(),
                    stringsAsFactors = FALSE)
  )
}
##### Source files management (download, extract, ...)
LastDownloadCVEDate <- function() {
  mitre <- strptime(LastDownloadMITRECVEDate(), format = "%Y-%m-%d")
  nist <- strptime(LastDownloadNISTCVEDate(), format = "%Y-%m-%d")
  return(as.character(max(nist, mitre)))
}

LastDownloadNISTCVEDate <- function(){
  doc <- xml2::read_html("https://nvd.nist.gov/vuln/data-feeds")
  txt <- rvest::html_table(rvest::html_nodes(doc, "#body-section > div:nth-child(2) > div:nth-child(11) > div > table"), fill = T)[[1]]
  names(txt) <- txt[2,]
  txt <- txt[3:nrow(txt),]
  txt$Updated <- strptime(txt$Updated, format = "%m/%d/%Y")
  return(as.character(max(txt$Updated)))
}

LastDownloadMITRECVEDate <- function(){
  doc.html <- XML::htmlParse("http://cve.mitre.org/data/downloads/index.html#download")
  txt <- XML::xmlValue(XML::xpathSApply(doc.html, '//div[@class="smaller"]')[[1]])
  last <- stringr::str_extract_all(pattern = "(.*-.*)", string = txt, simplify = T)[1,1]
  return(last)
}

DownloadCVEData <- function(savepath, verbose, from.year, to.year) {
  # Data folders
  if (!dir.exists(paste(savepath, "cve", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "cve", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }
  if (!dir.exists(paste(savepath, "cve", "mitre", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "cve", "mitre", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }
  if (!dir.exists(paste(savepath, "cve", "nist", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "cve", "nist", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }

  # Download MITRE source data
  utils::download.file(url = "http://cve.mitre.org/data/downloads/allitems.csv.gz",
                       destfile = paste(savepath, "cve", "mitre","allitems.csv.gz",
                                        sep = ifelse(.Platform$OS.type == "windows", "\\", "/")),
                       quiet = !verbose)

  # Download NIST data
  for (year in from.year:to.year) {
    # JSON sources
    nist.file <- paste("nvdcve-1.0-", year, ".json.gz", sep = "")
    nist.url <- paste("https://static.nvd.nist.gov/feeds/json/cve/1.0/", nist.file, sep = "")
    utils::download.file(url = nist.url,
                         destfile = paste(savepath, "cve", "nist", nist.file,
                                          sep = ifelse(.Platform$OS.type == "windows", "\\", "/")),
                         quiet = !verbose)

    # Spanish translations by INCIBE
    nist.file <- paste("nvdcve-", year, "trans.xml.gz", sep = "")
    nist.url <- paste("https://nvd.nist.gov/download/", nist.file, sep = "")
    utils::download.file(url = nist.url,
                         destfile = paste(savepath, "cve", "nist", nist.file,
                                          sep = ifelse(.Platform$OS.type == "windows", "\\", "/")),
                         quiet = !verbose)
  }
}

ExtractCVEFiles <- function(savepath, verbose) {
  # Uncompress gzip XML files
  gzs <- list.files(path = paste(savepath, "cve", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")),
                    pattern = ".gz", full.names = TRUE, recursive = TRUE)
  apply(X = data.frame(gzs = gzs, stringsAsFactors = F),
        1, function(x) R.utils::gunzip(x, overwrite = TRUE, remove = TRUE))
}
