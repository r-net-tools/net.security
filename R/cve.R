#### Exported Functions ----------------------------------------------------------------------------


#' Get data frame with CVE information
#'
#' @return Data frame
#' @export
GetCVEData <- function() {
  DownloadCVEData(dest = tempdir())
  ExtractDataFiles(path = tempdir())

  cves.mitre <- ParseCVEMITREData(path = tempdir())
  cves.nist <- ParseCVENISTData(path = tempdir(), years = "all")

  # TODO: Unify the data.frames
  cves <- list(mitre = cves.mitre, nist = cves.nist)
  return(cves)
}


#### MITRE Private Functions -----------------------------------------------------------------------------

#' Arrange CVE information into data frame
#'
#' @param cve.file String
#'
#' @return Data frame
ParseCVEMITREData <- function(path) {
  # TODO: Parse XML files
  cve.file <-   paste(path, "cve", "mitre", "allitems.csv",
                      sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  column.names <- c("cve","status","description","references","phase","votes","comments")
  column.classes <- c("character","factor","character","character","character","character","character")
  cves <- utils::read.csv(file = cve.file,
                          skip = 9,
                          col.names = column.names,
                          colClasses = column.classes)
  return(cves)
}


#### NIST Private Functions -----------------------------------------------------------------------------

#' ParseCVENISTData
#'
#' @param years numeric vector with values between 2002 and current year
#'
#' @return data frame
ParseCVENISTData <- function(path, years = as.integer(format(Sys.Date(), "%Y"))) {
  if (years == "all") years <- 2002:as.integer(format(Sys.Date(), "%Y"))
  years.ok <- 2002:as.integer(format(Sys.Date(), "%Y"))
  if (any(!(years %in% years.ok))) {
    # wrong years defined
    cves <- data.frame(stringsAsFactors = F)
  } else {
    cves <- NewNISTEntry()
    for (year in years) {
      cves <- rbind(cves, GetNISTvulnsByYear(path, year))
    }
  }
  return(cves)
}

#' Create CVE data.frame from NIST entries for specified year
#'
#' @param year value between 2002 and current year, default value is set as current year
#' @return data frame
#' @example year = 2012
GetNISTvulnsByYear <- function(path, year = as.integer(format(Sys.Date(), "%Y"))) {
  # Reference: https://scap.nist.gov/schema/nvd/vulnerability_0.4.xsd
  # TODO: Improve efficience 1 lapply instead of 2
  nistfile <- paste("nvdcve-2.0-", year, ".xml", sep = "")
  nistpath <- paste(path, "cve","nist", nistfile,
                    sep = ifelse(.Platform$OS.type == "windows","\\","/"))
  doc <- XML::xmlTreeParse(file = nistpath, useInternalNodes = T)
  entries <- XML::xmlChildren(XML::xmlRoot(doc))
  lentries <- lapply(entries, GetNISTEntry)
  df <- plyr::ldply(lentries, data.frame)

  # Tidy Data
  df$.id    <- NULL
  df$cve.id <- as.character(df$cve.id)
  df$cwe    <- as.character(sapply(as.character(df$cwe), function(x) jsonlite::fromJSON(x)))
  df$cwe    <- sub(pattern = "list()",replacement = NA, x = df$cwe)

  return(df)
}

#' Parse from NIST XML CVE entry to data.frame
#'
#' @param node XML Node
#'
#' @return data frame
GetNISTEntry <- function(node) {
  # TODO: Tidy data frame

  entry <- NewNISTEntry()
  lnode <- XML::xmlChildren(node)

  # Parse "xsd:*:vulnerabilityType" fields
  osvdb.ext <- osvdb.ext2df(lnode[["osvdb-ext"]])
  vulnerable.configuration <- vulnerable.configuration2df(lnode[["vulnerable-configuration"]])
  vulnerable.software.list <- vulnerable.software.list2df(lnode[["vulnerable-software-list"]])
  cve.id <- cve.id2df((lnode[["cve-id"]]))
  discovered.datetime <- discovered.datetime2df(lnode[["discovered-datetime"]])
  disclosure.datetime <- disclosure.datetime2df(lnode[["disclosure-datetime"]])
  exploit.publish.datetime <- exploit.publish.datetime2df(lnode[["exploit-publish-datetime"]])
  published.datetime <- published.datetime2df(lnode[["published-datetime"]])
  last.modified.datetime <- last.modified.datetime2df(lnode[["last-modified-datetime"]])
  cvss <- cvss2df(lnode[["cvss"]])
  security.protection <- security.protection2df(lnode[["security-protection"]])
  assessment.check <- assessment.check2df(lnode[["assessment_check"]])
  cwe <- cwe2df(lnode[["cwe"]])
  references <- references2df(lnode[["references"]])
  fix.action <- fix.action2df(lnode[["fix_action"]])
  scanner <- scanner2df(lnode[["scanner"]])
  summary <- summary2df(lnode[["summary"]])
  technical.description <- technical.description2df(lnode[["technical_description"]])
  attack.scenario <- attack.scenario2df(lnode[["attack_scenario"]])

  entry <- rbind(entry,
                 c(osvdb.ext,
                   vulnerable.configuration,
                   vulnerable.software.list,
                   cve.id,
                   discovered.datetime,
                   disclosure.datetime,
                   exploit.publish.datetime,
                   published.datetime,
                   last.modified.datetime,
                   cvss,
                   security.protection,
                   assessment.check,
                   cwe,
                   references,
                   fix.action,
                   scanner,
                   summary,
                   technical.description,
                   attack.scenario)
  )
  names(entry) <- names(NewNISTEntry())

  return(entry)
}


osvdb.ext2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

#' Parse vulnerable-configuration node and returns a JSON with simple list of CPE's
#' or CPE pairs of software, configuration
#'
#' @param node
#'
#' @return
#' @export
#'
#' @examples
vulnerable.configuration2df <- function(node) {
  # TODO: Improve parser
  # i = 418

  if (is.null(node)) return(jsonlite::toJSON(node))
  # detect first logical test type
  logic.type <- XML::xmlAttrs(XML::xmlChildren(node)[[1]])[["operator"]]
  if (logic.type == "OR") {
    # Configuration list of CPE's
    rdf <- as.character(grep(pattern = "cpe",
                             x = unlist(XML::xmlToList(XML::xmlChildren(node)[[1]])),
                             value = T))
    rdf <- jsonlite::toJSON(rdf)
  } else {
    if (logic.type == "AND") {
      node.cpes <- XML::xmlChildren(XML::xmlChildren(node)[[1]])
      if (length(node.cpes) == 3){
        if (is.null(dim(node.cpes))) {
          # Malformed configuration? (ex: CVE-2008-6714)
          rdf <- as.character(grep(pattern = "cpe",
                                   x = unlist(XML::xmlToList(XML::xmlChildren(node)[[1]])),
                                   value = T))
        } else {
          if (all(sapply(node.cpes, XML::xmlAttrs)[1,] == "OR")) {
            # Configuration applies in certantly OS, APP and Configuration (ex: CVE-2007-2583)
            osver <- as.character(grep(pattern = "cpe",
                                       x = unlist(XML::xmlToList(node.cpes[[1]])),
                                       value = T))
            soft <- as.character(grep(pattern = "cpe",
                                      x = unlist(XML::xmlToList(node.cpes[[2]])),
                                      value = T))
            conf <- as.character(grep(pattern = "cpe",
                                      x = unlist(XML::xmlToList(node.cpes[[3]])),
                                      value = T))
            rdf <- as.data.frame.matrix(data.table::CJ(osver, soft))
            rdf2 <- as.data.frame.matrix(data.table::CJ(soft, conf))
            # names(rdf2) <- c("V2","V3")
            rdf <- dplyr::left_join(rdf, rdf2, by = c("V1" = "V2"))
            names(rdf) <- NULL
          } else {
            # TODO: understand what is the meaning of this case
            rdf <- XML::xmlToList(node.cpes)
          }
        }
      } else {
        if (length(node.cpes) == 2) {
          if (any(names(XML::xmlToList(node.cpes[[2]])) %in% c("operator","negate"))) {
            # Malformed configuration? (ex: CVE-2009-2044)
            rdf <- as.character(grep(pattern = "cpe",
                                      x = unlist(XML::xmlToList(node.cpes[[1]])),
                                      value = T))
            names(rdf) <- NULL
          } else {
            # Configuration applies in pairs OS-APP, APP-Conf, OS-Update, App-Plugin, etc.
            soft <- as.character(grep(pattern = "cpe",
                                      x = unlist(XML::xmlToList(node.cpes[[1]])),
                                      value = T))
            conf <- as.character(grep(pattern = "cpe",
                                      x = unlist(XML::xmlToList(node.cpes[[2]])),
                                      value = T))
            rdf <- as.data.frame.matrix(data.table::CJ(soft, conf))
            names(rdf) <- NULL
          }
        } else {
          if (length(node.cpes) == 1) {
            # Configuration list of CPE's
            rdf <- as.character(grep(pattern = "cpe",
                                     x = unlist(XML::xmlToList(XML::xmlChildren(node)[[1]])),
                                     value = T))
          } else {
            # Malformed -> Configuration list of CPE's (ex. CVE-2009-2044)
            rdf <- lapply(node.cpes, XML::xmlToList)
          }
        }
      }
      rdf <- jsonlite::toJSON(rdf)
    } else {
      rdf <- NodeToJson(node)
    }
  }

  return(rdf)
}

vulnerable.software.list2df <- function(node) {
  # TODO: Improve parser
  if (is.null(node)) return(jsonlite::toJSON(node))
  rdf <- jsonlite::toJSON(sapply(XML::xmlChildren(node), XML::xmlValue))
  return(rdf)
}

cve.id2df <- function(node) {
  # TODO: Improve parser
  return(NodeToChar(node))
}

discovered.datetime2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

disclosure.datetime2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

exploit.publish.datetime2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

published.datetime2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

last.modified.datetime2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

cvss2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

security.protection2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

assessment.check2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

cwe2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

references2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

fix.action2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

scanner2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

summary2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

technical.description2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}

attack.scenario2df <- function(node) {
  # TODO: Improve parser
  return(NodeToJson(node))
}


#' Create empty data frame for CVE NIST information
#'
#' @return data frame
NewNISTEntry <- function() {
  return(data.frame(osvdb.ext = character(),
                    vulnerable.configuration = character(),
                    vulnerable.software.list = character(),
                    cve.id = character(),
                    discovered.datetime = character(),
                    disclosure.datetime = character(),
                    exploit.publish.datetime = character(),
                    published.datetime = character(),
                    last.modified.datetime = character(),
                    cvss = character(),
                    security.protection = character(),
                    assessment.check = character(),
                    cwe = character(),
                    references = character(),
                    fix.action = character(),
                    scanner = character(),
                    summary = character(),
                    technical.description = character(),
                    attack.scenario = character(),
                    stringsAsFactors = FALSE)
  )
}


#### Private Functions -----------------------------------------------------------------------------

#' Download CVE information
#'
#' @param dest String with directory where to store files to be downloaded.
DownloadCVEData <- function(dest) {
  curdir <- setwd(dir = dest)

  # Data folders
  if (!dir.exists("cve")) {
    dir.create("cve")
    dir.create("cve/mitre")
    dir.create("cve/nist")
  }

  # Download MITRE data (http://cve.mitre.org/data/downloads/index.html#download)
  utils::download.file(url = "http://cve.mitre.org/data/downloads/allitems.xml.gz",
                destfile = paste(tempdir(), "cve", "mitre", "allitems.xml.gz",
                                 sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  utils::download.file(url = "http://cve.mitre.org/schema/cve/cve_1.0.xsd",
                destfile = paste(tempdir(), "cve", "mitre", "cve_1.0.xsd",
                                 sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  utils::download.file(url = "http://cve.mitre.org/data/downloads/allitems.csv.gz",
                destfile = paste(tempdir(), "cve", "mitre","allitems.csv.gz",
                                 sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))

  # Download NIST data ()
  for (year in 2002:as.integer(format(Sys.Date(), "%Y"))) {
    nist.file <- paste("nvdcve-2.0-", year, ".xml.gz", sep = "")
    nist.url <- paste("https://static.nvd.nist.gov/feeds/xml/cve/", nist.file, sep = "")
    utils::download.file(url = nist.url,
                         destfile = paste(tempdir(), "cve", "nist", nist.file,
                                          sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
    # Spanish translations by INCIBE
    nist.file <- paste("nvdcve-", year, "trans.xml.gz", sep = "")
    nist.url <- paste("https://nvd.nist.gov/download/", nist.file, sep = "")
    utils::download.file(url = nist.url,
                         destfile = paste(tempdir(), "cve", "nist", nist.file,
                                          sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }

  setwd(curdir)
}

#' Extract compressed files
#'
#' @param path String, the directory containing the files to be extracted
ExtractDataFiles <- function(path) {
  # Uncompress gzip XML files
  gzs <- list.files(path = paste(path,"cve", sep = "/"), pattern = ".gz",
                    full.names = TRUE, recursive = TRUE)
  apply(X = data.frame(gzs = gzs, stringsAsFactors = F),
        1, function(x) R.utils::gunzip(x, overwrite = TRUE, remove = TRUE))
}

#' Transform XML node as string
#'
#' @param x XML Node
#'
#' @return Character
NodeToChar <- function(x) {
  if (is.null(x)) x <- ""
  return(as.character(unlist(XML::xmlToList(x))))
}

#' Transform XML node as JSON string
#'
#' @param x XML Node
#'
#' @return json
NodeToJson <- function(x) {
  if (is.null(x)) x <- "<xml></xml>"
  return(jsonlite::toJSON(XML::xmlToList(x)))
}


