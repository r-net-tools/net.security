# References: https://capec.mitre.org/data/index.html
#' Download, parse and return a tidy data frame with CAPEC information
#'
#' @return data frame
#' @export
#'
#' @examples
GetCAPECData <- function() {
  DownloadCAPECData(dest = tempdir())
  capec <- data.frame()
  capec.source.file <- paste(tempdir(), "capec", "capec_v2.8.xml",
                             sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  capec.categories <- ParseCAPECData.categories(capec.source.file)

  capec <- list(capec.categories)
  return(capec)
}

#### Private Functions -----------------------------------------------------------------------------

#' Title
#'
#' @param dest. String
DownloadCAPECData <- function(dest) {
  curdir <- setwd(dest)
  if (!dir.exists("capec")) {
    dir.create("capec")
  }
  capec.url  <- "https://capec.mitre.org/data/xml/capec_v2.8.xml"
  destfile <- "capec/capec_v2.8.xml"
  utils::download.file(url = capec.url, destfile = destfile)
  setwd(curdir)
}

#' Title
#'
#' @param cwe.file String
#'
#' @return Data frame
ParseCAPECData.categories <- function(capec.source.file) {

  doc <- XML::xmlParse(capec.source.file)
  raw.capec.views <- XML::xpathApply(doc, "//capec:View")
  raw.capec.cates <- XML::xmlToDataFrame(XML::xpathApply(doc, "//capec:Category"))
  raw.capec.atcks <- XML::xmlToDataFrame(XML::xpathApply(doc, "//capec:Attack_Pattern"))
  raw.capec.envrs <- XML::xmlToDataFrame(XML::xpathApply(doc, "//capec:Environment"))

  # Category IDs
  cat.id = sapply(XML::getNodeSet(doc, "//capec:Category/@ID"), function(x) x[1])
  # Category Names
  cat.name = sapply(XML::getNodeSet(doc, "//capec:Category/@Name"), function(x) x[1])
  # Category Status
  cat.status = sapply(XML::getNodeSet(doc, "//capec:Category/@Status"), function(x) x[1])
  # Category Parent Views
  parents <- sapply(cat.id,
                    function(x)
                      unique(as.character(sapply(XML::getNodeSet(
                        doc,
                        paste("//capec:Category[@ID='", x,
                              "']/capec:Relationships/capec:Relationship/capec:Relationship_Views/capec:Relationship_View_ID",
                              sep = "")
                      ),
                      XML::xmlValue))
                      )
  )
  names(parents) <- NULL
  parents <- sapply(parents, jsonlite::toJSON)

  categories <- data.frame(id = cat.id,
                           name = cat.name,
                           status = cat.status,
                           description = raw.capec.cates$Description,
                           attack.prerequisites = raw.capec.cates$Attack_Prerequisites,
                           resources.required = raw.capec.cates$Resources_Required,
                           parent.view = parents,
                           stringsAsFactors = FALSE
                           )
  return(categories)
}
