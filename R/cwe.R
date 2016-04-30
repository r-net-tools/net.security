#' DownloadCWEData, it downloads https://cwe.mitre.org/data/xml/views/2000.xml.zip
#' that containts all kind of information related with CWE
#'
#' @param destfile, path where the file will be stored
#' @export
#'
#' @examples
#' DownloadCWEData()
DownloadCWEData <- function(path = "inst/tmpdata") {
  destfile <- paste(path, "2000.xml.zip", sep = "/")
  download.file(url = "https://cwe.mitre.org/data/xml/views/2000.xml.zip",
                destfile = destfile)
  unzip(zipfile = destfile, exdir = path)
}

#' GetCWETitle, returns CWE's title
#'
#' @param cwe
#' @return character
#' @export
#' @examples
#' GetCWETitle(cwe = "99")
GetCWETitle <- function(cwe = "100") {
  doc <- GetCWEData()
  xpath <- paste("//Weakness[@ID = '", cwe, "']/@Name", sep = "")
  return(unlist(XML::xpathApply(doc, xpath))[["Name"]])
}

#' GetCWEChildrenIDs, return all CWEs direct child of input CWE
#'
#' @param cwe, only one. Default="102"
#' @return character
#' @export
#' @examples
#' GetCWEChildrenIDs()
#' GetCWEChildrenIDs("675")
GetCWEChildrenIDs <- function(cwe = "102") {
  doc <- GetCWEData()
  xpath <- paste("//Weakness[Relationships/Relationship/Relationship_Target_ID = '",
                 cwe,
                 "' and ",
                 " Relationships/Relationship/Relationship_Nature = 'ChildOf'",
                 " and ",
                 "Relationships/Relationship/Relationship_Target_Form = 'Weakness']/@ID",
                 sep = "")
  return(as.character(XML::xpathApply(doc, xpath)))
}

#--------------------------------------------------------------PRIVATE FUNCTIONS

#' GetCWEData, parse xml.path
#'
#' @param xml.path, absolute path. Default = "inst/tmpdata/2000.xml"
#' @return "XMLInternalDocument" "XMLAbstractDocument"
#' @examples
#' doc <- GetCWEData()
GetCWEData <- function(xml.path = "inst/tmpdata/2000.xml") {
  return(XML::xmlParse(xml.path))
}

#--------------------------------------------------------------OLD FUNCTIONS
# GetCWEChildrenNodes <- function(doc, cwe = "102") {
#   xpath <- paste("//Weakness[Relationships/Relationship/Relationship_Target_ID = '",
#                  cwe,
#                  "' and Relationships/Relationship/Relationship_Nature = 'ChildOf'",
#                  " and Relationships/Relationship/Relationship_Target_Form = 'Weakness']",
#                  sep = "")
#   return(XML::xpathApply(doc, xpath))
# }
#
#
#
# GetAllCWEChildrenIDs <- function(doc, cwe = "102") {
#   childs <- GetCWEChildrenIDs(doc, cwe)
#
#   if (identical(childs, character(0))) {
#     return(cwe)
#   } else {
#     return(unique(c(cwe, unlist(lapply(childs, function(x) GetAllCWEChildrenIDs(doc, x))))))
#   }
# }
