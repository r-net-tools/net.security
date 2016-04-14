library(XML)

UpdateCWEData <- function() {
  download.file(url = "https://cwe.mitre.org/data/xml/views/2000.xml.zip",
                destfile = "inst/tmpdata/2000.xml.zip")
}

GetRawCWEData <- function() {
  return(XML::xmlParse(unzip("inst/tmpdata/2000.xml.zip")))
}

GetCWETitle <- function(doc, cwe = "100") {
  xpath <- paste("//Weakness[@ID = '", cwe, "']/@Name", sep = "")
  return(unlist(XML::xpathApply(doc, xpath))[["Name"]])
}

GetCWEChildrenNodes <- function(doc, cwe = "100") {
  xpath <- paste("//Weakness[Relationships/Relationship/Relationship_Target_ID = '",
                 cwe, 
                 "' and Relationships/Relationship/Relationship_Nature = 'ChildOf'",
                 " and Relationships/Relationship/Relationship_Target_Form = 'Weakness']",
                 sep = "")
  return(XML::xpathApply(doc, xpath))
}

GetCWEChildrenIDs <- function(doc, cwe = "100") {
  xpath <- paste("//Weakness[Relationships/Relationship/Relationship_Target_ID = '",
                 cwe,
                  "' and ",
                 " Relationships/Relationship/Relationship_Nature = 'ChildOf'",
                 " and ",
                 "Relationships/Relationship/Relationship_Target_Form = 'Weakness']/@ID",
                 sep = "")
  return(as.character(XML::xpathApply(doc, xpath)))
}

GetAllCWEChildrenIDs <- function(doc, cwe = "100") {
  childs <- GetCWEChildrenIDs(doc, cwe)

  if (identical(childs, character(0))) {
    return(cwe)
  } else {
    return(unique(c(cwe, unlist(lapply(childs, function(x) GetAllCWEChildrenIDs(doc, x))))))
  }
}
