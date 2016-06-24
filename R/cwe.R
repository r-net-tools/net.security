#' GetCWEData Download current CWE definitions, parse them and return the info as data frame
#'
#' @param path where MITRE CWE definitions will be downloaded and unziped (don't finish with /). Default set as inst/tmpdata
#'
#' @return data frame
#' @export
#'
#' @examples
#' df <- GetCWEData()
#' df <- GetCWEData("/tmp")
GetCWEData <- function(path = "inst/tmpdata"){
  path <- DownloadCWEData(path)
  doc <- XML::xmlParse(path)
  raw.cwes <- XML::xpathApply(doc, "//Weakness")
  cwes <- as.data.frame(t(XML::xmlSApply(raw.cwes, XML::xmlAttrs)), stringsAsFactors = FALSE)
  cwes$code_standard <- paste("CWE-", cwes$ID, sep = "")
  cwes.basic <- XML::xmlToDataFrame(raw.cwes)

  #Description
  raw.cwes.descr <- XML::xpathSApply(doc, "//Weakness/Description")
  cwes$descr.summary <- sapply(raw.cwes.descr,
                               function(x)
                               XML::xmlValue(x[["Description_Summary"]]))
  cwes$descr.details <- sapply(raw.cwes.descr,
                               function(x)
                               XML::xmlValue(x[["Extended_Description"]]))
  #Relationships
  raw.cwes.rels <- GetListNodes(raw.cwes, "Relationships")
  cwes$relationships <- ListNodesToJson(raw.cwes.rels)

  #Weakness_Ordinalities
  raw.cwes.ord <- GetListNodes(raw.cwes, "Weakness_Ordinalities")
  cwes$ordinalities <- ListNodesToJson(raw.cwes.ord)

  #Applicable_Platforms
  cwes$platforms <- cwes.basic$Applicable_Platforms

  #Time_of_Introduction
  raw.cwes.toi <- GetListNodes(raw.cwes, "Time_of_Introduction")
  cwes$time.intro <- ListNodesToJson(raw.cwes.toi)

  #Common_Consequences
  raw.cwes.cc <- GetListNodes(raw.cwes, "Common_Consequences")
  cwes$consequences <- ListNodesToXML(raw.cwes.cc)

  #Potential_Mitigations
  raw.cwes.mitigation <- GetListNodes(raw.cwes, "Potential_Mitigations")
  cwes$mitigation <- ListNodesToXML(raw.cwes.mitigation)

  #Causal_Nature
  cwes$causal <- cwes.basic$Causal_Nature

  #Demonstrative_Examples
  raw.cwes.demos <- GetListNodes(raw.cwes, "Demonstrative_Examples")
  cwes$demos <- ListNodesToXML(raw.cwes.demos)

  #Taxonomy_Mappings
  raw.cwes.map <- GetListNodes(raw.cwes, "Taxonomy_Mappings")
  cwes$mapping <- ListNodesToJson(raw.cwes.map)

  #Content_History
  raw.cwes.hist <- GetListNodes(raw.cwes, "Content_History")
  cwes$history <- ListNodesToXML(raw.cwes.hist)

  #Relationship_Notes
  raw.cwes.rels.notes <- GetListNodes(raw.cwes, "Relationship_Notes")
  cwes$relationship.notes <- ListNodesToXML(raw.cwes.rels.notes)

  #Maintenance_Notes
  raw.cwes.maint.notes <- GetListNodes(raw.cwes, "Maintenance_Notes")
  cwes$maintenance.notes <- ListNodesToXML(raw.cwes.maint.notes)

  #Background_Details
  raw.cwes.back <- GetListNodes(raw.cwes, "Background_Details")
  cwes$background <- ListNodesToJson(raw.cwes.back)

  #Modes_of_Introduction
  raw.cwes.mintro <- GetListNodes(raw.cwes, "Modes_of_Introduction")
  cwes$introduction.mode <- ListNodesToJson(raw.cwes.mintro)

  #Other_Notes
  raw.cwes.other <- GetListNodes(raw.cwes, "Other_Notes")
  cwes$other.notes <- ListNodesToJson(raw.cwes.other)

  #References
  #Related_Attack_Patterns
  #Observed_Examples
  #Theoretical_Notes
  #Affected_Resources
  cwes$aff.resources <- cwes.basic$Causal_Nature

  #Research_Gaps
  #Alternate_Terms
  #Terminology_Notes
  #Likelihood_of_Exploit
  cwes$exploits <- cwes.basic$Likelihood_of_Exploit

  #Detection_Methods
  #Functional_Areas
  cwes$functional.areas <- cwes.basic$Functional_Areas

  #White_Box_Definitions
  #Enabling_Factors_for_Exploitation
  #Relevant_Properties

  return(cwes)
}

# functions helpers for data parsing
GetListNodes <- function(doc, node){
  return(sapply(doc, function(x) x[[node]]))
}
ListNodesToJson <- function(doc){
  return(sapply(doc, function(x) ifelse(test = is.null(x),
                                        yes = "[]",
                                        no = jsonlite::toJSON(XML::xmlToDataFrame(x))))
  )
}
ListNodesToXML <- function(doc){
  return(sapply(doc, function(x) ifelse(test = is.null(x),
                                        yes = "[]",
                                        no = XML::saveXML(x)))
         )
}

#' DownloadCWEData, it downloads https://cwe.mitre.org/data/xml/views/2000.xml.zip
#' that containts all kind of information related with CWE
#'
#' @param destfile, path where the file will be stored
#' @return XML path
#' @examples DownloadCWEData()
DownloadCWEData <- function(path = "inst/tmpdata") {
  destfile <- paste(path, "2000.xml.zip", sep = "/")
  download.file(url = "https://cwe.mitre.org/data/xml/views/2000.xml.zip",
                destfile = destfile)
  unzip(zipfile = destfile, exdir = path)
  return(paste(path, "2000.xml", sep = "/"))
}
