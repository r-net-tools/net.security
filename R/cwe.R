#### Exported Functions ----------------------------------------------------------------------------

#' Get data frame with CWE information
#'
#' @return data frame
#' @export
GetCWEData <- function() {
  DownloadCWEData(dest = tempdir())

  utils::unzip(zipfile = "cwe/2000.xml.zip", exdir = "cwe")
  cwe.source.file <- paste(tempdir(), "cwe", "2000.xml",
                           sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  cwes <- ParseCWEData(cwe.source.file)
  return(cwes)
}


#### Private Functions -----------------------------------------------------------------------------

#' Download CWE information
#'
#' @param dest String
DownloadCWEData <- function(dest) {
  curdir <- setwd(dest)
  if (!dir.exists("cwe")) {
    dir.create("cwe")
  }
  cwe.url  <- "https://cwe.mitre.org/data/xml/views/2000.xml.zip"
  destfile <- paste("cwe", "2000.xml",
                    sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::download.file(url = cwe.url, destfile = destfile)
  setwd(curdir)
}

#' Arrange CWE information into data frame
#'
#' @param cwe.file String
#'
#' @return Data frame
ParseCWEData <- function(cwe.file) {

  doc <- XML::xmlParse(cwe.file)
  raw.cwes <- XML::xpathApply(doc, "//Weakness")
  cwes <- as.data.frame(t(XML::xmlSApply(raw.cwes, XML::xmlAttrs)),
                        stringsAsFactors = FALSE)
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
  cwes$cwe.parents <- sapply(cwes$ID, function(x) GetParents(cwes, x, compact = T))

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
  cwes$aff.resources <- cwes.basic$Affected_Resources

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

######## Functions helpers for data parsing -------------------------------------------
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

#' Get parents from a given CWE
#' Given a CWE code, returns its direct parents.set compact=T and results will be semicolon-separated
#'
#' @param cwes data frame
#' @param CWE number
#' @param compact boolean
GetParents <- function(cwes, CWE = "", compact = FALSE) {
  parents <- ""
  relations <- jsonlite::fromJSON(dplyr::filter(cwes, ID == CWE)[["relationships"]])
  if (length(relations) > 0) {
    filtered <- dplyr::filter(relations,
                              Relationship_Target_Form == "Weakness" & Relationship_Nature == "ChildOf")
    x <- dplyr::select(filtered, Relationship_Target_ID)
    # x <- dplyr::filter(relations, Relationship_Target_Form == "Weakness" & Relationship_Nature == "ChildOf") %>% dplyr::select(Relationship_Target_ID)
    if (nrow(x) > 0) {
      parents <- x[,c("Relationship_Target_ID")]
    }
  }
  if (compact) {
    parents <- paste(parents, sep = ";", collapse = ";")
  }
  return(parents)
}
