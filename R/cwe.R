LastDownloadCWEDate <- function(){
  return(Sys.Date())
}

GetCWEData <- function(savepath = tempdir()) {
  print("Downloading raw data...")
  DownloadCWEData(savepath)
  print("Unzip, extract, etc...")
  cwes.file <- ExtractCWEFiles(savepath)
  print("Processing MITRE raw data...")
  cwes <- ParseCWEData(cwes.file)
  # Sort and filter by WIP
  cwes <- cwes[c("code_standard", "Name", "Weakness_Abstraction", "Status",
                 "descr.summary", "descr.details", "ID", "cwe.parents",
                 "time.intro", "consequences", "exploits", "related.capec", "ordinalities",
                 "platforms", "aff.resources", "causal", "mitigation",  "demos",
                 "mapping", "history", "relationship.notes", "maintenance.notes",
                 "background", "introduction.mode", "other.notes", "functional.areas")]
  names(cwes) <- c("code_standard", "Name", "Weakness_Abstraction", "Status",
                   "descr.summary", "descr.details", "cwe.id", "cwe.parents.ids",
                   "time.intro", "consequences", "exploits", "related.capec", "ordinalities",
                   "platforms", "aff.resources", "causal", "mitigation",  "demos",
                   "mapping", "history", "relationship.notes", "maintenance.notes",
                   "background", "introduction.mode", "other.notes", "functional.areas")
  cwes <- cwes[,c("code_standard", "Name", "Weakness_Abstraction", "Status",
                  "descr.summary", "descr.details", "cwe.id", "cwe.parents.ids",
                  "time.intro", "consequences", "related.capec", "exploits", "ordinalities",
                  "platforms", "aff.resources", "causal", "mitigation")]
  print(paste("CWES data frame building process finished."))
  return(cwes)
}

DownloadCWEData <- function(savepath) {
  if (!dir.exists(paste(savepath, "cwe", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "cwe", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }
  cwe.url  <- "https://cwe.mitre.org/data/xml/views/2000.xml.zip"
  destfile <- paste(savepath, "cwe", "2000.xml.zip",sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::download.file(url = cwe.url, destfile = destfile)
}

ExtractCWEFiles <- function(savepath) {
  # Uncompress gzip XML files
  cwes.zip <- paste(savepath, "cwe", "2000.xml.zip", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  cwes.xml <- paste(savepath, "cwe", "2000.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::unzip(zipfile = cwes.zip, exdir = cwes.xml)
  cwes.xml <- paste(cwes.xml, "2000.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  return(cwes.xml)
}

ParseCWEData <- function(cwes.file) {

  doc <- XML::xmlParse(cwes.file)
  raw.cwes <- XML::xpathApply(doc, "//Weakness")
  cwes <- as.data.frame(t(XML::xmlSApply(raw.cwes, XML::xmlAttrs)),
                        stringsAsFactors = FALSE)
  cwes$code_standard <- paste("CWE-", cwes$ID, sep = "")
  cwes.basic <- XML::xmlToDataFrame(raw.cwes)
  cwes$Status <- as.factor(XML::xpathSApply(doc, "//Weakness/@Status"))
  cwes$Weakness_Abstraction <- as.factor(XML::xpathSApply(doc, "//Weakness/@Weakness_Abstraction"))

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
  cwes$ordinalities <- OrdinalitiesNodesToJson(raw.cwes.ord)

  #Applicable_Platforms
  cwes$platforms <- stringr::str_wrap(cwes.basic$Applicable_Platforms)
  cwes$platforms[is.na(cwes$platforms)] <- ""
  cwes$platforms[nchar(cwes$platforms) == 0] <- NA

  #Time_of_Introduction
  raw.cwes.toi <- GetListNodes(raw.cwes, "Time_of_Introduction")
  cwes$time.intro <- TimeIntroNodesToJson(raw.cwes.toi)

  #Common_Consequences
  raw.cwes.cc <- GetListNodes(raw.cwes, "Common_Consequences")
  cwes$consequences <- CommonConsequencesNodesToJSON(raw.cwes.cc)

  #Potential_Mitigations
  raw.cwes.mitigation <- GetListNodes(raw.cwes, "Potential_Mitigations")
  cwes$mitigation <- MitigationNodesToJSON(raw.cwes.mitigation)

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
  cwes$introduction.mode <- ModeIntroductionNodesToJson(raw.cwes.mintro)

  #Other_Notes
  raw.cwes.other <- GetListNodes(raw.cwes, "Other_Notes")
  cwes$other.notes <- ListNodesToJson(raw.cwes.other)

  #References

  #Related_Attack_Patterns
  raw.cwes.capec <- GetListNodes(raw.cwes, "Related_Attack_Patterns")
  cwes$related.capec <- RelatedAttackPatternsNodesToJson(raw.cwes.capec)

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

RelatedAttackPatternsNodesToJson <- function(doc){
  CAPEC2JSON <- function(xml.capec) {
    capec <- xml.capec
    lcapec <- XML::getNodeSet(xml.capec, "Related_Attack_Pattern")
    lcapec <- sapply(lcapec, XML::xmlValue)
    # lcapec <- paste("CAPEC", lcapec, sep = "-")
    capec <- jsonlite::toJSON(lcapec)
    return(capec)
  }
  x <- sapply(doc, function(x) ifelse(test = is.null(x),
                                      yes = "[]",
                                      no = CAPEC2JSON(x)))
  return(x)

}

MitigationNodesToJSON <- function(doc){
  GetMitigation <- function(miti) {
    phase <- XML::getNodeSet(miti, "Mitigation_Phase")
    if (length(phase) > 0) {
      phase <- stringr::str_wrap(sapply(phase, XML::xmlValue))
    } else {
      phase <- ""
    }
    strat <- XML::getNodeSet(miti, "Mitigation_Strategy")
    if (length(strat) > 0) {
      strat <- stringr::str_wrap(sapply(strat, XML::xmlValue))
    } else {
      strat <- ""
    }
    descr <- XML::getNodeSet(miti, "Mitigation_Description")
    if (length(descr) > 0) {
      descr <- stringr::str_wrap(sapply(descr, XML::xmlValue))
      descr <- stringr::str_replace_all(descr, "\n", "")
    } else {
      descr <- ""
    }
    effec <- XML::getNodeSet(miti, "Mitigation_Effectiveness")
    if (length(effec) > 0) {
      effec <- stringr::str_wrap(sapply(effec, XML::xmlValue))
    } else {
      effec <- ""
    }
    effec.notes <- XML::getNodeSet(miti, "Mitigation_Effectiveness_Notes")
    if (length(effec.notes) > 0) {
      effec.notes <- stringr::str_wrap(sapply(effec.notes, XML::xmlValue))
      effec.notes <- stringr::str_replace_all(effec.notes, "\n", "")
    } else {
      effec.notes <- ""
    }
    miti <- list(phase = phase, strategy = strat, description = descr,
                 eff.value = effec, eff.notes = effec.notes)
    return(miti)
  }

  Miti2JSON <- function(xml.mitis) {
    miti <- xml.mitis
    lmiti <- XML::getNodeSet(xml.mitis, "Mitigation")
    lmiti <- lapply(lmiti, GetMitigation)
    miti <- jsonlite::toJSON(lmiti)
    return(miti)
  }
  x <- sapply(doc, function(x) ifelse(test = is.null(x),
                                      yes = "[]",
                                      no = Miti2JSON(x)))
  return(x)
}

CommonConsequencesNodesToJSON <- function(doc){
  GetConsequence <- function(cons) {
    scope <- XML::getNodeSet(cons, "Consequence_Scope")
    if (length(scope) > 0) {
      scope <- stringr::str_wrap(sapply(scope, XML::xmlValue))
    } else {
      scope <- ""
    }
    impact <- XML::getNodeSet(cons, "Consequence_Technical_Impact")
    if (length(impact) > 0) {
      impact <- stringr::str_wrap(sapply(impact, XML::xmlValue))
    } else {
      impact <- ""
    }
    note <- XML::getNodeSet(cons, "Consequence_Note")
    if (length(note) > 0) {
      note <- stringr::str_wrap(sapply(note, XML::xmlValue))
      note <- stringr::str_replace_all(note, "\n", "")
    } else {
      note <- ""
    }
    cons <- list(scope = scope, impact = impact, note = note)
    return(cons)
  }
  Cons2JSON <- function(xml.conss) {
    cons <- xml.conss
    lcons <- XML::getNodeSet(xml.conss, "Common_Consequence")
    lcons <- lapply(lcons, GetConsequence)
    cons <- jsonlite::toJSON(lcons)
    return(cons)
  }
  x <- sapply(doc, function(x) ifelse(test = is.null(x),
                                      yes = "[]",
                                      no = Cons2JSON(x)))
  return(x)
}

ModeIntroductionNodesToJson <- function(doc){
  Time2JSON <- function(x){
    return(jsonlite::toJSON(stringr::str_wrap(as.character(x$Text))))
  }
  x <- sapply(doc, function(x) ifelse(test = is.null(x),
                                      yes = "[]",
                                      no = Time2JSON(XML::xmlToDataFrame(x)))
  )
  return(x)
}

TimeIntroNodesToJson <- function(doc){
  Time2JSON <- function(x){
    return(jsonlite::toJSON(as.character(x$text)))
  }
  x <- sapply(doc, function(x) ifelse(test = is.null(x),
                                        yes = "[]",
                                        no = Time2JSON(XML::xmlToDataFrame(x)))
  )
  return(x)
}

OrdinalitiesNodesToJson <- function(doc) {
  Ord2JSON <- function(x) {
    if ((nrow(x) >= 1) && (ncol(x) == 1)) {
      ord <- as.character(x$Ordinality)
    } else {
      ord <- paste(x$Ordinality, ": ",
                   stringr::str_wrap(x$Ordinality_Description),sep = "")
    }
    return(jsonlite::toJSON(ord))
  }
  x <- sapply(doc, function(x) ifelse(test = is.null(x),
                                      yes = "[]",
                                      no = Ord2JSON(XML::xmlToDataFrame(x))))
  return(x)
}

GetParents <- function(cwes, CWE = "", compact = FALSE) {
  # Workaround for non standard evaluation
  # http://stackoverflow.com/questions/9439256/how-can-i-handle-r-cmd-check-no-visible-binding-for-global-variable-notes-when
  ID <- NULL
  Relationship_Target_Form <- NULL
  Relationship_Nature <- NULL
  Relationship_Target_ID <- NULL

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
