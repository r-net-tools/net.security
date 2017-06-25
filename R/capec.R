#### References: https://capec.mitre.org/data/index.html

GetCAPECData <- function(savepath = tempdir()) {
  DownloadCAPECData(savepath)
  capec <- data.frame()
  capec.source.file <- paste(savepath, "capec", "capec_v2.10.xml",
                             sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  doc <- XML::xmlParse(capec.source.file)
  # capec.views <- ParseCAPECData.views(doc)
  # capec.categories <- ParseCAPECData.categories(doc)
  capec.attacks <- ParseCAPECData.attacks(doc)

  # capec <- list(views = capec.views,
  #               categories = capec.categories,
  #               attacks = capec.attacks)
  print(paste("CAPEC data frame building process finished."))
  return(capec.attacks)
}

#### Private Functions -----------------------------------------------------------------------------

DownloadCAPECData <- function(savepath) {
  if (!dir.exists(paste(savepath, "capec", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "capec", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }
  capec.url  <- "https://capec.mitre.org/data/xml/capec_v2.10.xml"
  destfile <- paste(savepath, "capec", "capec_v2.10.xml",sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::download.file(url = capec.url, destfile = destfile)
}

ParseCAPECData.views <- function(doc) {
  # TODO
  raw.capec.views <- XML::xpathApply(doc, "//capec:View")
  # View IDs
  view.id <- sapply(XML::getNodeSet(doc, "//capec:View/@ID"), function(x) x[1])
  # View Names
  view.name <- sapply(XML::getNodeSet(doc, "//capec:View/@Name"), function(x) x[1])
  # Category Status
  view.status <- sapply(XML::getNodeSet(doc, "//capec:View/@Status"), function(x) x[1])
  # View objective
  view.objective <- sapply(XML::getNodeSet(doc, "//capec:View/capec:View_Objective", fun = XML::xmlValue), function(x) x[1])
  # Category Parent Views
  targets <- XMLChildren2JSON(doc, "capec:View", view.id,
                              "/capec:Relationships/capec:Relationship/capec:Relationship_Target_ID")

  views <- data.frame(stringsAsFactors = FALSE)
  views <- data.frame(id = view.id,
                      name = view.name,
                      status = view.status,
                      objective = view.objective,
                      targets = targets,
                      stringsAsFactors = FALSE
  )
  return(views)
}

ParseCAPECData.categories <- function(doc) {

  raw.capec.cates <- XML::xmlToDataFrame(XML::xpathApply(doc, "//capec:Category"))

  # Category IDs
  cat.id = sapply(XML::getNodeSet(doc, "//capec:Category/@ID"), function(x) x[1])
  # Category Names
  cat.name = sapply(XML::getNodeSet(doc, "//capec:Category/@Name"), function(x) x[1])
  # Category Status
  cat.status = sapply(XML::getNodeSet(doc, "//capec:Category/@Status"), function(x) x[1])
  # Category Parent Views
  parents <- XMLChildren2JSON(doc, "capec:Category", cat.id,
                              "/capec:Relationships/capec:Relationship/capec:Relationship_Views/capec:Relationship_View_ID")

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


ParseCAPECData.attacks <- function(doc) {
  raw.capec.atcks <- XML::xmlToDataFrame(XML::xpathApply(doc, "//capec:Attack_Pattern"))

  # Attack IDs
  att.id = as.character(sapply(XML::getNodeSet(doc, "//capec:Attack_Pattern/@ID"), function(x) x[1]))
  # Attack Names
  att.name = as.character(sapply(XML::getNodeSet(doc, "//capec:Attack_Pattern/@Name"), function(x) x[1]))
  # Attack Status
  att.status = as.factor(sapply(XML::getNodeSet(doc, "//capec:Attack_Pattern/@Status"), function(x) x[1]))
  # Attack Pattern_Abstraction
  att.pattern.abstraction = as.factor(sapply(XML::getNodeSet(doc, "//capec:Attack_Pattern/@Pattern_Abstraction"), function(x) x[1]))
  # Attack Pattern_Completeness
  att.pattern.completeness = as.factor(sapply(XML::getNodeSet(doc, "//capec:Attack_Pattern/@Pattern_Completeness"), function(x) x[1]))
  # Attack Methods
  att.method <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Methods_of_Attack/capec:Method_of_Attack")
  # Attacker Skills
  att.acker.skills.lvl <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id,
                                       "/capec:Attacker_Skills_or_Knowledge_Required/capec:Attacker_Skill_or_Knowledge_Required/capec:Skill_or_Knowledge_Level")
  att.acker.skills.type <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id,
                                           "/capec:Attacker_Skills_or_Knowledge_Required/capec:Attacker_Skill_or_Knowledge_Required/capec:Skill_or_Knowledge_Type")
  # Resources Required
  att.requirements.resources <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Resources_Required/capec:Text")
  # Probing Techniques
  att.probing.techniques <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Probing_Techniques/capec:Probing_Technique/capec:Description")
  # Solutions and Mitigations
  att.solutions.mitigations <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Solutions_and_Mitigations/capec:Solution_or_Mitigation/capec:Text")
  # Attack Motivation and Consequences
  att.motivation.consquences <- GetConsequences(doc, att.id)
  # Injection Vector
  att.inject.vect <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Injection_Vector/capec:Text")
  # Payload
  att.payload <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Payload/capec:Text")
  # Activation_Zone
  att.act.zone <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Activation_Zone/capec:Text")
  # Related CWEs
  att.cwes <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID")
  # Related CVEs
  att.cves <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Related_Vulnerabilities/capec:Related_Vulnerability/capec:Vulnerability_ID")
  # Relevant Security Requirements
  att.sec.req <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Relevant_Security_Requirements/capec:Relevant_Security_Requirement/capec:Text")
  # Related Security Principles
  att.sec.pples <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Related_Security_Principles/capec:Related_Security_Principle/capec:Text")
  # Related guidelines
  att.guidelines <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Related_Guidelines/capec:Related_Guideline/capec:Text")
  # Purposes
  att.purposes <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Purposes/capec:Purpose")
  # IMPACT
  att.impact.conf <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:CIA_Impact/capec:Confidentiality_Impact")
  att.impact.inte <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:CIA_Impact/capec:Integrity_Impact")
  att.impact.avai <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:CIA_Impact/capec:Availability_Impact")
  # Technical Context
  att.architectural.ctxt <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Technical_Context/capec:Architectural_Paradigms/capec:Architectural_Paradigm")
  att.frameworks.ctxt <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Technical_Context/capec:Frameworks/capec:Framework")
  att.platforms.ctxt <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Technical_Context/capec:Platforms/capec:Platform")
  att.languages.ctxt <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Technical_Context/capec:Languages/capec:Language")
  # Obfuscation Techniques
  att.obfuscation <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Obfuscation_Techniques/capec:Obfuscation_Technique/capec:Description/capec:Text")
  # Indicators-Warnings_of_Attack
  att.indicators.of.attack <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Indicators-Warnings_of_Attack/capec:Indicator-Warning_of_Attack/capec:Description/capec:Text")

  # Attacks Data Frame
  attacks <- data.frame(id = att.id,
                        name = att.name,
                        status = att.status,
                        pattern.abstraction = att.pattern.abstraction,
                        pattern.completeness = att.pattern.completeness,
                        description = raw.capec.atcks$Description,
                        prerequisites = raw.capec.atcks$Attack_Prerequisites,
                        severeity = as.factor(raw.capec.atcks$Typical_Severity),
                        exploit.likehood = as.factor(raw.capec.atcks$Typical_Likelihood_of_Exploit),
                        attack.method = att.method,
                        attacker.skills.level = att.acker.skills.lvl,
                        attacker.skills.type = att.acker.skills.type,
                        resources.required = att.requirements.resources,
                        probing.techniques = att.probing.techniques,
                        solutions.mitigations = att.solutions.mitigations,
                        motivation.consequences = att.motivation.consquences,
                        injection.vector = att.inject.vect,
                        payload = att.payload,
                        activation.zone = att.act.zone,
                        related.cwes = att.cwes,
                        related.cves = att.cves,
                        related.security.principles = att.sec.pples,
                        related.guidelines = att.guidelines,
                        security.requirements = att.sec.req,
                        purposes = att.purposes,
                        impact.confidentiality = att.impact.conf,
                        impact.integrity = att.impact.inte,
                        impact.availability = att.impact.avai,
                        context.architecture = att.architectural.ctxt,
                        context.framework = att.frameworks.ctxt,
                        context.platform = att.platforms.ctxt,
                        context.language = att.languages.ctxt,
                        obfuscation.techniques = att.obfuscation,
                        attack.warnings = att.indicators.of.attack,

                        stringsAsFactors = FALSE)
  return(attacks)
}

# Private functions about CAPEC Parser Helpers ---------------------------------
GetConsequence <- function(x) {
  cons <- data.frame(consequence.scope = as.character(jsonlite::toJSON(as.character(XML::xmlToList(x)[grep("Consequence_Scope", names(XML::xmlToList(x)))]))),
                     consequence.impact = as.character(jsonlite::toJSON(as.character(XML::xmlToList(x)[grep("Consequence_Technical_Impact", names(XML::xmlToList(x)))]))),
                     consequence.notes = as.character(jsonlite::toJSON(XML::xmlToList(x)[grep("Consequence_Note", names(XML::xmlToList(x)))]$Consequence_Note)),
                     stringsAsFactors = FALSE)
  return(cons)
}

GetConsequences <- function(doc, att.id) {
  cons <- sapply(att.id,
                 function(x)
                   as.character(jsonlite::toJSON(dplyr::bind_rows(lapply(XML::getNodeSet(doc,
                                                                            paste("//capec:Attack_Pattern[@ID='", x,
                                                                                  "']/capec:Attack_Motivation-Consequences/capec:Attack_Motivation-Consequence",
                                                                                  sep = "")),
                                                            GetConsequence))
                   ))
  )
  names(cons) <- NULL
  return(cons)
}

# Private functions about data manipulation  -----------------------------------

XMLChildren2JSON <- function(doc, xpath.root, root.id, xpath.children, json = TRUE) {
  childs     <- sapply(root.id,
                       function(x)
                         unique(as.character(sapply(XML::getNodeSet(
                           doc,
                           paste("//",xpath.root,"[@ID='", x,
                                 "']",xpath.children,
                                 sep = "")
                         ),
                         XML::xmlValue))
                         )
  )
  names(childs) <- NULL
  if (json) childs <- sapply(childs, jsonlite::toJSON)
  return(childs)
}
