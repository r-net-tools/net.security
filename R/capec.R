#### References: https://capec.mitre.org/data/index.html

GetCAPECData <- function(savepath = tempdir(), verbose = TRUE) {
  if (verbose) print("Downloading CAPEC raw data...")

  DownloadCAPECData(savepath)
  if (verbose) print("Indexing CAPEC XML data...")
  capec <- data.frame()
  capec.source.file <- paste(savepath, "capec", "capec_v2.10.xml",
                             sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))

  doc <- xml2::read_xml(capec.source.file)

  if (verbose) print("Parsing CAPEC Views...")
  capec.views <- ParseCAPECData.views(doc)
  if (verbose) print("Parsing CAPEC Categories...")
  capec.categories <- ParseCAPECData.categories(doc)
  if (verbose) print("Parsing CAPEC Attacks...")
  capec.attacks <- ParseCAPECData.attacks(doc, verbose)

  # TODO: Unify data.frames
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
  raw.capec.views <- rvest::xml_nodes(doc, xpath = "//capec:View")
  view.id <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:View/@ID"))
  view.name <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:View/@Name"))
  view.status <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:View/@Status"))
  view.objective <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:View/capec:View_Objective"))
  # TODO: Improve realitonship using capec:View_Filter node as xpath to find related IDs
  view.relationship <- sapply(raw.capec.views, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Relationships/capec:Relationship/capec:Relationship_Target_ID"))))
  views <- data.frame(stringsAsFactors = FALSE)
  views <- data.frame(id = view.id,
                      name = view.name,
                      status = view.status,
                      objective = view.objective,
                      view.relationship = view.relationship,
                      stringsAsFactors = FALSE
  )
  return(views)
}

ParseCAPECData.categories <- function(doc) {
  raw.capec.cats <- rvest::xml_nodes(doc, xpath = "//capec:Category")
  cat.id <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Category/@ID"))
  cat.name <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Category/@Name"))
  cat.status <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Category/@Status"))
  cat.descr <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Category/capec:Description"))
  cat.related.cwes <- sapply(raw.capec.cats, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID"))))
  cat.attack.prerequisites <- sapply(raw.capec.cats, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Attack_Prerequisites/capec:Attack_Prerequisite/capec:Text"))))
  cat.resources.required <- sapply(raw.capec.cats, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Resources_Required/capec:Text"))))
  cat.relationship <- sapply(raw.capec.cats, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Relationships/capec:Relationship/capec:Relationship_Target_ID"))))
  categories <- data.frame(id = cat.id,
                           name = cat.name,
                           status = cat.status,
                           description = cat.descr,
                           related.cwes = cat.related.cwes,
                           attack.prerequisites = cat.attack.prerequisites,
                           resources.required = cat.resources.required,
                           relationship = cat.relationship,
                           stringsAsFactors = FALSE
  )
  return(categories)
}

ParseCAPECData.attacks <- function(doc, verbose = TRUE) {
  i <- 1
  if (verbose) pb <- utils::txtProgressBar(min = 0, max = 28, style = 3, title = "CAPEC data")
  if (verbose) print("Parsing Attacks basic attributes ...")
  raw.capec.atcks <- rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern")
  att.id <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern/@ID"))
  att.name <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern/@Name"))
  att.status <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern/@Status"))
  att.pattern.abstraction <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern/@Pattern_Abstraction"))
  att.pattern.completeness <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern/@Pattern_Completeness"))
  att.descr <- sapply(raw.capec.atcks, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Description/capec:Summary"))))
  if (verbose) print("Parsing attacks prerequisites ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.attack.prerequisites <- sapply(raw.capec.atcks, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Attack_Prerequisites/capec:Attack_Prerequisite/capec:Text"))))
  if (verbose) print("Parsing attacks severity ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.severity <- sapply(raw.capec.atcks,
                         function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Severity")), character(0)),
                                             yes = "",
                                             no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Severity")))})
  if (verbose) print("Parsing exploitability info ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.likelihood.exploit <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Likelihood_of_Exploit/capec:Likelihood")), character(0)),
                                                       yes = "",
                                                       no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Likelihood_of_Exploit/capec:Likelihood")))})
  att.likelihood.exploit.descr <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Likelihood_of_Exploit/capec:Explanation")), character(0)),
                                                       yes = "",
                                                       no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Likelihood_of_Exploit/capec:Explanation")))})
  if (verbose) print("Parsing methods of attack and cve examples ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.methods.of.attack <- sapply(raw.capec.atcks, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Methods_of_Attack/capec:Method_of_Attack"))))
  att.examples.cves <- sapply(raw.capec.atcks,
                              function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Examples-Instances/capec:Example-Instance/capec:Example-Instance_Related_Vulnerabilities")), character(0)),
                                                  yes = "[]",
                                                  no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Examples-Instances/capec:Example-Instance/capec:Example-Instance_Related_Vulnerabilities"))))})
  if (verbose) print("Parsing hacking skills and resources required ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.hack.skills <- sapply(raw.capec.atcks,
                            function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Attacker_Skills_or_Knowledge_Required/capec:Attacker_Skill_or_Knowledge_Required")), character(0)),
                                                yes = "[]",
                                                no = RJSONIO::toJSON(xml2::as_list(rvest::html_nodes(x, xpath = "capec:Attacker_Skills_or_Knowledge_Required/capec:Attacker_Skill_or_Knowledge_Required"))))})
  att.resources.required <- sapply(raw.capec.atcks, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Resources_Required/capec:Text"))))
  if (verbose) print("Parsing proving and obfuscation techniques, also indicators of attack ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.proving.techniques <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Probing_Techniques/capec:Probing_Technique")), character(0)),
                                                       yes = "[]",
                                                       no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Probing_Techniques/capec:Probing_Technique"))))})
  att.indicators.warnings.of.Attack <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Indicators-Warnings_of_Attack/capec:Indicator-Warning_of_Attack")), character(0)),
                                                       yes = "[]",
                                                       no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Indicators-Warnings_of_Attack/capec:Indicator-Warning_of_Attack"))))})
  att.obfuscation.techniques <- sapply(raw.capec.atcks,
                                              function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Obfuscation_Techniques/capec:Obfuscation_Technique")), character(0)),
                                                                  yes = "[]",
                                                                  no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Obfuscation_Techniques/capec:Obfuscation_Technique"))))})
  if (verbose) print("Parsing solutions and mitigations ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.solutions.mitigations <- sapply(raw.capec.atcks,
                                       function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Solutions_and_Mitigations/capec:Solution_or_Mitigation")), character(0)),
                                                           yes = "",
                                                           no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Solutions_and_Mitigations/capec:Solution_or_Mitigation"))))})
  if (verbose) print("Parsing motivation consequences ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.attack.motivation.consequences <- sapply(raw.capec.atcks,
                                      function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Attack_Motivation-Consequences/capec:Attack_Motivation-Consequence")), character(0)),
                                                          yes = "[]",
                                                          no = {
                                                              RJSONIO::toJSON(lapply(rvest::html_nodes(x, xpath = "capec:Attack_Motivation-Consequences/capec:Attack_Motivation-Consequence"),
                                                                                   function(y) {
                                                                                     con <- list(
                                                                                       scope = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Consequence_Scope")),
                                                                                       impact = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Consequence_Technical_Impact")),
                                                                                       note = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Consequence_Note"))
                                                                                     )
                                                                                     con <- con[sapply(con, function(x) !identical(x, character(0)))]
                                                                                     con
                                                                                   }))
                                                          })})
  if (verbose) print("Parsing injection vector, activation zone and payload info ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.injection.vector <- sapply(raw.capec.atcks,
                                       function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Injection_Vector/capec:Text")), character(0)),
                                                           yes = "[]",
                                                           no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Injection_Vector/capec:Text"))))})
  att.payload <- sapply(raw.capec.atcks,
                                 function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Payload/capec:Text")), character(0)),
                                                     yes = "[]",
                                                     no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Payload/capec:Text"))))})
  att.activation.zone <- sapply(raw.capec.atcks,
                        function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Activation_Zone/capec:Text")), character(0)),
                                            yes = "[]",
                                            no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Activation_Zone/capec:Text"))))})
  att.payload.activation.impact <- sapply(raw.capec.atcks,
                                function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Payload_Activation_Impact/capec:Description/capec:Text")), character(0)),
                                                    yes = "[]",
                                                    no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Payload_Activation_Impact/capec:Description/capec:Text"))))})
  if (verbose) print("Parsing related CWE, CVE, CAPEC and other standards ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.related.cwe.target <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID")), character(0)),
                                                       yes = "[]",
                                                       no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID[../capec:Weakness_Relationship_Type/text() = 'Targeted']/text()"))))})
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.related.cwe.second <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID")), character(0)),
                                                       yes = "[]",
                                                       no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID[../capec:Weakness_Relationship_Type/text() = 'Secondary']/text()"))))})
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.related.cves <- sapply(raw.capec.atcks,
                             function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Vulnerabilities/capec:Related_Vulnerability")), character(0)),
                                                 yes = "[]",
                                                 no = {
                                                   RJSONIO::toJSON(
                                                     lapply(
                                                       rvest::html_nodes(x, xpath = "capec:Related_Vulnerabilities/capec:Related_Vulnerability"),
                                                       function(y) {
                                                         vulns <- rvest::html_text(rvest::xml_nodes(y, xpath = "capec:Vulnerability_Description/capec:Text"))
                                                         if (identical(vulns, character(0))) vulns <- ""
                                                         names(vulns) <- rvest::html_text(rvest::xml_nodes(y, xpath = "capec:Vulnerability_ID"))
                                                         vulns
                                                       }
                                                     )
                                                   )
                                                 }
                             )
                             }
  )
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.related.capec <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Attack_Patterns/capec:Related_Attack_Pattern")), character(0)),
                                                       yes = "[]",
                                                       no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Attack_Patterns/capec:Related_Attack_Pattern/capec:Relationship_Target_ID"))))})
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.related.attack.patterns <- sapply(raw.capec.atcks,
                                               function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Attack_Patterns/capec:Related_Attack_Pattern")), character(0)),
                                                                   yes = "[]",
                                                                   no = {
                                                                     RJSONIO::toJSON(lapply(rvest::html_nodes(x, xpath = "capec:Related_Attack_Patterns/capec:Related_Attack_Pattern"),
                                                                                            function(y) {
                                                                                              con <- list(
                                                                                                related.view = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Relationship_Views/capec:Relationship_View_ID")),
                                                                                                target.form = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Relationship_Target_Form")),
                                                                                                nature = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Relationship_Nature")),
                                                                                                target.id = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Relationship_Target_ID"))
                                                                                              )
                                                                                            }))
                                                                   })})
  if (verbose) print("Parsing security requirements, principles and guidelines ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.relevant.security.requirements <- sapply(raw.capec.atcks,
                              function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Relevant_Security_Requirements/capec:Relevant_Security_Requirement/capec:Text")), character(0)),
                                                  yes = "[]",
                                                  no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Relevant_Security_Requirements/capec:Relevant_Security_Requirement/capec:Text"))))})
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.related.security.principles <- sapply(raw.capec.atcks,
                                               function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Security_Principles/capec:Related_Security_Principle/capec:Text")), character(0)),
                                                                   yes = "[]",
                                                                   no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Security_Principles/capec:Related_Security_Principle/capec:Text"))))})
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.related.guidelines <- sapply(raw.capec.atcks,
                                            function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Guidelines/capec:Related_Guideline/capec:Text")), character(0)),
                                                                yes = "[]",
                                                                no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Guidelines/capec:Related_Guideline/capec:Text"))))})
  if (verbose) print("Parsing purposes ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.purposes <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Purposes/capec:Purpose")), character(0)),
                                                       yes = "[]",
                                                       no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Purposes/capec:Purpose"))))})
  if (verbose) print("Parsing impact CIA values ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.impact.confidentiality <- sapply(raw.capec.atcks,
                         function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Confidentiality_Impact")), character(0)),
                                             yes = "",
                                             no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Confidentiality_Impact")))})
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.impact.integrity <- sapply(raw.capec.atcks,
                                       function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Integrity_Impact")), character(0)),
                                                           yes = "",
                                                           no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Integrity_Impact")))})
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.impact.availability <- sapply(raw.capec.atcks,
                                       function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Availability_Impact")), character(0)),
                                                           yes = "",
                                                           no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Availability_Impact")))})
  if (verbose) print("Parsing context technical architectures, frameworks, platforms and languages ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.tech.architectural.paradigms <- sapply(raw.capec.atcks,
                                            function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Architectural_Paradigms/capec:Architectural_Paradigm")), character(0)),
                                                                yes = "[]",
                                                                no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Architectural_Paradigms/capec:Architectural_Paradigm"))))})
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.tech.frameworks <- sapply(raw.capec.atcks,
                                             function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Frameworks/capec:Framework")), character(0)),
                                                                 yes = "[]",
                                                                 no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Frameworks/capec:Framework"))))})
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.tech.platforms <- sapply(raw.capec.atcks,
                                function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Platforms/capec:Platform")), character(0)),
                                                    yes = "[]",
                                                    no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Platforms/capec:Platform"))))})
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.tech.languages <- sapply(raw.capec.atcks,
                               function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Languages/capec:Language")), character(0)),
                                                   yes = "[]",
                                                   no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Languages/capec:Language"))))})
  if (verbose) print("Parsing references, books, links ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  att.references <- sapply(raw.capec.atcks,
                           function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Attack_Patterns/capec:Related_Attack_Pattern")), character(0)),
                                               yes = "[]",
                                               no = {
                                                 RJSONIO::toJSON(lapply(rvest::html_nodes(x, xpath = "capec:References/capec:Reference"),
                                                                        function(y) {
                                                                          con <- list(
                                                                            author = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Reference_Author")),
                                                                            title = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Reference_Title")),
                                                                            section = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Reference_Section")),
                                                                            edition = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Reference_Edition")),
                                                                            publication = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Reference_Publication")),
                                                                            publisher = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Reference_Publisher")),
                                                                            date = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Reference_Date")),
                                                                            pubDate = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Reference_PubDate")),
                                                                            link = rvest::html_text(rvest::html_nodes(y, xpath = "capec:Reference_Link"))
                                                                          )
                                                                          con <- con[sapply(con, function(x) !identical(x, character(0)))]
                                                                          con
                                                                        }))
                                               })})
  if (verbose) print("Building attacks tidy data.frame ...")
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}

  # Attacks Data Frame
  attacks <- data.frame(id = att.id,
                        name = att.name,
                        status = as.factor(att.status),
                        pattern.abstraction = as.factor(att.pattern.abstraction),
                        pattern.completeness = as.factor(att.pattern.completeness),
                        descr = att.descr,
                        attack.prerequisites = att.attack.prerequisites,
                        severity = as.factor(att.severity),
                        likelihood.exploit = as.factor(att.likelihood.exploit),
                        likelihood.exploit.descr = att.likelihood.exploit.descr,
                        methods.of.attack = att.methods.of.attack,
                        examples.cves = att.examples.cves,
                        hack.skills = att.hack.skills,
                        resources.required = att.resources.required,
                        proving.techniques = att.proving.techniques,
                        indicators.warnings.of.Attack = att.indicators.warnings.of.Attack,
                        obfuscation.techniques = att.obfuscation.techniques,
                        solutions.mitigations = att.solutions.mitigations,
                        attack.motivation.consequences = att.attack.motivation.consequences,
                        injection.vector = att.injection.vector,
                        payload = att.payload,
                        activation.zone = att.activation.zone,
                        payload.activation.impact = att.payload.activation.impact,
                        related.cwe.target = att.related.cwe.target,
                        related.cwe.second = att.related.cwe.second,
                        related.cves = att.related.cves,
                        related.capec = att.related.capec,
                        related.attack.patterns = att.related.attack.patterns,
                        relevant.security.requirements = att.relevant.security.requirements,
                        related.security.principles = att.related.security.principles,
                        related.guidelines = att.related.guidelines,
                        purposes = att.purposes,
                        impact.confidentiality = as.factor(att.impact.confidentiality),
                        impact.integrity = as.factor(att.impact.integrity),
                        impact.availability = as.factor(att.impact.availability),
                        tech.architectural.paradigms = att.tech.architectural.paradigms,
                        tech.frameworks = att.tech.frameworks,
                        tech.platforms = att.tech.platforms,
                        tech.languages = att.tech.languages,
                        references = att.references,
                        stringsAsFactors = FALSE)
  if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}

  close(pb)
  return(attacks)
}
