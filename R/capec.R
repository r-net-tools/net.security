#### References: https://capec.mitre.org/data/index.html

GetCAPECData <- function(savepath = tempdir()) {
  DownloadCAPECData(savepath)
  capec <- data.frame()
  capec.source.file <- paste(savepath, "capec", "capec_v2.10.xml",
                             sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))

  doc <- xml2::read_xml(capec.source.file)

  capec.views <- ParseCAPECData.views(doc)
  capec.categories <- ParseCAPECData.categories(doc)
  capec.attacks <- ParseCAPECData.attacks(doc)

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

ParseCAPECData.attacks <- function(doc) {
  raw.capec.atcks <- rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern")
  att.id <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern/@ID"))
  att.name <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern/@Name"))
  att.status <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern/@Status"))
  att.pattern.abstraction <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern/@Pattern_Abstraction"))
  att.pattern.completeness <- rvest::html_text(rvest::xml_nodes(doc, xpath = "//capec:Attack_Pattern/@Pattern_Completeness"))
  att.descr <- sapply(raw.capec.atcks, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Description/capec:Summary"))))
  # TODO: Parse extended description using capec:Attack_Execution_Flow node as xpath
  att.attack.prerequisites <- sapply(raw.capec.atcks, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Attack_Prerequisites/capec:Attack_Prerequisite/capec:Text"))))
  att.severity <- sapply(raw.capec.atcks,
                         function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Severity")), character(0)),
                                             yes = "",
                                             no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Severity")))})
  att.likelihood.exploit <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Likelihood_of_Exploit/capec:Likelihood")), character(0)),
                                                       yes = "",
                                                       no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Likelihood_of_Exploit/capec:Likelihood")))})
  att.likelihood.exploit.descr <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Likelihood_of_Exploit/capec:Explanation")), character(0)),
                                                       yes = "",
                                                       no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:Typical_Likelihood_of_Exploit/capec:Explanation")))})
  att.methods.of.attack <- sapply(raw.capec.atcks, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Methods_of_Attack/capec:Method_of_Attack"))))
  att.examples.cves <- sapply(raw.capec.atcks,
                              function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Examples-Instances/capec:Example-Instance/capec:Example-Instance_Related_Vulnerabilities")), character(0)),
                                                  yes = "[]",
                                                  no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Examples-Instances/capec:Example-Instance/capec:Example-Instance_Related_Vulnerabilities"))))})
  att.hack.skills <- sapply(raw.capec.atcks,
                            function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Attacker_Skills_or_Knowledge_Required/capec:Attacker_Skill_or_Knowledge_Required")), character(0)),
                                                yes = "[]",
                                                no = RJSONIO::toJSON(xml2::as_list(rvest::html_nodes(x, xpath = "capec:Attacker_Skills_or_Knowledge_Required/capec:Attacker_Skill_or_Knowledge_Required"))))})
  att.resources.required <- sapply(raw.capec.atcks, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Resources_Required/capec:Text"))))
  att.relationship <- sapply(raw.capec.atcks, function(x) RJSONIO::toJSON(rvest::html_text(rvest::xml_nodes(x, xpath = "capec:Related_Attack_Patterns/capec:Related_Attack_Pattern/capec:Relationship_Target_ID"))))
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
  att.solutions.mitigations <- sapply(raw.capec.atcks,
                                       function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Solutions_and_Mitigations/capec:Solution_or_Mitigation")), character(0)),
                                                           yes = "",
                                                           no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Solutions_and_Mitigations/capec:Solution_or_Mitigation"))))})
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
                                                                                   }))
                                                          })})
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
  att.related.cwe.target <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID")), character(0)),
                                                       yes = "[]",
                                                       no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID[../capec:Weakness_Relationship_Type/text() = 'Targeted']/text()"))))})
  att.related.cwe.second <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID")), character(0)),
                                                       yes = "[]",
                                                       no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID[../capec:Weakness_Relationship_Type/text() = 'Secondary']/text()"))))})
  att.related.cves <- sapply(raw.capec.atcks,
                             function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Vulnerabilities/capec:Related_Vulnerability")), character(0)),
                                                 yes = "[]",
                                                 no = {
                                                   RJSONIO::toJSON(
                                                     lapply(
                                                       rvest::html_nodes(x, xpath = "capec:Related_Vulnerabilities/capec:Related_Vulnerability"),
                                                       function(y) {
                                                         vulns <- rvest::html_text(rvest::xml_nodes(y, xpath = "capec:Vulnerability_Description/capec:Text"))
                                                         names(vulns) <- rvest::html_text(rvest::xml_nodes(y, xpath = "capec:Vulnerability_ID"))
                                                         vulns
                                                       }
                                                     )
                                                   )
                                                 }
                             )
                             }
  )
  att.related.capec <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Attack_Patterns/capec:Related_Attack_Pattern")), character(0)),
                                                       yes = "[]",
                                                       no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Attack_Patterns/capec:Related_Attack_Pattern/capec:Relationship_Target_ID"))))})
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
  att.relevant.security.requirements <- sapply(raw.capec.atcks,
                              function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Relevant_Security_Requirements/capec:Relevant_Security_Requirement/capec:Text")), character(0)),
                                                  yes = "[]",
                                                  no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Relevant_Security_Requirements/capec:Relevant_Security_Requirement/capec:Text"))))})
  att.related.security.principles <- sapply(raw.capec.atcks,
                                               function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Security_Principles/capec:Related_Security_Principle/capec:Text")), character(0)),
                                                                   yes = "[]",
                                                                   no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Security_Principles/capec:Related_Security_Principle/capec:Text"))))})
  att.related.guidelines <- sapply(raw.capec.atcks,
                                            function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Guidelines/capec:Related_Guideline/capec:Text")), character(0)),
                                                                yes = "[]",
                                                                no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Related_Guidelines/capec:Related_Guideline/capec:Text"))))})
  att.purposes <- sapply(raw.capec.atcks,
                                   function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Purposes/capec:Purpose")), character(0)),
                                                       yes = "[]",
                                                       no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Purposes/capec:Purpose"))))})
  att.impact.confidentiality <- sapply(raw.capec.atcks,
                         function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Confidentiality_Impact")), character(0)),
                                             yes = "",
                                             no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Confidentiality_Impact")))})
  att.impact.integrity <- sapply(raw.capec.atcks,
                                       function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Integrity_Impact")), character(0)),
                                                           yes = "",
                                                           no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Integrity_Impact")))})
  att.impact.availability <- sapply(raw.capec.atcks,
                                       function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Availability_Impact")), character(0)),
                                                           yes = "",
                                                           no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Availability_Impact")))})
  att.impact.availability <- sapply(raw.capec.atcks,
                                    function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Availability_Impact")), character(0)),
                                                        yes = "",
                                                        no = rvest::html_text(rvest::html_nodes(x, xpath = "capec:CIA_Impact/capec:Availability_Impact")))})
  att.tech.architectural.paradigms <- sapply(raw.capec.atcks,
                                            function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Architectural_Paradigms/capec:Architectural_Paradigm")), character(0)),
                                                                yes = "[]",
                                                                no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Architectural_Paradigms/capec:Architectural_Paradigm"))))})
  att.tech.frameworks <- sapply(raw.capec.atcks,
                                             function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Frameworks/capec:Framework")), character(0)),
                                                                 yes = "[]",
                                                                 no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Frameworks/capec:Framework"))))})
  att.tech.platforms <- sapply(raw.capec.atcks,
                                function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Platforms/capec:Platform")), character(0)),
                                                    yes = "[]",
                                                    no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Platforms/capec:Platform"))))})
  att.tech.languages <- sapply(raw.capec.atcks,
                               function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Languages/capec:Language")), character(0)),
                                                   yes = "[]",
                                                   no = RJSONIO::toJSON(rvest::html_text(rvest::html_nodes(x, xpath = "capec:Technical_Context/capec:Languages/capec:Language"))))})
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






  # Attacks Data Frame
  attacks <- data.frame(id = att.id,
                        name = att.name,
                        status = att.status,
                        pattern.abstraction = att.pattern.abstraction,
                        pattern.completeness = att.pattern.completeness,
                        description = att.descr,
                        prerequisites = raw.capec.atcks$Attack_Prerequisites,
                        severeity = as.factor(raw.capec.atcks$Typical_Severity),
                        exploit.likehood = as.factor(raw.capec.atcks$Typical_Likelihood_of_Exploit),
                        exploit.likehood.descr = att.likelihood.exploit.descr,
                        attack.method = att.method,
                        attacker.skills = att.hack.skills,
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

  # # Attack IDs
  # att.id = as.character(sapply(XML::getNodeSet(doc, "//capec:Attack_Pattern/@ID"), function(x) x[1]))
  # # Attack Names
  # att.name = as.character(sapply(XML::getNodeSet(doc, "//capec:Attack_Pattern/@Name"), function(x) x[1]))
  # # Attack Status
  # att.status = as.factor(sapply(XML::getNodeSet(doc, "//capec:Attack_Pattern/@Status"), function(x) x[1]))
  # # Attack Pattern_Abstraction
  # att.pattern.abstraction = as.factor(sapply(XML::getNodeSet(doc, "//capec:Attack_Pattern/@Pattern_Abstraction"), function(x) x[1]))
  # # Attack Pattern_Completeness
  # att.pattern.completeness = as.factor(sapply(XML::getNodeSet(doc, "//capec:Attack_Pattern/@Pattern_Completeness"), function(x) x[1]))
  # # Attack Methods
  # att.method <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Methods_of_Attack/capec:Method_of_Attack")
  # # Attacker Skills
  # att.acker.skills.lvl <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id,
  #                                      "/capec:Attacker_Skills_or_Knowledge_Required/capec:Attacker_Skill_or_Knowledge_Required/capec:Skill_or_Knowledge_Level")
  # att.acker.skills.type <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id,
  #                                          "/capec:Attacker_Skills_or_Knowledge_Required/capec:Attacker_Skill_or_Knowledge_Required/capec:Skill_or_Knowledge_Type")
  # # Resources Required
  # att.requirements.resources <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Resources_Required/capec:Text")
  # # Probing Techniques
  # att.probing.techniques <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Probing_Techniques/capec:Probing_Technique/capec:Description")
  # # Solutions and Mitigations
  # att.solutions.mitigations <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Solutions_and_Mitigations/capec:Solution_or_Mitigation/capec:Text")
  # # Attack Motivation and Consequences
  # att.motivation.consquences <- GetConsequences(doc, att.id)
  # # Injection Vector
  # att.inject.vect <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Injection_Vector/capec:Text")
  # # Payload
  # att.payload <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Payload/capec:Text")
  # # Activation_Zone
  # att.act.zone <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Activation_Zone/capec:Text")
  # # Related CWEs
  # att.cwes <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Related_Weaknesses/capec:Related_Weakness/capec:CWE_ID")
  # # Related CVEs
  # att.cves <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Related_Vulnerabilities/capec:Related_Vulnerability/capec:Vulnerability_ID")
  # # Relevant Security Requirements
  # att.sec.req <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Relevant_Security_Requirements/capec:Relevant_Security_Requirement/capec:Text")
  # # Related Security Principles
  # att.sec.pples <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Related_Security_Principles/capec:Related_Security_Principle/capec:Text")
  # # Related guidelines
  # att.guidelines <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Related_Guidelines/capec:Related_Guideline/capec:Text")
  # # Purposes
  # att.purposes <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Purposes/capec:Purpose")
  # # IMPACT
  # att.impact.conf <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:CIA_Impact/capec:Confidentiality_Impact")
  # att.impact.inte <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:CIA_Impact/capec:Integrity_Impact")
  # att.impact.avai <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:CIA_Impact/capec:Availability_Impact")
  # # Technical Context
  # att.architectural.ctxt <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Technical_Context/capec:Architectural_Paradigms/capec:Architectural_Paradigm")
  # att.frameworks.ctxt <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Technical_Context/capec:Frameworks/capec:Framework")
  # att.platforms.ctxt <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Technical_Context/capec:Platforms/capec:Platform")
  # att.languages.ctxt <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Technical_Context/capec:Languages/capec:Language")
  # # Obfuscation Techniques
  # att.obfuscation <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Obfuscation_Techniques/capec:Obfuscation_Technique/capec:Description/capec:Text")
  # # Indicators-Warnings_of_Attack
  # att.indicators.of.attack <- XMLChildren2JSON(doc, "capec:Attack_Pattern", att.id, "/capec:Indicators-Warnings_of_Attack/capec:Indicator-Warning_of_Attack/capec:Description/capec:Text")

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
