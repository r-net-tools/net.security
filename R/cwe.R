LastDownloadCWEDate <- function(){
  return(Sys.Date())
}

GetCWEData <- function(savepath = tempdir()) {
  print("Downloading raw data from MITRE...")
  DownloadCWEData(savepath)
  print("Unzip, extract, etc...")
  cwes.file <- ExtractCWEFiles(savepath)
  print("Processing CWE raw data...")
  cwes <- ParseCWEData(cwes.file)
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

  print("Parsing basic attributes...")

  # Load Weakness raw data
  doc <- suppressWarnings(rvest::html(cwes.file))
  raw.cwes <- rvest::html_nodes(doc, "weakness")
  # Extract Weakness node attributes
  cwes <- as.data.frame(t(sapply(raw.cwes, rvest::html_attrs)), stringsAsFactors = F)
  names(cwes) <- c("ID", "Name", "Abstraction", "Structure", "Status")
  # Set factors (improve setting levels according to XSD)
  cwes$Abstraction <- as.factor(cwes$Abstraction)
  cwes$Structure <- as.factor(cwes$Structure)
  cwes$Status <- as.factor(cwes$Status)
  # Add extra field with code standard
  cwes$Code_Standard <- paste("CWE-", cwes$ID, sep = "")

  print("Parsing Description...")

  cwes$Description <- sapply(rvest::html_nodes(doc, xpath = "//weakness/description"),
                             rvest::html_text)
  cwes$Extended_Description <- sapply(raw.cwes,
                                      function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "extended_description")), character(0)),
                                                          yes = "",
                                                          no = rvest::html_text(rvest::html_nodes(x, "extended_description")))})

  print("Parsing Related Weakness...")

  cwes$Related_Weakness <- sapply(raw.cwes,
                                  function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "related_weakness")), character(0)),
                                                      yes = "[\"\"]",
                                                      no = RJSONIO::toJSON(lapply(rvest::html_nodes(x, "related_weakness"),
                                                                                  rvest::html_attrs),
                                                                            pretty = T))
                                              }
                                  )

  print("Parsing Weakness Ordinality...")

  cwes$Weakness_Ordinality <- sapply(raw.cwes,
                                    function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "weakness_ordinality")), character(0)),
                                                        yes = "[\"\"]",
                                                        no = RJSONIO::toJSON(lapply(rvest::html_nodes(x, "weakness_ordinality"),
                                                                                     function(x) rvest::html_text(rvest::html_children(x))),
                                                                              pretty = T))
                                    }
  )

  print("Parsing Applicable Platforms...")

  cwes$Applicable_Platforms <- sapply(raw.cwes,
                                  function(x) {ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "applicable_platforms")), character(0)),
                                                      yes = "{}",
                                                      no = {
                                                             y <- lapply(rvest::html_children(rvest::html_nodes(x, "applicable_platforms")), rvest::html_attrs)
                                                             names(y) <- rvest::html_name(rvest::html_children(rvest::html_nodes(x, "applicable_platforms")))
                                                             RJSONIO::toJSON(y, pretty = T)
                                                      })
                                  }
  )

  print("Parsing Background Details...")

  cwes$Background_Details <- sapply(raw.cwes,
                                  function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "background_details")), character(0)),
                                                     yes = "[\"\"]",
                                                     no = RJSONIO::toJSON(lapply(rvest::html_nodes(x, "background_details"),
                                                                                 rvest::html_text),
                                                                          pretty = T))
  )

  print("Parsing Alternate Terms...")

  cwes$Alternate_Terms <- sapply(raw.cwes,
                                    function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "alternate_terms")), character(0)),
                                                       yes = "[\"\"]",
                                                       no = RJSONIO::toJSON(lapply(rvest::html_children(rvest::html_nodes(x, "alternate_terms")),
                                                                                   rvest::html_text),
                                                                            pretty = T))
  )

  print("Parsing Modes Of Introduction...")

  cwes$Modes_Of_Introduction <- sapply(raw.cwes,
                                 function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "modes_of_introduction")), character(0)),
                                                    yes = "[\"\"]",
                                                    no = RJSONIO::toJSON(lapply(
                                                                                  lapply(rvest::html_children(rvest::html_nodes(x, "modes_of_introduction")),
                                                                                         function(x) rvest::html_children(x)),
                                                                                  function(y) {
                                                                                    z <- rvest::html_text(y)
                                                                                    names(z) <- rvest::html_name(y)
                                                                                    z
                                                                                  }
                                                                                ),
                                                    pretty = T))
  )

  print("Parsing Likelihood Of Exploit...")

  cwes$Likelihood_Of_Exploit <- sapply(raw.cwes,
                                 function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "likelihood_of_exploit")), character(0)),
                                                    yes = "",
                                                    no = rvest::html_text(rvest::html_nodes(x, "likelihood_of_exploit"))
                                                    )
  )
  cwes$Likelihood_Of_Exploit <- as.factor(cwes$Likelihood_Of_Exploit)

  print("Parsing Common Consequences...")

  cwes$Common_Consequences <- sapply(raw.cwes,
                                       function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "common_consequences")), character(0)),
                                                          yes = "[\"\"]",
                                                          no = RJSONIO::toJSON(lapply(
                                                            lapply(rvest::html_children(rvest::html_nodes(x, "common_consequences")),
                                                                   function(x) rvest::html_children(x)),
                                                            function(y) {
                                                              z <- rvest::html_text(y)
                                                              names(z) <- rvest::html_name(y)
                                                              z
                                                            }
                                                          ),
                                                          pretty = T))
  )

  print("Parsing Detection Methods...")

  cwes$Detection_Methods <- sapply(raw.cwes,
                                     function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "detection_methods")), character(0)),
                                                        yes = "[\"\"]",
                                                        no = RJSONIO::toJSON(lapply(
                                                          lapply(rvest::html_children(rvest::html_nodes(x, "detection_methods")),
                                                                 function(x) rvest::html_children(x)),
                                                          function(y) {
                                                            z <- rvest::html_text(y)
                                                            names(z) <- rvest::html_name(y)
                                                            z
                                                          }
                                                        ),
                                                        pretty = T))
  )

  print("Parsing Potential Mitigations...")

  cwes$Potential_Mitigations <- sapply(raw.cwes,
                                   function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "potential_mitigations")), character(0)),
                                                      yes = "[\"\"]",
                                                      no = RJSONIO::toJSON(lapply(
                                                        lapply(rvest::html_children(rvest::html_nodes(x, "potential_mitigations")),
                                                               function(x) rvest::html_children(x)),
                                                        function(y) {
                                                          z <- rvest::html_text(y)
                                                          names(z) <- rvest::html_name(y)
                                                          z
                                                        }
                                                      ),
                                                      pretty = T))
  )

  print("Parsing Observed Examples...")

  cwes$Observed_Examples <- sapply(raw.cwes,
                                       function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "observed_examples")), character(0)),
                                                          yes = "[\"\"]",
                                                          no = RJSONIO::toJSON(lapply(
                                                            lapply(rvest::html_children(rvest::html_nodes(x, "observed_examples")),
                                                                   function(x) rvest::html_children(x)),
                                                            function(y) {
                                                              z <- rvest::html_text(y)
                                                              names(z) <- rvest::html_name(y)
                                                              z
                                                            }
                                                          ),
                                                          pretty = T))
  )

  print("Parsing Functional Areas...")

  cwes$Functional_Areas <- sapply(raw.cwes,
                                   function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "functional_areas")), character(0)),
                                                      yes = "[\"\"]",
                                                      no = RJSONIO::toJSON(sapply(rvest::html_children(rvest::html_nodes(x, "functional_areas")), rvest::html_text)))
  )

  print("Parsing Affected Resources...")

  cwes$Affected_Resources <- sapply(raw.cwes,
                                  function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "affected_resources")), character(0)),
                                                     yes = "[\"\"]",
                                                     no = RJSONIO::toJSON(sapply(rvest::html_children(rvest::html_nodes(x, "affected_resources")), rvest::html_text)))
  )

  print("Parsing Taxonomy Mappings...")

  cwes$Taxonomy_Mappings <- sapply(raw.cwes,
                                   function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "taxonomy_mappings")), character(0)),
                                                      yes = "[\"\"]",
                                                      no = RJSONIO::toJSON({w <- lapply(
                                                                                        lapply(rvest::html_children(rvest::html_nodes(x, "taxonomy_mappings")),
                                                                                               function(x) rvest::html_children(x)),
                                                                                        function(y) {
                                                                                          z <- rvest::html_text(y)
                                                                                          names(z) <- rvest::html_name(y)
                                                                                          z
                                                                                        })
                                                                            names(w) <- unlist(rvest::html_attrs(rvest::html_children(rvest::html_nodes(x, "taxonomy_mappings"))))
                                                                            w}, pretty = T))
  )

  print("Parsing Related Attack Patterns...")

  cwes$Related_Attack_Patterns <- sapply(raw.cwes,
                                    function(x) ifelse(test = identical(rvest::html_text(rvest::html_nodes(x, "related_attack_patterns")), character(0)),
                                                       yes = "[\"\"]",
                                                       no = RJSONIO::toJSON(sapply(rvest::html_children(rvest::html_nodes(x, "related_attack_patterns")), rvest::html_attrs)))
  )

  return(cwes)
}
