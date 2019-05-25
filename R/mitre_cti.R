# ATT&CK and CAPEC catalogs from MITRE CTI Repository

## ATT&CK mapping with STIX

#' ATT&CK mapping with STIX
#' @export
#'
#' @return list of data frames representing each map table
attck2stix <- function() {
  doc <- xml2::read_html("https://github.com/mitre/cti/blob/master/USAGE.md")
  attck2stix <- rvest::html_table(doc)
  names(attck2stix) <- c("Objects",
                         stringr::str_trim(sapply(rvest::html_nodes(doc, xpath = "//table/preceding::h3[1]"),
                                                  rvest::html_text))[2:5])
  return(attck2stix)
}

# ATT&CK DATA MODEL

newAttckCommon <- function(id.cti = NA,
                           type = NA,
                           modified = NA,
                           created = NA,
                           Entry_ID = NA,
                           Entry_URL = NA,
                           Entry_Title = NA,
                           Entry_Text = NA,
                           Citation = NA,
                           Deprecated = NA,
                           Revoked = NA,
                           Old_ATTCK_ID = NA) {
  df <- data.frame(id.cti = id.cti,
                   type = type,
                   modified = modified,
                   created = created,
                   entry.id = Entry_ID,
                   entry.url = Entry_URL,
                   entry.title = Entry_Title,
                   entry.text = Entry_Text,
                   citation = Citation,
                   deprecated = Deprecated,
                   revoked = Revoked,
                   old.attck.id = Old_ATTCK_ID,
                   stringsAsFactors = FALSE)
  return(df)
}

newAttckTechnique <- function(Entry_Title = NA,
                              Tactic = NA,
                              Description = NA,
                              Mitigation = NA,
                              Detection = NA,
                              Detection.defenses = NA,
                              Adversary = NA,
                              Adversary.easy = NA,
                              Examples = NA,
                              Platform = NA,
                              Data_Sources = NA,
                              Permissions_Required = NA,
                              Effective_Permissions = NA,
                              Defense_Bypassed = NA,
                              System_Requirements = NA,
                              Network_Requirements = NA,
                              Remote_Support = NA,
                              Contributors = NA,
                              Impact_Type = NA) {
  df <- data.frame(entry.title = Entry_Title,
                   tactic = Tactic,
                   description = Description,
                   mitigation = Mitigation,
                   detection = Detection,
                   detection.defenses = Detection.defenses,
                   adversary = Adversary,
                   adversary.easy = Adversary.easy,
                   examples = Examples,
                   platform = Platform,
                   data.sources = Data_Sources,
                   permissions.required = Permissions_Required,
                   effective.permissions = Effective_Permissions,
                   defense.bypassed = Defense_Bypassed,
                   system.requirements = System_Requirements,
                   network.requirements = Network_Requirements,
                   remote.support = Remote_Support,
                   contributors = Contributors,
                   impact.type = Impact_Type,
                   stringsAsFactors = FALSE)

  return(df)
}

newAttckSoftware <- function(Techniques_Used = NA,
                             Aliases = NA,
                             Groups = NA,
                             Contributors = NA,
                             Labels = NA,
                             Platforms = NA) {
  df <- data.frame(techniques.used = Techniques_Used,
                   aliases = Aliases,
                   groups = Groups,
                   contributors = Contributors,
                   soft.labels = Labels,
                   soft.platform = Platforms,
                   stringsAsFactors = FALSE)
  return(df)
}

newAttckGroups <- function(Techniques_Used = NA,
                           Alias_Descriptions = NA,
                           Software = NA,
                           Contributors = NA) {
  df <- data.frame(techniques.used = Techniques_Used,
                   alias.description = Alias_Descriptions,
                   software = Software,
                   contributors = Contributors,
                   stringsAsFactors = FALSE)
  return(df)

}

newAttckRelation <- function(relationship_type = NA,
                             source_ref = NA,
                             target_ref = NA) {
  df <- data.frame(relationship.type = relationship_type,
                   source.ref = source_ref,
                   target.ref = target_ref,
                   stringsAsFactors = FALSE)

  return(df)
}

#' Function to provide source JSON files by domain and STIX Object type
#'
#' @param domain default set as random between "pre-attack", "enterprise-attack", "mobile-attack". Must be the same name of MITRE CTI Repository folders at github.com
#' @param object default set as random between "attack-pattern", "intrusion-set", "malware", "tool", "course-of-action", "x-mitre-tactic", "x-mitre-matrix". Must be the same name of MITRE CTI Repository folders at github.com
#'
#' @return data.frame with filename and raw url as columns
#'
#' @examples
#' \dontrun{
#' pre.attck.pattern <- getGitHubCTIfiles(domain = "pre-attack", object = "attack-pattern")
#' mob.malware <- getGitHubCTIfiles(domain = "mob-attack", object = "malware")
#' }
getGitHubCTIfiles <- function(domain = sample(c("pre-attack", "enterprise-attack", "mobile-attack"), 1),
                              object = sample(c("attack-pattern", "intrusion-set",
                                                "malware", "tool", "course-of-action",
                                                "x-mitre-tactic", "x-mitre-matrix"), 1)) {
  # TODO: deal with 1000 files limit:
  #       - Get directory sha: https://developer.github.com/v3/repos/contents/#response-if-content-is-a-directory
  #       - Get directory tree: https://developer.github.com/v3/git/trees/#get-a-tree
  giturl <- paste("https://api.github.com/repos/mitre/cti/contents", domain, object, sep = "/")
  req <- httr::content(httr::GET(giturl))
  if (is.null(names(req))) {
    src.files <- data.frame(filename = unlist(lapply(req, "[", "name"), use.names = F),
                            src.file = unlist(lapply(req, "[", "download_url"), use.names = F),
                            stringsAsFactors = FALSE)
  } else {
    src.files <- data.frame(filename = character(),
                            src.file = character(),
                            stringsAsFactors = FALSE)
  }

  return(src.files)
}


### MAPPING CONCEPTS

#' Extract common propierties from attack pattern object (parsed with RJSONIO::fromJSON)
#'
#' @param attack.pattern list
#' @param domain must be "pre-attack", "enterprise-attack" or "mobile-attack"
#'
#' @return data.frame compliant with CTI USAGE document
#'
#' @examples
#' \dontrun{
#' sf <- "https://github.com/mitre/cti/raw/master/<domain>/<object>/<file>.json"
#' attack.pattern <- RJSONIO::fromJSON(sf)
#' df.common <- MapCommonPropierties(attack.pattern)
#' }
MapCommonPropierties <- function(attack.obj = NA, domain = NA) {
  if (domain == "pre-attack") {
    domain <- "mitre-pre-attack"
  } else if (domain == "enterprise-attack") {
    domain <- "mitre-attack"
  } else {
    domain <- "mitre-mobile-attack"
  }
  df.common <- plyr::ldply(attack.obj[["objects"]],
                           function(ap.obj){
                             if (ap.obj$type %in% c("x-mitre-tactic", "intrusion-set")) {
                               domain <- "mitre-attack"
                             }
                             ap.obj.ref <- which(sapply(ap.obj[["external_references"]],
                                                        function(x) {
                                                          x[["source_name"]]
                                                        }) == domain)

                             if (length(ap.obj.ref) > 0) {
                               ap.obj.ref.id <- ap.obj[["external_references"]][[ap.obj.ref]][["external_id"]]
                               ap.obj.ref.url <- ap.obj[["external_references"]][[ap.obj.ref]][["url"]]
                             } else {
                               ap.obj.ref.id <- NA
                               ap.obj.ref.url <- NA
                             }

                             df.pre <- newAttckCommon(id.cti = ap.obj$id,
                                                      type = ap.obj$type,
                                                      modified = ap.obj$modified,
                                                      created = ap.obj$created,
                                                      Entry_ID = ap.obj.ref.id,
                                                      Entry_URL = ap.obj.ref.url,
                                                      Entry_Title = ifelse(test = is.null(ap.obj$name),
                                                                           yes = "-", no = ap.obj$name),
                                                      Entry_Text = ifelse(test = is.null(ap.obj$description),
                                                                          yes = "-", no = ap.obj$description),
                                                      Citation = jsonlite::base64_enc(jsonlite::toJSON(ap.obj$external_references)),
                                                      Deprecated = ifelse(test = "x_mitre_deprecated" %in% names(ap.obj),
                                                                          yes = ap.obj$x_mitre_deprecated,
                                                                          no = FALSE),
                                                      Revoked = ifelse(test = "revoked" %in% names(ap.obj),
                                                                       yes = ap.obj$revoked,
                                                                       no = NA),
                                                      Old_ATTCK_ID = ifelse(test = "x_mitre_old_attack_id" %in% names(ap.obj),
                                                                            yes = ap.obj$x_mitre_old_attack_id,
                                                                            no = NA))
                           })
  return(df.common)
}

MapTactics <- function(x.mitre.tactic = NA, domain = NA) {
  if (domain == "pre-attack") {
    domain <- "mitre-pre-attack"
  } else if (domain == "enterprise-attack") {
    domain <- "mitre-attack"
  } else {
    domain <- "mitre-mobile-attack"
  }
  df.tactic <- plyr::ldply(x.mitre.tactic[["objects"]],
                          function(ap.obj){
                            df.tac <- data.frame(x.mitre.tactic = ifelse(test = "x_mitre_shortname" %in% names(ap.obj),
                                                                           yes = ap.obj$x_mitre_shortname,
                                                                           no = NA),
                                                 stringsAsFactors = FALSE)
                          })
  return(df.tactic)
}

#' Extract Technique propierties from attack pattern object (parsed with RJSONIO::fromJSON)
#'
#' @param attack.pattern list based on STIX
#' @param domain must be "pre-attack", "enterprise-attack" or "mobile-attack"
#'
#' @return data.frame compliant with CTI USAGE document
#'
#' @examples
#' \dontrun{
#' sf <- "https://github.com/mitre/cti/raw/master/<domain>/<object>/<file>.json"
#' attack.pattern <- RJSONIO::fromJSON(sf)
#' df.ent.tech <- MapTechniques(attack.pattern, "enerprise-attack")
#' }
MapTechniques <- function(attack.pattern = NA, domain = NA) {
  if (domain == "pre-attack") {
    domain <- "mitre-pre-attack"
  } else if (domain == "enterprise-attack") {
    domain <- "mitre-attack"
  } else {
    domain <- "mitre-mobile-attack"
  }

  df.techniques <- plyr::ldply(attack.pattern[["objects"]],
                           function(ap.obj){
                             ap.obj.kch <- which(sapply(ap.obj[["kill_chain_phases"]],
                                                        function(x) {
                                                          x[["kill_chain_name"]]
                                                        }) == domain)
                             if (length(ap.obj.kch) > 0) {
                               ap.obj.kch <- paste(unique(sapply(ap.obj[["kill_chain_phases"]][ap.obj.kch], "[[", "phase_name")),
                                                   collapse = ", ")
                             } else {
                               ap.obj.kch <- NA
                             }

                             df.pre <- newAttckTechnique(Entry_Title = ap.obj$name,
                                                         Tactic = ap.obj.kch,
                                                         Description = ifelse(test = is.null(ap.obj$description),
                                                                              yes = "-", no = ap.obj$description),
                                                         Mitigation = NA,
                                                         Detection = ifelse(test = "x_mitre_detectable_by_common_defenses_explanation" %in% names(ap.obj),
                                                                            yes = ap.obj$x_mitre_detectable_by_common_defenses_explanation,
                                                                            no = NA),
                                                         Detection.defenses = ifelse(test = "x_mitre_detectable_by_common_defenses" %in% names(ap.obj),
                                                                                     yes = ap.obj$x_mitre_detectable_by_common_defenses,
                                                                                     no = NA),
                                                         Adversary = ifelse(test = "x_mitre_difficulty_for_adversary_explanation" %in% names(ap.obj),
                                                                            yes = ap.obj$x_mitre_difficulty_for_adversary_explanation,
                                                                            no = NA),
                                                         Adversary.easy = ifelse(test = "x_mitre_difficulty_for_adversary" %in% names(ap.obj),
                                                                                 yes = ap.obj$x_mitre_difficulty_for_adversary,
                                                                                 no = NA),
                                                         Examples = NA,
                                                         Platform = ifelse(test = "x_mitre_platforms" %in% names(ap.obj),
                                                                           yes = ap.obj$x_mitre_platforms,
                                                                           no = NA),
                                                         Data_Sources = ifelse(test = "x_mitre_data_sources" %in% names(ap.obj),
                                                                               yes = ap.obj$x_mitre_data_sources,
                                                                               no = NA),
                                                         Permissions_Required = ifelse(test = "x_mitre_permissions_required" %in% names(ap.obj),
                                                                                       yes = ap.obj$x_mitre_permissions_required,
                                                                                       no = NA),
                                                         Effective_Permissions = ifelse(test = "x_mitre_effective_permissions" %in% names(ap.obj),
                                                                                        yes = ap.obj$x_mitre_effective_permissions,
                                                                                        no = NA),
                                                         Defense_Bypassed = ifelse(test = "x_mitre_defense_bypassed" %in% names(ap.obj),
                                                                                   yes = ap.obj$x_mitre_defense_bypassed,
                                                                                   no = NA),
                                                         System_Requirements = ifelse(test = "x_mitre_system_requirements" %in% names(ap.obj),
                                                                                      yes = ap.obj$x_mitre_system_requirements,
                                                                                      no = NA),
                                                         Network_Requirements = ifelse(test = "x_mitre_network_requirements" %in% names(ap.obj),
                                                                                       yes = ap.obj$x_mitre_network_requirements,
                                                                                       no = NA),
                                                         Remote_Support = ifelse(test = "x_mitre_remote_support" %in% names(ap.obj),
                                                                                 yes = ap.obj$x_mitre_remote_support,
                                                                                 no = NA),
                                                         Contributors = ifelse(test = "x_mitre_contributors" %in% names(ap.obj),
                                                                               yes = ap.obj$x_mitre_contributors,
                                                                               no = NA),
                                                         Impact_Type = ifelse(test = "x_mitre_impact_type" %in% names(ap.obj),
                                                                              yes = ap.obj$x_mitre_impact_type,
                                                                              no = NA))
                           })

  return(df.techniques)
}

#' Extract Group propierties from intrusion set object (parsed with RJSONIO::fromJSON)
#'
#' @param intrusion.set list based on STIX
#' @param domain must be "pre-attack", "enterprise-attack" or "mobile-attack"
#'
#' @return data.frame
MapGroups <- function(intrusion.set = NA, domain = NA) {
  if (domain == "pre-attack") {
    domain <- "mitre-pre-attack"
  } else if (domain == "enterprise-attack") {
    domain <- "mitre-attack"
  } else {
    domain <- "mitre-mobile-attack"
  }
  df.group <- plyr::ldply(intrusion.set[["objects"]],
                           function(ap.obj){
                             df.pre <- newAttckGroups(Techniques_Used = NA,
                                                      Alias_Descriptions = paste(ap.obj[["aliases"]],
                                                                                 collapse = ", "),
                                                      Software = NA,
                                                      Contributors = ifelse(test = "x_mitre_contributors" %in% names(ap.obj),
                                                                            yes = ap.obj$x_mitre_contributors,
                                                                            no = NA))
                           })
  return(df.group)
}

MapSoftware <- function(software.obj = NA, domain = domain) {
  if (domain == "pre-attack") {
    domain <- "mitre-pre-attack"
  } else if (domain == "enterprise-attack") {
    domain <- "mitre-attack"
  } else {
    domain <- "mitre-mobile-attack"
  }
  df.soft <- plyr::ldply(software.obj[["objects"]],
                          function(ap.obj){
                            df.pre <- newAttckSoftware(Techniques_Used = NA,
                                                       Aliases = ifelse(test = "x_mitre_aliases" %in% names(ap.obj),
                                                                        yes = paste(ap.obj[["x_mitre_aliases"]],
                                                                                    collapse = ", "),
                                                                        no = NA),
                                                       Groups = NA,
                                                       Contributors = ifelse(test = "x_mitre_contributors" %in% names(ap.obj),
                                                                             yes = paste(ap.obj[["x_mitre_contributors"]],
                                                                                         collapse = ", "),
                                                                             no = NA),
                                                       Labels = ifelse(test = "labels" %in% names(ap.obj),
                                                                       yes = paste(ap.obj[["labels"]],
                                                                                   collapse = ", "),
                                                                       no = NA),
                                                       Platforms = ifelse(test = "x_mitre_platforms" %in% names(ap.obj),
                                                                          yes = paste(ap.obj[["x_mitre_platforms"]],
                                                                                      collapse = ", "),
                                                                          no = NA))
                          })
  return(df.soft)

}

MapMitigation <- function(course.action = NA, domain = domain) {
  if (domain == "pre-attack") {
    domain <- "mitre-pre-attack"
  } else if (domain == "enterprise-attack") {
    domain <- "mitre-attack"
  } else {
    domain <- "mitre-mobile-attack"
  }
  df.mitigation <- plyr::ldply(course.action[["objects"]],
                           function(ap.obj){
                             df.tac <- data.frame(mitigation = ifelse(test = "description" %in% names(ap.obj),
                                                                          yes = ap.obj$description,
                                                                          no = NA),
                                                  stringsAsFactors = FALSE)
                           })
  return(df.mitigation)
}

MapRelations <- function(relationship = NA, domain = NA) {
  if (domain == "pre-attack") {
    domain <- "mitre-pre-attack"
  } else if (domain == "enterprise-attack") {
    domain <- "mitre-attack"
  } else {
    domain <- "mitre-mobile-attack"
  }

  df.relations <- plyr::ldply(relationship[["objects"]],
                          function(ap.obj){
                            df.pre <- newAttckRelation(relationship_type = ap.obj$relationship_type,
                                                       source_ref = ap.obj$source_ref,
                                                       target_ref = ap.obj$target_ref)
                          })
  return(df.relations)

}

### BUILD DATA MODELS

#' Read MITRE CTI Repository files retaled to x-mitre-tactic, extract data,
#' map variables from STIX to ATT&CK model and return tidy data.frame.
#'
#' @param domain must be "pre-attack", "enterprise-attack" or "mobile-attack"
#'
#' @return data.frame
parseAttckmodel.tact <- function(domain = sample(c("pre-attack",
                                                   "enterprise-attack",
                                                   "mobile-attack"), 1)) {
  sf.x.mitre.tactic <- getGitHubCTIfiles(domain, "x-mitre-tactic")

  # parse each file
  df.tact <- plyr::ldply(sf.x.mitre.tactic$src.file,
                         function(sf) {
                           # read source JSON file
                           x.mitre.tactic <- RJSONIO::fromJSON(sf)
                           # Map common properties
                           df.common <- MapCommonPropierties(attack.obj = x.mitre.tactic,
                                                             domain = domain)
                           df.tactics <- MapTactics(x.mitre.tactic = x.mitre.tactic,
                                                          domain = domain)
                           dom <- data.frame(domain = domain, stringsAsFactors = FALSE)
                           dsf <- data.frame(src.file = sf, stringsAsFactors = FALSE)
                           cbind(dom, df.common, df.tactics, dsf)
                         })

  return(df.tact)
}

#' Read MITRE CTI Repository files retaled to attack-pattern, extract data,
#' map variables from STIX to ATT&CK model and return tidy data.frame.
#'
#' @param domain must be "pre-attack", "enterprise-attack" or "mobile-attack"
#'
#' @return data.frame
parseAttckmodel.tech <- function(domain = sample(c("pre-attack",
                                                   "enterprise-attack",
                                                   "mobile-attack"), 1)) {
  sf.attack.pattern <- getGitHubCTIfiles(domain, "attack-pattern")

  # parse each file
  df.tech <- plyr::ldply(sf.attack.pattern$src.file,
                        function(sf) {
                          # read source JSON file
                          attack.pattern <- RJSONIO::fromJSON(sf)
                          # Map common properties
                          df.common <- MapCommonPropierties(attack.obj = attack.pattern,
                                                            domain = domain)
                          df.techniques <- MapTechniques(attack.pattern = attack.pattern,
                                                         domain = domain)
                          dom <- data.frame(domain = domain, stringsAsFactors = FALSE)
                          dsf <- data.frame(src.file = sf, stringsAsFactors = FALSE)
                          cbind(dom, df.common, df.techniques, dsf)
                        })

  return(df.tech)
}


#' Read MITRE CTI Repository files retaled to intrusion-set, extract data,
#' map variables from STIX to ATT&CK model and return tidy data.frame.
#'
#' @param domain must be "pre-attack", "enterprise-attack" or "mobile-attack"
#'
#' @return data.frame
parseAttckmodel.group <- function(domain = sample(c("pre-attack",
                                                    "enterprise-attack",
                                                    "mobile-attack"), 1)) {
  sf.intrusion.set <- getGitHubCTIfiles(domain, "intrusion-set")

  # parse each file
  df.group <- plyr::ldply(sf.intrusion.set$src.file,
                        function(sf) {
                          # read source JSON file
                          intrusion.set <- RJSONIO::fromJSON(sf)
                          # Map common properties
                          df.common <- MapCommonPropierties(attack.obj = intrusion.set,
                                                            domain = domain)
                          df.groups <- MapGroups(intrusion.set = intrusion.set,
                                                 domain = domain)
                          dom <- data.frame(domain = domain, stringsAsFactors = FALSE)
                          dsf <- data.frame(src.file = sf, stringsAsFactors = FALSE)
                          cbind(dom, df.common, df.groups, dsf)
                        })

  return(df.group)
}

parseAttckmodel.soft <- function(domain = sample(c("pre-attack",
                                                   "enterprise-attack",
                                                   "mobile-attack"), 1)) {
  # MALWARE
  sf.maltool <- getGitHubCTIfiles(domain, "malware")
  sf.maltool <- dplyr::bind_rows(sf.maltool, getGitHubCTIfiles(domain, "tool"))

  # parse each file
  df.software <- plyr::ldply(sf.maltool$src.file,
                          function(sf) {
                            # read source JSON file
                            maltool <- RJSONIO::fromJSON(sf)
                            # Map common properties
                            df.common <- MapCommonPropierties(attack.obj = maltool,
                                                              domain = domain)
                            df.soft <- MapSoftware(software.obj = maltool,
                                                   domain = domain)
                            dom <- data.frame(domain = domain, stringsAsFactors = FALSE)
                            dsf <- data.frame(src.file = sf, stringsAsFactors = FALSE)
                            cbind(dom, df.common, df.soft, dsf)
                          })


  return(df.software)
}

parseAttckmodel.miti <- function(domain = sample(c("pre-attack",
                                                   "enterprise-attack",
                                                   "mobile-attack"), 1)) {
  sf.course.action <- getGitHubCTIfiles(domain, "course-of-action")

  # parse each file
  df.miti <- plyr::ldply(sf.course.action$src.file,
                        function(sf) {
                          # read source JSON file
                          courseact <- RJSONIO::fromJSON(sf)
                          # Map common properties
                          df.common <- MapCommonPropierties(attack.obj = courseact,
                                                            domain = domain)
                          df.mitigation <- MapMitigation(course.action = courseact,
                                                       domain = domain)
                          dom <- data.frame(domain = domain, stringsAsFactors = FALSE)
                          dsf <- data.frame(src.file = sf, stringsAsFactors = FALSE)
                          cbind(dom, df.common, df.mitigation, dsf)
                        })

  return(df.miti)

}

#' Read MITRE CTI Repository files retaled to relationship, extract data,
#' map variables from STIX to ATT&CK model and return tidy data.frame.
#'
#' @param domain must be "pre-attack", "enterprise-attack" or "mobile-attack"
#'
#' @return data.frame
parseAttckmodel.rels <- function(domain = sample(c("pre-attack",
                                                      "enterprise-attack",
                                                      "mobile-attack"), 1)) {
  sf.relationship <- getGitHubCTIfiles(domain, "relationship")

  # parse each file
  df.rel <- plyr::ldply(sf.relationship$src.file,
                        function(sf) {
                          # read source JSON file
                          relationship <- RJSONIO::fromJSON(sf)
                          # Map common properties
                          df.common <- MapCommonPropierties(attack.obj = relationship,
                                                            domain = domain)
                          df.relations <- MapRelations(relationship = relationship,
                                                    domain = domain)
                          dom <- data.frame(domain = domain, stringsAsFactors = FALSE)
                          dsf <- data.frame(src.file = sf, stringsAsFactors = FALSE)
                          cbind(dom, df.common, df.relations, dsf)
                        })

  return(df.rel)

}

### EXPORTED FUNCTIONS

#' Read MITRE CTI Repository browsing domain directories to extract data from x-mitre-tactic files,
#' map variables from STIX to ATT&CK model and return tidy data.frame with Tactic variables.
#'
#' @return data.frame
#' @export
#'
#' @examples
#' \dontrun{
#' df.tactics <- parseAttck.Tactics()
#' }
parseAttck.Tactics <- function() {
  df.pre <- parseAttckmodel.tact(domain = "pre-attack")
  df.ent <- parseAttckmodel.tact(domain = "enterprise-attack")
  df.mob <- parseAttckmodel.tact(domain = "mobile-attack")

  df <- dplyr::bind_rows(df.pre, df.ent, df.mob)

  return(df)
}


#' Read MITRE CTI Repository browsing domain directories to extract data from attack-pattern files,
#' map variables from STIX to ATT&CK model and return tidy data.frame with Technique variables.
#'
#' @return data.frame
#' @export
#'
#' @examples
#' \dontrun{
#' df.techniques <- parseAttck.Techniques()
#' }
parseAttck.Techniques <- function() {
  df.pre <- parseAttckmodel.tech(domain = "pre-attack")
  df.ent <- parseAttckmodel.tech(domain = "enterprise-attack")
  df.mob <- parseAttckmodel.tech(domain = "mobile-attack")

  df <- dplyr::bind_rows(df.pre, df.ent, df.mob)

  return(df)
}

#' Read MITRE CTI Repository browsing domain directories to extract data from intrusion-set files,
#' map variables from STIX to ATT&CK model and return tidy data.frame with Group variables.
#'
#' @return data.frame
#' @export
#'
#' @examples
#' \dontrun{
#' df.groups <- parseAttck.Groups()
#' }
parseAttck.Groups <- function() {
  df.pre <- parseAttckmodel.group(domain = "pre-attack")
  df.ent <- parseAttckmodel.group(domain = "enterprise-attack")
  df.mob <- parseAttckmodel.group(domain = "mobile-attack")

  df <- dplyr::bind_rows(df.pre, df.ent, df.mob)

  return(df)
}

#' Read MITRE CTI Repository browsing domain directories to extract data from malware and tool files,
#' build model and return tidy data.frame with Software variables.
#'
#' @return data.frame
#' @export
#'
#' @examples
#' \dontrun{
#' df.software <- parseAttck.Software()
#' }
parseAttck.Software <- function() {
  df.pre <- parseAttckmodel.soft(domain = "pre-attack")
  df.ent <- parseAttckmodel.soft(domain = "enterprise-attack")
  df.mob <- parseAttckmodel.soft(domain = "mobile-attack")

  df <- dplyr::bind_rows(df.pre, df.ent, df.mob)

  return(df)
}

#' Read MITRE CTI Repository browsing domain directories to extract data from course-of-action files,
#' build model and return tidy data.frame with Mitigation variables.
#'
#' @return data.frame
#' @export
#'
#' @examples
#' \dontrun{
#' df.mitigations <- parseAttck.Mitigation()
#' }
parseAttck.Mitigation <- function() {
  df.pre <- parseAttckmodel.miti(domain = "pre-attack")
  df.ent <- parseAttckmodel.miti(domain = "enterprise-attack")
  df.mob <- parseAttckmodel.miti(domain = "mobile-attack")

  df <- dplyr::bind_rows(df.pre, df.ent, df.mob)

  return(df)
}


#' Read MITRE CTI Repository browsing domain directories to extract data from relationship files,
#' build model and return tidy data.frame with relationship variables.
#'
#' @return data.frame
#' @export
#'
#' @examples
#' \dontrun{
#' df.relationships <- parseAttck.Relationships()
#' }
parseAttck.Relationships <- function() {
  df.pre <- parseAttckmodel.rels(domain = "pre-attack")
  df.ent <- parseAttckmodel.rels(domain = "enterprise-attack")
  df.mob <- parseAttckmodel.rels(domain = "mobile-attack")

  df <- dplyr::bind_rows(df.pre, df.ent, df.mob)

  return(df)
}

# BUILD TIDY DATA FRAMES

buildAttckTactics <- function() {
  df.tactics <- parseAttck.Tactics()
}
