# ATT&CK and CAPEC catalogs from MITRE CTI Repository

## ATT&CK mapping with STIX

#' ATT&CK mapping with STIX
#'
#' @return list of data frames representing each map table
#' @export
attck2stix <- function() {
  doc <- xml2::read_html("https://github.com/mitre/cti/blob/master/USAGE.md")
  attck2stix <- rvest::html_table(doc)
  names(attck2stix) <- c("Objects",
                         stringr::str_trim(sapply(rvest::html_nodes(doc, xpath = "//table/preceding::h3[1]"),
                                                  rvest::html_text))[2:5])
  return(attck2stix)
}

# ATT&CK DATA MODEL

newAttckCommon <- function(Entry_ID = NA,
                           Entry_URL = NA,
                           Entry_Title = NA,
                           Entry_Text = NA,
                           Citation = NA,
                           Deprecated = NA,
                           Revoked = NA,
                           Old_ATTCK_ID = NA) {
  df <- data.frame(entry.id = Entry_ID,
                   entry.url = Entry_URL,
                   entry.title = Entry_Title,
                   entry.text = Entry_Text,
                   citation = Citation,
                   deprecated = Deprecated,
                   old.attck.id = Old_ATTCK_ID,
                   stringsAsFactors = FALSE)
  return(df)
}

newAttckTechnique <- function(Entry_Title = NA,
                              Tactic = NA,
                              Description = NA,
                              Mitigation = NA,
                              Detection = NA,
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

}

newAttckSoftware <- function() {

}

newAttckGroups <- function() {

}


# PRE-ATTCK


## PRE-ATTCK TECHNIQUES (STIX:attack-pattern)

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
  giturl <- paste("https://api.github.com/repos/mitre/cti/contents", domain, object, sep = "/")
  req <- httr::content(httr::GET(giturl))
  src.files <- data.frame(filename = unlist(lapply(req, "[", "name"), use.names = F),
                                  src.file = unlist(lapply(req, "[", "download_url"), use.names = F),
                                  stringsAsFactors = FALSE)
  return(src.files)
}

#' Extract common propiertis from attack pattern object (parsed with RJSONIO::fromJSON)
#'
#' @param attack.pattern list
#'
#' @return data.frame compliant with CTI USAGE document
#'
#' @examples
#' \dontrun{
#' sf <- "https://github.com/mitre/cti/raw/master/<domain>/<object>/<file>.json"
#' attack.pattern <- RJSONIO::fromJSON(sf)
#' df.common <- MapCommonPropierties(attack.pattern)
#' }
preMapCommonPropierties <- function(attack.pattern) {
  df.common <- plyr::ldply(attack.pattern[["objects"]],
                           function(ap.obj){
                             ap.obj.ref <- which(sapply(ap.obj[["external_references"]],
                                                        function(x) {
                                                          x[["source_name"]]
                                                        }) == "mitre-pre-attack")
                             ap.obj.ref <- ap.obj[["external_references"]][[ap.obj.ref]]

                             df.pre <- newAttckCommon(Entry_ID = ap.obj.ref["external_id"],
                                                      Entry_URL = ap.obj.ref["url"],
                                                      Entry_Title = ap.obj$name,
                                                      Entry_Text = ap.obj$description,
                                                      Citation = jsonlite::base64_enc(jsonlite::toJSON(ap.obj$external_references)),
                                                      Deprecated = ifelse(test = "x_mitre_deprecated" %in% names(ap.obj),
                                                                          yes = ap.obj$x_mitre_deprecated,
                                                                          no = FALSE),
                                                      Revoked = ifelse(test = "revoked" %in% names(ap.obj),
                                                                       yes = ap.obj$revoked,
                                                                       no = NA),
                                                      Old_ATTCK_ID = ap.obj$x_mitre_old_attack_id)
                           })
  return(df.common)
}

preMapTechniques <- function(attack.pattern) {

  df.techniques <- plyr::ldply(attack.pattern[["objects"]],
                           function(ap.obj){
                             ap.obj.kch <- which(sapply(ap.obj[["kill_chain_phases"]],
                                                        function(x) {
                                                          x[["kill_chain_name"]]
                                                        }) == "mitre-pre-attack")
                             ap.obj.kch <- unique(ap.obj[["kill_chain_phases"]][[ap.obj.kch]]["phase_name"])

                             df.pre <- newAttckTechnique(Entry_Title = ap.obj$name,
                                                         Tactic = ap.obj.kch,
                                                         Description = ap.obj$description,
                                                         Mitigation = NA,
                                                         Detection = NA,
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

#' Read MITRE CTI Repository files in pre-attack directory, extract data,
#' map variables from STIX to ATT&CK model and return tidy data.frame.
#'
#' @return data.frame
#' @export
#'
#' @examples
#' \dontrun{
#' df.pre <- parseAttckPREmodel()
#' }
parseAttckPREmodel <- function() {
  pre.attck.pattern <- getGitHubCTIfiles(domain = "pre-attack",
                                         object = "attack-pattern")

  # parse each file
  df.pre <- plyr::ldply(pre.attck.pattern$src.file[1:10],
                        function(sf) {
                          # read source JSON file
                          attack.pattern <- RJSONIO::fromJSON(sf)
                          # Map common properties
                          df.common <- preMapCommonPropierties(attack.pattern)
                          df.techniques <- preMapTechniques(attack.pattern)
                          # plyr::rbind.fill(df.common, df.techniques)
                          cbind(df.common, df.techniques)
                        })

  return(df.pre)
}

