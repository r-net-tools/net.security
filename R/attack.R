# References: https://www.mitre.org/publications/technical-papers/mitre-attack-design-and-philosophy

#' Title
#'
#' @param savepath
#' @param verbose
#'
#' @return
#' @export
#'
#' @examples
GetATTCKData <- function(verbose = TRUE) {
  if (verbose) print("Processing ATT&CK raw data...")
  if (verbose) print("[+] ATT&CK's PRE DOMAIN")
  attck.pre <- ParseATTCKpre(verbose)
  if (verbose) print("[+] ATT&CK's ENTERPRISE DOMAIN")
  attck.ent <- ParseATTCKent(verbose)
  if (verbose) print("[+] ATT&CK's MOBILE DOMAIN")
  attck.mob <- ParseATTCKmob(verbose)

  # Join domains
  tactics <- dplyr::bind_rows(attck.pre$tactics, attck.ent$tactics, attck.mob$tactics)
  techniques <- dplyr::bind_rows(attck.pre$techniques, attck.ent$techniques, attck.mob$techniques)
  groups <- dplyr::bind_rows(attck.pre$groups, attck.ent$groups, attck.mob$groups)
  software <- dplyr::bind_rows(attck.ent$software, attck.mob$software)
  mitigations <- attck.mob$mitigations
  relations <- dplyr::bind_rows(attck.pre$relations, attck.ent$relations, attck.mob$relations)

  attck <- list(tactics = tactics, techniques = techniques, groups = groups,
                software = software, mitigations = mitigations, relations = relations)
  if (verbose) print(paste("ATT&CK data sets created."))
  return(attck)
}

ParseATTCKpre <- function(verbose = TRUE) {
  if (verbose) print("[PRE] Processing Tactics raw data...")
  tactics.raw <- ParseTacticsPRE(verbose)
  if (verbose) print("[PRE] Processing Techniques raw data...")
  techniques.raw <- ParseTechniquesPRE(verbose)
  if (verbose) print("[PRE] Processing Groups raw data...")
  groups.raw <- ParseGroupsPRE(verbose)
  if (verbose) print("[PRE] Building data sets relationships...")
  relations <- ParseRelationsPRE(tactics.raw, techniques.raw, groups.raw, verbose)

  # Tidy data sets
  if (verbose) print("[PRE] Tidy raw data...")
  tactics <- unique(dplyr::select(tactics.raw, id, name, description, source, deprecated))
  tactics$domain <- rep("PRE", nrow(tactics))
  # Description is equal to definition, but the second one is in HTML
  techniques.raw$description <- techniques.raw$definition
  techniques <- unique(dplyr::select(techniques.raw, -tactic, -definition))
  techniques$domain <- rep("PRE", nrow(techniques))
  groups <- unique(dplyr::select(groups.raw, id, name, aliases, description, source))
  groups$domain <- rep("PRE", nrow(groups))

  attck <- list(tactics = tactics, techniques = techniques,
                groups = groups, relations = relations)

  if (verbose) print("[PRE] ATT&CK PRE data sets created.")

  return(attck)
}

ParseATTCKent <- function(verbose) {
  if (verbose) print("[ENT] Processing Tactics raw data...")
  tactics.raw <- ParseTacticsEnt(verbose)
  if (verbose) print("[ENT] Processing Techniques raw data...")
  techniques.raw <- ParseTechniquesEnt(verbose)
  if (verbose) print("[ENT] Processing Software raw data...")
  software.raw <- ParseSoftwareEnt(verbose)
  if (verbose) print("[ENT] Processing Groups raw data...")
  groups.raw <- ParseGroupsEnt(verbose)
  if (verbose) print("[ENT] Building data sets relationships...")
  relations <- ParseRelationsEnt(tactics.raw, techniques.raw, groups.raw, software.raw, verbose)

  # Tidy data sets
  tactics <- tactics.raw
  tactics$domain <- rep("ENT", nrow(tactics))
  good <- c("id", "name", "description", "mitigation", "examples", "source")
  techniques <- unique(dplyr::select(techniques.raw, good))
  techniques$deprecated <- rep(FALSE, nrow(techniques))
  techniques$domain <- rep("ENT", nrow(techniques))
  good <- c("id", "name", "description", "aliases", "type", "source")
  software <- unique(dplyr::select(software.raw, good))
  software$domain <- rep("ENT", nrow(software))
  good <- c("id", "name", "description", "aliases", "source")
  groups <- unique(dplyr::select(groups.raw, good))
  groups$domain <- rep("ENT", nrow(groups))

  attck <- list(tactics = tactics, techniques = techniques, software = software,
                groups = groups, relations = relations)
  if (verbose) print("[ENT] ATT&CK Enterprise data sets created.")

  return(attck)
}

ParseATTCKmob <- function(verbose) {
  if (verbose) print("[MOB] Processing Tactics raw data...")
  tactics.raw <- ParseTacticsMob(verbose)
  if (verbose) print("[MOB] Processing Techniques raw data...")
  techniques.raw <- ParseTechniquesMob(verbose)
  if (verbose) print("[MOB] Processing Software raw data...")
  software.raw <- ParseSoftwareMob(verbose)
  if (verbose) print("[MOB] Processing Groups raw data...")
  groups.raw <- ParseGroupsMob(verbose)
  if (verbose) print("[MOB] Processing Mitigations raw data...")
  mitigations.raw <- ParseMitigationsMob(verbose)
  if (verbose) print("[MOB] Building data sets relationships...")
  relations <- ParseRelationsMob(tactics.raw, techniques.raw, groups.raw, software.raw, mitigations.raw, verbose)

  # Tidy data sets
  tactics <- unique(dplyr::select(tactics.raw, id, name, description, source))
  tactics$domain <- rep("MOB", nrow(tactics))
  tactics$deprecated <- rep(FALSE, nrow(tactics))
  techniques <- unique(dplyr::select(techniques.raw, id, name, description, source, detection, mitigation, examples, mtc.id))
  techniques$deprecated <- rep(FALSE, nrow(techniques))
  techniques$domain <- rep("MOB", nrow(techniques))
  software <- unique(dplyr::select(software.raw, id, name, description, type, aliases, source))
  software$domain <- rep("MOB", nrow(software))
  groups <- unique(dplyr::select(groups.raw, -soft.id))
  groups$domain <- rep("MOB", nrow(groups))
  mitigations <- unique(dplyr::select(mitigations.raw, id, name, description, source))
  mitigations$domain <- rep("MOB", nrow(mitigations))

  attck <- list(tactics = tactics, techniques = techniques, software = software,
                groups = groups, mitigations = mitigations, relations = relations)
  if (verbose) print("[MOB] ATT&CK Mobile data sets created.")

  return(attck)
}


#############
# Tactics
##

ParseTacticsPRE <- function(verbose = TRUE) {
  if (verbose) print("[PRE]  - Processing Tactics basic information...")
  source.url <- "https://attack.mitre.org/pre-attack/index.php/Tactics"
  doc <- xml2::read_html(source.url)

  # Extract basic information
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  tactic.ids <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x,xpath = "./td[1]/a/@href"), trim = T))
  tactic.ids <- sapply(tactic.ids, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])])
  names(tactic.ids) <- NULL
  tactic.names <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  tactic.urls <- sapply(t.list, function(x) paste("https://attack.mitre.org",
                                                       rvest::html_text(rvest::html_nodes(x,
                                                                                          xpath = "./td[1]/a/@href"),
                                                                        trim = T),
                                                       sep = ""))
  df.basic <- data.frame(id = tactic.ids,
                         name = tactic.names,
                         source = tactic.urls,
                         stringsAsFactors = FALSE)

  if (verbose) print("[PRE]  - Processing Tactics details and relationships...")
  df <- data.frame(id = character(),
                   description = character(),
                   deprecated = character(),
                   technique.id = character(),
                   technique.name = character(),
                   technique.desc = character(),
                   technique.url = character(),
                   stringsAsFactors = FALSE)

  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  for (src.url in unique(df.basic$source)) {
    df <- rbind(df, ExtractTacticPRE(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractTacticPRE <- function(source.url = "https://attack.mitre.org/pre-attack/index.php/Adversary_OPSEC") {
  doc <- xml2::read_html(source.url)

  # Parse headers as list of nodes
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]')
  xpath <- sprintf("//p[count(preceding-sibling::h2)=%d]", seq_along(headlines) - 1)

  df <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                   rvest::html_text, trim = TRUE),
                                        paste, collapse = "\n")
                         ,
                         rvest::html_text(rvest::html_node(headlines, "span")))
  df <- as.data.frame(t(df[df != ""]), stringsAsFactors = FALSE)

  # Detect deprecated tactic
  deprecated <- "Deprecated" %in% rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table/th'))

  tactic <- data.frame(tactic.id = stringr::str_split(source.url, "/")[[1]][length(stringr::str_split(source.url, "/")[[1]])],
                       tactic.descr = df[,1],
                       deprecated = deprecated,
                       stringsAsFactors = FALSE)

  # Extract related techniques
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr[@data-row-number]")

  tech.id <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a/@title")))
  tech.url <- sapply(tech.id, function(x) paste("https://attack.mitre.org/pre-attack/index.php/", x, sep = ""))
  names(tech.url) <- NULL
  tech.id <- as.character(sapply(tech.id, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])]))
  tech.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]")))
  tech.descr <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[3]")))

  # Build tactic raw data.frame
  df <- data.frame(id = rep(tactic$tactic.id, length(tech.name)),
                   description = rep(tactic$tactic.descr, length(tech.name)),
                   deprecated = rep(tactic$deprecated, length(tech.name)),
                   technique.id = tech.id,
                   technique.name = tech.name,
                   technique.desc = tech.descr,
                   technique.url = tech.url,
                   stringsAsFactors = FALSE)

  return(df)
}

ParseTacticsEnt <- function(verbose = TRUE) {
  if (verbose) print("[ENT]  - Processing Tactics basic information...")
  source.url <- "https://attack.mitre.org/wiki/Category:Tactic"
  doc <- xml2::read_html(source.url)

  t.list <- rvest::html_nodes(x = doc, css = "#mw-pages > div > div > div > ul > li > a")
  df.basic <- as.data.frame(t(as.matrix(as.data.frame(rvest::html_attrs(t.list)))),
                            row.names = FALSE, stringsAsFactors = FALSE)
  df.basic$id <- sapply(stringr::str_split(df.basic$href, "/"), function(x) x[3])
  df.basic$href <- sapply(df.basic$href, function(x) paste("https://attack.mitre.org", x, sep = ""))
  names(df.basic) <- c("source", "name", "id")

  df.basic <- df.basic[, c("id", "name", "source")]

  if (verbose) print("[ENT]  - Processing Tactics details and relationships...")
  df <- data.frame(id = character(),
                   description = character(),
                   deprecated = character(),
                   source = character(),
                   technique.id = character(),
                   technique.name = character(),
                   technique.desc = character(),
                   technique.url = character(),
                   stringsAsFactors = FALSE)

  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  for (src.url in unique(df.basic$source)) {
    df <- rbind(df, ExtractTacticEnt(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractTacticEnt <- function(source.url = "https://attack.mitre.org/wiki/Collection") {
  doc <- xml2::read_html(source.url)

  # Parse headers as list of nodes
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]')
  xpath <- sprintf("//p[count(preceding-sibling::h2)=%d]", seq_along(headlines) - 1)

  df <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                   rvest::html_text, trim = TRUE),
                                        paste, collapse = "\n")
                         ,
                         rvest::html_text(rvest::html_node(headlines, ".mw-headline")))
  df <- as.data.frame(t(df[df != ""]), stringsAsFactors = FALSE)

  # Detect deprecated tactic
  deprecated <- "Deprecated" %in% rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table/th'))

  tactic <- data.frame(id = stringr::str_split(source.url, "/")[[1]][length(stringr::str_split(source.url, "/")[[1]])],
                       description = df[,2],
                       deprecated = deprecated,
                       stringsAsFactors = FALSE)

  # Extract related techniques
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr[@data-row-number]")

  tech.id <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a/@title")))
  tech.url <- sapply(tech.id, function(x) paste("https://attack.mitre.org/wiki/", x, sep = ""))
  names(tech.url) <- NULL
  tech.id <- as.character(sapply(tech.id, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])]))
  tech.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]")))
  tech.descr <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[3]")))

  # Build tactic raw data.frame
  df <- data.frame(id = rep(tactic$id, length(tech.name)),
                   description = rep(tactic$description, length(tech.name)),
                   deprecated = rep(tactic$deprecated, length(tech.name)),
                   technique.id = tech.id,
                   technique.name = tech.name,
                   technique.desc = tech.descr,
                   technique.url = tech.url,
                   stringsAsFactors = FALSE)

  return(tactic)
}

ParseTacticsMob <- function(verbose = TRUE) {
  if (verbose) print("[MOB]  - Processing Pre-Exploit Tactics basic information...")
  source.url <- "https://attack.mitre.org/mobile/index.php/Category:Pre-Exploit_Tactic"
  doc <- xml2::read_html(source.url)
  t.list <- rvest::html_nodes(x = doc, xpath = '//*[@id="mw-pages"]/div/ul/li')
  tactic.id <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./a/@href"), trim = TRUE))
  tactic.url <- sapply(tactic.id, function(x) paste("https://attack.mitre.org", x, sep = ""))
  names(tactic.url) <- NULL
  tactic.id <- as.character(sapply(tactic.id, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])]))
  tactic.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./a/@title"), trim = TRUE))
  df.basic.pre.exploit <- data.frame(id = tactic.id,
                                     name = tactic.name,
                                     source = tactic.url,
                                     tactic.type = rep("Pre-Adversary Device Access", length(tactic.id)),
                                     stringsAsFactors = FALSE)

  if (verbose) print("[MOB]  - Processing Post-Exploit Tactics basic information...")
  source.url <- "https://attack.mitre.org/mobile/index.php/Category:Tactic"
  doc <- xml2::read_html(source.url)
  t.list <- rvest::html_nodes(x = doc, xpath = '//*[@id="mw-pages"]/div/div/div/ul/li')
  tactic.id <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./a/@href"), trim = TRUE))
  tactic.url <- sapply(tactic.id, function(x) paste("https://attack.mitre.org", x, sep = ""))
  names(tactic.url) <- NULL
  tactic.id <- as.character(sapply(tactic.id, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])]))
  tactic.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./a/@title"), trim = TRUE))
  df.basic.common <- data.frame(id = tactic.id,
                                name = tactic.name,
                                source = tactic.url,
                                tactic.type = rep("Post-Adversary Device Access", length(tactic.id)),
                                stringsAsFactors = FALSE)

  if (verbose) print("[MOB]  - Processing Off-Device Tactics basic information...")
  source.url <- "https://attack.mitre.org/mobile/index.php/Category:Off_Device_Tactic"
  doc <- xml2::read_html(source.url)
  t.list <- rvest::html_nodes(x = doc, xpath = '//*[@id="mw-pages"]/div/ul/li')
  tactic.id <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./a/@href"), trim = TRUE))
  tactic.url <- sapply(tactic.id, function(x) paste("https://attack.mitre.org", x, sep = ""))
  names(tactic.url) <- NULL
  tactic.id <- as.character(sapply(tactic.id, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])]))
  tactic.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./a/@title"), trim = TRUE))
  df.basic.off.device <- data.frame(id = tactic.id,
                                    name = tactic.name,
                                    source = tactic.url,
                                    tactic.type = rep("Without Adversary Device Access", length(tactic.id)),
                                    stringsAsFactors = FALSE)

  df.basic <- rbind(df.basic.pre.exploit, df.basic.common, df.basic.off.device)

  if (verbose) print("[MOB]  - Processing Tactics details and relationships...")
  df <- data.frame(id = character(),
                   description = character(),
                   source = character(),
                   stringsAsFactors = FALSE)

  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  for (src.url in unique(df.basic$source)) {
    df <- rbind(df, ExtractTacticMob(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractTacticMob <- function(source.url = "https://attack.mitre.org/mobile/index.php/App_Delivery_via_Authorized_App_Store") {
  doc <- xml2::read_html(source.url)

  # Detect deprecated tactic
  deprecated <- "Deprecated" %in% rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table/th'))

  tactic.id <- stringr::str_split(source.url, "/")[[1]]
  tactic.id <- tactic.id[length(tactic.id)]

  # Parse headers as list of nodes
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]|//*[self::h1]')
  xpath <- sprintf("//p[count(preceding-sibling::h1)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h1)=%d] | //p[count(preceding-sibling::h2)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h2)=%d]",
                   seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1)
  tactic <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                   rvest::html_text, trim = TRUE),
                                        paste, collapse = "\n")
                         ,
                         rvest::html_text(rvest::html_node(headlines, ".mw-headline")))
  tactic <- as.data.frame(t(tactic[tactic != ""]), stringsAsFactors = FALSE)
  tactic <- tactic[,!is.na(names(tactic))]
  names(tactic) <- c("description", "techniques.header")
  tactic$id <- rep(tactic.id, nrow(tactic))
  tactic <- tactic[, c("id", "description")]
  tactic$source <- rep(source.url, nrow(tactic))
  tactic$deprecated <- deprecated

  # Extract related techniques
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr[@data-row-number]")

  tech.id <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a/@title")))
  tech.url <- sapply(tech.id, function(x) paste("https://attack.mitre.org/mobile/index.php/", x, sep = ""))
  names(tech.url) <- NULL
  tech.id <- as.character(sapply(tech.id, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])]))
  tech.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]")))
  tech.descr <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[3]")))

  # Build tactic raw data.frame
  tactic <- data.frame(id = rep(tactic$id, length(tech.id)),
                       description = rep(tactic$description, length(tech.id)),
                       deprecated = rep(tactic$deprecated, length(tech.id)),
                       technique.id = tech.id,
                       technique.name = tech.name,
                       technique.desc = tech.descr,
                       technique.url = tech.url,
                       stringsAsFactors = FALSE)

  return(tactic)
}

#############
# Techniques
##

ParseTechniquesPRE <- function(verbose = TRUE) {
  if (verbose) print("[PRE]  - Processing Techniques basic information...")
  source.url <- "https://attack.mitre.org/pre-attack/index.php/All_Techniques"
  doc <- xml2::read_html(source.url)

  # Extract tactic and techniques relationship
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  tech.id <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[3]"), trim = T))
  tech.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  tech.url <- sapply(t.list, function(x) paste("https://attack.mitre.org",
                                                       rvest::html_text(rvest::html_nodes(x,
                                                                                          xpath = "./td[1]/a/@href"),
                                                                        trim = T),
                                                       sep = ""))
  tech.descr <- sapply(t.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[4]")),
                                                                           pattern = '>(.*?)</td',
                                                                           proto = data.frame(chr = character()))$chr))

  df.basic <- data.frame(id = tech.id,
                         name = tech.name,
                         description = tech.descr,
                         source = tech.url,
                         stringsAsFactors = FALSE)

  if (verbose) print("[PRE]  - Processing Techniques details and relationships...")
  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  df <- data.frame(ID = character(),
                   Tactic = character(),
                   Definition = character(),
                   Detection = character(),
                   stringsAsFactors = FALSE)

  for (src.url in unique(df.basic$source)) {
    df <- plyr::rbind.fill(df, ExtractTechniquePRE(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  # Tidy data
  good <- names(which(apply(df, 2, function(x) sum(is.na(x))) < nrow(df.basic)/2))
  df <- dplyr::select(df, good)
  names(df) <- stringr::str_replace_all(tolower(names(df)), " ", ".")

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractTechniquePRE <- function(source.url = "https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1043") {
  doc <- xml2::read_html(source.url)

  xml2::xml_remove(rvest::html_nodes(doc, ".scite-content"))
  xml2::xml_remove(rvest::html_nodes(doc, ".toc"))

  # Detect Deprecated
  deprecated <- FALSE
  if (length(rvest::html_nodes(x = doc, xpath = '//*[@id="DEPRECATION_WARNING"]/parent::*')) > 0) {
    xml2::xml_remove(rvest::html_nodes(doc, xpath = '//*[@id="DEPRECATION_WARNING"]/parent::*'))
    deprecated <- TRUE
  }

  # Parse headers as list of nodes
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]|//*[self::h1]')
  xpath <- sprintf("//p[count(preceding-sibling::h1)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h1)=%d] | //p[count(preceding-sibling::h2)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h2)=%d]",
                   seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1)

  df <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                   as.character, trim = TRUE),
                                        paste, collapse = "\n")
                         ,
                         rvest::html_text(headlines))
  df <- as.data.frame(t(df[df != ""]), stringsAsFactors = FALSE)
  df$deprecated <- rep(deprecated, nrow(df))

  df2 <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/td'), trim = T)
  names(df2) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/th[@scope="row"]'), trim = T)
  df2 <- as.data.frame(t(df2), stringsAsFactors = F)

  df <- cbind.data.frame(df2, df)

  return(df)
}

ParseTechniquesEnt <- function(verbose = TRUE) {
  if (verbose) print("[ENT]  - Processing Techniques basic information...")
  source.url <- "https://attack.mitre.org/wiki/All_Techniques"
  doc <- xml2::read_html(source.url)

  # Extract techniques basic information
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  tech.id <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[3]"), trim = T))
  tech.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  tech.url <- sapply(t.list, function(x) paste("https://attack.mitre.org",
                                               rvest::html_text(rvest::html_nodes(x,
                                                                                  xpath = "./td[1]/a/@href"),
                                                                trim = T),
                                               sep = ""))

  df.basic <- data.frame(id = tech.id,
                         name = tech.name,
                         source = tech.url,
                         stringsAsFactors = FALSE)

  if (verbose) print("[ENT]  - Processing Techniques details and relationships...")
  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  df <- data.frame(ID = character(),
                   Tactic = character(),
                   Definition = character(),
                   Detection = character(),
                   stringsAsFactors = FALSE)

  for (src.url in unique(df.basic$source)) {
    df <- plyr::rbind.fill(df, ExtractTechniqueEnt(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  # Tidy data
  good <- names(which(apply(df, 2, function(x) sum(is.na(x))) < nrow(df.basic)/2))
  df <- dplyr::select(df, good)
  names(df) <- tolower(names(df))

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractTechniqueEnt <- function(source.url = "https://attack.mitre.org/wiki/Technique/T1156") {
  doc <- xml2::read_html(source.url)
  # Parse headers as list of nodes
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]|//*[self::h1]')
  xpath <- sprintf("//p[count(preceding-sibling::h1)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h1)=%d] | //p[count(preceding-sibling::h2)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h2)=%d]",
                   seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1)

  df <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                   as.character, trim = TRUE),
                                        paste, collapse = "\n")
                         ,
                         rvest::html_text(headlines))
  df <- as.data.frame(t(df[df != ""]), stringsAsFactors = FALSE)

  df2 <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/td'), trim = T)
  names(df2) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/th[@scope="row"]'), trim = T)
  df2 <- as.data.frame(t(df2), stringsAsFactors = F)

  df <- cbind.data.frame(df2, df)

  tech.name <- rvest::html_text(rvest::html_node(x = doc, css = ".firstHeading"))
  df$description <- df[, tech.name]
  df <- df[, !(names(df) %in% tech.name)]

  return(df)

}

ParseTechniquesMob <- function(verbose = TRUE) {
  if (verbose) print("[MOB]  - Processing Techniques basic information...")
  source.url <- "https://attack.mitre.org/mobile/index.php/All_Techniques"
  doc <- xml2::read_html(source.url)

  # Extract techniques basic information
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  tech.ids <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[5]"), trim = T))
  tech.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]"), trim = T))
  tech.urls <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a/@title"), trim = T))
  tech.urls <- sapply(tech.urls, function(x) paste("https://attack.mitre.org/mobile/index.php/", x, sep = ""))
  names(tech.urls) <- NULL
  tech.descr <- sapply(t.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[6]")),
                                                                       pattern = '>(.*?)</td',
                                                                       proto = data.frame(chr = character()))$chr))

  df.basic <- data.frame(id = tech.ids,
                         name = tech.name,
                         description = tech.descr,
                         source = tech.urls,
                         stringsAsFactors = FALSE)

  if (verbose) print("[MOB]  - Processing Techniques details and relationships...")
  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  df <- data.frame(ID = character(),
                   Tactic = character(),
                   Platform = character(),
                   Detection = character(),
                   stringsAsFactors = FALSE)

  for (src.url in unique(df.basic$source)) {
    df <- plyr::rbind.fill(df, ExtractTechniqueMob(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  # Tidy data
  good <- names(which(apply(df, 2, function(x) sum(is.na(x))) < nrow(df.basic)*0.9))
  df <- dplyr::select(df, good)
  names(df) <- stringr::str_replace_all(tolower(names(df)), " ", ".")

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractTechniqueMob <- function(source.url = "https://attack.mitre.org/mobile/index.php/Technique/MOB-T1046") {
  doc <- xml2::read_html(source.url)
  xml2::xml_remove(rvest::html_nodes(doc, ".toc"))

  # Parse headers as list of nodes
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]|//*[self::h1]')
  xpath <- sprintf("//p[count(preceding-sibling::h1)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h1)=%d] | //p[count(preceding-sibling::h2)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h2)=%d]",
                   seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1)

  df <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                   as.character, trim = TRUE),
                                        paste, collapse = "\n")
                         ,
                         rvest::html_text(headlines))
  df <- as.data.frame(t(df[df != ""]), stringsAsFactors = FALSE)

  df2 <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/td'), trim = T)
  names(df2) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/th[@scope="row"]'), trim = T)
  df2 <- as.data.frame(t(df2), stringsAsFactors = F)

  df <- cbind.data.frame(df2, df)

  return(df)
}

#############
# Software
##

ParseSoftwareEnt <- function(verbose = TRUE) {
  if (verbose) print("[ENT]  - Processing Software basic information...")
  source.url <- "https://attack.mitre.org/wiki/Software"
  doc <- xml2::read_html(source.url)

  # Extract basic information
  s.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  software.ids <- sapply(s.list, function(x) rvest::html_text(rvest::html_nodes(x,xpath = "./td[1]/a/@href"), trim = T))
  software.urls <- sapply(software.ids, function(x) paste("https://attack.mitre.org", x, sep = ""))
  names(software.urls) <- NULL
  software.ids <- sapply(software.ids, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])])
  names(software.ids) <- NULL
  software.names <- sapply(s.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  software.descr <- sapply(s.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[3]")),
                                                                       pattern = '>(.*?)</td',
                                                                       proto = data.frame(chr = character()))$chr))

  df.basic <- data.frame(id = software.ids,
                         name = software.names,
                         description = software.descr,
                         source = software.urls,
                         stringsAsFactors = FALSE)

  if (verbose) print("[ENT]  - Processing Software details and relationships...")
  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  df <- data.frame(ID = character(),
                   Name = character(),
                   Aliases = character(),
                   stringsAsFactors = FALSE)

  for (src.url in unique(df.basic$source)) {
    df <- plyr::rbind.fill(df, ExtractSoftwareEnt(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  # Tidy data
  good <- names(which(apply(df, 2, function(x) sum(is.na(x))) < nrow(df)*0.9))
  df <- dplyr::select(df, good)
  names(df) <- tolower(names(df))

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractSoftwareEnt <- function(source.url = "https://attack.mitre.org/wiki/Software/S0045") {
  doc <- xml2::read_html(source.url)
  # Remove toc
  xml2::xml_remove(rvest::html_nodes(doc, ".toc"))
  # Parse headers as list of nodes
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]|//*[self::h1]')
  xpath <- sprintf("//p[count(preceding-sibling::h1)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h1)=%d] | //p[count(preceding-sibling::h2)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h2)=%d]",
                   seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1)
  df <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                   as.character, trim = TRUE),
                                        paste, collapse = "\n")
                         ,
                         rvest::html_text(headlines))
  df <- as.data.frame(t(df[df != ""]), stringsAsFactors = FALSE)

  # Detect relationship on headers: techniques used and groups
  if (c("Techniques Used") %in% names(df)) {
    tup <- xpath[which(names(df) %in% "Techniques Used")]
  }
  if (c("Groups") %in% names(df)) {
    gup <- xpath[which(names(df) %in% "Groups")]
  }

  df2 <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/td'), trim = T)
  names(df2) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/th[@scope="row"]'), trim = T)
  df2 <- as.data.frame(t(df2), stringsAsFactors = F)

  df <- cbind.data.frame(df2, df)

  # Extract details for techniques used
  if (c("Techniques Used") %in% names(df)) {
    t.used <- rvest::xml_nodes(doc, xpath = tup)
    tech.used.id <- sapply(t.used, function(x) stringr::str_extract(string = as.character(x), pattern = "T\\d\\d\\d\\d"))
    tech.used.id <- tech.used.id[!is.na(tech.used.id)]
    df$tech.used <- paste(tech.used.id, collapse = ",")
    tech.used.desc <- sapply(t.used, function(x) rvest::html_text(x, trim = T))
    tech.used.desc <- tech.used.desc[which(sapply(tech.used.desc, nchar) > 3)]
    tech.used.name <- sapply(t.used, function(x) rvest::html_text(rvest::html_node(x, xpath = './/a'), trim = T))
    tech.used.name <- tech.used.name[!is.na(tech.used.name)]

    techu <- data.frame(tech.used.id = tech.used.id,
                        tech.used.name = tech.used.name,
                        tech.used.desc = tech.used.desc,
                        stringsAsFactors = F)
    # df <- dplyr::select(df, -`Techniques Used`)
    df <- tidyr::separate_rows(df, tech.used, sep = ",")
    df <- dplyr::left_join(df, techu, by = c("tech.used" = "tech.used.id"))
  } else {
    df$tech.used <- NA
  }

  # Extract details for groups using this software
  if (c("Groups") %in% names(df)) {
    group.used.id <- rvest::xml_nodes(doc, xpath = gup)
    group.used.id <- sapply(group.used.id, function(x) stringr::str_extract(string = as.character(x), pattern = "G\\d\\d\\d\\d"))
    group.used.id <- group.used.id[!is.na(group.used.id)]
    df$groups.using <- paste(group.used.id, collapse = ",")
    # df <- dplyr::select(df, -Groups)
    df <- tidyr::separate_rows(df, groups.using, sep = ",")
  } else {
    df$groups.using <- NA
  }

  return(df)
}

ParseSoftwareMob <- function(verbose = TRUE) {
  if (verbose) print("[MOB]  - Processing Software basic information...")
  source.url <- "https://attack.mitre.org/mobile/index.php/Software"
  doc <- xml2::read_html(source.url)

  # Extract basic information
  s.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  software.ids <- sapply(s.list, function(x) rvest::html_text(rvest::html_nodes(x,xpath = "./td[1]/a/@href"), trim = T))
  software.urls <- sapply(software.ids, function(x) paste("https://attack.mitre.org", x, sep = ""))
  names(software.urls) <- NULL
  software.ids <- sapply(software.ids, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])])
  names(software.ids) <- NULL
  software.names <- sapply(s.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  software.descr <- sapply(s.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[3]")),
                                                                       pattern = '>(.*?)</td',
                                                                       proto = data.frame(chr = character()))$chr))

  df.basic <- data.frame(id = software.ids,
                         name = software.names,
                         description = software.descr,
                         source = software.urls,
                         stringsAsFactors = FALSE)

  if (verbose) print("[MOB]  - Processing Software details and relationships...")
  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  df <- data.frame(ID = character(),
                   Aliases = character(),
                   Type = character(),
                   stringsAsFactors = FALSE)

  for (src.url in unique(df.basic$source)) {
    df <- plyr::rbind.fill(df, ExtractSoftwareMob(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  # Tidy data
  good <- c(names(which(apply(df, 2, function(x) sum(is.na(x))) < nrow(df)*0.7)), "groups.using")
  df <- dplyr::select(df, good)
  names(df) <- stringr::str_replace_all(tolower(names(df)), " ", ".")
  df <- dplyr::select(df, -techniques.used)

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractSoftwareMob <- function(source.url = "https://attack.mitre.org/mobile/index.php/Software/MOB-S0026") {
  doc <- xml2::read_html(source.url)
  # Remove toc
  xml2::xml_remove(rvest::html_nodes(doc, ".toc"))
  # Parse headers as list of nodes
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]|//*[self::h1]')
  xpath <- sprintf("//p[count(preceding-sibling::h1)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h1)=%d] | //p[count(preceding-sibling::h2)=%d] | //div[@id='mw-content-text']/ul[count(preceding-sibling::h2)=%d]",
                   seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1, seq_along(headlines) - 1)
  df <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                   as.character, trim = TRUE),
                                        paste, collapse = "\n")
                         ,
                         rvest::html_text(headlines))
  df <- as.data.frame(t(df[df != ""]), stringsAsFactors = FALSE)

  # Detect relationship on headers: techniques used and groups
  if (c("Techniques Used") %in% names(df)) {
    tup <- xpath[which(names(df) %in% "Techniques Used")]
  }
  if (c("Groups") %in% names(df)) {
    gup <- xpath[which(names(df) %in% "Groups")]
  }

  df2 <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/td'), trim = T)
  names(df2) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/th[@scope="row"]'), trim = T)
  df2 <- as.data.frame(t(df2), stringsAsFactors = F)

  df <- cbind.data.frame(df2, df)

  # Extract details for techniques used
  if (c("Techniques Used") %in% names(df)) {
    t.used <- rvest::xml_nodes(doc, xpath = tup)
    tech.used.id <- sapply(t.used, function(x) stringr::str_extract(string = as.character(x), pattern = "T\\d\\d\\d\\d"))
    tech.used.id <- tech.used.id[!is.na(tech.used.id)]
    df$tech.used <- paste(tech.used.id, collapse = ",")
    tech.used.desc <- sapply(t.used, function(x) rvest::html_text(x, trim = T))
    tech.used.desc <- tech.used.desc[which(sapply(tech.used.desc, nchar) > 3)]
    tech.used.name <- sapply(t.used, function(x) rvest::html_text(rvest::html_node(x, xpath = './/a'), trim = T))
    tech.used.name <- tech.used.name[!is.na(tech.used.name)]

    techu <- data.frame(tech.used.id = tech.used.id,
                        tech.used.name = tech.used.name,
                        tech.used.desc = tech.used.desc,
                        stringsAsFactors = F)
    # df <- dplyr::select(df, -`Techniques Used`)
    df <- tidyr::separate_rows(df, tech.used, sep = ",")
    df <- dplyr::left_join(df, techu, by = c("tech.used" = "tech.used.id"))
  } else {
    df$tech.used <- NA
  }

  # Extract details for groups using this software
  if (c("Groups") %in% names(df)) {
    group.used.id <- rvest::xml_nodes(doc, xpath = gup)
    group.used.id <- sapply(group.used.id, function(x) stringr::str_extract(string = as.character(x), pattern = "G\\d\\d\\d\\d"))
    group.used.id <- group.used.id[!is.na(group.used.id)]
    df$groups.using <- paste(group.used.id, collapse = ",")
    # df <- dplyr::select(df, -Groups)
    df <- tidyr::separate_rows(df, groups.using, sep = ",")
  } else {
    df$groups.using <- NA
  }

  return(df)
}

#############
# Groups
##

ParseGroupsPRE <- function(verbose = TRUE) {
  if (verbose) print("[PRE]  - Processing Groups basic information...")
  source.url <- "https://attack.mitre.org/pre-attack/index.php/Groups"
  doc <- xml2::read_html(source.url)

  # Extract basic information
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  group.ids <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x,xpath = "./td[1]/a/@href"), trim = T))
  group.ids <- sapply(group.ids, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])])
  names(group.ids) <- NULL
  group.names <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  group.urls <- sapply(t.list, function(x) paste("https://attack.mitre.org",
                                                  rvest::html_text(rvest::html_nodes(x,
                                                                                     xpath = "./td[1]/a/@href"),
                                                                   trim = T),
                                                  sep = ""))
  groups.aliases <- sapply(t.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[2]")),
                                                                     pattern = '>(.*?)</td',
                                                                     proto = data.frame(chr = character()))$chr))
  groups.descr <- sapply(t.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[3]")),
                                                                     pattern = '>(.*?)</td',
                                                                     proto = data.frame(chr = character()))$chr))

  df.basic <- data.frame(id = group.ids,
                         name = group.names,
                         source = group.urls,
                         aliases = groups.aliases,
                         description = groups.descr,
                         stringsAsFactors = FALSE)

  if (verbose) print("[PRE]  - Processing Groups details and relationships...")
  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  df <- data.frame(id = character(),
                   tech.name = character(),
                   tactic.name = character(),
                   tech.used = character(),
                   stringsAsFactors = FALSE)

  for (src.url in unique(df.basic$source)) {
    df <- plyr::rbind.fill(df, ExtractGroupPRE(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractGroupPRE <- function(source.url = "https://attack.mitre.org/pre-attack/index.php/Group/PRE-G0006") {
  doc <- xml2::read_html(source.url)

  xml2::xml_remove(rvest::html_nodes(doc, ".scite-content"))
  xml2::xml_remove(rvest::html_nodes(doc, ".toc"))

  # Detect Deprecated
  deprecated <- FALSE
  if (length(rvest::html_nodes(x = doc, xpath = '//*[@id="DEPRECATION_WARNING"]/parent::*')) > 0) {
    xml2::xml_remove(rvest::html_nodes(doc, xpath = '//*[@id="DEPRECATION_WARNING"]/parent::*'))
    deprecated <- TRUE
  }

  tech.raw <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id=\"mw-content-text\"]/ul/li'), trim = TRUE)
  tech.raw <- stringr::str_split(string = tech.raw, pattern = " - ")
  tech.name <- sapply(tech.raw,
                      function(x) {
                        stringr::str_replace(string = stringr::str_extract(string = x[1], pattern = ".*\\("), pattern = " \\(", replacement = "")[[1]]
                      })
  tactic.name <- sapply(tech.raw,
                      function(x) {
                        stringr::str_replace_all(string = stringr::str_extract(string = x[1], pattern = "\\(.*\\)"), pattern = "\\)|\\(", replacement = "")[[1]]
                      })
  tech.used <- sapply(tech.raw, function(x) x[2])

  group.id <- stringr::str_split(source.url, "/")[[1]]
  group.id <- group.id[length(group.id)]

  df <- data.frame(id = rep(group.id, length(tech.name)),
                   tech.name = tech.name,
                   tactic.name = tactic.name,
                   tech.used = tech.used,
                   stringsAsFactors = FALSE)

  return(df)
}

ParseGroupsEnt <- function(verbose = TRUE) {
  if (verbose) print("[ENT]  - Processing Groups basic information...")
  source.url <- "https://attack.mitre.org/wiki/Groups"
  doc <- xml2::read_html(source.url)

  # Extract basic information
  g.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  group.ids <- sapply(g.list, function(x) rvest::html_text(rvest::html_nodes(x,xpath = "./td[1]/a/@href"), trim = T))
  group.urls <- sapply(group.ids, function(x) paste("https://attack.mitre.org", x, sep = ""))
  names(group.urls) <- NULL
  group.ids <- sapply(group.ids, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])])
  names(group.ids) <- NULL
  group.names <- sapply(g.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  group.aliases <- sapply(g.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[2]")),
                                                                       pattern = '>(.*?)</td',
                                                                       proto = data.frame(chr = character()))$chr))
  group.descr <- sapply(g.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[3]")),
                                                                     pattern = '>(.*?)</td',
                                                                     proto = data.frame(chr = character()))$chr))

  df.basic <- data.frame(id = group.ids,
                         name = group.names,
                         source = group.urls,
                         aliases = group.aliases,
                         description = group.descr,
                         stringsAsFactors = FALSE)

  if (verbose) print("[ENT]  - Processing Groups details and relationships...")
  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  df <- data.frame(id = character(),
                   stringsAsFactors = FALSE)

  for (src.url in unique(df.basic$source)) {
    df <- plyr::rbind.fill(df, ExtractGroupEnt(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractGroupEnt <- function(source.url = "https://attack.mitre.org/wiki/Group/G0007") {
  doc <- xml2::read_html(source.url)

  xml2::xml_remove(rvest::html_nodes(doc, ".toc"))
  xml2::xml_remove(rvest::html_nodes(doc, "#mw-content-text > ul > li > span > a"))

  # Detect Deprecated
  deprecated <- FALSE
  if (length(rvest::html_nodes(x = doc, xpath = '//*[@id="DEPRECATION_WARNING"]/parent::*')) > 0) {
    xml2::xml_remove(rvest::html_nodes(doc, xpath = '//*[@id="DEPRECATION_WARNING"]/parent::*'))
    deprecated <- TRUE
  }

  group.id <- stringr::str_split(source.url, "/")[[1]]
  group.id <- group.id[length(group.id)]
  headlines <- rvest::html_text(rvest::html_nodes(doc, xpath = '//h2[span[@id!="Navigation menu"]]'))

  # Extract techniques used by the group
  if ("Techniques Used" %in% headlines) {
    if ((which(headlines == "Techniques Used") + 1) >= length(headlines)) {
      # There are more info after Techniques
      xpath <- paste('//h2[span[@id="Techniques_Used"]]',
                     '/following-sibling::ul[following::h2[span[@id="',
                     headlines[which(headlines == "Techniques Used") + 1],
                     '"]]]', sep = "")
    } else {
      # References is the following info
      xpath <- paste('//h2[span[@id="Techniques Used"]]',
                     '/following-sibling::ul[following::h2[span[@id!="Techniques Used"]]]',
                     ' | ',
                     '//h2[span[@id="Techniques Used"]]/',
                     'following-sibling::ul[following::div]',
                     sep = "")
    }
    tech.raw <- rvest::html_nodes(x = doc, xpath = xpath)
    tech.ids <- sapply(tech.raw, function(x) rvest::html_text(rvest::html_nodes(x, xpath = './li/a[1]/@title'), trim = TRUE))
    tech.ids <- stringr::str_replace_all(tech.ids, "Technique/", "")
    tech.names <- sapply(tech.raw, function(x) rvest::html_text(rvest::html_nodes(x, xpath = './li/a[1]'), trim = TRUE))
    tech.used <- sapply(tech.raw, function(x) rvest::html_text(rvest::html_nodes(x, xpath = './li'),trim = TRUE))
    df.tech <- data.frame(id = rep(group.id, length(tech.names)),
                          tech.id = tech.ids,
                          tech.name = tech.names,
                          tech.used = tech.used,
                          stringsAsFactors = FALSE)
  } else {
    df.tech <- NA
  }

  # Extract software used by the group
  if ("Software" %in% headlines) {
    if ((which(headlines == "Software") + 1) <= length(headlines)) {
      # There are more info after Software
      xpath <- paste('//h2[span[@id="Software"]]',
                     '/following-sibling::ul[following::h2[span[@id="',
                     headlines[which(headlines == "Software") + 1],
                     '"]]]', sep = "")
    } else {
      # References is the following info
      xpath <- paste('//h2[span[@id="Software"]]',
                     '/following-sibling::ul[following::h2[span[@id!="Software"]]]',
                     ' | ',
                     '//h2[span[@id="Software"]]/',
                     'following-sibling::ul[following::div[@class="scite-content"]]',
                     sep = "")
    }
    soft.raw <- rvest::html_nodes(x = doc, xpath = xpath)
    soft.ids <- sapply(soft.raw, function(x) rvest::html_text(rvest::html_nodes(x, xpath = './li/a[1]/@title'), trim = TRUE))
    soft.ids <- stringr::str_replace_all(soft.ids, "Software/", "")
    df.soft <- data.frame(id = rep(group.id, length(soft.ids)),
                          soft.id = soft.ids,
                          stringsAsFactors = FALSE)
  } else {
    df.soft <- NA
  }

  df <- data.frame(id = group.id, stringsAsFactors = FALSE)
  if (is.data.frame(df.tech)) {
    df <- dplyr::left_join(df, df.tech, by = c("id"))
  }
  if (is.data.frame(df.soft)) {
    df <- dplyr::left_join(df, df.soft, by = c("id"))
  }

  return(df)
}

ParseGroupsMob <- function(verbose = TRUE) {
  if (verbose) print("[MOB]  - Processing Groups basic information...")
  source.url <- "https://attack.mitre.org/mobile/index.php/Groups"
  doc <- xml2::read_html(source.url)

  # Extract basic information
  g.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  group.ids <- sapply(g.list, function(x) rvest::html_text(rvest::html_nodes(x,xpath = "./td[1]/a/@href"), trim = T))
  group.urls <- sapply(group.ids, function(x) paste("https://attack.mitre.org", x, sep = ""))
  names(group.urls) <- NULL
  group.ids <- sapply(group.ids, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])])
  names(group.ids) <- NULL
  group.names <- sapply(g.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  group.aliases <- sapply(g.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[2]")),
                                                                      pattern = '>(.*?)</td',
                                                                      proto = data.frame(chr = character()))$chr))
  group.descr <- sapply(g.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[3]")),
                                                                    pattern = '>(.*?)</td',
                                                                    proto = data.frame(chr = character()))$chr))

  df.basic <- data.frame(id = group.ids,
                         name = group.names,
                         source = group.urls,
                         aliases = group.aliases,
                         description = group.descr,
                         stringsAsFactors = FALSE)

  if (verbose) print("[MOB]  - Processing Groups details and relationships...")
  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  df <- data.frame(id = character(),
                   stringsAsFactors = FALSE)

  for (src.url in unique(df.basic$source)) {
    df <- plyr::rbind.fill(df, ExtractGroupMob(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractGroupMob <- function(source.url = "https://attack.mitre.org/mobile/index.php/Group/MOB-G0007") {
  doc <- xml2::read_html(source.url)

  xml2::xml_remove(rvest::html_nodes(doc, ".toc"))
  xml2::xml_remove(rvest::html_nodes(doc, "#mw-content-text > ul > li > span > a"))

  # Detect Deprecated
  deprecated <- FALSE
  if (length(rvest::html_nodes(x = doc, xpath = '//*[@id="DEPRECATION_WARNING"]/parent::*')) > 0) {
    xml2::xml_remove(rvest::html_nodes(doc, xpath = '//*[@id="DEPRECATION_WARNING"]/parent::*'))
    deprecated <- TRUE
  }

  group.id <- stringr::str_split(source.url, "/")[[1]]
  group.id <- group.id[length(group.id)]
  headlines <- rvest::html_text(rvest::html_nodes(doc, xpath = '//h2[span[@id!="Navigation menu"]]'))

  # Extract software used by the group
  if ("Software" %in% headlines) {
    if ((which(headlines == "Software") + 1) <= length(headlines)) {
      # There are more info after Software
      xpath <- paste('//h2[span[@id="Software"]]',
                     '/following-sibling::ul[following::h2[span[@id="',
                     headlines[which(headlines == "Software") + 1],
                     '"]]]', sep = "")
    } else {
      # References is the following info
      xpath <- paste('//h2[span[@id="Software"]]',
                     '/following-sibling::ul[following::h2[span[@id!="Software"]]]',
                     ' | ',
                     '//h2[span[@id="Software"]]/',
                     'following-sibling::ul[following::div]',
                     sep = "")
    }
    soft.raw <- rvest::html_nodes(x = doc, xpath = xpath)
    soft.ids <- sapply(soft.raw, function(x) rvest::html_text(rvest::html_nodes(x, xpath = './li/a[1]/@title'), trim = TRUE))
    soft.ids <- stringr::str_replace_all(soft.ids, "Software/", "")
    df.soft <- data.frame(id = rep(group.id, length(soft.ids)),
                          soft.id = soft.ids,
                          stringsAsFactors = FALSE)
  } else {
    df.soft <- NA
  }

  df <- data.frame(id = group.id, stringsAsFactors = FALSE)
  if (is.data.frame(df.soft)) {
    df <- dplyr::left_join(df, df.soft, by = c("id"))
  }

  return(df)
}

#############
# Relations
##

ParseRelationsPRE <- function(tactics.raw, techniques.raw, groups.raw, verbose = TRUE) {
  tactics <- dplyr::select(tactics.raw, id, name, technique.id)
  techniques <- dplyr::select(techniques.raw, id, name, tactic)
  groups <- dplyr::select(groups.raw, id, tech.name, tactic.name)

  df <- data.frame(from = character(),
                   to = character(),
                   source = character(),
                   target = character(),
                   info = character(),
                   stringsAsFactors = FALSE)

  # Groups - Techniques
  rg <- dplyr::left_join(groups.raw,
                        unique(dplyr::select(techniques, id, name)),
                        by = c("tech.name" = "name"))
  rg <- dplyr::select(rg, -aliases, -description, -source, -name)
  names(rg) <- c("group.id", "tech.name", "tactic.name", "relation.descr", "tech.id")
  r <- unique(dplyr::select(rg, group.id, tech.id, relation.descr))
  names(r) <- c("from", "to", "info")
  r$source <- rep("group", nrow(r))
  r$target <- rep("technique", nrow(r))
  df <- rbind(df, r)

  # Groups - Tactics
  rg <- dplyr::left_join(rg,
                        unique(dplyr::select(tactics, id, name)),
                        by = c("tactic.name" = "name"))
  names(rg) <- c("group.id", "tech.name", "tactic.name", "relation.descr", "tech.id", "tactic.id")
  r <- unique(dplyr::select(rg, group.id, tactic.id, relation.descr))
  names(r) <- c("from", "to", "info")
  r$source <- rep("group", nrow(r))
  r$target <- rep("tactic", nrow(r))
  df <- rbind(df, r)

  # Techniques - Tactics
  r <- dplyr::left_join(techniques,
                        unique(dplyr::select(tactics, id, name)),
                        by = c("tactic" = "name"))
  names(r) <- c("tech.id", "tech.name", "tactic.name", "tactic.id")
  r <- unique(dplyr::select(r, tech.id, tactic.id))
  names(r) <- c("from", "to")
  r$source <- rep("technique", nrow(r))
  r$target <- rep("tactic", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Tactics - Techniques
  r <- unique(dplyr::select(tactics.raw, id, technique.id, technique.desc))
  names(r) <- c("from", "to", "info")
  r$source <- rep("tactic", nrow(r))
  r$target <- rep("technique", nrow(r))
  df <- rbind(df, r)

  df$domain <- rep("PRE", nrow(df))
  df <- unique(df)

  return(df)
}

ParseRelationsEnt <- function(tactics.raw, techniques.raw, groups.raw, software.raw, verbose = TRUE) {
  tactics <- dplyr::select(tactics.raw, id, name)
  techniques <- dplyr::select(techniques.raw, -source, -mitigation, -description, -contents, -examples)
  groups <- dplyr::select(groups.raw, id, tech.id, tech.used, soft.id)
  software <- dplyr::select(software.raw, id, type, platform, tech.used, groups.using)

  # Expand data.frames: one observation in one row
  names(techniques) <- c("id", "name", "tactic", "platform", "permissions.required", "data.sources")
  techniques <- tidyr::separate_rows(tidyr::separate_rows(tidyr::separate_rows(tidyr::separate_rows(techniques,
                                                                                                    platform, sep = ", "),
                                                                               tactic, sep = ", "),
                                                          `permissions.required`, sep = ", "),
                                     data.sources, sep = ", ")

  df <- data.frame(from = character(),
                   to = character(),
                   source = character(),
                   target = character(),
                   info = character(),
                   stringsAsFactors = FALSE)

  # Techniques - Tactics
  r <- dplyr::left_join(unique(dplyr::select(techniques, id, name, tactic)),
                        tactics,
                        by = c("tactic" = "name"))
  names(r) <- c("tech.id", "tech.name", "tactic.name", "tactic.id")
  r <- unique(dplyr::select(r, tech.id, tactic.id))
  names(r) <- c("from", "to")
  r$source <- rep("technique", nrow(r))
  r$target <- rep("tactic", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Techniques - Platform
  r <- unique(dplyr::select(techniques, id, platform))
  names(r) <- c("from", "to")
  r$source <- rep("technique", nrow(r))
  r$target <- rep("platform", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Techniques - Permissions required
  r <- unique(dplyr::select(techniques, id, permissions.required))
  names(r) <- c("from", "to")
  r$source <- rep("technique", nrow(r))
  r$target <- rep("permissions.required", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Techniques - Data sources
  r <- unique(dplyr::select(techniques, id, data.sources))
  names(r) <- c("from", "to")
  r$source <- rep("technique", nrow(r))
  r$target <- rep("data.sources", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Tactics - Techniques
  # r <- unique(dplyr::select(tactics.raw, id, technique.id, technique.desc))
  # names(r) <- c("from", "to", "info")
  # r$source <- rep("tactic", nrow(r))
  # r$target <- rep("technique", nrow(r))
  # df <- rbind(df, r)

  # Groups - Techniques
  r <- unique(dplyr::select(groups, id, tech.id, tech.used))
  names(r) <- c("from", "to", "info")
  r$source <- rep("group", nrow(r))
  r$target <- rep("technique", nrow(r))
  df <- rbind(df, r)

  # Groups - Software
  r <- unique(dplyr::select(groups, id, soft.id))
  names(r) <- c("from", "to")
  r$source <- rep("group", nrow(r))
  r$target <- rep("software", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Software - Technique
  r <- unique(dplyr::select(software, id, tech.used))
  names(r) <- c("from", "to")
  r$source <- rep("software", nrow(r))
  r$target <- rep("technique", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Software - Groups
  r <- unique(dplyr::select(software, id, groups.using))
  names(r) <- c("from", "to")
  r$source <- rep("software", nrow(r))
  r$target <- rep("groups", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Software - Platform
  r <- unique(dplyr::select(software, id, platform))
  names(r) <- c("from", "to")
  r$source <- rep("software", nrow(r))
  r$target <- rep("platform", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  df$domain <- rep("Enterprise", nrow(df))
  df <- unique(df)

  return(df)
}

ParseRelationsMob <- function(tactics.raw, techniques.raw, groups.raw, software.raw, mitigations.raw, verbose = TRUE) {
  tactics <- dplyr::select(tactics.raw, id, name, technique.id)
  techniques <- dplyr::select(techniques.raw, id, tactic, platform)
  groups <- dplyr::select(groups.raw, id, soft.id)
  software <- dplyr::select(software.raw, id, type, tech.used, groups.using)
  mitigations <- dplyr::select(mitigations.raw, id, tech.id)

  # Expand data.frames: one observation in one row
  techniques <- tidyr::separate_rows(tidyr::separate_rows(techniques,
                                                          platform, sep = ", "),
                                     tactic, sep = ", ")

  df <- data.frame(from = character(),
                   to = character(),
                   source = character(),
                   target = character(),
                   info = character(),
                   stringsAsFactors = FALSE)

  # Tactics - Techniques
  r <- unique(dplyr::select(tactics.raw, id, technique.id, technique.desc))
  names(r) <- c("from", "to", "info")
  r$source <- rep("tactic", nrow(r))
  r$target <- rep("technique", nrow(r))
  df <- rbind(df, r)

  # Groups - Software
  r <- unique(dplyr::select(groups, id, soft.id))
  names(r) <- c("from", "to")
  r$source <- rep("group", nrow(r))
  r$target <- rep("software", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Mitigations - Techniques
  r <- unique(mitigations)
  names(r) <- c("from", "to")
  r$source <- rep("mitigation", nrow(r))
  r$target <- rep("technique", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Software - Technique
  r <- unique(dplyr::select(software, id, tech.used))
  names(r) <- c("from", "to")
  r$source <- rep("software", nrow(r))
  r$target <- rep("technique", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Software - Groups
  r <- unique(dplyr::select(software, id, groups.using))
  names(r) <- c("from", "to")
  r$source <- rep("software", nrow(r))
  r$target <- rep("groups", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Techniques - Tactics
  r <- dplyr::left_join(unique(dplyr::select(techniques, id, tactic)),
                        unique(dplyr::select(tactics, id, name)),
                        by = c("tactic" = "name"))
  names(r) <- c("tech.id", "tactic.name", "tactic.id")
  r <- unique(dplyr::select(r, tech.id, tactic.id))
  names(r) <- c("from", "to")
  r$source <- rep("technique", nrow(r))
  r$target <- rep("tactic", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  # Techniques - Platform
  r <- unique(dplyr::select(techniques, id, platform))
  names(r) <- c("from", "to")
  r$source <- rep("technique", nrow(r))
  r$target <- rep("platform", nrow(r))
  r$info <- rep(NA, nrow(r))
  df <- rbind(df, r)

  df$domain <- rep("MOB", nrow(df))
  df <- unique(df)

  return(df)
}

#############
# Mitigations
##

ParseMitigationsMob <- function(verbose = TRUE) {
  if (verbose) print("[MOB]  - Processing Mitigations basic information...")
  source.url <- "https://attack.mitre.org/mobile/index.php/All_Mitigations"
  doc <- xml2::read_html(source.url)

  # Extract mitigations basic information
  m.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  mitig.ids <- sapply(m.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[2]"), trim = T))
  mitig.name <- sapply(m.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]"), trim = T))
  mitig.urls <- sapply(m.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a/@title"), trim = T))
  mitig.urls <- sapply(mitig.ids, function(x) paste("https://attack.mitre.org/mobile/index.php/Mitigation/", x, sep = ""))
  names(mitig.urls) <- NULL
  mitig.descr <- sapply(m.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[3]")),
                                                                   pattern = '>(.*?)</td',
                                                                   proto = data.frame(chr = character()))$chr))

  df.basic <- data.frame(id = mitig.ids,
                         name = mitig.name,
                         description = mitig.descr,
                         source = mitig.urls,
                         stringsAsFactors = FALSE)

  if (verbose) print("[MOB]  - Processing Mitigations details and relationships...")
  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  df <- data.frame(ID = character(),
                   Tactic = character(),
                   Platform = character(),
                   Detection = character(),
                   stringsAsFactors = FALSE)

  for (src.url in unique(df.basic$source)) {
    df <- plyr::rbind.fill(df, ExtractMitigationMob(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  # Tidy data
  good <- names(which(apply(df, 2, function(x) sum(is.na(x))) < nrow(df.basic)*0.9))
  df <- dplyr::select(df, good)
  names(df) <- stringr::str_replace_all(tolower(names(df)), " ", ".")

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractMitigationMob <- function(source.url = "https://attack.mitre.org/mobile/index.php/Mitigation/MOB-M1005") {
  doc <- xml2::read_html(source.url)

  mitig.id <- stringr::str_split(source.url, "/")[[1]]
  mitig.id <- mitig.id[length(mitig.id)]
  headlines <- rvest::html_text(rvest::html_nodes(doc, xpath = '//h2[span[@id!="Navigation menu"]]'))

  # Extract techniques used by the group
  if ("Techniques Addressed by Mitigation" %in% headlines) {
    if ((which(headlines == "Techniques Addressed by Mitigation") + 1) <= length(headlines)) {
      # There are more info after Techniques
      xpath <- paste('//h2[span[@id="Techniques_Addressed_by_Mitigation"]]',
                     '/following-sibling::ul[following::h2[span[@id="',
                     headlines[which(headlines == "Techniques_Addressed_by_Mitigation") + 1],
                     '"]]]', sep = "")
    } else {
      # References is the following info
      xpath <- paste('//h2[span[@id="Techniques_Addressed_by_Mitigation"]]',
                     '/following-sibling::ul[following::h2[span[@id!="Techniques_Addressed_by_Mitigation"]]]',
                     ' | ',
                     '//h2[span[@id="Techniques_Addressed_by_Mitigation"]]/',
                     'following-sibling::ul[following::div]',
                     sep = "")
    }
    tech.raw <- rvest::html_nodes(x = doc, xpath = xpath)
    tech.ids <- sapply(tech.raw, function(x) rvest::html_text(rvest::html_nodes(x, xpath = './li/a[1]/@title'), trim = TRUE))
    tech.ids <- stringr::str_replace_all(tech.ids, "Technique/", "")
    df.tech <- data.frame(id = rep(mitig.id, length(tech.ids)),
                          tech.id = tech.ids,
                          stringsAsFactors = FALSE)
  } else {
    df.tech <- NA
  }

  df <- data.frame(id = mitig.id, stringsAsFactors = FALSE)
  if (is.data.frame(df.tech)) {
    df <- dplyr::left_join(df, df.tech, by = c("id"))
  }

  return(df)
}
