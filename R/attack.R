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
  attck <- list(attck.pre, attck.ent, attck.mob)
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
  techniques <- unique(dplyr::select(techniques.raw, -tactic))
  groups <- unique(dplyr::select(groups.raw, id, name, aliases, description, source))

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
  techniques <- techniques.raw
  good <- c("id", "name", "description", "aliases", "source")
  software <- unique(dplyr::select(software.raw, good))
  groups <- unique(dplyr::select(groups.raw, good))

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
  if (verbose) print("[MOB] Building data sets relationships...")
  relations <- ParseRelationsEnt(tactics.raw, techniques.raw, groups.raw, software.raw, verbose)

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
                                     stringsAsFactors = FALSE)

  if (verbose) print("[MOB]  - Processing Common Tactics basic information...")
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
  print(source.url)
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
  names(df) <- tolower(names(df))

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

  # Extract tactic and techniques relationship
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

################################################################################
##### OLD_CODE
################################################################################

ParseATTCKData <- function(savepath, verbose) {
  amatrix <- ParseMatrix()
  tactic.urls <- unique(amatrix[, c("tactic.url", "matrix")])
  tactics <- ParseTactics(tactic.urls = tactic.urls)
  techniques <- ParseTechniques()
  groups <- ParseGroups()
  software <- ParseSoftware()

  attck <- list(amatrix, tactics, techniques, groups, software)
  return(attck)
}

#' Title
#'
#' @return
#' @export
#'
#' @examples
ParseTechniques <- function() {
  techniquesEnt <- ParseTechniquesEnt()
  techniquesPRE <- ParseTechniquesPRE()
  techniquesMob <- ParseTechniquesMob()
  df <- plyr::rbind.fill(techniquesEnt, techniquesPRE, techniquesMob)
  return(df)
}

#' Title
#'
#' @return
#' @export
#'
#' @examples
ParseMatrix <- function() {
  ParsePre <- function(pre.url = "https://attack.mitre.org/pre-attack/index.php/Main_Page") {
    doc <- xml2::read_html(pre.url)

    # Parse headers as list of nodes
    headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]')
    xpath <- sprintf("//p[count(preceding-sibling::h2)=%d]", seq_along(headlines) - 1)

    df <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                               rvest::html_text, trim = TRUE),
                                    paste, collapse = "\n")
                     ,
                     rvest::html_text(rvest::html_node(headlines, "span")))
    df <- as.data.frame(t(df[df != ""]), stringsAsFactors = FALSE)

    m.pre <- rvest::html_nodes(x = doc, xpath = "//div/table")
    # TODO: m.pre extract info from other headers

    # Extract tactic and techniques relationship
    m.pre <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
    tnt <- lapply(m.pre, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")))
    names(tnt) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th"))

    df <- data.frame(tactic = character(),
                     technique = character(),
                     stringsAsFactors = FALSE)
    for (tactic in names(tnt)) {
      df <- rbind(df, data.frame(tactic = rep(stringr::str_replace_all(string = tactic, pattern = " ", replacement = "_"),
                                              length(tnt[[tactic]])),
                                 technique = tnt[[tactic]],
                                 stringsAsFactors = FALSE))
    }

    # Add tactics attributes
    df.tactic.urls <- data.frame(tactic = stringr::str_replace_all(string = names(tnt), pattern = " ", replacement = "_"),
                                 tactic.name = names(tnt),
                                 tactic.url = rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th/a/@href")),
                                 stringsAsFactors = FALSE)
    # Add techniques attributes
    df.technique.urls <- plyr::ldply(m.pre, function(x) data.frame(technique = rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")),
                                                                   technique.name = rvest::html_text(rvest::html_nodes(x, xpath = "./td")),
                                                                   technique.url = rvest::html_text(rvest::html_nodes(x, xpath = "./td/a/@href")),
                                                                   stringsAsFactors = FALSE))

    # Tidy data
    df <- dplyr::left_join(df, df.tactic.urls, by = c("tactic"))
    df <- dplyr::left_join(df, df.technique.urls, by = c("technique"))

    df$matrix <- rep("PRE-ATT&CK", nrow(df))

    return(df)
  }

  ParseEntAll <- function(entall.url = "https://attack.mitre.org/wiki/Main_Page") {
    doc <- xml2::read_html(entall.url)

    # Extract tactic and techniques relationship
    m.entall <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
    m.entall <- m.entall[2:length(m.entall)]
    tnt <- lapply(m.entall, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")))
    names(tnt) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th"))

    df <- data.frame(tactic = character(),
                     technique = character(),
                     stringsAsFactors = FALSE)
    for (tactic in names(tnt)) {
      df <- rbind(df, data.frame(tactic = rep(stringr::str_replace_all(string = tactic, pattern = " ", replacement = "_"),
                                              length(tnt[[tactic]])),
                                 technique = tnt[[tactic]],
                                 stringsAsFactors = FALSE))
    }

    # Add tactics attributes
    df.tactic.urls <- data.frame(tactic = stringr::str_replace_all(string = names(tnt), pattern = " ", replacement = "_"),
                                 tactic.name = names(tnt),
                                 tactic.url = rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th/a/@href")),
                                 stringsAsFactors = FALSE)
    # Add techniques attributes
    df.technique.urls <- plyr::ldply(m.entall, function(x) data.frame(technique = rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")),
                                                                      technique.name = rvest::html_text(rvest::html_nodes(x, xpath = "./td")),
                                                                      technique.url = rvest::html_text(rvest::html_nodes(x, xpath = "./td/a/@href")),
                                                                      stringsAsFactors = FALSE))

    # Tidy data
    df <- dplyr::left_join(df, df.tactic.urls, by = c("tactic"))
    df <- dplyr::left_join(df, df.technique.urls, by = c("technique"))

    df$matrix <- rep("Enterprise", nrow(df))

    return(df)
  }

  ParseEntWin <- function(entwin.url = "https://attack.mitre.org/wiki/Windows_Technique_Matrix") {
    doc <- xml2::read_html(entwin.url)

    # Extract tactic and techniques relationship
    m.entwin <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
    tnt <- lapply(m.entwin, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")))
    names(tnt) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th"))

    df <- data.frame(tactic = character(),
                     technique = character(),
                     stringsAsFactors = FALSE)
    for (tactic in names(tnt)) {
      df <- rbind(df, data.frame(tactic = rep(stringr::str_replace_all(string = tactic, pattern = " ", replacement = "_"),
                                              length(tnt[[tactic]])),
                                 technique = tnt[[tactic]],
                                 stringsAsFactors = FALSE))
    }

    # Add tactics attributes
    df.tactic.urls <- data.frame(tactic = stringr::str_replace_all(string = names(tnt), pattern = " ", replacement = "_"),
                                 tactic.name = names(tnt),
                                 tactic.url = rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th/a/@href")),
                                 stringsAsFactors = FALSE)
    # Add techniques attributes
    df.technique.urls <- plyr::ldply(m.entwin, function(x) data.frame(technique = rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")),
                                                                      technique.name = rvest::html_text(rvest::html_nodes(x, xpath = "./td")),
                                                                      technique.url = rvest::html_text(rvest::html_nodes(x, xpath = "./td/a/@href")),
                                                                      stringsAsFactors = FALSE))

    # Tidy data
    df <- dplyr::left_join(df, df.tactic.urls, by = c("tactic"))
    df <- dplyr::left_join(df, df.technique.urls, by = c("technique"))

    df$matrix <- rep("Windows", nrow(df))

    return(df)
  }

  ParseEntMac <- function(entmac.url = "https://attack.mitre.org/wiki/Mac_Technique_Matrix") {
    doc <- xml2::read_html(entmac.url)

    # Extract tactic and techniques relationship
    m.entmac <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
    tnt <- lapply(m.entmac, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")))
    names(tnt) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th"))

    df <- data.frame(tactic = character(),
                     technique = character(),
                     stringsAsFactors = FALSE)
    for (tactic in names(tnt)) {
      df <- rbind(df, data.frame(tactic = rep(stringr::str_replace_all(string = tactic, pattern = " ", replacement = "_"),
                                              length(tnt[[tactic]])),
                                 technique = tnt[[tactic]],
                                 stringsAsFactors = FALSE))
    }

    # Add tactics attributes
    df.tactic.urls <- data.frame(tactic = stringr::str_replace_all(string = names(tnt), pattern = " ", replacement = "_"),
                                 tactic.name = names(tnt),
                                 tactic.url = rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th/a/@href")),
                                 stringsAsFactors = FALSE)
    # Add techniques attributes
    df.technique.urls <- plyr::ldply(m.entmac, function(x) data.frame(technique = rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")),
                                                                      technique.name = rvest::html_text(rvest::html_nodes(x, xpath = "./td")),
                                                                      technique.url = rvest::html_text(rvest::html_nodes(x, xpath = "./td/a/@href")),
                                                                      stringsAsFactors = FALSE))

    # Tidy data
    df <- dplyr::left_join(df, df.tactic.urls, by = c("tactic"))
    df <- dplyr::left_join(df, df.technique.urls, by = c("technique"))

    df$matrix <- rep("Mac", nrow(df))

    return(df)
  }

  ParseEntLnx <- function(entlnx.url = "https://attack.mitre.org/wiki/Linux_Technique_Matrix") {
    doc <- xml2::read_html(entlnx.url)

    # Extract tactic and techniques relationship
    m.entlnx <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
    tnt <- lapply(m.entlnx, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")))
    names(tnt) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th"))

    df <- data.frame(tactic = character(),
                     technique = character(),
                     stringsAsFactors = FALSE)
    for (tactic in names(tnt)) {
      df <- rbind(df, data.frame(tactic = rep(stringr::str_replace_all(string = tactic, pattern = " ", replacement = "_"),
                                              length(tnt[[tactic]])),
                                 technique = tnt[[tactic]],
                                 stringsAsFactors = FALSE))
    }

    # Add tactics attributes
    df.tactic.urls <- data.frame(tactic = stringr::str_replace_all(string = names(tnt), pattern = " ", replacement = "_"),
                                 tactic.name = names(tnt),
                                 tactic.url = rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th/a/@href")),
                                 stringsAsFactors = FALSE)
    # Add techniques attributes
    df.technique.urls <- plyr::ldply(m.entlnx, function(x) data.frame(technique = rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")),
                                                                      technique.name = rvest::html_text(rvest::html_nodes(x, xpath = "./td")),
                                                                      technique.url = rvest::html_text(rvest::html_nodes(x, xpath = "./td/a/@href")),
                                                                      stringsAsFactors = FALSE))

    # Tidy data
    df <- dplyr::left_join(df, df.tactic.urls, by = c("tactic"))
    df <- dplyr::left_join(df, df.technique.urls, by = c("technique"))

    df$matrix <- rep("Linux", nrow(df))

    return(df)
  }

  ParseMobile <- function(entmob.url = "https://attack.mitre.org/mobile/index.php/Main_Page") {
    doc <- xml2::read_html(entmob.url)

    # Extract tactic and techniques relationship
    m.entmob <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
    tnt <- lapply(m.entmob, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")))
    names(tnt) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th"))

    df <- data.frame(tactic = character(),
                     technique = character(),
                     stringsAsFactors = FALSE)
    for (tactic in names(tnt)) {
      df <- rbind(df, data.frame(tactic = rep(stringr::str_replace_all(string = tactic, pattern = " ", replacement = "_"),
                                              length(tnt[[tactic]])),
                                 technique = tnt[[tactic]],
                                 stringsAsFactors = FALSE))
    }

    # Add tactics attributes
    df.tactic.urls <- data.frame(tactic = stringr::str_replace_all(string = names(tnt), pattern = " ", replacement = "_"),
                                 tactic.name = names(tnt),
                                 tactic.url = rvest::html_text(rvest::html_nodes(x = doc, xpath = "//div/table/tr/th/a/@href")),
                                 stringsAsFactors = FALSE)
    # Add techniques attributes
    df.technique.urls <- plyr::ldply(m.entmob, function(x) data.frame(technique = rvest::html_text(rvest::html_nodes(x, xpath = "./td/@id")),
                                                                      technique.name = rvest::html_text(rvest::html_nodes(x, xpath = "./td")),
                                                                      technique.url = rvest::html_text(rvest::html_nodes(x, xpath = "./td/a/@href")),
                                                                      stringsAsFactors = FALSE))

    # Tidy data
    df <- dplyr::left_join(df, df.tactic.urls, by = c("tactic"))
    df <- dplyr::left_join(df, df.technique.urls, by = c("technique"))

    df$matrix <- rep("Mobile", nrow(df))

    return(df)
  }

  m.pre <- ParsePre()
  m.ent.all <- ParseEntAll()
  m.ent.win <- ParseEntWin()
  m.ent.mac <- ParseEntMac()
  m.ent.lnx <- ParseEntLnx()
  m.mobile  <- ParseMobile()

  m <- rbind(m.pre, m.ent.all, m.ent.win, m.ent.mac, m.ent.lnx, m.mobile)

  m$tactic.url <- as.character(sapply(m$tactic.url,
                                      function(x)
                                        paste("https://attack.mitre.org", x, sep = "")))
  m$technique.url <- as.character(sapply(m$technique.url,
                                         function(x)
                                           paste("https://attack.mitre.org", x, sep = "")))
  # m$tactic <- as.factor(m$tactic)
  # m$technique <- as.factor(m$technique)
  # m$matrix <- as.factor(m$matrix)

  return(m)
}

#' Title
#'
#' @param tactic.urls
#'
#' @return
#' @export
#'
#' @examples
ParseTactics <- function(tactic.urls) {
  ExtractTactic <- function(src.url) {
    doc <- xml2::read_html(src.url)

    # Parse headers as list of nodes
    headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]')
    xpath <- sprintf("//p[count(preceding-sibling::h2)=%d]", seq_along(headlines) - 1)

    df <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                     rvest::html_text, trim = TRUE),
                                          paste, collapse = "\n")
                           ,
                           rvest::html_text(rvest::html_node(headlines, "span")))
    df <- as.data.frame(t(df[df != ""]), stringsAsFactors = FALSE)

    t <- data.frame(tactic = stringr::str_split(src.url, "/")[[1]][length(stringr::str_split(src.url, "/")[[1]])],
                    tactic.descr = df[,1],
                    stringsAsFactors = FALSE)

    # Extract techniques description
    tact <- rvest::html_nodes(x = doc, xpath = "//div/table/tr[@data-row-number]")
    # TODO: Pagination or API call with limit=300

    t.tech.title <- sapply(tact, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td/a/@title")))
    t.tech.title <- as.character(sapply(t.tech.title, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])]))
    t.tech.name <- sapply(tact, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]")))
    t.tech.descr <- sapply(tact, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[3]")))
    t.tech.url <- sapply(tact, function(x) paste("https://attack.mitre.org",
                                               rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a/@href")), sep = ""))

    t.tech <- data.frame(tactic = rep(t$tactic, length(t.tech.name)),
                         tactic.descr = rep(t$tactic.descr, length(t.tech.name)),
                         tactic.url = src.url,
                         technique = t.tech.title,
                         technique.name = t.tech.name,
                         technique.desc = t.tech.descr,
                         technique.url = t.tech.url,
                         stringsAsFactors = FALSE)

    return(t.tech)
  }

  df <- data.frame(tactic = character(),
                   tactic.descr = character(),
                   tactic.url = character(),
                   technique = character(),
                   technique.name = character(),
                   technique.desc = character(),
                   technique.url = character(),
                   stringsAsFactors = FALSE)
  for (src.url in unique(tactic.urls$tactic.url)) {
    df <- rbind(df, ExtractTactic(src.url))
  }

  df <- dplyr::left_join(df, tactic.urls)

  return(df)
}


#' Title
#'
#' @param techniques.url
#'
#' @return
#' @export
#'
#' @examples
ParseTechniquesMob <- function(techniques.url = "https://attack.mitre.org/mobile/index.php/All_Techniques") {
  getTechniqueWikiInfo <- function(tech.url = "https://attack.mitre.org/mobile/index.php/Technique/MOB-T1056") {
    doc <- xml2::read_html(tech.url)
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

    good <- c("ID", "Tactic type", "Tactic", "Platform", "Mitigation", "MTC ID",
              "Contents", "Examples", "Detection", "technique.name", "technique.platform",
              "technique.descr", "technique.url")
    cont <- names(df)[!(names(df) %in% good)]
    df$Contents <- jsonlite::toJSON(dplyr::select(df, cont))
    df <- dplyr::select(df, -cont, Contents)

    return(df)
  }

  doc <- xml2::read_html(techniques.url)

  # Extract tactic and techniques relationship
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  t.techniques <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[5]"), trim = T))
  t.techniques.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  t.techniques.platform <- stringr::str_replace_all(sapply(t.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[4]")),
                                                                              pattern = '>(.*?)</td',
                                                                              proto = data.frame(chr = character()))$chr)),
                                                    pattern = "<br>",
                                                    replacement = ",")
  t.techniques.url <- sapply(t.list, function(x) paste("https://attack.mitre.org",
                                                       rvest::html_text(rvest::html_nodes(x,
                                                                                          xpath = "./td[1]/a/@href"),
                                                                        trim = T),
                                                       sep = ""))
  t.techniques.descr <- sapply(t.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[6]")),
                                                                           pattern = '>(.*?)</td',
                                                                           proto = data.frame(chr = character()))$chr))

  tnt <- data.frame(technique = t.techniques,
                    technique.name = t.techniques.name,
                    technique.platform = t.techniques.platform,
                    technique.descr = t.techniques.descr,
                    technique.url = t.techniques.url,
                    stringsAsFactors = FALSE)

  df <- lapply(unique(tnt$technique.url), function(x) getTechniqueWikiInfo(x))
  df <- do.call(plyr::rbind.fill, df)

  df <- dplyr::left_join(df, tnt, by = c("ID" = "technique"))
  df <- tidyr::separate_rows(tidyr::separate_rows(df,
                                                  `Platform`, sep = ","),
                             `Tactic`, sep = ",")
  df$Platform <- stringr::str_trim(df$Platform)
  df$Tactic <- stringr::str_trim(df$Tactic)

  return(df)
}

#' Title
#'
#' @return
#' @export
#'
#' @examples
ParseGroups <- function() {
  groups.url <- "https://attack.mitre.org/wiki/Groups"

  groups <- data.frame()

  return(groups)

}

#' Title
#'
#' @return
#' @export
#'
#' @examples
ParseSoftware <- function(software.url = "https://attack.mitre.org/wiki/Software") {
  getSoftwareWikiInfo <- function(soft.url = "https://attack.mitre.org/wiki/Software/S0045") {
    print(soft.url)
    doc <- xml2::read_html(soft.url)
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
    df$Name <- rvest::html_text(headlines[[1]])
    if (c("Techniques Used") %in% names(df)) {
      tup <- which(names(df) %in% "Techniques Used")
    }
    if (c("Groups") %in% names(df)) {
      gup <- which(names(df) %in% "Groups")
    }

    df2 <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/td'), trim = T)
    names(df2) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/th[@scope="row"]'), trim = T)
    df2 <- as.data.frame(t(df2), stringsAsFactors = F)

    df <- cbind.data.frame(df2, df)

    good <- c("ID", "Name", "Aliases", "Type", "Platform", "Techniques Used", "Groups")
    selected <- names(df)[(names(df) %in% good)]
    df <- dplyr::select(df, selected)

    if (c("Techniques Used") %in% names(df)) {
      t.used <- rvest::xml_nodes(doc, xpath = xpath[tup])
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
      df <- dplyr::select(df, -`Techniques Used`)
      df <- tidyr::separate_rows(df, tech.used, sep = ",")
      df <- dplyr::left_join(df, techu, by = c("tech.used" = "tech.used.id"))
    } else {
      df$tech.used <- NA
    }

    if (c("Groups") %in% names(df)) {
      group.used.id <- rvest::xml_nodes(doc, xpath = xpath[gup])
      group.used.id <- sapply(group.used.id, function(x) stringr::str_extract(string = as.character(x), pattern = "G\\d\\d\\d\\d"))
      group.used.id <- group.used.id[!is.na(group.used.id)]
      df$groups.using <- paste(group.used.id, collapse = ",")
      df <- dplyr::select(df, -Groups)
      df <- tidyr::separate_rows(df, groups.using, sep = ",")
    } else {
      df$groups.using <- NA
    }

    return(df)
  }

  doc <- xml2::read_html(software.url)

  # Extract software and aliases relationship
  s.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  s.software.name <- sapply(s.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  s.software.aliases <- stringr::str_replace_all(sapply(s.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[2]")),
                                                                                                       pattern = '>(.*?)</td',
                                                                                                       proto = data.frame(chr = character()))$chr)),
                                                    pattern = "<br>",
                                                    replacement = ",")
  s.software.url <- sapply(s.list, function(x) paste("https://attack.mitre.org",
                                                       rvest::html_text(rvest::html_nodes(x,
                                                                                          xpath = "./td[1]/a/@href"),
                                                                        trim = T),
                                                       sep = ""))
  s.software.descr <- sapply(s.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[3]")),
                                                                           pattern = '>(.*?)</td',
                                                                           proto = data.frame(chr = character()))$chr))
  s.software <- sapply(s.software.url, function(x) stringr::str_split(x, "/")[[1]][length(stringr::str_split(x, "/")[[1]])])
  names(s.software) <- NULL

  tnt <- data.frame(software = s.software,
                    software.name = s.software.name,
                    software.aliases = s.software.aliases,
                    software.descr = s.software.descr,
                    software.url = s.software.url,
                    stringsAsFactors = FALSE)

  df <- lapply(unique(tnt$software.url), function(x) getSoftwareWikiInfo(x))
  df <- do.call(plyr::rbind.fill, df)

  df <- dplyr::left_join(df, tnt, by = c("ID" = "software"))
  df <- tidyr::separate_rows(tidyr::separate_rows(df,
                                                  `groups.using`, sep = ","),
                             `tech.used`, sep = ",")

  return(df)
}
