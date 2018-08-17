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
  if (verbose) print("[PRE] Processing Software raw data...")
  groups.raw <- ParseGroupsPRE(verbose)
  if (verbose) print("[PRE] Building data sets relationships...")
  relations.raw <- ParseRelationsPRE(verbose)

  # Tidy data sets
  if (verbose) print("[PRE] Tidy raw data...")
  tactics <- tactics.raw
  techniques <- techniques.raw
  groups <- groups.raw
  relations <- relations.raw

  attck <- list(tactics, techniques, groups, relations)

  if (verbose) print("[PRE] ATT&CK PRE data sets created.")

  return(attck)
}

ParseATTCKent <- function(verbose) {
  if (verbose) print("Processing ATT&CK Enterprise raw data...")
  tactics <- data.frame()
  techniques <- data.frame()
  software <- data.frame()
  groups <- data.frame()
  relations <- data.frame()

  attck <- list(tactics, techniques, software, groups, relations)
  if (verbose) print("ATT&CK Enterprise data sets created.")

  return(attck)
}

ParseATTCKmob <- function(verbose) {
  if (verbose) print("Processing ATT&CK Mobile raw data...")
  tactics <- data.frame()
  techniques <- data.frame()
  software <- data.frame()
  groups <- data.frame()
  relations <- data.frame()

  attck <- list(tactics, techniques, software, groups, relations)
  if (verbose) print("ATT&CK Mobile data sets created.")

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

#############
# Software
##

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


#############
# Relations
##

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
ParseTechniquesEnt <- function(techniques.url = "https://attack.mitre.org/wiki/All_Techniques") {
  getTechniqueWikiInfo <- function(tech.url = "https://attack.mitre.org/wiki/Technique/T1156") {
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

    good <- c("ID", "Tactic", "Platform", "Permissions Required", "Data Sources",
              "Mitigation", "Detection", "References", "Effective Permissions",
              "Contributors", "Contents", "Examples", "CAPEC ID", "System Requirements",
              "Supports Remote", "Requires Network", "Defense Bypassed")
    cont <- names(df)[!(names(df) %in% good)]
    df$Contents <- df[[cont]]
    df[[cont]] <- NULL

    return(df)
  }

  doc <- xml2::read_html(techniques.url)

  # Extract tactic and techniques relationship
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  t.techniques <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[3]"), trim = T))
  t.techniques.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a"), trim = T))
  t.techniques.url <- sapply(t.list, function(x) paste("https://attack.mitre.org",
                                                       rvest::html_text(rvest::html_nodes(x,
                                                                                          xpath = "./td[1]/a/@href"),
                                                                        trim = T),
                                                       sep = ""))
  t.techniques.descr <- sapply(t.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[4]")),
                                                                           pattern = '>(.*?)</td',
                                                                           proto = data.frame(chr = character()))$chr))

  tnt <- data.frame(technique = t.techniques,
                    technique.name = t.techniques.name,
                    technique.descr = t.techniques.descr,
                    technique.url = t.techniques.url,
                    stringsAsFactors = FALSE)

  df <- lapply(unique(tnt$technique.url), function(x) getTechniqueWikiInfo(x))
  df <- do.call(plyr::rbind.fill, df)

  df <- tidyr::separate_rows(
    tidyr::separate_rows(
      tidyr::separate_rows(
        tidyr::separate_rows(
          tidyr::separate_rows(
            tidyr::separate_rows(
              tidyr::separate_rows(
                tidyr::separate_rows(df,
                                     `Defense Bypassed`, sep = ","),
                Contributors, sep = ","),
              `Effective Permissions`, sep = ","),
            Tactic, sep = ","),
          Platform, sep = ","),
        `Permissions Required`, sep = ","),
      `Data Sources`, sep = ","),
    `CAPEC ID`, sep = ",")

  df$Platform <- stringr::str_trim(df$Platform)
  df$Tactic <- stringr::str_trim(df$Tactic)

  df <- dplyr::left_join(df, tnt, by = c("ID" = "technique"))

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
