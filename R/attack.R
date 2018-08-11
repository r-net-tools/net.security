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
GetATTCKData <- function(savepath = tempdir(), verbose = T) {
  # if (verbose) print("Downloading raw data from MITRE...")
  # attck.files <- DownloadATTCKData(savepath, verbose)
  if (verbose) print("Processing ATT&CK raw data...")
  attck <- ParseATTCKData(savepath, verbose)
  if (verbose) print(paste("ATT&CK data frame building process finished."))
  return(attck)
}

# DownloadATTCKData <- function(savepath, verbose) {
#   # Download ATT&CK matrix
#
#   # Download Tactics raw data
#
#   # Download Techniques raw data
#
#   # Download Groups raw data
#
#   # Download Software raw data
#
# }

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

  # df <- data.frame(technique = character(),
  #                  technique.name = character(),
  #                  technique.desc = character(),
  #                  technique.platform = character(),
  #                  technique.sysreq = character(),
  #                  technique.permision.required = character(),
  #                  technique.effective.permision = character(),
  #                  technique.data.source = character(),
  #                  technique.support.remote = character(),
  #                  technique.defense.bypassed = character(),
  #                  technique.capec = character(),
  #                  technique.contributor = character(),
  #                  technique.examples = character(),
  #                  technique.detection = character(),
  #                  technique.mitigation = character(),
  #                  stringsAsFactors = FALSE)

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
ParseTechniquesPRE <- function(techniques.url = "https://attack.mitre.org/pre-attack/index.php/All_Techniques") {
  getTechniqueWikiInfo <- function(tech.url = "https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1043") {
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

    good <- c("ID", "Tactic", "Difficulty for the Adversary", "Detection",
              "Similar Techniques for Other Tactics", "technique.name",
              "technique.platform", "technique.descr", "technique.url")
    cont <- names(df)[!(names(df) %in% good)]
    df$Contents <- jsonlite::toJSON(dplyr::select(df, cont))
    df <- dplyr::select(df, -cont, Contents)

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
                                                  `technique.platform`, sep = ","),
                             `Tactic`, sep = ",")

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
  getSoftwareWikiInfo <- function(soft.url = "https://attack.mitre.org/wiki/Software/S0204") {
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
    if (c("Techniques Used") %in% names(df)) {
      tup <- which(names(df) %in% "Techniques Used")
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
      group.used.id <- rvest::xml_nodes(doc, xpath = xpath[which(names(df) %in% "Groups")])
      group.used.id <- sapply(group.used.id, function(x) stringr::str_extract(string = as.character(x), pattern = "T\\d\\d\\d\\d"))
      group.used.id <- group.used.id[!is.na(group.used.id)]
      df$groups.using <- paste(group.used.id, collapse = ",")
      df <- tidyr::separate_rows(df, groups.using, sep = ",")
    } else {
      df$groups.using <- NA
    }

    df2 <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/td'), trim = T)
    names(df2) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[1]/tr/th[@scope="row"]'), trim = T)
    df2 <- as.data.frame(t(df2), stringsAsFactors = F)

    df <- cbind.data.frame(df2, df)

    good <- c("ID", "Aliases", "Type", "Platform", "tech.used", "tech.used.name",
              "tech.used.desc", "groups.using", "Contents")
    cont <- names(df)[!(names(df) %in% good)]
    df$Contents <- as.character(jsonlite::toJSON(dplyr::select(df, cont)))
    df <- dplyr::select(df, -cont, Contents)

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
