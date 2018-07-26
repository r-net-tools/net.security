# References: https://www.mitre.org/publications/technical-papers/mitre-attack-design-and-philosophy

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
  tactics <- ParseTactics()
  techniques <- ParseTechniques()
  groups <- ParseGroups()
  software <- ParseSoftware()

  attck <- list(amatrix, tactics, techniques, groups, software)
  return(attck)
}

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

    df$tactic <- as.factor(df$tactic)

    return(df)
  }

  ParseEntAll <- function(entall.url = "https://attack.mitre.org/wiki/Main_Page") {
    m <- xml2::read_html(entall.url)
    df <- data.frame(stringsAsFactors = FALSE)
    return(df)
  }
  ParseEntWin <- function(entwin.url = "https://attack.mitre.org/wiki/Windows_Technique_Matrix") {
    m <- xml2::read_html(entwin.url)
    df <- data.frame(stringsAsFactors = FALSE)
    return(df)
  }
  ParseEntMac <- function(entmac.url = "https://attack.mitre.org/wiki/Mac_Technique_Matrix") {
    m <- xml2::read_html(entmac.url)
    df <- data.frame(stringsAsFactors = FALSE)
    return(df)
  }
  ParseEntLnx <- function(entlnx.url = "https://attack.mitre.org/wiki/Linux_Technique_Matrix") {
    m <- xml2::read_html(entlnx.url)
    df <- data.frame(stringsAsFactors = FALSE)
    return(df)
  }
  ParseMobile <- function(entmob.url = "https://attack.mitre.org/mobile/index.php/Main_Page") {
    m <- xml2::read_html(entmob.url)
    df <- data.frame(stringsAsFactors = FALSE)
    return(df)
  }

  m.pre <- ParsePre()
  m.ent.all <- ParseEntAll()
  m.ent.win <- ParseEntWin()
  m.ent.mac <- ParseEntMac()
  m.ent.lnx <- ParseEntLnx()
  m.mobile  <- ParseMobile()

  matrix <- list(m.pre, m.ent.all, m.ent.win, m.ent.mac, m.ent.lnx, m.mobile)

  return(matrix)
}

ParseTactics <- function() {
  tactics.url <- "https://attack.mitre.org/wiki/All_Techniques"
  tactics.url <- "https://attack.mitre.org/wiki/Category:Technique"

  tactics <- data.frame()

  return(tactics)
}

ParseTechniques <- function() {
  techniques.url <- "https://attack.mitre.org/wiki/All_Techniques"

  techniques <- data.frame()

  return(techniques)
}

ParseGroups <- function() {
  groups.url <- "https://attack.mitre.org/wiki/Groups"

  groups <- data.frame()

  return(groups)

}

ParseSoftware <- function() {
  software.url <- "https://attack.mitre.org/wiki/Software"

  software <- data.frame()

  return(software)
}
