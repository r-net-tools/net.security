GetCARETData <- function(savepath = tempdir(), verbose = T) {
  if (verbose) print("Downloading raw data from MITRE...")
  # caret.file <- DownloadCARETData(savepath)
  if (verbose) print("Processing CARET raw data...")
  car <- ParseCARETData(verbose)
  if (verbose) print(paste("CARET data frame building process finished."))
  return(caret)
}

DownloadCARETData <- function(savepath) {
  # if (!dir.exists(paste(savepath, "caret", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
  #   dir.create(paste(savepath, "caret", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  # }
  # caret.url  <- "blob:https://car.mitre.org/d6d94237-1c76-4a40-a0a6-37bfae799806"
  # destfile <- paste(savepath, "caret", "caret-data.json",sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  # utils::download.file(url = caret.url, destfile = destfile)
  caret.file <- "inst/schemas/caret-data.json"
  return(caret.file)
}

ParseCARETData <- function(verbose) {
  if (verbose) print("[CAR]  - Processing Cyber Analytic Repository basic information...")

  source.url <- "https://car.mitre.org/wiki/Full_Analytic_List"
  doc <- xml2::read_html(RCurl::getURL(url = source.url, ssl.verifypeer = FALSE))

  # Extract tactic and techniques relationship
  t.list <- rvest::html_nodes(x = doc, xpath = "//div/table/tr")
  car.id <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[1]/a/@title"), trim = T))
  car.name <- sapply(t.list, function(x) rvest::html_text(rvest::html_nodes(x, xpath = "./td[2]"), trim = T))
  car.url <- sapply(t.list, function(x) paste("https://car.mitre.org",
                                               rvest::html_text(rvest::html_nodes(x,
                                                                                  xpath = "./td[1]/a/@href"),
                                                                trim = T),
                                               sep = ""))
  car.descr <- sapply(t.list, function(x) as.character(strcapture(x = as.character(rvest::html_nodes(x, xpath = "./td[3]")),
                                                                   pattern = '>(.*?)</td',
                                                                   proto = data.frame(chr = character()))$chr))

  df.basic <- data.frame(id = car.id,
                         name = car.name,
                         description = car.descr,
                         source = car.url,
                         stringsAsFactors = FALSE)

  if (verbose) print("[CAR]  - Processing Cyber Analytic Repository details and relationships...")
  df <- data.frame(id = character(),
                   type = character(),
                   stringsAsFactors = FALSE)
  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  for (src.url in unique(df.basic$source)) {
    df <- plyr::rbind.fill(df, ExtractCAR(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  names(df) <- stringr::str_replace_all(tolower(names(df)), " ", ".")

  df <- dplyr::left_join(df.basic, df, by = c("id"))

  return(df)
}

ExtractCAR <- function(source.url = "https://car.mitre.org/wiki/CAR-2013-05-009") {
  doc <- xml2::read_html(RCurl::getURL(url = source.url, ssl.verifypeer = FALSE))

  deprecated <- FALSE

  df <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[@class="infobox skipempty"]/tr/td'), trim = T)
  names(df) <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table[@class="infobox skipempty"]/tr/th[@scope="row"]'), trim = T)
  df <- as.data.frame(t(df), stringsAsFactors = F)
  df$deprecated <- rep(deprecated, nrow(df))

  df$id <- stringr::str_replace(source.url, "https://car.mitre.org/wiki/", "")
  df$Owner <- NULL
  names(df) <- stringr::str_replace_all(tolower(names(df)), " ", ".")

  if ("type" %in% names(df)) {
    df <- tidyr::separate_rows(df, type, sep = ", ")
  }
  if ("information.domain" %in% names(df)) {
    df <- tidyr::separate_rows(df, information.domain, sep = ", ")
  }
  if ("network.subtypes" %in% names(df)) {
    df <- tidyr::separate_rows(df, network.subtypes, sep = ", ")
  }
  if ("network.protocols" %in% names(df)) {
    df <- tidyr::separate_rows(df, network.protocols, sep = ", ")
  }
  if ("analytic.subtypes" %in% names(df)) {
    df <- tidyr::separate_rows(df, analytic.subtypes, sep = ", ")
  }

  # Extract ATT&CK relationship
  tech.ids <- rvest::html_text(rvest::html_nodes(x = doc, xpath = "//table[starts-with(@class,'attack_refs')]/tr/td[1]/a/@title"))
  tech.ids <- stringr::str_replace(tech.ids, "attack:Technique/", "")
  tactic.names <- rvest::html_text(rvest::html_nodes(x = doc, xpath = "//table[starts-with(@class,'attack_refs')]/tr/td[2]"))
  coverage <- rvest::html_text(rvest::html_nodes(x = doc, xpath = "//table[starts-with(@class,'attack_refs')]/tr/td[3]"))

  df2 <- data.frame(tech.id = tech.ids,
                    tactic.name = tactic.names,
                    coverage = coverage,
                    car.id = rep(stringr::str_replace(source.url, "https://car.mitre.org/wiki/", ""), length(tech.ids)),
                    stringsAsFactors = FALSE)

  df2 <- tidyr::separate_rows(df2, tactic.name, sep = ", ")
  df <- dplyr::left_join(df, df2, by = c("id" = "car.id"))

  return(df)
}


# ParseCARETData2 <- function(caret.file, verbose) {
#   caret.raw <- RJSONIO::fromJSON(caret.file)
#
#   car.data.model <- plyr::ldply(caret.raw$dataModel,
#                                 function(x) {
#                                   plyr::ldply(x$actions,
#                                               function(y) {
#                                                 data.frame(object = rep(x$name, length(x$fields)),
#                                                            action = rep(y, length(x$fields)),
#                                                            field = x$fields,
#                                                            stringsAsFactors = F)
#                                               }
#                                   )
#                                 })
#   car.sensors <- plyr::ldply(caret.raw$sensors,
#                              function(x) {
#                                data.frame(name = rep(x$name, length(x$fields)),
#                                           field = x$fields,
#                                           stringsAsFactors = F)
#                              })
#   car.groups <- plyr::ldply(caret.raw$groups,
#                             function(x) {
#                               plyr::ldply(x$techniques,
#                                           function(y) {
#                                             data.frame(name = x$name,
#                                                        technique = y,
#                                                        id = x$ID,
#                                                        aliases = as.character(jsonlite::toJSON(x$aliases)),
#                                                        stringsAsFactors = F)
#                                           }
#                               )
#                             })
#   car.techniques <- plyr::ldply(caret.raw$techniques,
#                                 function(x) {
#                                   plyr::ldply(x$tactics,
#                                               function(y) {
#                                                 data.frame(url = paste("https://attack.mitre.org/wiki", x$name, sep = "/"),
#                                                            tactic = y,
#                                                            id = x$ID,
#                                                            display_name = x$display_name,
#                                                            stringsAsFactors = F)
#                                               }
#                                   )
#                                 })
#
#   car.analytics <- plyr::ldply(caret.raw$analytics,
#                                function(x) {
#                                  plyr::ldply(x[[2]],
#                                              function(y) {
#                                                if (length(y$tactics) > 1) {
#                                                  plyr::ldply(y$tactics, function(z) {
#                                                    data.frame(id = x$name,
#                                                               name = x$shortName,
#                                                               tactic.name = z,
#                                                               cover = y$coverage,
#                                                               tech.id = stringr::str_replace(string = y$technique, pattern = "Technique/", replacement = ""),
#                                                               stringsAsFactors = F)
#                                                  })
#                                                } else {
#                                                  data.frame(id = x$name,
#                                                             name = x$shortName,
#                                                             tactic.name = y$tactics,
#                                                             cover = y$coverage,
#                                                             tech.id = stringr::str_replace(string = y$technique, pattern = "Technique/", replacement = ""),
#                                                             stringsAsFactors = F)
#                                                }
#                                              }
#                                  )
#                                })
#   car.url <- "https://car.mitre.org/wiki/Full_Analytic_List"
#   car.html <- RCurl::getURL(url = car.url, ssl.verifypeer = FALSE)
#   doc <- xml2::read_html(car.html)
#
#   car.analytics <- dplyr::left_join(x = car.analytics,
#                                     y = as.data.frame(cbind(car.id = rvest::html_text(rvest::xml_nodes(doc,
#                                                                                                        xpath = '//div[@id="mw-content-text"]/table/tr/td[@class="Analytic smwtype_wpg"]/a/@title')),
#                                                             car.hypothesis = rvest::html_text(rvest::xml_nodes(doc,
#                                                                                                                xpath = '//div[@id="mw-content-text"]/table/tr/td[@class="Hypothesis smwtype_txt"]'))),
#                                                       stringsAsFactors = F),
#                                     by = c("id" = "car.id"))
#
#   # Extract relations
#   df <- data.frame(from = character(),
#                    to = character(),
#                    source = character(),
#                    target = character(),
#                    info = character(),
#                    stringsAsFactors = FALSE)
#
#   # Extract relations CAR - tactic
#   car2tactic <- unique(dplyr::select(car.analytics, id, tactic.name, cover))
#
#   # Extract relations CAR - technique
#   car2tech <- unique(dplyr::select(car.analytics, id, tech.id, cover))
#
#   # Tidy data
#
#
#   caret <- list(data.model = car.data.model,
#                 sensors = car.sensors,
#                 analytics = car.analytics)
#
#   return(caret)
# }
#
# getTechniqueWikiInfo <- function(tech.url = "https://attack.mitre.org/wiki/Technique/T1156") {
#   # Parse all techniques wiki info
#   # tech.extra <- rvest::html_nodes(x = tech.doc, xpath = '//div[@id="toc"]')
#   #
#   # # Get TOC info
#   # if (length(tech.extra > 1)) {
#   #   columns <- rvest::html_text(rvest::html_nodes(x = tech.doc, xpath = '//div[@id="toc"]/ul/li/a/span[2]'))
#   # } else {
#   #   columns <- c()
#   # }
#
#   # Get Wiki info
#   tech.doc <- xml2::read_html(tech.url)
#   content <- rvest::html_nodes(x = tech.doc, xpath = '//div[@id="content"]')
#   headlines <- rvest::html_nodes(content, xpath = "//*[self::h1 or self::h2]")
#   xpath <- sprintf("//p[count(preceding-sibling::h2)=%d]", seq_along(headlines)-1)
#   techwiki <- purrr::map(xpath, ~rvest::html_nodes(x = content, xpath = .x)) %>% # Get the text inside the headlines
#     purrr::map(rvest::html_text, trim = TRUE) %>% # get per node in between
#     purrr::map_chr(paste, collapse = "\n") %>% # collapse the text inbetween
#     purrr::set_names(headlines %>% rvest::html_node("span") %>% rvest::html_text())
#   techwiki <- as.data.frame(t(techwiki[techwiki != ""]))
#   names(techwiki)[1] <- "Description"
#   id <- stringr::str_split(string = tech.url, pattern = "/")[[1]]
#   techwiki$id <- id[length(id)]
#
#   return(techwiki)
#
# }
