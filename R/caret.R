GetCARETData <- function(savepath = tempdir(), verbose = T) {
  if (verbose) print("Downloading raw data from MITRE...")
  # caret.file <- DownloadCARETData(savepath)
  if (verbose) print("Processing CARET raw data...")
  car <- ParseCAR(verbose)
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

ParseCAR <- function(verbose = TRUE) {
  if (verbose) print("Processing CAR raw data...")
  if (verbose) print("[+] Cyber Analytic Repository Data Model")
  datamodel.raw <- ParseCARDataModel(verbose)
  if (verbose) print("[+] Cyber Analytic Repository Sensors")
  sensors.raw <- ParseCARSensors(verbose)
  if (verbose) print("[+] Cyber Analytic Repository information")
  car.raw <- ParseCARData(verbose)

  relations <- ParseCARRelations(datamodel.raw, sensors.raw, car.raw, verbose)
}

ParseCARDataModel <- function(verbose) {
  if (verbose) print("[CAR]  - Processing Data Models raw data...")
  source.url <- "https://car.mitre.org/wiki/Category:Data_Model"
  doc <- xml2::read_html(RCurl::getURL(url = source.url, ssl.verifypeer = FALSE))

  dm.sources <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-pages"]/div/div/div/ul/li/a/@href'))
  dm.ids <- stringr::str_replace(dm.sources, "/wiki/Data_Model/", "")
  dm.sources <- as.character(sapply(dm.sources, function(x) paste("https://car.mitre.org", x, sep = "")))

  df.basic <- data.frame(id = dm.ids,
                         source = dm.sources,
                         stringsAsFactors = FALSE)

  if (verbose) print("[CAR]  - Processing Data Model details and relationships...")
  df <- data.frame(id = character(),
                   description = character(),
                   action = character(),
                   field = character(),
                   stringsAsFactors = FALSE)

  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  for (src.url in unique(df.basic$source)) {
    df <- rbind(df, ExtractCARDataModel(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  df <- dplyr::left_join(df.basic, df, by = c("id"))
  names(df) <- c("id", "source", "description", "action", "field", "sensor")

  return(df)
}

ExtractCARDataModel <- function(source.url = "https://car.mitre.org/wiki/Data_Model/driver") {
  source.html <- RCurl::getURL(url = source.url, ssl.verifypeer = FALSE)
  source.html <- stringr::str_replace_all(source.html, "<br />", ", ")
  doc <- xml2::read_html(source.html)
  dm.id <- stringr::str_replace(source.url, "https://car.mitre.org/wiki/Data_Model/", "")

  # Parse headers as list of nodes
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]')
  xpath <- sprintf("//p[count(preceding-sibling::h2)=%d]", seq_along(headlines) - 1)

  dm <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                   rvest::html_text, trim = TRUE),
                                        paste, collapse = "\n")
                         ,
                         rvest::html_text(rvest::html_node(headlines, "span")))
  dm <- as.data.frame(t(dm[dm != ""]), stringsAsFactors = FALSE)

  dm <- data.frame(id = stringr::str_replace(source.url, "https://car.mitre.org/wiki/Data_Model/", ""),
                   description = dm[,1],
                   stringsAsFactors = FALSE)

  # Extract related techniques
  fields <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table/tr[1]/th'))
  fields <- fields[fields != ""]

  actions <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-content-text"]/table/tr[position()>1]/th'))

  df <- as.data.frame.matrix(merge(actions, fields))
  names(df) <- c("action", "field")
  df$id <- rep(dm.id, nrow(df))

  # Extract Sensors relationship
  cover.map <- rvest::html_table(xml2::xml_find_first(doc, xpath = '//table[@class="sensor_table wikitable"]'))
  rn.cm <- cover.map[,1]
  cover.map <- cover.map[,-1]
  cover.map <- as.data.frame.matrix(apply(cover.map, 2, function(x) stringr::str_replace(x, ",$", "")), stringsAsFactors = FALSE)
  row.names(cover.map) <- rn.cm

  df <- dplyr::left_join(dm, df, by = c("id"))
  df$sensor <- apply(df, 1, function(x) cover.map[x[3],x[4]])

  df <- tidyr::separate_rows(df, sensor, sep = ", ")
  df$sensor[which(df$sensor == "")] <- NA

  return(df)
}

ParseCARSensors <- function(verbose) {
  if (verbose) print("[CAR]  - Processing Sensors raw data...")
  source.url <- "https://car.mitre.org/wiki/Category:Sensors"
  doc <- xml2::read_html(RCurl::getURL(url = source.url, ssl.verifypeer = FALSE))

  s.sources <- rvest::html_text(rvest::html_nodes(x = doc, xpath = '//*[@id="mw-pages"]/div/ul/li/a/@href'))
  s.ids <- stringr::str_replace(s.sources, "/wiki/", "")
  s.sources <- as.character(sapply(s.sources, function(x) paste("https://car.mitre.org", x, sep = "")))

  df.basic <- data.frame(id = s.ids,
                         source = s.sources,
                         stringsAsFactors = FALSE)

  if (verbose) print("[CAR]  - Processing Sensors details and relationships...")
  df <- data.frame(id = character(),
                   stringsAsFactors = FALSE)

  if (verbose) {pb <- utils::txtProgressBar(min = 0, max = nrow(df.basic), style = 3); i <- 1}

  for (src.url in unique(df.basic$source)) {
    df <- rbind(df, ExtractCARSensor(src.url))
    if (verbose) {utils::setTxtProgressBar(pb, i); i <- i + 1}
  }

  df <- dplyr::left_join(df.basic, df, by = c("id"))
  names(df) <- c("id", "source", "description", "action", "field", "sensor")

  return(df)

}

ExtractCARSensor <- function(source.url = "https://car.mitre.org/wiki/Autoruns") {
  doc <- xml2::read_html(RCurl::getURL(url = source.url, ssl.verifypeer = FALSE))

  # Parse headers as list of nodes
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h2]')
  xpath <- sprintf("//p[count(preceding-sibling::h2)=%d]", seq_along(headlines) - 1)

  s <- purrr::set_names(purrr::map_chr(purrr::map(purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x)),
                                                   rvest::html_text, trim = TRUE),
                                        paste, collapse = "\n")
                         ,
                         rvest::html_text(rvest::html_node(headlines, "span")))
  s <- as.data.frame(t(s[s != ""]), stringsAsFactors = FALSE)

  s <- data.frame(id = stringr::str_replace(source.url, "https://car.mitre.org/wiki/Data_Model/", ""),
                   description = s[,1],
                   stringsAsFactors = FALSE)
  s$id <- stringr::str_replace(source.url, "https://car.mitre.org/wiki/", "")

  # Extract Data Model coverage
  headlines <- rvest::html_nodes(x = doc, xpath = '//*[self::h3]')
  xpath <- sprintf("//table[count(preceding-sibling::h3)=%d]", seq_along(headlines) - 1)

  c <- purrr::map(xpath, ~rvest::html_nodes(x = doc, xpath = .x))
  names(c) <- rvest::html_text(headlines)

}

ParseCARData <- function(verbose) {
  if (verbose) print("[CAR]  - Processing CAR basic information...")

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

  if (verbose) print("[CAR]  - Processing CAR details and relationships...")
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
  if ("host.subtypes" %in% names(df)) {
    df <- tidyr::separate_rows(df, host.subtypes, sep = ", ")
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

ParseCARRelations <- function(datamodel.raw, sensors.raw, car.raw, verbose) {
  df <- data.frame(from = character(),
                   to = character(),
                   source = character(),
                   target = character(),
                   info = character(),
                   stringsAsFactors = FALSE)

  # CAR - Techniques
  r <- unique(dplyr::select(car, id, tech.id, coverage))
  names(r) <- c("from", "to", "info")
  r$info <- as.character(sapply(r$info,
                                function(x)
                                  jsonlite::toJSON(paste("[coverage:", x, "]", sep = ""))
  )
  )
  r$source <- rep("CAR", nrow(r))
  r$target <- rep("Technique", nrow(r))

  df <- dplyr::bind_rows(df, r)

  # CAR - Tactics
  tactics.url <- "https://attack.mitre.org/wiki/Category:Tactic"
  doc <- xml2::read_html(tactics.url)

  t.list <- rvest::html_nodes(x = doc, css = "#mw-pages > div > div > div > ul > li > a")
  tactics <- as.data.frame(t(as.matrix(as.data.frame(rvest::html_attrs(t.list)))),
                           row.names = FALSE, stringsAsFactors = FALSE)
  tactics$id <- sapply(stringr::str_split(tactics$href, "/"), function(x) x[3])
  tactics <- dplyr::select(tactics, id, title)

  r <- unique(dplyr::select(car, id, tactic.name, coverage))
  r <- dplyr::left_join(r, tactics, by = c("tactic.name" = "title"))
  names(r) <- c("from", "tactic.name", "info", "to")
  r$tactic.name <- NULL
  r$info <- as.character(sapply(r$info,
                                function(x)
                                  jsonlite::toJSON(paste("[coverage:", x, "]", sep = ""))
  )
  )
  r$source <- rep("CAR", nrow(r))
  r$target <- rep("Tactic", nrow(r))

  df <- dplyr::bind_rows(df, r)

  return(df)
}

