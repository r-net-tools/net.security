GetCARETData <- function(savepath = tempdir(), verbose = T) {
  if (verbose) print("Downloading raw data from MITRE...")
  caret.file <- DownloadCARETData(savepath)
  if (verbose) print("Processing CARET raw data...")
  caret <- ParseCARETData(caret.file, verbose)
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


ParseCARETData <- function(caret.file, verbose) {
  caret.raw <- RJSONIO::fromJSON(caret.file)

  car.data.model <- plyr::ldply(caret.raw$dataModel,
                                function(x) {
                                  plyr::ldply(x$actions,
                                              function(y) {
                                                data.frame(object = rep(x$name, length(x$fields)),
                                                           action = rep(y, length(x$fields)),
                                                           field = x$fields,
                                                           stringsAsFactors = F)
                                              }
                                  )
                                })
  car.sensors <- plyr::ldply(caret.raw$sensors,
                             function(x) {
                               data.frame(name = rep(x$name, length(x$fields)),
                                          field = x$fields,
                                          stringsAsFactors = F)
                             })
  # car.groups <- plyr::ldply(caret.raw$groups,
  #                           function(x) {
  #                             plyr::ldply(x$techniques,
  #                                         function(y) {
  #                                           data.frame(name = x$name,
  #                                                      technique = y,
  #                                                      id = x$ID,
  #                                                      aliases = as.character(jsonlite::toJSON(x$aliases)),
  #                                                      stringsAsFactors = F)
  #                                         }
  #                             )
  #                           })
  # car.techniques <- plyr::ldply(caret.raw$techniques,
  #                               function(x) {
  #                                 plyr::ldply(x$tactics,
  #                                             function(y) {
  #                                               data.frame(url = paste("https://attack.mitre.org/wiki", x$name, sep = "/"),
  #                                                          tactic = y,
  #                                                          id = x$ID,
  #                                                          display_name = x$display_name,
  #                                                          stringsAsFactors = F)
  #                                             }
  #                                 )
  #                               })

  car.analytics <- plyr::ldply(caret.raw$analytics,
                               function(x) {
                                 plyr::ldply(x[[2]],
                                             function(y) {
                                               if (length(y$tactics) > 1) {
                                                 plyr::ldply(y$tactics, function(z) {
                                                   data.frame(id = x$name,
                                                              name = x$shortName,
                                                              tactic.name = z,
                                                              cover = y$coverage,
                                                              tech.id = stringr::str_replace(string = y$technique, pattern = "Technique/", replacement = ""),
                                                              stringsAsFactors = F)
                                                 })
                                               } else {
                                                 data.frame(id = x$name,
                                                            name = x$shortName,
                                                            tactic.name = y$tactics,
                                                            cover = y$coverage,
                                                            tech.id = stringr::str_replace(string = y$technique, pattern = "Technique/", replacement = ""),
                                                            stringsAsFactors = F)
                                               }
                                             }
                                 )
                               })
  car.url <- "https://car.mitre.org/wiki/Full_Analytic_List"
  car.html <- RCurl::getURL(url = car.url, ssl.verifypeer = FALSE)
  doc <- xml2::read_html(car.html)

  car.analytics <- dplyr::left_join(x = car.analytics,
                                    y = as.data.frame(cbind(car.id = rvest::html_text(rvest::xml_nodes(doc,
                                                                                                       xpath = '//div[@id="mw-content-text"]/table/tr/td[@class="Analytic smwtype_wpg"]/a/@title')),
                                                            car.hypothesis = rvest::html_text(rvest::xml_nodes(doc,
                                                                                                               xpath = '//div[@id="mw-content-text"]/table/tr/td[@class="Hypothesis smwtype_txt"]'))),
                                                      stringsAsFactors = F),
                                    by = c("id" = "car.id"))

  caret <- list(data.model = car.data.model,
                sensors = car.sensors,
                analytics = car.analytics)

  return(caret)
}

getTechniqueWikiInfo <- function(tech.url = "https://attack.mitre.org/wiki/Technique/T1156") {
  # Parse all techniques wiki info
  # tech.extra <- rvest::html_nodes(x = tech.doc, xpath = '//div[@id="toc"]')
  #
  # # Get TOC info
  # if (length(tech.extra > 1)) {
  #   columns <- rvest::html_text(rvest::html_nodes(x = tech.doc, xpath = '//div[@id="toc"]/ul/li/a/span[2]'))
  # } else {
  #   columns <- c()
  # }

  # Get Wiki info
  tech.doc <- xml2::read_html(tech.url)
  content <- rvest::html_nodes(x = tech.doc, xpath = '//div[@id="content"]')
  headlines <- rvest::html_nodes(content, xpath = "//*[self::h1 or self::h2]")
  xpath <- sprintf("//p[count(preceding-sibling::h2)=%d]", seq_along(headlines)-1)
  techwiki <- purrr::map(xpath, ~rvest::html_nodes(x = content, xpath = .x)) %>% # Get the text inside the headlines
    purrr::map(rvest::html_text, trim = TRUE) %>% # get per node in between
    purrr::map_chr(paste, collapse = "\n") %>% # collapse the text inbetween
    purrr::set_names(headlines %>% rvest::html_node("span") %>% rvest::html_text())
  techwiki <- as.data.frame(t(techwiki[techwiki != ""]))
  names(techwiki)[1] <- "Description"
  id <- stringr::str_split(string = tech.url, pattern = "/")[[1]]
  techwiki$id <- id[length(id)]

  return(techwiki)

}
