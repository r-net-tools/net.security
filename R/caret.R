GetCARETData <- function(savepath = tempdir(), verbose = T) {
  print("Downloading raw data from MITRE...")
  caret.file <- DownloadCARETData(savepath)
  print("Processing CARET raw data...")
  caret <- ParseCARETData(caret.file, verbose)
  print(paste("CARET data frame building process finished."))
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
  car.groups <- plyr::ldply(caret.raw$groups,
                            function(x) {
                              plyr::ldply(x$techniques,
                                          function(y) {
                                            data.frame(name = x$name,
                                                       technique = y,
                                                       id = x$ID,
                                                       aliases = as.character(jsonlite::toJSON(x$aliases)),
                                                       stringsAsFactors = F)
                                          }
                              )
                            })
  car.techniques <- plyr::ldply(caret.raw$techniques,
                                function(x) {
                                  plyr::ldply(x$tactics,
                                              function(y) {
                                                data.frame(url = paste("https://attack.mitre.org/wiki", x$name, sep = "/"),
                                                           tactic = y,
                                                           id = x$ID,
                                                           display_name = x$display_name,
                                                           stringsAsFactors = F)
                                              }
                                  )
                                })

  tech.url <- "https://attack.mitre.org/wiki/All_Techniques"
  tech.doc <- xml2::read_html(tech.url)
  tech.descr <- sapply(X = rvest::html_nodes(x = tech.doc, xpath = '//td[@class="Technical-Description smwtype_txt"]'),
                       function(x) {
                         if (length(xml2::xml_children(x))) {
                           paste(as.character(xml2::xml_children(x)), collapse = "<br>")
                         } else {
                           as.character(xml2::xml_contents(x))
                         }

                       })
  tech.id <- sapply(X = rvest::html_nodes(x = tech.doc, xpath = '//td[@class="ID smwtype_txt"]'),
                       function(x) {
                         rvest::html_text(x)
                       })
  tech.extra <- as.data.frame(cbind(id = tech.id, description = tech.descr), stringsAsFactors = F)
  kk <- dplyr::left_join(car.techniques, tech.extra, c("id"="id"))

  # # Parse all techniques wiki info
  # car.techniques <- caret$techniques
  # tech.url <- unique(car.techniques$url)[2]
  # tech.doc <- xml2::read_html(tech.url)
  # tech.extra <- rvest::html_nodes(x = tech.doc, xpath = '//div[@id="toc"]')
  # if (length(tech.extra > 1)) {
  #   columns <- rvest::html_text(rvest::html_nodes(x = tech.doc, xpath = '//div[@id="toc"]/ul/li/a/span[2]'))
  # }


  car.analytics <- plyr::ldply(caret.raw$analytics,
                               function(x) {
                                 plyr::ldply(x[[2]],
                                             function(y) {
                                               if (length(y$tactics) > 1) {
                                                 plyr::ldply(y$tactics, function(z) {
                                                   data.frame(id = x$name,
                                                              name = x$shortName,
                                                              tactic = z,
                                                              cover = y$coverage,
                                                              tech = y$technique,
                                                              stringsAsFactors = F)
                                                 })
                                               } else {
                                                 data.frame(id = x$name,
                                                            name = x$shortName,
                                                            tactic = y$tactics,
                                                            cover = y$coverage,
                                                            tech = y$technique,
                                                            stringsAsFactors = F)
                                               }
                                             }
                                 )
                               })

  caret <- list(data.model = car.data.model,
                groups = car.groups,
                sensors = car.sensors,
                techniques = car.techniques,
                analytics = car.analytics)

  car.url <- "https://car.mitre.org/wiki/Full_Analytic_List"
  doc <- rvest::html(car.url)

  caret$analytics <- dplyr::left_join(x = caret$analytics,
                                      y = as.data.frame(cbind(car.id = rvest::html_text(rvest::xml_nodes(doc,
                                                                                                         xpath = '//div[@id="mw-content-text"]/table/tr/td[@class="Analytic smwtype_wpg"]/a/@title')),
                                                              car.hypothesis = rvest::html_text(rvest::xml_nodes(doc,
                                                                                                                 xpath = '//div[@id="mw-content-text"]/table/tr/td[@class="Hypothesis smwtype_txt"]'))),
                                                        stringsAsFactors = F),
                                      by = c("id" = "car.id"))

  return(caret)
}
