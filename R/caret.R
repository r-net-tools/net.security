GetCARETData <- function(savepath = tempdir(), verbose = T) {
  print("Downloading raw data from MITRE...")
  DownloadCARETData(savepath)
  print("Processing CARET raw data...")
  caret <- ParseCARETData(caret.file, verbose)
  print(paste("CARET data frame building process finished."))
  return(caret)
}

DownloadCARETData <- function(savepath) {
  if (!dir.exists(paste(savepath, "caret", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "caret", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }
  caret.url  <- "blob:https://car.mitre.org/d6d94237-1c76-4a40-a0a6-37bfae799806"
  destfile <- paste(savepath, "caret", "caret-data.json",sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::download.file(url = caret.url, destfile = destfile)
}

ParseCARETData <- function(caret.file, verbose) {
  # caret.file <- "inst/tmpdata/caret-data.json"
  caret.raw <- RJSONIO::fromJSON(caret.file)

  car.data.model <- plyr::ldply(caret.raw$dataModel,
                                function(x) {
                                  plyr::ldply(x$actions,
                                              function(y) {
                                                data.frame(name = rep(x$name, length(x$fields)),
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
                                                data.frame(name = x$name,
                                                           tactic = y,
                                                           id = x$ID,
                                                           display_name = x$display_name,
                                                           stringsAsFactors = F)
                                              }
                                  )
                                })
  car.analytics <- caret.raw$analytics
}
