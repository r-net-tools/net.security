
#' GetOVALData
#'
#' @return data frame
#'
#' @examples
#' oval.defs <- net.security::GetOVALData()
GetOVALData <- function(savepath = tempdir()) {
  DownloadOVALData(savepath)
  oval.source.file <- paste(savepath, "oval", "oval.xml",
                            sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  ovals <- ParseOVALData(oval.source.file)
  return(ovals)
}


DownloadOVALData <- function(savepath) {
  if (!dir.exists(paste(savepath, "oval", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "oval", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }
  # Download data (https://oval.cisecurity.org/repository/download)
  utils::download.file(url = "https://oval.cisecurity.org/repository/download/5.11.1/all/oval.xml",
                       destfile = paste(savepath, "oval", "oval.xml",
                                        sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
}

NewOVALItem <- function(){
  return(data.frame(class = character(),
                    id = character(),
                    version = character(),
                    title = character(),
                    affected.family = character(),
                    affected.platforms = character(),
                    affected.cpes = character(),
                    references = character(),
                    status = character(),
                    stringsAsFactors = FALSE)
  )
}

GetOVALItem <- function(oval.def) {
  df <- NewOVALItem()

  def.basic <- as.data.frame(t(XML::xmlAttrs(oval.def)), stringsAsFactors = F)
  def.data <- XML::xmlChildren(XML::xmlChildren(oval.def)[["metadata"]])

  def.title <- as.character(XML::xmlValue(def.data[["title"]]))
  if ("affected" %in% names(def.data)) {
    def.affected.family <- as.character(XML::xmlAttrs(def.data[["affected"]])[["family"]])
    def.affected.platforms <- as.character(jsonlite::toJSON(XML::xmlToDataFrame(XML::xmlChildren(def.data[["affected"]]))))
  } else {
    def.affected.family <- NA
    def.affected.platforms <- NA
  }
  def.oval.repo <- XML::xmlChildren(def.data[["oval_repository"]])
  if ("affected_cpe_list" %in% names(def.oval.repo)) {
    def.affected.cpes <- as.character(jsonlite::toJSON(XML::xmlToDataFrame(def.oval.repo[["affected_cpe_list"]])))
  } else {
    def.affected.cpes <- NA
  }
  if ("reference" %in% names(def.data)) {
    def.references <- as.character(jsonlite::toJSON(XML::xmlAttrs(def.data[["reference"]])))
  } else {
    def.references <- NA
  }

  def.status <- as.character(XML::xmlValue(XML::xmlChildren(def.data[["oval_repository"]])[["status"]]))

  df <- rbind(df, cbind(def.basic, def.title, def.affected.family,
                        def.affected.platforms, def.affected.cpes, def.references,
                        def.status, stringsAsFactors = FALSE),
              stringsAsFactors = FALSE)
  return(df)
}

ParseOVALData <- function(oval.source.file) {
  # doc2 <- XML::xmlTreeParse(oval.file)
  doc <- XML::xmlParse(oval.source.file)
  # raw.definitions <- XML::xpathSApply(doc, "//oval_definitions")
  root.xml <- XML::xmlChildren(doc)
  oval.xml <- XML::xmlChildren(root.xml[[1]])
  oval.defs <- XML::xmlChildren(oval.xml[["definitions"]])

  l.oval.defs <- lapply(oval.defs, GetOVALItem)
  ovals <- plyr::ldply(l.oval.defs, data.frame)

  # TidyData
  names(ovals) <- c("type", "class", "id", "version", "title", "affected.family",
                    "affected.platforms", "affected.cpes", "references", "status",
                    "deprecated")
  ovals$type <- as.factor(ovals$type)
  ovals$class <- as.factor(ovals$class)
  ovals$version <- as.factor(ovals$version)
  ovals$affected.family <- as.factor(ovals$affected.family)
  ovals$status <- as.factor(ovals$status)
  ovals$deprecated <- as.factor(ovals$deprecated)

  return(ovals)
}
