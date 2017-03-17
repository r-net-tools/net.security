#---- Public functions --------------------------------------------------------

#' DataSetStatus
#'
#' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' @return Pairs of datasate
#' @export
#' @examples
#' net.security::DataSetStatus(dataset = "all")
#' net.security::DataSetStatus(dataset = "cves")
DataSetStatus <- function(dataset = "all") {
  status <- "Unknown"

  if (tolower(dataset) %in% c("cves", "all")) {
    # Get Status from local cves data.frame
    print("* CVES dataset:")
    if (DataSetAvailable(dataset)) {
      cves.timestamp <- netsec.data[[1]][[paste(dataset,".ini", sep = "")]]
      print(paste("  Last update for CVES dataset at", as.character(cves.timestamp)))
      print(paste("  Data set with", as.character(nrow(netsec.data[[2]][[dataset]])), "rows and",
            as.character(ncol(netsec.data[[2]][[dataset]])), "variables."))
      cveonline <- strptime(net.security::LastDownloadCVEDate(), format = "%Y-%m-%d")
      cves.timestamp <- strptime(cves.timestamp, format = "%Y-%m-%d")
      print(paste("  Online RAW data updated at", cveonline))
      status <- paste("->CVES dataset", as.character(cveonline-cves.timestamp), "days outdated!")
    }
  }
  return(status)
}

#' DataSetUpdate
#'
#' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' @return Official source files download date time.
#' @export
#' @examples
#' net.security::DataSetUpdate(dataset = "all")
#' net.security::DataSetUpdate(dataset = "cves")
DataSetUpdate <- function(dataset = "all") {
  today <- Sys.Date()
  timestamp <- list()
  datasets <- list()

  # Update CVES dataset
  if (tolower(dataset) %in% c("cves", "all")) {
    #  Update local cves data.frame from official sources
    cves <- GetCVEData()
    #  build cves internal object (data.frame, date)
    datasets["cves"] <- list(cves)
    # Save temporal data frame
    save(object = cves, file = "inst/extdata/cves.rda", compress = "gzip")
    timestamp["cves.ini"] <- list(today)
    timestamp["cves.fin"] <- list(Sys.Date())
  }

  # Update and save datasets object
  netsec.data <- list(timestamp, datasets)
  save(object = netsec.data, file = "data/netsec.data.rda", compress = "gzip")

  return(as.character(today))
}

#' DataSetList
#'
#' @return List of available dataset values.
#' @export
#' @examples
#' net.security::DataSetList()
DataSetList <- function(){
  # Load local datasets and check which are available
  # return available as character array
  datasets <- ""

  # Search CVES dataset
  if (DataSetAvailable(dataset = "cves")) {
    datasets <- ifelse(datasets == "",
                       yes = "cves",
                       no = c(datasets, "cves"))
  }
  datasets <- ifelse(datasets == "",
                     yes = "Data sets not available. Use net.security::DataSetUpdate() ",
                     no = datasets)

  # Search CPES dataset
  if (DataSetAvailable(dataset = "cpes")) {
    datasets <- ifelse(datasets == "",
                 yes = "cpes",
                 no = c(datasets, "cpes"))
  }

  # Check if no datasets available
  datasets <- ifelse(datasets == "",
                     yes = "Data sets not available. Use net.security::DataSetUpdate() ",
                     no = datasets)
  return(datasets)
}

#' GetDataFrame
#'
#' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' @return Selected dataset as tidy data.frame
#' @export
#' @examples
#' cves <- net.security::GetDataFrame(dataset = "cves")
GetDataFrame <- function(dataset) {
  df <- data.frame()
  if (DataSetAvailable(dataset)) {
    df <- netsec.data[[2]][[dataset]]
  }
  return(df)
}


#---- Private functions --------------------------------------------------------

#' DataSetAvailable
#'
#' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' @return TRUE if dataset is available, FALSE if it needs an update.
DataSetAvailable <- function(dataset) {
  checkval <- FALSE
  # Check if dataset exists on environment | inst/tmpdata/dataset.rda | tempdir()/dataset.rda
  if (exists("netsec.data")) {
    checkval <- any(dataset %in% names(netsec.data[[2]]))
  }
  # Normalize how to store internal datasets
  return(checkval)
}
