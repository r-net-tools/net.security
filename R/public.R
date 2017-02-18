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
  if (dataset == "cves") {
    # Get Status from local cves data.frame
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
  if (dataset == "cves") {
    #  Update local cves data.frame from official sources
    #  df <- GetCVEData()
    #  build cves internal object (data.frame, date)
  }
  return(today)
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
  return(datasets)
}

#' GetDataFrame
#'
#' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' @return Selected dataset as tidy data.frame
#' @export
#' @examples
#' cves <- net.security::GetDataFrame(dataset = "cves")
GetDataFrame <- function(dataset = "cves") {
  df <- data.frame()
  if (dataset == "cves") {
    # if (DataSetAvailable(dataset = "cves")) {
    #   df <- GetCVEData()
    # }
  }
  return(df)
}


#---- Private functions --------------------------------------------------------
#' DataSetAvailable
#'
#' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' @return TRUE if dataset is available, FALSE if it needs an update.
DataSetAvailable <- function(dataset = "cves") {
  checkval <- FALSE
  # Check if dataset exists on environment | inst/tmpdata/dataset.rda | tempdir()/dataset.rda
  # Normalize how to store internal datasets
  return(checkval)
}
