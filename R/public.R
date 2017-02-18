#' DataSetStatus
#'
#' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#'
#' @return
#' @export
#'
#' @examples
DataSetStatus <- function(dataset = "all") {
  status <- "Unknown"
  return(status)
}

#' DataSetUpdate
#'
#' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#'
#' @return
#' @export
#'
#' @examples
DataSetUpdate <- function(dataset = "all") {
  today <- Sys.Date()
  return(today)
}

#' DataSetList
#'
#' @return
#' @export
#'
#' @examples
DataSetList <- function(){
  datasets <- ""
  return(datasets)
}
