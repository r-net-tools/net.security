#' #---- Public functions --------------------------------------------------------
#'
#' #' DataSetStatus
#' #'
#' #' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' #' @return Pairs of datasate
#' #' @export
#' DataSetStatus <- function(dataset = "all") {
#'   #' # @examples
#'   #' net.security::DataSetStatus(dataset = "all")
#'   #' net.security::DataSetStatus(dataset = "cves")
#'   status <- "Unknown"
#'   if (tolower(dataset) %in% c("cves", "all")) {
#'     # Get Status from local cves data.frame
#'   }
#'   return(status)
#' }
#'
#' #' DataSetUpdate
#' #'
#' #' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' #' @return Official source files download date time.
#' #' @export
#' DataSetUpdate <- function(dataset = "all") {
#'   #' # @examples
#'   #' net.security::DataSetUpdate(dataset = "all")
#'   #' net.security::DataSetUpdate(dataset = "cves")
#'   today <- Sys.Date()
#'   datasets <- list()
#'   if (tolower(dataset) %in% c("cves", "all")) {
#'     #  Update local cves data.frame from official sources
#'     df.cves <- GetCVEData()
#'     #  build cves internal object (data.frame, date)
#'     datasets["cves"] <- list(df.cves)
#'     # Save temporal data frame
#'     save(object = df.cves, file = "inst/tmpdata/cves.rda", compress = "gzip")
#'   }
#'   netsec.data <- list(today, datasets)
#'   save(object = netsec.data, file = "inst/extdata/netsec.data.rda", compress = "gzip")
#'   return(as.character(today))
#' }
#'
#' #' DataSetList
#' #'
#' #' @return List of available dataset values.
#' #' @export
#' DataSetList <- function(){
#'   #' # @examples
#'   #' net.security::DataSetList()
#'   # Load local datasets and check which are available
#'   # return available as character array
#'   datasets <- character(0)
#'   if (DataSetAvailable(dataset = "cves")) {
#'     datasets <- ifelse(datasets == character(0),
#'                        yes = "cves",
#'                        no = c(datasets, "cves"))
#'   }
#'   datasets <- ifelse(datasets == character(0),
#'                      yes = "Data sets not available. Use net.security::DataSetUpdate() ",
#'                      no = datasets)
#'   return(datasets)
#' }
#'
#' #' GetDataFrame
#' #'
#' #' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' #' @return Selected dataset as tidy data.frame
#' #' @export
#' GetDataFrame <- function(dataset = "cves") {
#'   #' examples
#'   #' cves <- net.security::GetDataFrame(dataset = "cves")
#'   df <- data.frame()
#'   if (DataSetAvailable(dataset = "cves")) {
#'     df <- netsec.data[[2]][["cves"]]
#'   }
#'   return(df)
#' }
#'
#'
#' #---- Private functions --------------------------------------------------------
#'
#' #' DataSetAvailable
#' #'
#' #' @param dataset Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' #' @return TRUE if dataset is available, FALSE if it needs an update.
#' DataSetAvailable <- function(dataset = "cves") {
#'   checkval <- FALSE
#'   # Check if dataset exists on environment | inst/tmpdata/dataset.rda | tempdir()/dataset.rda
#'   if (any("netsec.data.rda" %in% ls(parent.env(globalenv())))) {
#'     checkval <- any(dataset %in% names(netsec.data[[2]]))
#'   }
#'   # Normalize how to store internal datasets
#'   return(checkval)
#' }
