#' Shows data set basic information
#'
#' \code{DataSetStatus} prints to console size of data set, download date and date of new public raw data.
#'
#' This is a generic function. Just specify which standard and it will print its
#' information. Type "all" or leave it without parameters and it will print info
#' for all available datasets.
#'
#' @param ds Selects the data set for this operation. Default set to "all".
#'           Check available option with DataSetList()
#' @return Pairs of datasate
#' @export
#' @examples
#' DataSetStatus("cves")
#' \dontrun{
#' DataSetStatus()
#' }
DataSetStatus <- function(ds = "all") {
  status <- "Unknown"

  if (tolower(ds) %in% c("cves", "all")) {
    # Get Status from local cves data.frame
    if (DataSetAvailable("cves")) {
      print("-: CVES dataset:")
      cves.timestamp <- netsec.data[[1]][["cves.ini"]]
      print(paste(" |- Last update for CVES dataset at", as.character(cves.timestamp)))
      print(paste(" |- Data set with", as.character(nrow(netsec.data[[2]][["cves"]])), "rows and",
            as.character(ncol(netsec.data[[2]][["cves"]])), "variables."))
      cveonline <- strptime(LastDownloadCVEDate(), format = "%Y-%m-%d")
      cves.timestamp <- strptime(cves.timestamp, format = "%Y-%m-%d")
      print(paste(" |- Online RAW data updated at", cveonline))
      if ((cveonline-cves.timestamp)<=0) {
        print(paste(" |- No updates needed for CVES dataset."))
      } else {
        print(paste(" |- CVES dataset", as.character(cveonline-cves.timestamp), "days outdated."))
      }
      status <- "."
    }
  }
  if (tolower(ds) %in% c("cpes", "all")) {
    # Get Status from local cpes data.frame
    if (DataSetAvailable("cpes")) {
      print("-: CPES dataset:")
      cpes.timestamp <- netsec.data[[1]][["cpes.ini"]]
      print(paste(" |- Last update for CPES dataset at", as.character(cpes.timestamp)))
      print(paste(" |- Data set with", as.character(nrow(netsec.data[[2]][["cpes"]])), "rows and",
                  as.character(ncol(netsec.data[[2]][["cpes"]])), "variables."))
      cpeonline <- strptime(LastDownloadCPEDate(), format = "%Y-%m-%d")
      cpes.timestamp <- strptime(cpes.timestamp, format = "%Y-%m-%d")
      print(paste(" |- Online RAW data updated at", cpeonline))
      if ((cpeonline-cpes.timestamp)<=0) {
        print(paste(" |- No updates needed for CPES dataset."))
      } else {
        print(paste(" |- CPES dataset", as.character(cpeonline-cpes.timestamp), "days outdated."))
      }
      status <- "."
    }
  }
  return(status)
}

#' DataSetUpdate
#'
#' @param ds Selects the data set for this operation. Default set to "all".
#'           Check available options with DataSetList()
#' @return Official source files download date time.
#' @export
#' @examples
#' \dontrun{
#' net.security::DataSetUpdate(ds = "all")
#' }
#' \dontrun{
#' net.security::DataSetUpdate(ds = "cves")
#' }
DataSetUpdate <- function(ds = "all") {
  today <- Sys.Date()
  timestamp <- list()
  datasets <- netsec.data$datasets

  # Update CVES dataset
  if (tolower(ds) %in% c("cves", "all")) {
    #  Update local cves data.frame from official sources
    cves <- GetCVEData()
    # Update dataset object
    netsec.data$dwinfo[["cves.ini"]] <- today
    netsec.data$dwinfo[["cves.fin"]] <- Sys.Date()
    datasets[["cves"]] <- cves
    netsec.data$datasets <- datasets

    # cveonline <- strptime(LastDownloadCVEDate(), format = "%Y-%m-%d")
    # cves.timestamp <- strptime(netsec.data[[1]][["cves.ini"]], format = "%Y-%m-%d")
    # if ((cveonline - cves.timestamp) <= 0) {
    #   print(paste(" |- No updates needed for CPES dataset."))
    # } else {
    #   print(paste(" |- CPES dataset", as.character(cpeonline-cpes.timestamp), "days outdated."))
    # }

    # upd <- LastDownloadCVEDate()
    # if (any(grepl("cves", names(netsec.data$dwinfo))) &
    #     (netsec.data$dwinfo$cves.ini >= upd)) {
    #   print("You have the newest CVES dataset.")
    # } else {
    #
    #   # Save sample cves data frame
    #   # print("Compressing and saving random sample of CVEs to local file...")
    #   # cves.sample <- cves[sample(nrow(cves), 500), ]
    #   # save(object = cves.sample, file = "data/cves.sample.rda", compress = "xz")
    # }
  }

  # Update CPES dataset
  if (tolower(ds) %in% c("cpes", "all")) {
    #  Update local cpes data.frame from official sources
    cpes <- GetCPEData()
    # Update dataset object
    netsec.data$dwinfo[["cpes.ini"]] <- today
    netsec.data$dwinfo[["cpes.fin"]] <- Sys.Date()
    datasets[["cpes"]] <- cpes
    netsec.data$datasets <- datasets
  }

  # Update and save datasets object
  # netsec.data <- list(timestamp, datasets)
  # names(netsec.data) <- c("dwinfo","datasets")
  print("Compressing and saving data sets to local file...")
  save(object = netsec.data, file = "R/sysdata.rda", compress = "xz")

  # TODO: Update netsec.data in parent.env(environment())
  warning("Package needs rebuild to use updated data sets.")
  # assign(x = netsec.data, value = net.sec.data, envir = parent.env(environment()))

  return(as.character(today))
}

#' DataSetList
#'
#' @return List of available datasets.
#' @export
#' @examples
#' net.security::DataSetList()
DataSetList <- function(){
  # Load local datasets and check which are available
  # return available as character array
  datasets <- ""

  # Search CVES dataset
  if (DataSetAvailable(ds = "cves")) {
    ifelse(datasets == "",
           yes = datasets <- "cves",
           no = datasets[length(datasets) + 1] <- "cves")
  }

  # Search CPES dataset
  if (DataSetAvailable(ds = "cpes")) {
    ifelse(datasets == "",
           yes = datasets <- "cpes",
           no = datasets[length(datasets) + 1] <- "cpes")
  }

  # Check if no datasets available
  datasets <- ifelse(datasets == "",
                     yes = "Data sets not available. Use net.security::DataSetUpdate() ",
                     no = datasets)
  return(datasets)
}

#' GetDataFrame
#'
#' @param ds Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' @return Selected dataset as tidy data.frame
#' @export
#' @examples
#' cves <- net.security::GetDataFrame(ds = "cves")
GetDataFrame <- function(ds) {
  df <- data.frame()
  if (DataSetAvailable(ds)) {
    df <- netsec.data[["datasets"]][[ds]]
  } else {
    warning(paste(toupper(ds), "data set not available. Use net.security::DataSetUpdate()"))
  }
  return(df)
}


#---- Private functions --------------------------------------------------------

#' DataSetAvailable
#'
#' @param ds Selects the data set for this operation. Default set to "all". Check available option with DataSetList()
#' @return TRUE if dataset is available, FALSE if it needs an update.
DataSetAvailable <- function(ds) {
  checkval <- FALSE
  if (exists("netsec.data")) {
    checkval <- any(tolower(ds) %in% names(netsec.data[["datasets"]]))
  }
  # Normalize how to store internal datasets
  return(checkval)
}
