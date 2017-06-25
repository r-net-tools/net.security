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
#' @return Print information about data set status.
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
      cves.timestamp <- strptime(netsec.data[[1]][["cves.ini"]], format = "%Y-%m-%d")
      print(paste(" |- Last update for CVES dataset at", as.character(cves.timestamp)))
      print(paste(" |- Data set with", as.character(nrow(netsec.data[[2]][["cves"]])), "rows and",
            as.character(ncol(netsec.data[[2]][["cves"]])), "variables."))
      cveonline <- strptime(LastDownloadCVEDate(), format = "%Y-%m-%d")
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
      cpes.timestamp <- strptime(netsec.data[[1]][["cpes.ini"]], format = "%Y-%m-%d")
      print(paste(" |- Last update for CPES dataset at", as.character(cpes.timestamp)))
      print(paste(" |- Data set with", as.character(nrow(netsec.data[[2]][["cpes"]])), "rows and",
                  as.character(ncol(netsec.data[[2]][["cpes"]])), "variables."))
      cpeonline <- strptime(LastDownloadCPEDate(), format = "%Y-%m-%d")
      print(paste(" |- Online RAW data updated at", cpeonline))
      if ((cpeonline-cpes.timestamp)<=0) {
        print(paste(" |- No updates needed for CPES dataset."))
      } else {
        print(paste(" |- CPES dataset", as.character(cpeonline-cpes.timestamp), "days outdated."))
      }
      status <- "-:"
    }
  }
  if (tolower(ds) %in% c("cwes", "all")) {
    # Get Status from local cwes data.frame
    if (DataSetAvailable("cwes")) {
      print("-: CWES dataset:")
      cwes.timestamp <- strptime(netsec.data[[1]][["cwes.ini"]], format = "%Y-%m-%d")
      print(paste(" |- Last update for CWES dataset at", as.character(cwes.timestamp)))
      print(paste(" |- Data set with", as.character(nrow(netsec.data[[2]][["cwes"]])), "rows and",
                  as.character(ncol(netsec.data[[2]][["cwes"]])), "variables."))
      # cweonline <- strptime(LastDownloadCWEDate(), format = "%Y-%m-%d")
      # print(paste(" |- Online RAW data updated at", cweonline))
      # if ((cweonline-cwes.timestamp)<=0) {
      #   print(paste(" |- No updates needed for CWES dataset."))
      # } else {
      #   print(paste(" |- CWES dataset", as.character(cweonline-cwes.timestamp), "days outdated."))
      # }
    }
  }
  if (tolower(ds) %in% c("capec", "all")) {
    # Get Status from local capec data.frame
    if (DataSetAvailable("capec")) {
      print("-: CAPEC dataset:")
      capec.timestamp <- strptime(netsec.data[[1]][["capec.ini"]], format = "%Y-%m-%d")
      print(paste(" |- Last update for CAPEC dataset at", as.character(capec.timestamp)))
      print(paste(" |- Data set with", as.character(nrow(netsec.data[[2]][["capec"]])), "rows and",
                  as.character(ncol(netsec.data[[2]][["capec"]])), "variables."))
      # cweonline <- strptime(LastDownloadCWEDate(), format = "%Y-%m-%d")
      # print(paste(" |- Online RAW data updated at", cweonline))
      # if ((cweonline-cwes.timestamp)<=0) {
      #   print(paste(" |- No updates needed for CWES dataset."))
      # } else {
      #   print(paste(" |- CWES dataset", as.character(cweonline-cwes.timestamp), "days outdated."))
      # }
    }
  }
  return(status)
}

#' Update local data sets and update R/sysdata.rda file
#'
#' \code{DataSetUpdate} Starts the process for updating local data sets available with \code{\link{GetDataFrame}} function.
#'
#' The process include the following phases:
#' \enumerate{
#'    \item Download files from MITRE, NIST and INCIBE sources.
#'    \item Process MITRE raw data.
#'    \item Process NIST raw data. One file per year.
#'    \item Indexing data. Includes CSV and XML parsing. Build data frame.
#'    \item Tidy data frame.
#'    \item Compress and save data.frame to internal data.
#' }
#'
#' @param ds Selects the data set for this operation. Default set to "all".
#'           Check available options with DataSetList()
#' @param samples if TRUE it will create sample data.frames and store them in /data
#' @param use.remote if TRUE it will download sysdata.rda from net.security github
#' @return Date Official source files download date time.
#' @export
#' @examples
#' \dontrun{
#' net.security::DataSetUpdate(ds = "all")
#' }
#' \dontrun{
#' net.security::DataSetUpdate(ds = "cves")
#' }
DataSetUpdate <- function(ds = "all", samples = FALSE, use.remote = TRUE) {

  ds <- tolower(ds)
  if (ds %in% c("all", "cves", "cpes", "cwes", "capec")) {
    cves.ini <- Sys.Date()
    cpes.ini <- Sys.Date()
    cwes.ini <- Sys.Date()
    capec.ini <- Sys.Date()
    timestamp <- list()
    datasets <- netsec.data$datasets
    cves.nrow <- nrow(netsec.data$datasets$cves)
    cpes.nrow <- nrow(netsec.data$datasets$cpes)
    cwes.nrow <- nrow(netsec.data$datasets$cwes)
    capec.nrow <- nrow(netsec.data$datasets$capec)

    # Get updated data.frames
    if (use.remote) {
      # Get sysdata.rda and update local data
      utils::download.file(url = "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda",
                    destfile = paste(tempdir(),"sysdata.rda",sep = "\\"))
      load(file = paste(tempdir(),"sysdata.rda",sep = "\\"))
      if (tolower(ds) %in% c("cves", "all")) {
        #  Update local cves data.frame from official sources
        cves <- netsec.data$datasets$cves
        cves.ini <- netsec.data$dwinfo[["cves.ini"]]
      }
      if (tolower(ds) %in% c("cpes", "all")) {
        #  Update local cpes data.frame from official sources
        cpes <- netsec.data$datasets$cpes
        cpes.ini <- netsec.data$dwinfo[["cpes.ini"]]
      }
      if (tolower(ds) %in% c("cwes", "all")) {
        #  Update local cwes data.frame from official sources
        cwes <- netsec.data$datasets$cwes
        cwes.ini <- netsec.data$dwinfo[["cwes.ini"]]
      }
      if (tolower(ds) %in% c("capec", "all")) {
        #  Update local capec data.frame from official sources
        capec <- netsec.data$datasets$capec
        capec.ini <- netsec.data$dwinfo[["capec.ini"]]
      }
      rm(netsec.data)
    } else {
      if (tolower(ds) %in% c("cves", "all")) {
        print("Updating local cves data.frame from official sources.")
        cves <- GetCVEData()
      }
      if (tolower(ds) %in% c("cpes", "all")) {
        print("Updating local cpes data.frame from official sources.")
        cpes <- GetCPEData()
      }
      if (tolower(ds) %in% c("cwes", "all")) {
        print("Updating local cwes data.frame from official sources.")
        cwes <- GetCWEData()
      }
      if (tolower(ds) %in% c("capec", "all")) {
        print("Updating local capec data.frame from official sources.")
        capec <- GetCAPECData()
      }
    }

    # Update local data
    if (tolower(ds) %in% c("cves", "all")) {
      #  Update package datasets with updated cves data.frame
      netsec.data$dwinfo[["cves.ini"]] <- cves.ini
      netsec.data$dwinfo[["cves.fin"]] <- cves.ini
      datasets[["cves"]] <- cves
      new.cves <- as.character(nrow(cves) - cves.nrow)
      print(paste("Updated CVEs data.frame has", new.cves, " new observations."))
    }
    if (tolower(ds) %in% c("cpes", "all")) {
      #  Update package datasets with updated cpes data.frame
      netsec.data$dwinfo[["cpes.ini"]] <- cpes.ini
      netsec.data$dwinfo[["cpes.fin"]] <- cpes.ini
      datasets[["cpes"]] <- cpes
      new.cpes <- as.character(nrow(cpes) - cpes.nrow)
      print(paste("Updated CPEs data.frame has", new.cpes, " new observations."))
    }
    if (tolower(ds) %in% c("cwes", "all")) {
      #  Update package datasets with updated cwes data.frame
      netsec.data$dwinfo[["cwes.ini"]] <- cwes.ini
      netsec.data$dwinfo[["cwes.fin"]] <- cwes.ini
      datasets[["cwes"]] <- cwes
      new.cwes <- as.character(nrow(cwes) - cwes.nrow)
      print(paste("Updated CWEs data.frame has", new.cwes, " new observations."))
    }
    if (tolower(ds) %in% c("capec", "all")) {
      #  Update package datasets with updated capec data.frame
      netsec.data$dwinfo[["capec.ini"]] <- capec.ini
      netsec.data$dwinfo[["capec.fin"]] <- capec.ini
      datasets[["capec"]] <- capec
      new.capec <- as.character(nrow(capec) - capec.nrow)
      print(paste("Updated CAPECs data.frame has", new.capec, " new observations."))
    }
    netsec.data$datasets <- datasets

    # Save samples if needed
    if (samples) {
      if (tolower(ds) %in% c("cves", "all")) {
        #  Update local cves data.frame from official sources
        # Save sample cves data frame
        cves.sample <- cves[sample(nrow(cves), 1000), ]
        cves.sample[] <- lapply(cves.sample, as.character)
        save(object = cves.sample, file = "data/cves.sample.rda", compress = "xz")
      }
      if (tolower(ds) %in% c("cpes", "all")) {
        #  Update local cpes data.frame from official sources
        # Save sample cves data frame
        cpes.sample <- cpes[sample(nrow(cpes), 1000), ]
        cpes.sample[] <- lapply(cpes.sample, as.character)
        # cols <- names(cves)[sapply(cves, class) == "factor"]
        # cpes.sample[cols] <- lapply(cpes.sample[cols], factor)
        save(object = cpes.sample, file = "data/cpes.sample.rda", compress = "xz")
      }
      if (tolower(ds) %in% c("cwes", "all")) {
        #  Update local cwes data.frame from official sources
        # Save sample cves data frame
        cwes.sample <- cwes[sample(nrow(cwes), 100), ]
        cwes.sample[] <- lapply(cwes.sample, as.character)
        # cols <- names(cves)[sapply(cves, class) == "factor"]
        # cpes.sample[cols] <- lapply(cpes.sample[cols], factor)
        save(object = cwes.sample, file = "data/cwes.sample.rda", compress = "xz")
      }
      if (tolower(ds) %in% c("capec", "all")) {
        #  Update local capec data.frame from official sources
        # Save sample capec data frame
        capec.sample <- capec[sample(nrow(capec), 100), ]
        capec.sample[] <- lapply(capec.sample, as.character)
        # cols <- names(capec)[sapply(capec, class) == "factor"]
        # capec.sample[cols] <- lapply(capec.sample[cols], factor)
        save(object = capec.sample, file = "data/capec.sample.rda", compress = "xz")
      }
    }
    print("Compressing and saving data sets to local file...")
    save(object = netsec.data, file = "R/sysdata.rda", compress = "xz")

    # TODO: Update netsec.data in parent.env(environment())
    # https://www.r-bloggers.com/package-wide-variablescache-in-r-packages/
    warning("Package needs rebuild to use updated data sets.")
    # assign(x = netsec.data, value = netsec.data, envir = parent.env(environment()))
  } else {
    warning("Invalid option. Use net.security::DataSetList() to show available options.")
  }

  return(as.character(Sys.Date()))
}

#' Show data set status.
#'
#' \code{DataSetList} Show data set status. Prints information about update status and number of observations of local data sets.
#'
#' Check the internal data structure and returns a character vector with names of available data.frames.
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

  # Search CWES dataset
  if (DataSetAvailable(ds = "cwes")) {
    ifelse(datasets == "",
           yes = datasets <- "cwes",
           no = datasets[length(datasets) + 1] <- "cwes")
  }
  # Search CAPEC dataset
  if (DataSetAvailable(ds = "capec")) {
    ifelse(datasets == "",
           yes = datasets <- "capec",
           no = datasets[length(datasets) + 1] <- "capec")
  }

  # Check if no datasets available
  datasets <- ifelse(datasets == "",
                     yes = "Data sets not available. Use net.security::DataSetUpdate() ",
                     no = datasets)
  return(datasets)
}

#' Get data sets as data frames.
#'
#' \code{GetDataFrame} Get data sets as data frames. Check data sets documentation for details of data frames.
#'
#' Returns the data.frame selected. "Unknown" if it's not available.
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

DataSetAvailable <- function(ds) {
  checkval <- FALSE
  if (exists("netsec.data")) {
    checkval <- any(tolower(ds) %in% names(netsec.data[["datasets"]]))
  }
  # Normalize how to store internal datasets
  return(checkval)
}
