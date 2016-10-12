#' UpdateDataSets Downloads source data from MITRE, NIST and others and create tidy data frames
#'
#' @param path where .rda files will be stored
#' @param stnd "all":all standards; "v":CVE; "e":exploitdb; "w":CWE; "a":CAPEC; "p":CPE; "o":OVAL
#'
#' @export
#' @examples
#' UpdateDataSets() # Default: Create all datasets in tempdir()
#' UpdateDataSets(path = "./data/security", stnd = "v") # Create /data/security/cves.rda
UpdateDataSets <- function(path = tempdir(), stnd = "all") {
  # Start the clock!
  # ptm <- proc.time()

  # Retrieve all data frames from its sources
  if (stnd == "all" | stnd == "v") {
    cves <- GetCVEData(origin = "all", savepath = path)
    # TODO: maybe it needs improvement
    path.cves <- paste(path, "cves.rda", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
    assign("cves", cves, envir = .GlobalEnv)
    save(cves, file = path.cves)
  }

  # Stop the clock
  # proc.time() - ptm
  # user  system elapsed
  # 3236.07   40.39 3416.52

  # Start the clock!
  # ptm <- proc.time()

  if (stnd == "all" | stnd == "w") {
    cwes <- GetCWEData(savepath = path)
    # TODO: maybe it needs improvement
    CleanTempPath(path, "cwe")
    path.cwes <- paste(path, "cwes.rda", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
    assign("cwes", cwes, envir = .GlobalEnv)
    save(cwes, file = path.cwes)
  }

  # Stop the clock
  # proc.time() - ptm
  # user  system elapsed
  # 15.06    0.15   24.67

  # Start the clock!
  # ptm <- proc.time()

  if (stnd == "all" | stnd == "p") {
    cpes <- GetCPEData(savepath = path)
    # TODO: maybe it needs improvement
    path.cpes <- paste(path, "cpes.rda", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
    assign("cpes", cpes, envir = .GlobalEnv)
    save(cpes, file = path.cpes)
  }

  # Stop the clock
  # proc.time() - ptm
  # user  system elapsed
  # 756.96   71.32  845.96

  # Start the clock!
  # ptm <- proc.time()

  if (stnd == "all" | stnd == "a") {
    capec <- GetCAPECData(savepath = path)
    # TODO: maybe it needs improvement
    path.capec <- paste(path, "capec.rda", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
    assign("capec", capec, envir = .GlobalEnv)
    save(capec, file = path.capec)
  }

  # Stop the clock
  # proc.time() - ptm
  # user  system elapsed
  # 116.22    0.58  124.95

  # Start the clock!
  # ptm <- proc.time()

  if (stnd == "all" | stnd == "o") {
    oval <- GetOVALData(savepath = path)
    # TODO: maybe it needs improvement
    path.oval <- paste(path, "oval.rda", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
    assign("oval", oval, envir = .GlobalEnv)
    save(oval, file = path.oval)
  }

  # Stop the clock
  # proc.time() - ptm
  # user  system elapsed
  # 222.31   17.03  249.67

  # Start the clock!
  # ptm <- proc.time()

  if (stnd == "all" | stnd == "e") {
    exploitdb <- GetExploitDB()
    # TODO: maybe it needs improvement
    path.exploitdb <- paste(path, "exploitdb.rda", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
    assign("exploitdb", exploitdb, envir = .GlobalEnv)
    save(exploitdb, file = path.exploitdb)
  }

  # Stop the clock
  # proc.time() - ptm
  # user  system elapsed
  # 10.64    0.01   13.38

  # TODO: Remove temporal folders with downloaded files
}

CleanTempPath <- function(path, folder) {
  rootpath <- paste(path, folder, sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  tmpfiles <- list.files(path = rootpath, full.names = TRUE, recursive = TRUE, include.dirs = TRUE)
  apply(X = data.frame(tmpfiles = tmpfiles, stringsAsFactors = F),
        1, function(x) {
          suppressMessages(file.remove(x))
          suppressMessages(unlink(x, recursive = TRUE))
          })
  suppressMessages(unlink(rootpath, recursive = TRUE))
}

#' TODO: get argv with this options:
#'    -p --path      : path where .rda files will be stored
#'    -s --standards : all > all standards
#'                       v > CVE
#'                       e > exploitdb
#'                       w > CWE
#'                       a > CAPEC
#'                       p > CPE
#'                       o > OVAL
#'
#' #!/usr/bin/env Rscript
# library(optparse)
#
# option_list <- list(
#   optparse::make_option(c("-p", "--path"), type = "character", default=tempdir(),
#               help="path where .rda files will be stored, temporal dir as default"),
#   optparse::make_option(c("-s", "--standards"), type="character", default=3,
#               help="all > all standards \n v > CVE \n e > exploitdb \n w > CWE \n a > CAPEC \n p > CPE \n o > OVAL")
# )
#
# parser <- optparse::OptionParser(usage="%prog [-p path] [-s options]", option_list=option_list)
#
# args <- optparse::parse_args(parser, positional_arguments = 1)
# opt <- args$options
# file <- args$args
#
# if(opt$count_lines) {
#   print(paste(length(readLines(file)) * opt$factor))
# }
#
# path <- tempdir()
# stnd <- "all"

# ptm <- proc.time()
# net.security::UpdateDataSets(path = "data", stnd = "w")
# proc.time() - ptm
# net.security::UpdateDataSets(path = "data", stnd = "a")
# proc.time() - ptm
# net.security::UpdateDataSets(path = "data", stnd = "p")
# proc.time() - ptm
# net.security::UpdateDataSets(path = "data", stnd = "o")
# proc.time() - ptm
# net.security::UpdateDataSets(path = "data", stnd = "v")
# proc.time() - ptm
# net.security::UpdateDataSets(path = "data", stnd = "e")
# proc.time() - ptm

