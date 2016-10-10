#!/usr/bin/env Rscript
library(net.security)
# library(optparse)

#' TODO: get argv with this options:
#'    -p --path      : path where .rda files will be stored
#'    -s --standards : all > all standards
#'                       v > CVE
#'                       e > exploitdb
#'                       w > CWE
#'                       a > CAPEC
#'                       p > CPE
#'                       o > OVAL

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

path <- tempdir()
stnd <- "all"

# Start the clock!
# ptm <- proc.time()

# Retrieve all data frames from its sources
if (stnd == "all" | stnd == "v") {
  cves <- net.security::GetCVEData(origin = "all", savepath = path)
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
  cwes <- net.security::GetCWEData(savepath = path)
  # TODO: maybe it needs improvement
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
  cpes <- net.security::GetCPEData()
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
  capec <- net.security::GetCAPECData()
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
  oval <- net.security::GetOVALData()
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
  exploitdb <- net.security::GetExploitDB()
  # TODO: maybe it needs improvement
  path.exploitdb <- paste(path, "exploitdb.rda", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  assign("exploitdb", exploitdb, envir = .GlobalEnv)
  save(exploitdb, file = path.exploitdb)
}

# Stop the clock
# proc.time() - ptm
# user  system elapsed
# 10.64    0.01   13.38


