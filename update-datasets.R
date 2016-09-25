#!/usr/bin/env Rscript
library(net.security)
library(optparse)

#' TODO: get argv with this options:
#'    -p --path      : path where .rda files will be stored
#'    -s --standards : all > all standards
#'                       v > CVE
#'                       e > exploitdb
#'                       w > CWE
#'                       a > CAPEC
#'                       p > CPE
#'                       o > OVAL

option_list <- list(
  optparse::make_option(c("-p", "--path"), type = "character", default=tempdir(),
              help="path where .rda files will be stored, temporal dir as default"),
  optparse::make_option(c("-s", "--standards"), type="character", default=3,
              help="all > all standards \n v > CVE \n e > exploitdb \n w > CWE \n a > CAPEC \n p > CPE \n o > OVAL")
)

parser <- optparse::OptionParser(usage="%prog [-p path] [-s options]", option_list=option_list)

args <- optparse::parse_args(parser, positional_arguments = 1)
opt <- args$options
file <- args$args

if(opt$count_lines) {
  print(paste(length(readLines(file)) * opt$factor))
}

# Retrieve all data frames from its sources
# cves <- net.security::GetCVEData(origin = "all")
# cwes <- net.security::GetCWEData()
# cpes <- net.security::GetCPEData()
# capec <- net.security::GetCAPECData()
# oval <- net.security::GetOVALData()
# exploitdb <- net.security::GetExploitDB()

# Save data frames
# save(cves, file = path.cves)
# save(cwes, file = path.cwes)
# save(cpes, file = path.cpes)
# save(capec, file = path.capec)
# save(oval, file = path.oval)
# save(exploitdb, file = path.exploitdb)
