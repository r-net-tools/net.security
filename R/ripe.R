#' GetRIPE.ASN
#'
#' @param path where RIPE files will be downloaded and unziped (don't finish with /). Default set as inst/tmpdata
#' @param download TRUE if you want to update the source data, default set as FALSE
#' @return data frame
#' @export
#'
#' @examples
#' ripe.asn <- GetRIPE.ASN()
#' ripe.asn <- GetRIPE.ASN(download = TRUE)
GetRIPE.ASN <- function(path = "inst/tmpdata", download = FALSE){
  # Download and read raw data
  path <- ifelse(download, DownloadRIPE.ASN(path), paste(path, "ripe/ripe.db.aut-num", sep = "/"))
  ripe.asn <- read.delim(file = path, sep = ":", header = FALSE, skip = 6,
                         quote = "\"", stringsAsFactors = FALSE)

  # Raw data to filtered data frame
  ripe.asn <- ripe.asn[ripe.asn$V1 %in% c("aut-num","as-name","descr","admin-c","tech-c","mnt-by","source","org","status","created","last-modified"),]
  ripe.asn$V1 <- as.factor(ripe.asn$V1)
  ripe.asn.lite <- ripe.asn[ripe.asn$V1 %in% c("aut-num","as-name","source","status"),]
  block.mark <- 1:nrow(ripe.asn.lite) %in% grep(pattern = "aut-num", x = ripe.asn.lite$V1)
  ripe.asn.lite <- split(ripe.asn.lite, cumsum(block.mark))
  ripe.asn.lite <- lapply(ripe.asn.lite, function(x) as.data.frame(t(as.data.frame(x$V2, x$V1))))
  ripe.asn.lite <- do.call("rbind.fill", ripe.asn.lite)

  # Tidy data
  ripe.asn.lite$V1 <- as.character.factor(ripe.asn.lite$V1)
  ripe.asn.lite$V2 <- as.character.factor(ripe.asn.lite$V2)
  names(ripe.asn.lite) <- c("aut.num","as.name","source","status")

  return(ripe.asn.lite)
}

#' GetRIPE.inet
#'
#' @param path where RIPE files will be downloaded and unziped (don't finish with /). Default set as inst/tmpdata
#' @param use.cached if you want to load from internal rds file
#' @param download TRUE if you want to update the source data, default set as FALSE
#'
#' @return data frame
#' @export
#'
#' @examples
#' ripe.inet <- GetRIPE.inet()
#' ripe.inet <- GetRIPE.inet(download = TRUE)
GetRIPE.inet <- function(path = "inst/tmpdata", download = FALSE, use.cached = FALSE) {
  if (use.cached) {
    return(readRDS(file = paste(path, "ripe/ripe.db.inetnum.rds", sep = "/")))
  } else {
    # Download raw data
    path <- ifelse(download, DownloadRIPE.ASN(path), paste(path, "ripe/ripe.db.inetnum", sep = "/"))
    ripe.inet <- read.delim(file = path, sep = ":", header = FALSE, skip = 6,
                            quote = "\"", stringsAsFactors = FALSE)

    # Raw data to filtered data frame
    ripe.inet <- ripe.inet[ripe.inet$V1 %in% c("inetnum","netname","country","admin-c","tech-c","status","mnt-by","created","last-modified","source","org"),]
    ripe.inet$V1 <- as.factor(ripe.inet$V1)
    ripe.inet.lite <- ripe.inet[ripe.inet$V1 %in% c("inetnum","netname","source","status","created","last-modified"),]
    block.mark <- 1:nrow(ripe.inet.lite) %in% grep(pattern = "inetnum", x = ripe.inet.lite$V1)
    ripe.inet.lite <- lapply(split(ripe.inet.lite, cumsum(block.mark)), function(x) stringr::str_trim(x$V2))
    # ripe.inet.lite size: 952 Mb aprox.

    # Tidy data
    ripe.inet.lite <- ripe.inet.lite[sapply(ripe.inet.lite, length) == 6]
    # Next step needs improvement, it's slow
    ripe.inet.lite <- as.data.frame.matrix(t(as.data.frame.list(ripe.inet.lite, stringsAsFactors = F)), stringsAsFactors = F)
    names(ripe.inet.lite) <- c("inetnum","netname","status","created","last.modified","source")
    ripe.inet.lite$source <- as.factor(ripe.inet.lite$source)
    ripe.inet.lite$status <- as.factor(ripe.inet.lite$status)

    # Save as RDS
    saveRDS(object = ripe.inet.lite, file = paste(path, ".rds", sep = ""))

    return(ripe.inet.lite)
  }
}

#' DownloadRIPE.ASN
#'
#' @param path where files will be stored
#' @return path of asn file unziped
DownloadRIPE.ASN <- function(path = "inst/tmpdata") {
  url <- "ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz"
  path <- paste(path, "ripe", sep = "/")
  dir.create(path, showWarnings = FALSE)
  destfile <- paste(path, "ripe.db.aut-num.gz", sep = "/")
  download.file(url, destfile)
  R.utils::gunzip(destfile)
  return(paste(path, "ripe.db.aut-num", sep = "/"))
}

#' DownloadRIPE.inet
#'
#' @param path where files will be stored
#' @return path of asn file unziped
DownloadRIPE.inet <- function(path = "inst/tmpdata") {
  url <- "ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz"
  path <- paste(path, "ripe", sep = "/")
  dir.create(path, showWarnings = FALSE)
  destfile <- paste(path, "ripe.db.inetnum.gz", sep = "/")
  download.file(url, destfile)
  R.utils::gunzip(destfile)
  return(paste(path, "ripe.db.inetnum", sep = "/"))
}

#' REFERENCES:
#'  - CrashCourse: http://www.slideshare.net/apnic/routing-registry-function-automation-using-rpki-rpsl
#'  - RIPE Docs: https://www.ripe.net/manage-ips-and-asns/db/support/documentation/ripe-database-documentation/rpsl-object-types/4-2-descriptions-of-primary-objects/4-2-4-description-of-the-inetnum-object

# # Parse as list of net blocks
# # Ref: http://www.r-bloggers.com/r-parallel-processing-using-multicore-package-2/
# # Ref: https://encrypted.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=8&ved=0ahUKEwixwPK3l_fKAhUHnRoKHYu4BEQQFghNMAc&url=http%3A%2F%2Fwww.jstatsoft.org%2Fv40%2Fi01%2Fpaper&usg=AFQjCNH3rcSknA7oCUQvDKqs7sdmpF1gMg&sig2=7hYnVFIx80F-vBeUK6DslQ
