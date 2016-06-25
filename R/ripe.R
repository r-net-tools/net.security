#' GetRIPE.ASN
#'
#' @param path where RIPE files will be downloaded and unziped (don't finish with /). Default set as inst/tmpdata
#' @param download TRUE if you want to update the source data, default set as FALSE#'
#' @return data frame
#' @export
#'
#' @examples
#' ripe.asn <- GetRIPE.ASN()
#' ripe.asn <- GetRIPE.ASN(download = TRUE)
GetRIPE.ASN <- function(path = "inst/tmpdata", download = FALSE){
  #
  path <- ifelse(download, DownloadRIPE.ASN(path), paste(path, "ripe/ripe.db.aut-num", sep = "/"))
  ripe.asn <- read.delim(file = path, sep = ":", header = FALSE, skip = 6,
                         quote = "\"", stringsAsFactors = FALSE)
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
  names(ripe.asn.lite) <- c("aut-num","as-name","source","status")

  return(ripe.asn.lite)
}

#' DownloadRIPE.ASN
#'
#' @param path where files will be stored
#' @return path of asn file unziped
#' @examples
DownloadRIPE.ASN <- function(path = "inst/tmpdata") {
  url <- "ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz"
  path <- paste(path, "ripe", sep="/")
  dir.create(path, showWarnings = FALSE)
  destfile <- paste(path, "ripe.db.aut-num.gz", sep = "/")
  download.file(url, destfile)
  R.utils::gunzip(destfile)
  return(paste(path, "ripe.db.aut-num", sep = "/"))
}

# # Ref: https://www.ripe.net/manage-ips-and-asns/db/support/documentation/ripe-database-documentation/rpsl-object-types/4-2-descriptions-of-primary-objects/4-2-4-description-of-the-inetnum-object
#
# # RIPE path and local file
# ripe.path <- "ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz"
# ripe.db.gz <- "data/ripe.db.inetnum.gz"
# ripe.db <- "data/ripe.db.inetnum"
#
# # Download and unzip
# if(!file.exists(ripe.db)){
#     download.file(ripe.path, destfile=ripe.db.gz)
#     gunzip(ripe.db.gz)
# }
#
# # Read file as data frame (~240s)
# # Parse as list of net blocks
# # Use 6Gb and is really super-slow... it needs improvement or limit nrow when read
# # Ref: http://www.r-bloggers.com/r-parallel-processing-using-multicore-package-2/
# # Ref: https://encrypted.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=8&ved=0ahUKEwixwPK3l_fKAhUHnRoKHYu4BEQQFghNMAc&url=http%3A%2F%2Fwww.jstatsoft.org%2Fv40%2Fi01%2Fpaper&usg=AFQjCNH3rcSknA7oCUQvDKqs7sdmpF1gMg&sig2=7hYnVFIx80F-vBeUK6DslQ
# ripe <- ripe2DF(10000)
#
# # Save ripe data frame
# saveRDS(object = ripe, file = "data/ripe.db.rds")
#
#
# ripe2DF <- function(filas = 10000){
#     ripe <- read.delim(file = ripe.db, sep = ":", header = FALSE, skip = 6,
#                        quote = "\"", stringsAsFactors = FALSE, nrows = filas)
#     # Transform to data frame
#     block.mark <- 1:nrow(ripe) %in% grep(pattern = "% Tags .*", x = ripe$V1)
#     ripe <- split(ripe, cumsum(block.mark))
#     selected.fields <- "^(inetnum|netname|country|org|admin-c|tech-c|status|notify|mnt-by|created|last-modified|source)$"
#     ripe <- lapply(ripe, function(x) x[grep(pattern = selected.fields, x = x$V1, perl = T),])
#     ripe <- lapply(ripe, function(x) as.data.frame(t(as.data.frame(x$V2, x$V1))))
#     ripe <- do.call("rbind.fill", ripe)
#     return(ripe)
# }
