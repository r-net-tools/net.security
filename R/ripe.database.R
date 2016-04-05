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
