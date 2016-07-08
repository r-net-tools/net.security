#' InfoASN based on public information provided by http://bgp.he.net/
#' Don't abuse, this is just for test purposes.
#'
#' @param asn number
InfoASN <- function(asn)
{
  asn.url <- paste("http://bgp.he.net/",asn,"#_prefixes", sep = "")
  asn.html <- XML::htmlParse(readLines(asn.url), asText = TRUE)
  asn.info <- XML::getNodeSet(asn.html, "//table[@id='table_prefixes4']")
  asn.info <- XML::readHTMLTable(asn.info[[1]])
  asn.info[] <- lapply(asn.info, as.character)
  return(asn.info)
}
