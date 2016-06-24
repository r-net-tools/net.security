#' InfoASN based on public information provided by http://bgp.he.net/
#' Don't abuse, this is just for test purposes.
#'
#' @param asn ASN number with letters, i.e.: "AS12345"
#' @param output_file is the path where asn info will be stored
#'
#' @return list of asn information
#' @examples
#' asn <- GetASN(asn = "AS12345")
InfoASN <- function(asn)
{
  asn.url <- paste("http://bgp.he.net/",asn,"#_prefixes", sep = "")
  asn.html <- XML::htmlParse(readLines(asn.url), asText = TRUE)
  asn.info <- XML::getNodeSet(asn.html, "//table[@id='table_prefixes4']")
  asn.info <- XML::readHTMLTable(asn.info[[1]])
  asn.info[] <- lapply(asn.info, as.character)
  return(asn.info)
}
