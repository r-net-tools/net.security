# ================
# Public Functions
# ================

#' InfoASN based on public information provided by http://bgp.he.net/
#' Don't abuse, this is just for test purposes.
#'
#' @param asn ASN number with letters, i.e.: "AS12345"
#' @param output_file is the path where asn info will be stored
#'
#' @return list of asn information
#' @export
#'
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

#' ParseNMAP Parser for nmap xml output
#'
#' @param file.input 
#' @param file.output.header 
#'
#' @return data frame
#' @export
#'
#' @examples
ParseNMAP <- function(file.input, file.output.header = "")
{
    # Parse input data
    xmlfile = XML::xmlParse(file.input)
    root <- XML::xmlRoot(xmlfile)
    nmap.info <- XML::xmlChildren(root)
    
    # Get scan information
    # scan.info <- as.data.frame(t(xmlAttrs(root)))
    
    # Foreach host
    i = 1
    dns.info <- data.frame()
    nmap.data <- data.frame()
    while (i <= XML::xmlSize(nmap.info))
    {
        if (XML::xmlName(nmap.info[[i]]) == "host")
        {
            host.status <- as.data.frame(t(XML::xmlAttrs(XML::xmlChildren(nmap.info[[i]])$status)))
            names(host.status) <- c("h.state","h.reason","h.reason_ttl")
            host.address <- as.data.frame(t(XML::xmlAttrs(XML::xmlChildren(nmap.info[[i]])$address)))
            if ("hostnames" %in% names(XML::xmlChildren(nmap.info[[i]])) & 
                XML::xmlValue(XML::xmlChildren(nmap.info[[i]])$hostnames) != "\n")
            {
                hostnames <- XML::xmlChildren(XML::xmlChildren(nmap.info[[i]])$hostnames)
                j = 1
                while (j <= length(hostnames))
                {
                    host.ip <- as.character(host.address$addr)
                    host.hostname <- as.data.frame(t(xmlAttrs(hostnames[[j]])))
                    dns.info <- rbind(dns.info, cbind(host.ip, host.hostname))
                    j = j + 1
                }
            }
            if ("ports" %in% names(XML::xmlChildren(nmap.info[[i]])))
            {
                ports <- XML::xmlChildren(XML::xmlChildren(nmap.info[[i]])$ports)
                j = 1
                while (j <= length(ports))
                {
                    if (XML::xmlName(ports[[j]]) == "port")
                    {
                        host.port <- as.data.frame(t(XML::xmlAttrs(ports[[j]])))
                        port.info <- XML::xmlChildren(ports[[j]])
                        port.detail <- cbind(as.data.frame(t(XML::xmlAttrs(port.info$state))),
                                             as.data.frame(t(XML::xmlAttrs(port.info$service))))
                        host.port <- cbind(host.port,port.detail)
                        nmap.data <- rbind.fill(nmap.data, cbind(host.address, host.status, host.port))
                    }
                    j = j + 1
                }
            }
            else
            {
                nmap.data <- rbind.fill(nmap.data, cbind(host.address, host.status))
            }
        }
        i = i + 1
    }
    nmap.data <- unique(nmap.data)
    nmap.data[] <- lapply(nmap.data, as.character)
    dns.info <- unique(dns.info)
    dns.info[] <- lapply(dns.info, as.character)
    
    # Save all results
    saveRDS(nmap.data, file = paste("output/",file.output.header,"nmap.data.rds",sep = ""))
    saveRDS(dns.info, file = paste("output/",file.output.header,"info.dns.rds",sep=""))
    
    return(nmap.data)
}
