# ================
# Public Functions
# ================

#' UpdateCVEData download CVE information from public databases such as MITRE and NIST
#'
#' @param Boolean value, if true it will download all data base, if false it will only download last updates.
#' @param It's implemented for EN(glish) or ES(pañol)
#' @export
#' @examples
#' UpdateCVEData(all = TRUE, lang = "ES")
UpdateCVEData <- function(all = FALSE, lang = "EN") {
    CheckDataFolders()
    UpdateMITRE(all = all)
    if (lang == "EN") {
        UpdateNIST(all = all, spanish = FALSE)
    } else {
        UpdateNIST(all = all, spanish = TRUE)
    }
    UncompressFiles()
}

#' GetSummaryByCVE returns a string with the description of the vulneravility and language
#'
#' @param String with CVE code in standrad mode (CVE-YYYY-XXXX)
#' @param It's implemented for EN(glish) or ES(pañol)
#' @export
#' @examples
#' description <- GetSummaryByCVE(cve = "CVE-2015-0002", lang = "ES")
GetSummaryByCVE <- function(cve = "CVE-2016-0002", lang = "EN") {
    # Load each source file
    if (lang == "ES") {
        nist.name <- paste("nvdcve-", substr(cve,5,8), "trans.xml", sep = "")
        nist.file <- paste(getwd(), "data/nist", nist.name, sep = "/")
    } else {
        nist.name   <- paste("nvdcve-2.0-", substr(cve,5,8), ".xml", sep = "")
        nist.file   <- paste(getwd(), "data/nist", nist.name, sep = "/")
    }

    # Parse NIST file
    nist  <- XML::htmlTreeParse(nist.file,  useInternalNodes = TRUE)

    # Select desired element from NIST
    if (lang == "ES") {
        nist.xpath <- paste("//entry[@name='", cve, "']/child::desc", sep = "")
        node.nist  <- XML::getNodeSet(nist, nist.xpath)
        nist.desc <- XML::xmlValue(node.nist[[1]])
    } else {
        nist.xpath <- paste("//entry[@id='", cve, "']", sep = "")
        node.nist  <- XML::getNodeSet(nist, nist.xpath)
        nist.desc  <- XML::xmlValue(XML::xmlChildren(node.nist[[1]])["summary"][[1]])
    }


    # MITRE
    #mitre.name  <- paste("allitems-cvrf-year-", substr(cve,5,8), ".xml", sep = "")
    #mitre.file  <- paste(getwd(), "data/mitre", mitre.name, sep = "/")
    #mitre <- XML::htmlTreeParse(mitre.file, useInternalNodes = TRUE)
    #node.mitre <- XML::getNodeSet(mitre, mitre.xpath)
    #mitre.desc <- GetDescriptionMitre(mitre.vuln)

    summary <- data.frame(nist = nist.desc,
                          stringsAsFactors = FALSE)

    return(summary)
}

# =================
# Private Functions
# =================

CheckDataFolders <- function() {
    dir.create(path = "data", showWarnings = FALSE)
    dir.create(path = "data/mitre", showWarnings = FALSE)
    dir.create(path = "data/nist", showWarnings = FALSE)
}

#' UpdateMITRE Update CVE DB from MITRE
#' Reference: http://cve.mitre.org/data/downloads/index.html#download
UpdateMITRE <- function(all = FALSE) {
    if (all == TRUE) {
        ## All and schema
        download.file(url = "http://cve.mitre.org/data/downloads/allitems.xml.gz",
                      destfile = "data/mitre/allitems.xml.gz")
        download.file(url = "http://cve.mitre.org/schema/cve/cve_1.0.xsd",
                      destfile = "data/mitre/cve_1.0.xsd")

        ## Year by year
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-1999.xml",
                      destfile = "data/mitre/allitems-cvrf-year-1999.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2000.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2000.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2001.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2001.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2002.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2002.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2003.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2003.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2004.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2004.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2005.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2005.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2006.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2006.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2007.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2007.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2008.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2008.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2009.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2009.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2010.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2010.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2011.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2011.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2012.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2012.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2013.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2013.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2014.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2014.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2015.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2015.xml")
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2016.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2016.xml")
    } else {
        download.file(url = "http://cve.mitre.org/data/downloads/allitems-cvrf-year-2016.xml",
                      destfile = "data/mitre/allitems-cvrf-year-2016.xml")
    }
}

#' UpdateNIST Update CVE DB from NIST
#' Reference: https://nvd.nist.gov/download.cfm
UpdateNIST <- function(all = FALSE, spanish = FALSE) {
    if (all == TRUE) {
        ### CVE's by year from 2002 to 2016
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2002.xml.gz")

        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2003.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2003.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2004.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2004.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2005.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2005.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2006.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2006.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2007.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2007.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2008.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2008.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2009.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2009.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2010.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2011.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2012.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2013.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2014.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2015.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2015.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2016.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-2016.xml.gz")

        ### Schema
        download.file(url = "https://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd",
                      destfile = "data/nist/nvd-cve-feed_2.0.xsd")

        ### Vendor statments
        download.file(url = "https://nvd.nist.gov/download/vendorstatements.xml.gz",
                      destfile = "data/nist/vendorstatements.xml.gz")

        ### Download spanish translations
        if (spanish == TRUE) {
            #### Schema
            download.file(url = "https://nvd.nist.gov/download/nvdcvetrans.xsd",
                          destfile = "data/nist/nvdcvetrans.xsd")

            #### CVE's translations year by year
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2002trans.xml.gz",
                          destfile = "data/nist/nvdcve-2002trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2003trans.xml.gz",
                          destfile = "data/nist/nvdcve-2003trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2004trans.xml.gz",
                          destfile = "data/nist/nvdcve-2004trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2005trans.xml.gz",
                          destfile = "data/nist/nvdcve-2005trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2006trans.xml.gz",
                          destfile = "data/nist/nvdcve-2006trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2007trans.xml.gz",
                          destfile = "data/nist/nvdcve-2007trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2008trans.xml.gz",
                          destfile = "data/nist/nvdcve-2008trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2009trans.xml.gz",
                          destfile = "data/nist/nvdcve-2009trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2010trans.xml.gz",
                          destfile = "data/nist/nvdcve-2010trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2011trans.xml.gz",
                          destfile = "data/nist/nvdcve-2011trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2012trans.xml.gz",
                          destfile = "data/nist/nvdcve-2012trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2013trans.xml.gz",
                          destfile = "data/nist/nvdcve-2013trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2014trans.xml.gz",
                          destfile = "data/nist/nvdcve-2014trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2015trans.xml.gz",
                          destfile = "data/nist/nvdcve-2015trans.xml.gz")
            download.file(url = "https://nvd.nist.gov/download/nvdcve-2016trans.xml.gz",
                          destfile = "data/nist/nvdcve-2016trans.xml.gz")
        }
    } else {
        ### Modified and Recent
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-Modified.xml.gz")
        download.file(url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Recent.xml.gz",
                      destfile = "data/nist/nvdcve-2.0-Recent.xml.gz")
        ### Download spanish translations
        if (spanish == TRUE) {
            download.file(url = "https://nvd.nist.gov/download/nvdcve-modifiedtrans.xml.gz",
                          destfile = "data/nist/nvdcve-modifiedtrans.xml.gz")
        }
    }
}

#' UncompressFiles on data/ folder
#'
#' @examples
#' UncompressFiles()
UncompressFiles <- function() {
    # Uncompress gzip XML files
    gzs <- list.files(path = paste(getwd(),"data", sep="/"), pattern = "*.xml.gz",
                      full.names = TRUE, recursive = TRUE)
    apply(X = data.frame(gzs = gzs, stringsAsFactors = F), 1, function(x) R.utils::gunzip(x))
}
