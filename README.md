![Alt text](inst/img/net.security.tiny.jpg?raw=true "net.security")

[![Project Status: WIP - Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](http://www.repostatus.org/badges/latest/wip.svg)](http://www.repostatus.org/#wip) 
[![Build Status](https://travis-ci.org/r-net-tools/net.security.svg?branch=master)](https://travis-ci.org/r-net-tools/net.security) 
[![Coverage Status](https://coveralls.io/repos/github/r-net-tools/net.security/badge.svg?branch=devel)](https://coveralls.io/github/r-net-tools/net.security?branch=devel)


#### Package for Data Driven Security purposes.

This package provides data sets for security standards and tools. It also have functions for update data sets.

## Install

From R console just type:  
`devtools::install_github(repo = "r-net-tools/net.security")`  

If you want to test future features, just add branch as parameter:  
`devtools::install_github(repo = "r-net-tools/net.security", ref = "devel")`  

## Usage

List available datasets. Results are used in other functions.
```r
> net.security::DataSetList()
[1] "cves"
[2] "cpes"
```

Show data set status. Prints information about update status and number of observations of local data sets.    
```r
> net.security::DataSetStatus()
[1] "-: CVES dataset:"
[1] " |- Last update for CVES dataset at 2017-03-17"
[1] " |- Data set with 103648 rows and 25 variables."
[1] " |- Online RAW data updated at 2017-03-21"
[1] " |- CVES dataset 4 days outdated."
[1] "-: CPES dataset:"
[1] " |- Last update for CPES dataset at 2017-03-21"
[1] " |- Data set with 117873 rows and 14 variables."
[1] " |- Online RAW data updated at 2017-03-21"
[1] " |- No updates needed for CPES dataset."
[1] "-:"
> 
```

Update data sets from official sources. Estimated duration: 1h for cves, 1/2h for cpes. 
```r
> net.security::DataSetUpdate("cves")
[1] "Downloading raw data..."
[1] "Unzip, extract, etc..."
[1] "Processing MITRE raw data..."
[1] "Processing NIST 2002 raw data..."
[1] "Processing NIST 2003 raw data..."
[1] "Processing NIST 2004 raw data..."
[1] "Processing NIST 2005 raw data..."
[1] "Processing NIST 2006 raw data..."
[1] "Processing NIST 2007 raw data..."
[1] "Processing NIST 2008 raw data..."
[1] "Processing NIST 2009 raw data..."
[1] "Processing NIST 2010 raw data..."
[1] "Processing NIST 2011 raw data..."
[1] "Processing NIST 2012 raw data..."
[1] "Processing NIST 2013 raw data..."
[1] "Processing NIST 2014 raw data..."
[1] "Processing NIST 2015 raw data..."
[1] "Processing NIST 2016 raw data..."
[1] "Processing NIST 2017 raw data..."
[1] "Indexing data..."
[1] "Tidy data..."
[1] "Process finished."
[1] "Compressing and saving data sets to local file..."
>
```

Get data sets as data frames. Check data sets documentation for details of data frames. 
```r
> cves <- net.security::GetDataFrame("cves")
> class(cves)
[1] "data.frame"
>
```

### Security Standards
#### CVE: Common Vulnerability Enumeration
Quick Reference: http://cve.mitre.org/about/faqs.html  
Raw Data:
 - MITRE: http://cve.mitre.org/data/downloads/index.html#download
 - NIST: https://nvd.nist.gov/download.cfm  
 
Standard:
 - [NIST Special Publication 800-51. Use of the Common. Vulnerabilities and Exposures. (CVE) Vulnerability Naming.](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-51.pdf)  
 - [NIST SP 800-51 Revision 1, Guide to Using Vulnerability Naming Schemes](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-51r1.pdf)  
  - [NIST: Vulnerability Data Model -DRAFT-](https://tools.ietf.org/html/draft-booth-sacm-vuln-model-02)  
  - [NIST XML schema (xsd file)](https://www.apt-browse.org/browse/ubuntu/trusty/universe/i386/libopenscap8/1.0.2-1/file/usr/share/openscap/schemas/cve/vulnerability_0.4.xsd)  

#### CPE: Common Platform Enumeration
Quick Reference: https://nvd.nist.gov/cpe.cfm  
Raw Data: 
 - NIST: http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz  
 
Standard:
 - [NISTIR 7695, Common Platform Enumeration: Naming Specification Version 2.3](http://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf)  
