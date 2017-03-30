![Alt text](inst/img/net.security.tiny.jpg?raw=true "net.security")

[![Project Status: WIP - Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](http://www.repostatus.org/badges/latest/wip.svg)](http://www.repostatus.org/#wip) 
[![Build Status](https://travis-ci.org/r-net-tools/net.security.svg?branch=oval)](https://travis-ci.org/r-net-tools/net.security) 
[![Coverage Status](https://coveralls.io/repos/github/r-net-tools/net.security/badge.svg?branch=oval)](https://coveralls.io/github/r-net-tools/net.security?branch=oval)


#### Package for Data Driven Security purposes.

This package provides functions for security standards data management. It comes with data frames of 1000 observations for each security standard. It's possible to update the data frames from official sources and build updated data sets. This process is slow, so the default option is set to download from this repository an updated set of data frames pre-built. We publish new data updates every month.  

## Install

From R console just type:  
```r
devtools::install_github(repo = "r-net-tools/net.security")
```  

If you want to test future features, just add branch as parameter:  
```r
devtools::install_github(repo = "r-net-tools/net.security", ref = "devel")
```  

### Linux - Debian
If you need to upgrade R to latest version, follow [this](https://cran.r-project.org/bin/linux/debian/) instructions step by step.

Latest versions of R made the installation of package dependencies automatically. Check the DESCRIPTION file for needed installed packages. Packages openssl, curl and XML will need system libraries that are not installed by default. Maybe you will need to install this:  
```sh
sudo apt-get install libssl-dev libcurl4-openssl-dev libxml2-dev
```

## Usage

List available datasets. Results are used in other functions.
```r
> net.security::DataSetList()
[1] "cves"
[2] "cpes"
[3] "oval"
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

Update data sets from official sources. Estimated duration: 1h for cves, 1/4h for cpes. Set `use.remote = FALSE` to download from offical sources. Default option get the updated data sets from this project.  
```r
> net.security::DataSetUpdate("cves", use.remote = FALSE)
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
[1] "Updated CVEs data.frame has 103081  new observations."
[1] "Compressing and saving data sets to local file..."
[1] "2017-03-29"
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

#### OVAL: Open Vulnerability and Assessment Language  
Quick Reference: https://oval.mitre.org/about/faqs.html  
Raw Data: 
 - [CIS](https://www.cisecurity.org/): https://oval.cisecurity.org/repository/download/5.11.1/all/oval.xml  
 
Standard:
 - [MITRE Documentation](https://oval.mitre.org/language/about/)  

