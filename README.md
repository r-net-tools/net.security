![Alt text](inst/img/net.security.tiny.jpg?raw=true "net.security")

[![Project Status: WIP - Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](http://www.repostatus.org/badges/latest/wip.svg)](http://www.repostatus.org/#wip) 
[![Build Status](https://travis-ci.org/r-net-tools/net.security.svg?branch=master)](https://travis-ci.org/r-net-tools/net.security) 
[![Coverage Status](https://coveralls.io/repos/github/r-net-tools/net.security/badge.svg?branch=master)](https://coveralls.io/github/r-net-tools/net.security?branch=master)


#### Package for Data Driven Security purposes.

This package provides data sets for security standards and tools. It also have functions for update data sets.

## Install

From R console just type:  
`devtools::install_github(repo = "r-net-tools/net.security")`  

If you want to test future features, just add branch as parameter:  
`devtools::install_github(repo = "r-net-tools/net.security", ref = "devel")`  

## Usage

Show last update date and number of observations.    
```r
net.security::DataSetStatus(dataset = "all")
net.security::DataSetStatus(dataset = "cves")
```

Update data sets from official sources.  
```r
net.security::DataSetUpdate(dataset = "all")
net.security::DataSetUpdate(dataset = "cves")
```

List available data frames.  
```r
net.security::DataSetList()
```

### Security Standards
#### CVE: Common Vulnerability Enumeration
Reference: http://cve.mitre.org/about/faqs.html  
Raw Data:
 - MITRE: http://cve.mitre.org/data/downloads/index.html#download
 - NIST: https://nvd.nist.gov/download.cfm  

Update dataset: `net.security::DataSetUpdate(dataset = "cves")`  
Data Frame: `cvess <- net.security::GetDataFrame(dataset = "cves")`  

