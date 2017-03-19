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

List available datasets. Results are used in other functions.
```r
> net.security::DataSetList()
[1] "cves"
```

Show last update and number of observations.    
```r
> net.security::DataSetStatus("cves")
[1] "* CVES dataset:"
[1] "  Last update for CVES dataset at 2017-03-17"
[1] "  Data set with 103648 rows and 25 variables."
[1] "  Online RAW data updated at 2017-03-18"
[1] "->CVES dataset 1 days outdated!"
```

Update data sets from official sources.  
```r
net.security::DataSetUpdate("cves")
```

Get data sets as data frames.  
```r
> cves <- net.security::GetDataFrame("cves")
> class(cves)
[1] "data.frame"

```

### Security Standards
#### CVE: Common Vulnerability Enumeration
Reference: http://cve.mitre.org/about/faqs.html  
Raw Data:
 - MITRE: http://cve.mitre.org/data/downloads/index.html#download
 - NIST: https://nvd.nist.gov/download.cfm  
