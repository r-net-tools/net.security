![Alt text](inst/img/net.security.tiny.jpg "net.security")

[![Project Status: Active - The project has reached a stable, usable state and is being actively developed.](http://www.repostatus.org/badges/latest/active.svg)](http://www.repostatus.org/#active) 
[![Build Status](https://travis-ci.org/r-net-tools/net.security.svg?branch=master)](https://travis-ci.org/r-net-tools/net.security) 
[![Coverage Status](https://coveralls.io/repos/github/r-net-tools/net.security/badge.svg?branch=master)](https://coveralls.io/github/r-net-tools/net.security?branch=master)
[![CRAN_Status_Badge](http://www.r-pkg.org/badges/version/net.security)](http://CRAN.R-project.org/package=net.security)


#### Package for Data Driven Security purposes.

This package provides functions for security standards data management. It comes with data frames of 1000 observations for each security standard and updates are possible from official sources to build updated data sets. This process is slow, so the default option is set to download from [this](https://github.com/r-net-tools/security.datasets) repository an updated set of pre-built data frames. New data updates are published every month.  

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
If you need to upgrade R to latest version, follow [this](https://CRAN.R-project.org/bin/linux/debian/) instructions step by step.

Latest versions of R automate the installation of package dependencies. Check the DESCRIPTION file for required packages. Openssl, curl and XML packages will need system libraries that are not installed by default. Perhaps you will need to install:  

```sh
sudo apt-get install libssl-dev libcurl4-openssl-dev libxml2-dev lzma
```

## Usage

**List available datasets**. Results are used in other functions.
```r
> net.security::DataSetList()
[1] "cves"  "cpes"  "cwes"  "capec"
```

**Show data set status**. Prints information about update status and number of observations of local data sets.    
```r
> net.security::DataSetStatus()
[1] "-: CVES dataset:"
[1] " |- Last update for CVES dataset at 2017-03-28"
[1] " |- Data set with 104075 rows and 24 variables."
[1] " |- Online RAW data updated at 2017-03-30"
[1] " |- CVES dataset 2 days outdated."
[1] "-: CPES dataset:"
[1] " |- Last update for CPES dataset at 2017-03-28"
[1] " |- Data set with 117994 rows and 14 variables."
[1] " |- Online RAW data updated at 2017-03-30"
[1] " |- CPES dataset 2 days outdated."
[1] "-: CWES dataset:"
[1] " |- Last update for CWES dataset at 2017-03-28"
[1] " |- Data set with 720 rows and 26 variables."
[1] "-: CAPEC dataset:"
[1] " |- Last update for CAPEC dataset at 2017-06-10"
[1] " |- Data set with 100 rows and 34 variables."
[1] "-:"
> 
```

**Update data sets** from official sources. Estimated duration: 1h for cves, 15min for cpes. Set use.remote = FALSE to download from offical sources. Default option gets the updated data sets from [this](https://github.com/r-net-tools/security.datasets) repository.  

```r
net.security::DataSetUpdate(samples = T, use.remote = F)
[1] "Updating local cves data.frame from official sources."
[1] "Downloading raw data from sources..."
[1] "Unzip, extract, etc..."
[1] "Processing MITRE raw data..."
[1] "Parsing MITRE cves from CSV source..."
[1] "Tidy MITRE data frame..."
[1] "Parsing MITRE data finished."
[1] "Processing NIST raw data..."
[1] "Parsing cves (year 2002) from json source..."
[1] "Parsing cves (year 2003) from json source..."
[1] "Parsing cves (year 2004) from json source..."
[1] "Parsing cves (year 2005) from json source..."
[1] "Parsing cves (year 2006) from json source..."
[1] "Parsing cves (year 2007) from json source..."
[1] "Parsing cves (year 2008) from json source..."
[1] "Parsing cves (year 2009) from json source..."
[1] "Parsing cves (year 2010) from json source..."
[1] "Parsing cves (year 2011) from json source..."
[1] "Parsing cves (year 2012) from json source..."
[1] "Parsing cves (year 2013) from json source..."
[1] "Parsing cves (year 2014) from json source..."
[1] "Parsing cves (year 2015) from json source..."
[1] "Parsing cves (year 2016) from json source..."
[1] "Parsing cves (year 2017) from json source..."
[1] "Tidy NIST data frame..."
[1] "Parsing NIST data finished."
[1] "Joining MITRE and NIST data..."
[1] "Updating local cpes data.frame from official sources."
[1] "Downloading raw data..."
[1] "Extracting data..."
[1] "Indexing data..."
[1] "CPES data frame building process finished."
[1] "Updating local cwes data.frame from official sources."
[1] "Downloading raw data from MITRE..."
[1] "Unzip, extract, etc..."
[1] "Processing CWE raw data..."
[1] "Parsing basic attributes..."
[1] "Parsing Description..."
[1] "Parsing Related Weakness..."
[1] "Parsing Weakness Ordinality..."
[1] "Parsing Applicable Platforms..."
[1] "Parsing Background Details..."
[1] "Parsing Alternate Terms..."
[1] "Parsing Modes Of Introduction..."
[1] "Parsing Likelihood Of Exploit..."
[1] "Parsing Common Consequences..."
[1] "Parsing Detection Methods..."
[1] "Parsing Potential Mitigations..."
[1] "Parsing Observed Examples..."
[1] "Parsing Functional Areas..."
[1] "Parsing Affected Resources..."
[1] "Parsing Taxonomy Mappings..."
[1] "Parsing Related Attack Patterns..."
[1] "CWES data frame building process finished."
[1] "Updating local capec data.frame from official sources."
[1] "CAPEC data frame building process finished."
[1] "Updated CVEs data.frame has 0 new observations."
[1] "Updated CPEs data.frame has 126485 new observations."
[1] "Updated CWEs data.frame has 630 new observations."
[1] "Updated CAPECs data.frame has 442 new observations."
[1] "Compressing and saving data sets to local file..."
[1] "2017-12-30"
Warning message:
In net.security::DataSetUpdate(samples = T, use.remote = F) :
  Package needs rebuild to use updated data sets.
> remove.packages("net.security", lib="~/R/lib/3.4")
> devtools::buil()
> devtools:install()
>
```

**Get data sets as data frames**. Check data sets documentation for details of data frames. 
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

#### CWE: Common Weakness Enumeration
Quick Reference: https://cwe.mitre.org/about/faq.html  
Raw Data: 
 - MITRE: https://cwe.mitre.org/data/xml/cwec_v2.10.xml.zip  
 
Standard:
 - [CWE XML Schema documentation](https://cwe.mitre.org/documents/schema/schema_v5.4.2.html)  
 - [CWE XSD File](https://cwe.mitre.org/data/xsd/cwe_schema_v5.4.2.xsd)  
 - [All CWE Standard content. PDF File](https://cwe.mitre.org/data/published/cwe_v2.10.pdf)  
 
#### CAPEC: Common Attack Pattern Enumeration and Classification  
Quick Reference: https://capec.mitre.org/about/index.html  
Raw Data: 
 - MITRE: https://capec.mitre.org/data/  
 
Standard: https://capec.mitre.org/documents/schema/index.html  
