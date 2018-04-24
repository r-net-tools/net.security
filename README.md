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
> setwd("/home/netsec/rpackages/net.security");library("net.security");net.security::DataSetUpdate(ds="all", samples=                                                                                                                        T, use.remote=F, force.update=T)
[1] "[*] Updating CVES data.frame..."
[1] "Downloading raw data from sources..."
trying URL 'http://cve.mitre.org/data/downloads/allitems.csv.gz'
Content type 'application/x-gzip' length 13419673 bytes (12.8 MB)
==================================================
downloaded 12.8 MB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2002.json.gz'
Content type 'application/x-gzip' length 1425906 bytes (1.4 MB)
==================================================
downloaded 1.4 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2002trans.xml.gz'
Content type 'application/x-gzip' length 73022 bytes (71 KB)
==================================================
downloaded 71 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2003.json.gz'
Content type 'application/x-gzip' length 425813 bytes (415 KB)
==================================================
downloaded 415 KB

trying URL 'https://nvd.nist.gov/download/nvdcve-2003trans.xml.gz'
Content type 'application/x-gzip' length 71181 bytes (69 KB)
==================================================
downloaded 69 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2004.json.gz'
Content type 'application/x-gzip' length 886494 bytes (865 KB)
==================================================
downloaded 865 KB

trying URL 'https://nvd.nist.gov/download/nvdcve-2004trans.xml.gz'
Content type 'application/x-gzip' length 64741 bytes (63 KB)
==================================================
downloaded 63 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2005.json.gz'
Content type 'application/x-gzip' length 1357615 bytes (1.3 MB)
==================================================
downloaded 1.3 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2005trans.xml.gz'
Content type 'application/x-gzip' length 35834 bytes (34 KB)
==================================================
downloaded 34 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2006.json.gz'
Content type 'application/x-gzip' length 2026378 bytes (1.9 MB)
==================================================
downloaded 1.9 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2006trans.xml.gz'
Content type 'application/x-gzip' length 411650 bytes (402 KB)
==================================================
downloaded 402 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2007.json.gz'
Content type 'application/x-gzip' length 2011794 bytes (1.9 MB)
==================================================
downloaded 1.9 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2007trans.xml.gz'
Content type 'application/x-gzip' length 645659 bytes (630 KB)
==================================================
downloaded 630 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2008.json.gz'
Content type 'application/x-gzip' length 2324110 bytes (2.2 MB)
==================================================
downloaded 2.2 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2008trans.xml.gz'
Content type 'application/x-gzip' length 657802 bytes (642 KB)
==================================================
downloaded 642 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2009.json.gz'
Content type 'application/x-gzip' length 2516023 bytes (2.4 MB)
==================================================
downloaded 2.4 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2009trans.xml.gz'
Content type 'application/x-gzip' length 483849 bytes (472 KB)
==================================================
downloaded 472 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2010.json.gz'
Content type 'application/x-gzip' length 3690051 bytes (3.5 MB)
==================================================
downloaded 3.5 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2010trans.xml.gz'
Content type 'application/x-gzip' length 452968 bytes (442 KB)
==================================================
downloaded 442 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2011.json.gz'
Content type 'application/x-gzip' length 9058713 bytes (8.6 MB)
==================================================
downloaded 8.6 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2011trans.xml.gz'
Content type 'application/x-gzip' length 399908 bytes (390 KB)
==================================================
downloaded 390 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2012.json.gz'
Content type 'application/x-gzip' length 3390763 bytes (3.2 MB)
==================================================
downloaded 3.2 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2012trans.xml.gz'
Content type 'application/x-gzip' length 462261 bytes (451 KB)
==================================================
downloaded 451 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2013.json.gz'
Content type 'application/x-gzip' length 3543945 bytes (3.4 MB)
==================================================
downloaded 3.4 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2013trans.xml.gz'
Content type 'application/x-gzip' length 511813 bytes (499 KB)
==================================================
downloaded 499 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2014.json.gz'
Content type 'application/x-gzip' length 3135734 bytes (3.0 MB)
==================================================
downloaded 3.0 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2014trans.xml.gz'
Content type 'application/x-gzip' length 618299 bytes (603 KB)
==================================================
downloaded 603 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2015.json.gz'
Content type 'application/x-gzip' length 2429416 bytes (2.3 MB)
==================================================
downloaded 2.3 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2015trans.xml.gz'
Content type 'application/x-gzip' length 585803 bytes (572 KB)
==================================================
downloaded 572 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2016.json.gz'
Content type 'application/x-gzip' length 2843982 bytes (2.7 MB)
==================================================
downloaded 2.7 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2016trans.xml.gz'
Content type 'application/x-gzip' length 629251 bytes (614 KB)
==================================================
downloaded 614 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2017.json.gz'
Content type 'application/x-gzip' length 4024597 bytes (3.8 MB)
==================================================
downloaded 3.8 MB

trying URL 'https://nvd.nist.gov/download/nvdcve-2017trans.xml.gz'
Content type 'application/x-gzip' length 776399 bytes (758 KB)
==================================================
downloaded 758 KB

trying URL 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.json.gz'
Content type 'application/x-gzip' length 26883 bytes (26 KB)
==================================================
downloaded 26 KB

trying URL 'https://nvd.nist.gov/download/nvdcve-2018trans.xml.gz'
Content type 'application/x-gzip' length 11164 bytes (10 KB)
==================================================
downloaded 10 KB

[1] "Unzip, extract, etc..."
[1] "Processing MITRE raw data..."
[1] "Parsing MITRE cves from CSV source..."
[1] "Tidy MITRE data frame..."
[1] "Parsing MITRE data finished."
[1] "Processing NIST raw data..."
[1] "Parsing cves (year 2002) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2003) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2004) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2005) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2006) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2007) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2008) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2009) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2010) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2011) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2012) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2013) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2014) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2015) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2016) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2017) from json source..."
  |======================================================================| 100%
[1] "Parsing cves (year 2018) from json source..."
  |======================================================================| 100%
[1] "Tidy NIST data frame..."
[1] "Parsing NIST data finished."
[1] "Joining MITRE and NIST data..."
[1] "CVES data.frame UPDATED!"
[1] "[*] Updating CPES data.frame..."
[1] "Downloading raw data..."
trying URL 'http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip'
Content type 'application/x-zip-compressed' length 2249601 bytes (2.1 MB)
==================================================
downloaded 2.1 MB

[1] "Extracting data..."
[1] "Building data frame..."
  |                                                                      |   0%
[1] "Indexing CPE XML and namespace schemas..."
  |=======                                                               |  10%
[1] "Parsing product title and cpe codes 2.x..."
  |==============                                                        |  20%
[1] "Extracting factors from cpe 2.3 code..."
  |===================================                                   |  50%
[1] "Parsing product links and references..."
  |==========================================                            |  60%
[1] "Adding references to data.frame ..."
  |========================================================              |  80%
[1] "Parsing check and OVAL references ..."
  |===============================================================       |  90%
[1] "Adding checks to data.frame ..."
  |======================================================================| 100%
[1] "CPES data frame building process finished."
[1] "CPES data.frame UPDATED!"
[1] "[*] Updating CWES data.frame..."
[1] "Downloading raw data from MITRE..."
trying URL 'https://cwe.mitre.org/data/xml/views/2000.xml.zip'
Content type 'application/zip' length 1051323 bytes (1.0 MB)
==================================================
downloaded 1.0 MB

[1] "Unzip, extract, etc..."
[1] "Processing CWE raw data..."
[1] "Parsing Basic attributes..."
  |====                                                                  |   6%
[1] "Parsing Description..."
  |========                                                              |  12%
[1] "Parsing Related Weakness..."
  |============                                                          |  18%
[1] "Parsing Weakness Ordinality..."
  |================                                                      |  24%
[1] "Parsing Applicable Platforms..."
  |=====================                                                 |  29%
[1] "Parsing Background Details..."
  |=========================                                             |  35%
[1] "Parsing Alternate Terms..."
  |=============================                                         |  41%
[1] "Parsing Modes Of Introduction..."
  |=================================                                     |  47%
[1] "Parsing Likelihood Of Exploit..."
  |=====================================                                 |  53%
[1] "Parsing Common Consequences..."
  |=========================================                             |  59%
[1] "Parsing Detection Methods..."
  |=============================================                         |  65%
[1] "Parsing Potential Mitigations..."
  |=================================================                     |  71%
[1] "Parsing Observed Examples..."
  |======================================================                |  76%
[1] "Parsing Functional Areas..."
  |==========================================================            |  82%
[1] "Parsing Affected Resources..."
  |==============================================================        |  88%
[1] "Parsing Taxonomy Mappings..."
  |==================================================================    |  94%
[1] "Parsing Related Attack Patterns..."
  |======================================================================| 100%
[1] "CWES data frame building process finished."
[1] "CWES data.frame UPDATED!"
[1] "[*] Updating CAPEC data.frame..."
[1] "Downloading CAPEC raw data..."
trying URL 'https://capec.mitre.org/data/xml/capec_v2.10.xml'
Content type 'application/xml' length 5316747 bytes (5.1 MB)
==================================================
downloaded 5.1 MB

[1] "Indexing CAPEC XML data..."
[1] "Parsing CAPEC Views..."
[1] "Parsing CAPEC Categories..."
[1] "Parsing CAPEC Attacks..."
  |                                                                      |   0%
[1] "Parsing Attacks basic attributes..."
[1] "Parsing attacks prerequisites ..."
  |==                                                                    |   4%
[1] "Parsing attacks severity ..."
  |=====                                                                 |   7%
[1] "Parsing exploitability info ..."
  |========                                                              |  11%
[1] "Parsing methods of attack and cveexamples ..."
  |==========                                                            |  14%
[1] "Parsing hacking skills and resources required ..."
  |============                                                          |  18%
[1] "Parsing proving and obfuscation techniques, also indicators of attack ..."
  |===============                                                       |  21%
[1] "Parsing solutions and mitigations..."
  |==================                                                    |  25%
[1] "Parsing motivation consequences ..."
  |====================                                                  |  29%
[1] "Parsing injection vector, activation zone and payload info ..."
  |======================                                                |  32%
[1] "Parsing related CWE, CVE, CAPEC and other standards ..."
  |===================================                                   |  50%
[1] "Parsing security requirements, principles and guidelines ..."
  |==========================================                            |  61%
[1] "Parsing purposes ..."
  |=============================================                         |  64%
[1] "Parsing impact CIA values ..."
  |====================================================                  |  75%
[1] "Parsing context technical architectures, frameworks, platforms and languages ..."
  |==============================================================        |  89%
[1] "Parsing references, books, links..."
  |=================================================================     |  93%
[1] "Building attacks tidy data.frame ..."
  |======================================================================| 100%
[1] "CAPEC data frame building process finished."
[1] "CAPEC data.frame UPDATED!"
[1] "Updated CVEs data.frame has 98903 new observations."
[1] "Updated CPEs data.frame has 126825 new observations."
[1] "Updated CWEs data.frame has 630 new observations."
[1] "Updated CAPECs data.frame has 442 new observations."
[1] "Building, compressing and saving samples..."
[1] "Compressing and saving data sets to local file..."
Removing package from ‘/home/netsec/R/x86_64-pc-linux-gnu-library/3.4’
(as ‘lib’ is unspecified)
'/usr/lib/R/bin/R' --no-site-file --no-environ --no-save --no-restore --quiet  \
  CMD build '/home/netsec/rpackages/net.security' --no-resave-data  \
  --no-manual

* checking for file ‘/home/netsec/rpackages/net.security/DESCRIPTION’ ... OK
* preparing ‘net.security’:
* checking DESCRIPTION meta-information ... OK
* checking for LF line-endings in source and make files and shell scripts
* checking for empty or unneeded directories
* looking to see if a ‘data/datalist’ file should be added
* building ‘net.security_0.3.5.tar.gz’

Installing net.security
'/usr/lib/R/bin/R' --no-site-file --no-environ --no-save --no-restore --quiet  \
  CMD INSTALL '/home/netsec/rpackages/net.security'  \
  --library='/home/netsec/R/x86_64-pc-linux-gnu-library/3.4' --install-tests

* installing *source* package ‘net.security’ ...
** R
** data
*** moving datasets to lazyload DB
** inst
** tests
** preparing package for lazy loading
** help
*** installing help indices
** building package indices
** testing if installed package can be loaded
* DONE (net.security)
Reloading installed net.security
[1] "2018-01-15"
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
  - [NIST JSON schema](https://scap.nist.gov/schema/nvd/feed/0.1/nvd_cve_feed_json_0.1_beta.schema)  
  - [CVE JSON schema 4.0](https://github.com/CVEProject/automation-working-group/tree/master/cve_json_schema)  
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
