![Alt text](img/net.security.tiny.jpg?raw=true "net.security")

[![Project Status: WIP - Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](http://www.repostatus.org/badges/latest/wip.svg)](http://www.repostatus.org/#wip) 
[![Build Status](https://travis-ci.org/r-net-tools/net.security.svg?branch=master)](https://travis-ci.org/r-net-tools/net.security) 
[![Coverage Status](https://coveralls.io/repos/github/r-net-tools/net.security/badge.svg?branch=master)](https://coveralls.io/github/r-net-tools/net.security?branch=master)


#### Package for Data Driven Security purposes.

## Install

From R console just type:  
`devtools::install_github(repo = "r-net-tools/net.security")`  

If you want to test future features, just add branch as parameter:  
`devtools::install_github(repo = "r-net-tools/net.security", ref = "devel")`  

## MITRE & NIST Standards
### CVE
Reference: http://cve.mitre.org/about/faqs.html  
Raw Data:
 - MITRE: http://cve.mitre.org/data/downloads/index.html#download
 - NIST: https://nvd.nist.gov/download.cfm

Data Frame:  
Example: `cves <- net.security::GetCVEData()`

### CWE
Reference: http://cwe.mitre.org/data/index.html#documentation  
Raw Data: https://cwe.mitre.org/data  
Data Frame:  
Example: `cwes <- net.security::GetCWEData()`  

### CPE
Reference: https://nvd.nist.gov/cpe.cfm  
Raw Data: http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz  
Data Frame:  
Example: `cpes <- net.security::GetCPEData()`  
 
### CAPEC
Reference: https://capec.mitre.org/data/xsd/ap_schema_v2.7.1.xsd  
Raw Data: https://capec.mitre.org/data/xml/capec_v2.8.xml  
Data Frame:  
Example: `capec <- net.security::GetCAPECData()`  

## ICANN Standards
References:
 - Crash Course: [slideshare](http://www.slideshare.net/apnic/routing-registry-function-automation-using-rpki-rpsl)

### RIPE
#### ASN
Reference:  
Raw Data: [RIPE FTP](http://ftp.ripe.net/ripe/dbase/split/)  
Data Frame:  
Example: `ripe.asn <- GetRIPE.ASN()`

#### INET IPv4
Reference: [RIPE Documentation](https://www.ripe.net/manage-ips-and-asns/db/support/documentation/ripe-database-documentation/rpsl-object-types/4-2-descriptions-of-primary-objects/4-2-4-description-of-the-inetnum-object)  
Raw Data: [RIPE FTP](http://ftp.ripe.net/ripe/dbase/split/)  
Data Frame:  
Example: `ripe.inet <- GetRIPE.inet()`  

## Network & Security Tools
### NMAP
Reference:  
Raw Data:  
Data Frame:  
Example: `df <- ParseNMAP("nmap.xml","prefix.output.files-")`  
