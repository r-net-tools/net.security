# net.security

[![Build Status](https://travis-ci.org/r-net-tools/net-security.svg?branch=devel)](https://travis-ci.org/r-net-tools/net-security)

Package for Data Driven Security purposes.

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

## ICANN Standards
References:
 - Crash Course: [slideshare](http://www.slideshare.net/apnic/routing-registry-function-automation-using-rpki-rpsl)

### RIPE
#### ASN
Reference:
Raw Data: [RIPE FTP](ftp://ftp.ripe.net/ripe/dbase/split/)
Data Frame:
Example: `ripe.asn <- GetRIPE.ASN()`

#### INET IPv4
Reference: [RIPE Documentation](https://www.ripe.net/manage-ips-and-asns/db/support/documentation/ripe-database-documentation/rpsl-object-types/4-2-descriptions-of-primary-objects/4-2-4-description-of-the-inetnum-object)
Raw Data: [RIPE FTP](ftp://ftp.ripe.net/ripe/dbase/split/)
Data Frame:
Example: `ripe.inet <- GetRIPE.inet()`

## Network & Security Tools
### NMAP
Reference:
Raw Data:
Data Frame:
Example: `df <- ParseNMAP("nmap.xml","prefix.output.files-")`
