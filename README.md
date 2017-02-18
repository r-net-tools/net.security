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

## Usage
Load package using `library("net.security")` then you can access directly to security standards data frames.
It also includes an API server mapping data driven security functions defined in ddsecurity.R

### Security Standards
#### CVE
Reference: http://cve.mitre.org/about/faqs.html  
Raw Data:
 - MITRE: http://cve.mitre.org/data/downloads/index.html#download
 - NIST: https://nvd.nist.gov/download.cfm  

Update dataset: `UpdateDataSets(path = "data", stnd = "v")`  
Data Frame: `View(cves)`  
API: `/cveinfo/<cve-code>`   

#### CWE
Reference: http://cwe.mitre.org/data/index.html#documentation  
Raw Data: https://cwe.mitre.org/data  
Update dataset: `UpdateDataSets(path = "data", stnd = "w")`  
Data Frame: `View(cwes)`  
API: `/cweinfo/<cwe-code>`

#### CAPEC
Reference: https://capec.mitre.org/data/index.html  
Reference: https://capec.mitre.org/data/xsd/ap_schema_v2.7.1.xsd  
Raw Data: https://capec.mitre.org/data/xml/capec_v2.8.xml  
Update dataset: `UpdateDataSets(path = "data", stnd = "a")`  
Data Frame: `View(capec$views)` or `View(capec$categories)` or `View(capec$attacks)`  
API: `/capec/view/<number>`  
API: `/capec/category/<number>`  
API: `/capec/attack/<number>`  

#### CPE
Reference: https://nvd.nist.gov/cpe.cfm  
Reference: http://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf  
Raw Data: http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz  
Update dataset: `UpdateDataSets(path = "data", stnd = "p")`  
Data Frame: `View(cpes)`  
API: `/cpe?name="<character>"`  
 
#### OVAL
Reference: https://oval.cisecurity.org/  
Raw Data: https://oval.cisecurity.org/repository/download/5.11.1/all/oval.xml  
Update dataset: `UpdateDataSets(path = "data", stnd = "o")`  
Data Frame: `View(oval)`  

### API
#### Start Server
Ensure that Rscript is in your PATH. Open system command line, go to this package and run the api.R script.
```bash
net.security$ Rscript api.R
Starting server to listen on port 8000
```

#### Examples

**CVE**  

[http://127.0.0.1:8000/cveinfo/CVE-2010-2012](http://127.0.0.1:8000/cveinfo/CVE-2010-2012)

![Alt text](img/api.screenshot.cve.jpg?raw=true "api net.security")

**CWE**

[http://127.0.0.1:8000/cweinfo/CWE-200](http://127.0.0.1:8000/cweinfo/CWE-200)

![Alt text](img/api.screenshot.cwe.jpg?raw=true "api net.security")

**CPE**

[http://localhost:8000/cpe?name="winamp 5.6"](http://localhost:8000/cpe?name=%22winamp%205.6%22)

![Alt text](img/api.screenshot.cpe.jpg?raw=true "api net.security")

**CAPEC View**

[http://127.0.0.1:8000/capec/view/1000](http://127.0.0.1:8000/capec/view/1000)

![Alt text](img/api.screenshot.capec.view.jpg?raw=true "api net.security")

**CAPEC Category**

[http://127.0.0.1:8000/capec/category/100](http://127.0.0.1:8000/capec/category/100)

![Alt text](img/api.screenshot.capec.category.jpg?raw=true "api net.security")

**CAPEC Attack**

[http://127.0.0.1:8000/capec/attack/256](http://127.0.0.1:8000/capec/attack/256)

![Alt text](img/api.screenshot.capec.attack.jpg?raw=true "api net.security")
