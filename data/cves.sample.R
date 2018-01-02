#' Sample of 1000 random CVEs (Common Vulnerability Enummeration)
#'
#' A data set containing public information about CVE information from MITRE and NIST.
#'
#' \describe{
#'   \item{cve.id}{CVE Identifier (also referred to by the community as "CVE IDs," "CVE entries," "CVE names," "CVE numbers," and "CVEs") are unique, common identifiers for publicly known cyber security vulnerabilities. (MITRE)}
#'   \item{status}{CANDIDATE or ENTRY. (MITRE)}
#'   \item{description}{The "Description" portion of CVE Identifier (CVE ID) entries are typically written by CVE Numbering Authorities (CNAs), MITRE's CVE Content Team, or individuals requesting a CVE ID. (MITRE)}
#'   \item{ref.mitre}{Each CVE Identifier includes appropriate references. The CVE website also includes a Reference Maps page with links to documents from the commonly used information sources that are used as references for CVE entries. More info: http://cve.mitre.org/data/refs/refkey.html (MITRE)}
#'   \item{phase}{Values can be Proposed, Interim, Modified or Assigned. Some time are followed with date with format %Y%m%d (MITRE)}
#'   \item{votes}{Values can be accept, modify, noop, recast, reject, reviewing or revote. They are usually followed by voter name. (MITRE)}
#'   \item{comments}{Comments about the vulnerability. (MITRE)}
#'   \item{}{}
#'   \item{affects}{Affected vendor product list as json.}
#'   \item{problem.type}{Related weaknesses, usually CWE ids.}
#'   \item{references}{References as json list.}
#'   \item{description}{"Defines a node or sub-node in an NVD applicability statement."}
#'   \item{vulnerable.configuration}{Vulnerable configurations defined as logical combination of CPE ids.}
#'   \item{cvss3.vector}{CVSS v3 vector string.}
#'   \item{cvss3.av}{CVSS v3 attack vector value.}
#'   \item{cvss3.ac}{CVSS v3 attack complexity value.}
#'   \item{cvss3.pr}{CVSS v3 privileges required value.}
#'   \item{cvss3.ui}{CVSS v3 user interaction value.}
#'   \item{cvss3.s}{CVSS v3 scope value.}
#'   \item{cvss3.c}{CVSS v3 confidentiality impact value.}
#'   \item{cvss3.i}{CVSS v3 integrity impact value.}
#'   \item{cvss3.a}{CVSS v3 availability impact value.}
#'   \item{cvss3.score}{CVSS v3 }
#'   \item{cvss3.severity}{CVSS v3 }
#'   \item{cvss3.score.exploit}{CVSS v3 }
#'   \item{cvss3.score.impact}{CVSS v3 }
#'   \item{cvss2.vector}{}
#'   \item{cvss2.av}{}
#'   \item{cvss2.ac}{}
#'   \item{cvss2.au}{}
#'   \item{cvss2.c}{}
#'   \item{cvss2.i}{}
#'   \item{cvss2.a}{}
#'   \item{cvss2.score}{}
#'   \item{cvss2.score.exploit}{}
#'   \item{cvss2.score.impact}{}
#'   \item{cvss2.getallprivilege}{}
#'   \item{cvss2.getusrprivilege}{}
#'   \item{cvss2.getothprivilege}{}
#'   \item{cvss2.requsrinter}{}
#'   \item{published.date}{}
#'   \item{last.modified}{}
#' }
#'
#' @docType data
#'
#' @name cves.sample
#'
#' @usage data(cves.sample)
#'
#' @format A data frame with 1000 rows and 24 columns.
#'
#' @keywords cve
#'
#' @source \url{http://cve.mitre.org/about/faqs.html}
"cves.sample"
