#' Sample of 1000 random CVEs (Common Vulnerability Enummeration)
#'
#' A data set containing public information about CVE information from MITRE and NIST.
#'
#' \describe{
#'   \item{cve}{CVE Identifier (also referred to by the community as "CVE IDs," "CVE entries," "CVE names," "CVE numbers," and "CVEs") are unique, common identifiers for publicly known cyber security vulnerabilities. (MITRE)}
#'   \item{status}{CANDIDATE or ENTRY. (MITRE)}
#'   \item{description}{The "Description" portion of CVE Identifier (CVE ID) entries are typically written by CVE Numbering Authorities (CNAs), MITRE's CVE Content Team, or individuals requesting a CVE ID. (MITRE)}
#'   \item{ref.mitre}{Each CVE Identifier includes appropriate references. The CVE website also includes a Reference Maps page with links to documents from the commonly used information sources that are used as references for CVE entries. More info: http://cve.mitre.org/data/refs/refkey.html (MITRE)}
#'   \item{phase}{Values can be Proposed, Interim, Modified or Assigned. Some time are followed with date with format %Y%m%d (MITRE)}
#'   \item{votes}{Values can be accept, modify, noop, recast, reject, reviewing or revote. They are usually followed by voter name. (MITRE)}
#'   \item{comments}{Comments about the vulnerability. (MITRE)}
#'   \item{cpe.config}{The id for the vulnerable configuration. The products that collectively characterize a particular IT platform type. (NIST)}
#'   \item{cpe.software}{The CPE name of the vulnerable software. (NIST)}
#'   \item{discovered.datetime}{The date that the vulnerability was first discovered.(NIST)}
#'   \item{disclosure.datetime}{The date and time that the vulnerability was disclosed to the public.(NIST)}
#'   \item{exploit.publish.datetime}{(NIST)}
#'   \item{published.datetime}{(NIST)}
#'   \item{last.modified.datetime}{(NIST)}
#'   \item{cvss}{CVSS v2 base score (NIST)}
#'   \item{cvss.vector}{CVSS v2 basic vector AV:[L,A,N]/AC:[H,M,L]/Au:[M,S,N]/C:[N,P,C]/I:[N,P,C]/A:[N,P,C] (NIST)}
#'   \item{security.protection}{The security protection type. Allowed values: ALLOWS_ADMIN_ACCESS, ALLOWS_USER_ACCESS, ALLOWS_OTHER_ACCESS. (NIST)}
#'   \item{assessment.check}{An optional list of equivalent assessment methods that specify additional system state that must be present for the vulnerability to exist. (NIST)}
#'   \item{cwe}{CWE reference extracted from other ref.nist and ref.mitre columns. (NIST)}
#'   \item{ref.nist}{The reference includes a link to a software patch or update instructions. (NIST)}
#'   \item{fix.action}{Allowed values: OFFICIAL_FIX, TEMPORARY_FIX or WORKAROUND (NIST)}
#'   \item{scanner}{Identifies a tool and any associated information about the tool, such as signature versions, that indicate the tool is capable or properly detecting and/or remediating the vulnerability or misconfiguration. (NIST)}
#'   \item{summary}{A short summary of the vulnerability. (NIST)}
#'   \item{technical.description}{The reference provides a technical description of the vulnerability. (NIST)}
#'   \item{attack.scenario}{The reference provides a sample attack scenario that demostrates how the vulnerability may be exploited. (NIST)}
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
