#' Sample of 500 random CVEs (Common Vulnerability Enummeration)
#'
#' A data set containing public information about CVE information from MITRE and NIST.
#'
#' \describe{
#'   \item{cve}{}
#'   \item{status}{}
#'   \item{description}{}
#'   \item{ref.mitre}{}
#'   \item{phase}{}
#'   \item{votes}{}
#'   \item{comments}{}
#'   \item{osvdb}{}
#'   \item{cpe.config}{}
#'   \item{cpe.software}{}
#'   \item{discovered.datetime}{}
#'   \item{disclosure.datetime}{}
#'   \item{exploit.publish.datetime}{}
#'   \item{published.datetime}{}
#'   \item{last.modified.datetime}{}
#'   \item{cvss}{}
#'   \item{security.protection}{}
#'   \item{assessment.check}{}
#'   \item{cwe}{}
#'   \item{ref.nist}{}
#'   \item{fix.action}{}
#'   \item{scanner}{}
#'   \item{summary}{}
#'   \item{technical.description}{}
#'   \item{attack.scenario}{}
#' }
#'
#' @docType data
#'
#' @name cves.sample
#'
#' @usage data(cves.sample)
#'
#' @format A data frame with 500 rows and 26 columns.
#'
#' @keywords cve
#'
#' @source \url{http://cve.mitre.org/about/faqs.html}
"cves.sample"
