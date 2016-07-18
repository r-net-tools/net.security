#' Common Platform Enumeration Entries
#'
#' A dataset containing entries with the information of the different platforms containing
#' over  100,000 rows.
#'
#' @format A data frame with +100,000 rows and 3 variables:
#' \describe{
#'   \item{cpe.22}{Title of the platform}
#'   \item{cpe.23}{Identifier for given platform}
#'   \item{cpe.ref}{URLs encoded as json with additional information regarding the cpe entry}
#'   ...
#' }
#' @source \url{https://cpe.mitre.org}
"cpes"

#' Common Vulnerabilities and Exposures
#'
#' A dataset containing the entries for the details for more than 92,000 CVE entries.
#'
#' @format A data frame with 53940 rows and 10 variables:
#' \describe{
#'  \item{cve}{CVE Identifier.}
#'  \item{status}{Factor, The status of the entry, either \emph{Candidate} of \emph{Entry}.}
#'  \item{description}{Brief description of the entry.}
#'  \item{references}{Additional infomation regarding the CVE entry.}
#'  \item{phase}{Phase of entry, including date of assignation}
#'  \item{votes}{Information regarding the votes of the different reviewers}
#'  \item{comments}{Additional notes regarding the entry.}
#' }
#' @source \url{https://cve.mitre.org}
"cves"

#' Common Vulnerabilities and Exposures from NIST
#'
#' A dataset containing the entries for the details of 77,630 CVE entries obtained from NIST
#' publicly available database.
#'
#' @format A data frame with 77,630 rows and 19 variables
#' \describe{
#'   \item{osvdb.ext}{}
#'   \item{vulnerable.configuration}{}
#'   \item{vulnerable.software.list}{}
#'   \item{cve.id}{}
#'   \item{discovered.datetime}{}
#'   \item{disclosure.datetime}{}
#'   \item{exploit.publish.datetime}{}
#'   \item{published.datetime}{}
#'   \item{last.modified.datetime}{}
#'   \item{cvss}{}
#'   \item{security.protection}{}
#'   \item{assessment.check}{}
#'   \item{cwe}{}
#'   \item{references}{}
#'   \item{fix.action}{}
#'   \item{scanner}{}
#'   \item{summary}{}
#'   \item{technical.description}{}
#'   \item{attack.scenario}{}
#' }
#' @source \url{https://nvd.nist.gov/download.cfm}
"cves.nist"

#' Common Weakness Enumeration
#'
#' A dataset containing the entries for the details for the 719 CWE entries.
#'
#' @format A data frame with 719 rows and 26 variables:
#' \describe{
#'  \item{ID}{CWE Identifier}
#'  \item{Name}{}
#'  \item{Weakness_Abstraction}{}
#'  \item{Status}{}
#'  \item{code_standard}{}
#'  \item{descr.summary}{}
#'  \item{descr.details}{}
#'  \item{relationships}{}
#'  \item{cwe.parents}{}
#'  \item{ordinalities}{}
#'  \item{platforms}{}
#'  \item{time.intro}{}
#'  \item{consequences}{}
#'  \item{mitigation}{}
#'  \item{causal}{}
#'  \item{demos}{}
#'  \item{mapping}{}
#'  \item{history}{}
#'  \item{relationship.notes}{}
#'  \item{maintenance.notes}{}
#'  \item{background}{}
#'  \item{introduction.mode}{}
#'  \item{other.notes}{}
#'  \item{aff.resources}{}
#'  \item{exploits}{}
#'  \item{functional.areas}{}
#' }
#' @source \url{https://cwe.mitre.org}
"cwes"

