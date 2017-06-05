#' Sample of 100 random CWEs (Common Weakness Enummeration)
#'
#' A data set containing public information about CWE information from MITRE.
#'
#' \describe{
#'    \item{ID}{}
#'    \item{Name}{}
#'    \item{Weakness_Abstraction}{The Weakness_Abstraction attribute defines the abstraction level for this weakness. Acceptable values are:
#'                                  - `Class`, which is the most abstract type of Weakness such as CWE-362 Race Conditions.
#'                                  - `Base`,  which is a more specific type of weakness that is still mostly independent of a specific resource or technology such as CWE-567 Unsynchronized Access to Shared Data.
#'                                  - `Variant`,  which is a weakness specific to a particular resource, technology or context.
#'                                  - `Incomplete`, for incomplete definition.
#'                                  - `Deprecated`, old definition.
#'                                  - `Draft`, Work in progress.  }
#'    \item{Status}{}
#'    \item{code_standard}{}
#'    \item{descr.summary}{}
#'    \item{descr.details}{}
#'    \item{relationships}{}
#'    \item{cwe.parents}{}
#'    \item{ordinalities}{}
#'    \item{platforms}{}
#'    \item{time.intro}{}
#'    \item{consequences}{}
#'    \item{mitigation}{}
#'    \item{causal}{}
#'    \item{demos}{}
#'    \item{mapping}{}
#'    \item{history}{}
#'    \item{relationship.notes}{}
#'    \item{maintenance.notes}{}
#'    \item{background}{}
#'    \item{introduction.mode}{}
#'    \item{other.notes}{}
#'    \item{aff.resources}{}
#'    \item{exploits}{}
#'    \item{functional.areas}{}
#' }
#'
#' @docType data
#'
#' @name cwes.sample
#'
#' @usage data(cwes.sample)
#'
#' @format A data frame with 100 rows and 26 columns.
#'
#' @keywords cwe
#'
#' @source \url{http://cwe.mitre.org/about/faq.html}
"cwes.sample"
