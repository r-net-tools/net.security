#' Sample of 1000 random OVAL (Open Vulnerability and Assessment Language)
#'
#' A data set containing public information about OVAL information from Center for Internet Security.
#'
#' \describe{
#'    \item{class}{The Class Enumeration defines the different classes of OVAL Definitions where each class specifies the overall intent of the OVAL Definition.}
#'    \item{id}{The globally unique identifier of the OVAL Definition.}
#'    \item{version}{The version of the globally unique OVAL Definition referenced by the definition_ref (id) property.}
#'    \item{title}{A short text title for the OVAL Definition.}
#'    \item{affected.family}{The high-level classification of the system type.}
#'    \item{affected.platforms}{}
#'    \item{affected.cpes}{}
#'    \item{references}{}
#'    \item{status}{}
#'    \item{deprecated}{}
#' }
#'
#' @docType data
#'
#' @name oval.sample
#'
#' @usage data(oval.sample)
#'
#' @format A data frame with 1000 rows and 11 columns.
#'
#' @keywords cve
#'
#' @source \url{https://oval.mitre.org/language/version5.10.1/OVAL_Language_Specification_01-20-2012.docx}
"oval.sample"
