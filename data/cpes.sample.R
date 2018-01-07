#' Sample of 1000 random CPEs (Common Platform Enummeration)
#'
#' A data set containing public information about CPE information from NIST.
#'
#' \describe{
#'   \item{title}{Human-readable title of the name. To support uses intended for multiple languages, the <cpe_dict:title> element supports the xml:lang attribute. At most one <cpe_dict:title> element MAY appear for each language.}
#'   \item{cpe.22}{The identifier name bound in CPE 2.2 format.}
#'   \item{cpe.23}{The identifier name bound in CPE 2.3 format.}
#'   \item{part}{The part attribute SHALL have one of these three string values:
#'                   - The value 'a', when the CPE is for a class of applications.
#'                   - The value 'o', when the WFN is for a class of operating systems.
#'                   - The value 'h', when the WFN is for a class of hardware devices.
#'                   }
#'   \item{vendor}{Values for this attribute SHOULD describe or identify the person or organization that manufactured or created the product}
#'   \item{product}{Values for this attribute SHOULD describe or identify the most common and recognizable title or name of the product.}
#'   \item{version}{Values for this attribute SHOULD be vendor-specific alphanumeric strings characterizing the particular release version of the product. }
#'   \item{update}{Values for this attribute SHOULD be vendor-specific alphanumeric strings characterizing the particular update, service pack, or point release of the product.}
#'   \item{edition}{The edition attribute is considered deprecated in this specification, and it SHOULD be assigned the logical value ANY except where required for backward compatibility with version 2.2 of the CPE specification. This attribute is referred to as the “legacy edition” attribute.}
#'   \item{language}{Values for this attribute SHALL be valid language tags as defined by [RFC5646], and SHOULD be used to define the language supported in the user interface of the product being described.}
#'   \item{sw_edition}{Values for this attribute SHOULD characterize how the product is tailored to a particular market or class of end users.}
#'   \item{target_sw}{Values for this attribute SHOULD characterize the software computing environment within which the product operates.}
#'   \item{target_hw}{Values for this attribute SHOULD characterize the software computing environment within which the product operates.}
#'   \item{other}{Values for this attribute SHOULD capture any other general descriptive or identifying information which is vendor- or product-specific and which does not logically fit in any other attribute value.}
#'   \item{references}{External references to additional descriptive material. Each reference consists of a piece of text (intended to be human-readable) and a URI (intended to be a URL pointing to a real resource).}
#'   \item{checks}{Calls out a check, such as an OVAL definition, that can confirm or reject an IT system as an instance of the named platform. Includes a REQUIRED check system specification URI (e.g., the URI for a particular version of OVAL), a REQUIRED check identifier, and an OPTIONAL external file reference (for example, a pointer to the file where the check is defined).}
#' }
#'
#' @docType data
#'
#' @name cpes.sample
#'
#' @usage data(cpes.sample)
#'
#' @format A data frame with 1000 rows and 14 columns.
#'
#' @keywords cpe
#'
#' @source \url{https://nvd.nist.gov/cpe.cfm}
"cpes.sample"
