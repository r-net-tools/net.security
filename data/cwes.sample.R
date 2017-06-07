#' Sample of 100 random CWEs (Common Weakness Enummeration)
#'
#' A data set containing public information about CWE information from MITRE.
#'
#' \describe{
#'    \item{code_standard}{CWE-XXXX}
#'    \item{Name}{This attribute is the string which identifies the entry. The name should focus on the weakness being described in the entry and should avoid focusing on the attack which exploits the weakness or the consequences of exploiting the weakness. All words in the entry name should be capitalized except for articles and prepositions unless they begin or end the name. Subsequent words in a hyphenated chain are also not capitalized. This is required for all Weaknesses.}
#'    \item{Weakness_Abstraction}{The Weakness_Abstraction attribute defines the abstraction level for this weakness. Acceptable values are:
#'                                  - `Class`, which is the most abstract type of Weakness such as CWE-362 Race Conditions.
#'                                  - `Base`,  which is a more specific type of weakness that is still mostly independent of a specific resource or technology such as CWE-567 Unsynchronized Access to Shared Data.
#'                                  - `Variant`,  which is a weakness specific to a particular resource, technology or context.
#'                                  - `Incomplete`, for incomplete definition.
#'                                  - `Deprecated`, old definition.
#'                                  - `Draft`, Work in progress.  }
#'    \item{Status}{The Status attribute defines the status level for this weakness.}
#'    \item{descr.summary}{This description should be short and should limit itself to describing the key points that define this entry. Further explanation can be included in the extended description element. This is required for all entries.}
#'    \item{descr.details}{This element provides a place for details important to the description of this entry to be included that are not necessary to convey the fundamental concept behind the entry. This is not required for all entries and should only be included where appropriate.}
#'    \item{cwe.id}{This attribute provides a unique identifier for the entry. It will be static for the lifetime of the entry. In the event that this entry becomes deprecated, the ID will not be reused and a pointer will be left in this entry to the replacement. This is required for all Weaknesses.}
#'    \item{cwe.parents.ids}{cwe parents ids separated by ; . Useful for graph representations.}
#'    \item{time.intro}{The Time_of_Introduction element contains the points of time in the software life cycle at which the weakness may be introduced. If there are multiple points of time at which the weakness may be introduced, then separate Introduction elements should be included for each. This element should be populated for all weakness bases and variants.}
#'    \item{consequences}{This element contains the common consequences associated with this weakness. It is populated by one or more individual Common_Consequence subelements. This should be included and completed as much as possible for all weaknesses.}
#'    \item{exploits}{This element contains a rough estimate at the likelihood of exploitation of an exposed weakness. Many factors can impact this value which is why it should only be regarded as an approximation.}
#'    \item{ordinalities}{This element describes when this entry is primary - where the weakness exists independent of other weaknesses, or when this entry might be resultant - where the weakness is typically related to the presence of some other weaknesses. The Ordinality subelement identifies whether or not we are providing context around when this entry is primary, or resultant. The Ordinality_Description contains the description of the context in which this entry is primary or resultant. It is important to note that it is possible for the same entry to be primary in some instances and resultant in others.}
#'    \item{platforms}{This structure contains the Languages, Operating_Systems, Hardware_Architectures, Architectural_Paradigms, Environments, Technology_Classes or Common Platforms on which this entry may exist. This should be filled out as much as possible for all Compound_Element and Weakness entries.}
#'    \item{aff.resources}{This element identifies system resources affected by this entry. It is populated by Affected_Resource elements.}
#'    \item{causal}{This element describes the nature of the underlying cause of the weakness. Is it an implicit underlying weakness or is it an issue of behavior on the part of the software developer? Appropriate values are either Implicit, occurring regardless of developer behavior, or Explicit, an explicit weakness resulting from behavior of the developer.}
#'    \item{mitigation}{This element contains the potential mitigations associated with this weakness. It contains one or more mitigation subelements which each represent individual mitigations for this weakness. This should be included and completed to the extent possible for all weakness bases and variants.}
#' }
#'
#' @docType data
#'
#' @name cwes.sample
#'
#' @usage data(cwes.sample)
#'
#' @format A data frame with 100 rows and 16 columns.
#'
#' @keywords cwe
#'
#' @source \url{http://cwe.mitre.org/about/faq.html}
"cwes.sample"
