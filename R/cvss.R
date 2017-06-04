# CVSS Tools

# CVSS v2.0
#
# BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
#

GetCVSSScore <- function(x) {
  if (is.na(x)) return("")
  x <- jsonlite::fromJSON(x)
  if (length(x) == 0) return("")
  x <- x$base_metrics

  s <- ifelse("text" %in% names(x$`availability-impact`),
              x$`availability-impact`$text,
              x$`availability-impact`)
  avail.impact <- switch(tolower(s),
                        complete = 0.66,
                        partial  = 0.275,
                        none     = 0.0)
  s <- ifelse("text" %in% names(x$`integrity-impact`),
              x$`integrity-impact`$text,
              x$`integrity-impact`)
  integrity.impact <- switch(tolower(s),
                             complete = 0.66,
                             partial  = 0.275,
                             none     = 0.0)
  s <- ifelse("text" %in% names(x$`confidentiality-impact`),
              x$`confidentiality-impact`$text,
              x$`confidentiality-impact`)
  confidentiality.impact <- switch(tolower(s),
                             complete = 0.66,
                             partial  = 0.275,
                             none     = 0.0)
  s <- ifelse("text" %in% names(x$authentication),
              x$authentication$text,
              x$authentication)
  authentication <- switch(tolower(s),
                           none = 0.704,
                           single_instance = 0.56,
                           multiple_instances = 0.45)
  s <- ifelse("text" %in% names(x$`access-complexity`),
              x$`access-complexity`$text,
              x$`access-complexity`)
  access.complexity <- switch(tolower(s),
                           low = 0.71,
                           medium = 0.61,
                           high = 0.35)
  s <- ifelse("text" %in% names(x$`access-vector`),
              x$`access-vector`$text,
              x$`access-vector`)
  access.vector <- switch(tolower(s),
                              local_access = 0.395,
                              adjacent_network = 0.646,
                              network = 1.0)

  impact <-  10.41*(1-(1-confidentiality.impact)*(1-integrity.impact)*(1-avail.impact))
  fimpact <- ifelse(impact == 0, 0, 1.176)
  exploitability <- 20 * access.vector * access.complexity * authentication
  base.score <- round(((0.6*impact)+(0.4*exploitability)-1.5)*fimpact,1)

  return(base.score)
}


GetCVSSVector <- function(x) {
  if (is.na(x)) return("")
  x <- jsonlite::fromJSON(x)
  if (length(x) == 0) return("")
  x <- x$base_metrics
  cvss.vector <- ""

  s <- ifelse("text" %in% names(x$`access-vector`),
              x$`access-vector`$text,
              x$`access-vector`)
  access.vector <- switch(tolower(s),
                          local = "L",
                          adjacent_network = "A",
                          network = "N")
  cvss.vector <- stringr::str_c(cvss.vector,"AV:",access.vector,"/")
  s <- ifelse("text" %in% names(x$`access-complexity`),
              x$`access-complexity`$text,
              x$`access-complexity`)
  access.complexity <- switch(tolower(s),
                              low = "L",
                              medium = "M",
                              high = "H")
  cvss.vector <- stringr::str_c(cvss.vector,"AC:",access.complexity,"/")
  s <- ifelse("text" %in% names(x$authentication),
              x$authentication$text,
              x$authentication)
  authentication <- switch(tolower(s),
                           none = "N",
                           single_instance = "S",
                           multiple_instances = "M")
  cvss.vector <- stringr::str_c(cvss.vector,"Au:",authentication,"/")
  s <- ifelse("text" %in% names(x$`confidentiality-impact`),
              x$`confidentiality-impact`$text,
              x$`confidentiality-impact`)
  confidentiality.impact <- switch(tolower(s),
                                   complete = "C",
                                   partial  = "P",
                                   none     = "N")
  cvss.vector <- stringr::str_c(cvss.vector,"C:",confidentiality.impact,"/")
  s <- ifelse("text" %in% names(x$`integrity-impact`),
              x$`integrity-impact`$text,
              x$`integrity-impact`)
  integrity.impact <- switch(tolower(s),
                             complete = "C",
                             partial  = "P",
                             none     = "N")
  cvss.vector <- stringr::str_c(cvss.vector,"I:",integrity.impact,"/")
  s <- ifelse("text" %in% names(x$`availability-impact`),
              x$`availability-impact`$text,
              x$`availability-impact`)
  avail.impact <- switch(tolower(s),
                         complete = "C",
                         partial  = "P",
                         none     = "N")
  cvss.vector <- as.character(stringr::str_c(cvss.vector,"A:",avail.impact))

  return(cvss.vector)
}
