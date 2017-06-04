# CVSS Tools

# CVSS v2.0

GetCVSS2Vector <- function(x) {
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

GetCVSS2Score <- function(x) {
  if (is.na(x)) return(as.numeric(NA))
  x <- jsonlite::fromJSON(x)
  if (length(x) == 0) return(as.numeric(NA))
  x <- x$base_metrics
  s <- ifelse("text" %in% names(x$score),
              x$score$text,
              x$score)
  score <- as.numeric(s)
  return(score)
}
