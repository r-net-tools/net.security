#' It builds a data frame with relations between CWE, CVE and CAPEC.
#'
#' @param as.igraph if true it will return igraph object, if false a data frame
#'
#' @return data.frame
#' @export
GetSecurityNetwork <- function(as.igraph = F) {
  # CVEs --> CWEs
  cves2cwes <- GetRelationCVE2CWE()
  cves2cwes$nature <- rep("ChildOf", nrow(cves2cwes))
  cves2cwes$weight <- rep(3, nrow(cves2cwes))
  cves2cwes$type <- rep("cve", nrow(cves2cwes))

  # CWEs --> CAPECs
  cwes2capec <- GetRelationCWE2CAPEC()
  cwes2capec$nature <- rep("CanPrecede", nrow(cwes2capec))
  cwes2capec$weight <- rep(4, nrow(cwes2capec))
  cwes2capec$type <- rep("attack", nrow(cwes2capec))

  # CWEs hierarcy
  cwes.hr <- GetCWEHierarcy(as_numbers = F)
  cwes.hr$nature <- as.character.factor(cwes.hr$nature)
  cwes.hr$weight <- as.numeric(cwes.hr$weight)

  sn <- dplyr::bind_rows(cves2cwes, cwes2capec, cwes.hr)

  return(sn)
}

GetRelationCVE2CWE <- function() {
  c.cwes <- sapply(netsec.data$datasets$cves$problem.type, function(x) length(jsonlite::fromJSON(x)))

  # No edges
  cves2cwes0 <- netsec.data$datasets$cves[c.cwes == 0, c("cve.id", "problem.type", "cvss2.score", "cvss3.score")]
  names(cves2cwes0) <- c("src", "target", "cvss2.score", "cvss3.score")
  cves2cwes0$cvss2.score[is.na(cves2cwes0$cvss2.score)] <- 0
  cves2cwes0$cvss3.score[is.na(cves2cwes0$cvss3.score)] <- 0
  cves2cwes0 <- dplyr::mutate(cves2cwes0, weight = pmax(cvss2.score, cvss3.score))
  cves2cwes0$cvss2.score <- NULL
  cves2cwes0$cvss3.score <- NULL
  cves2cwes0$target <- rep("NVD-CWE-noinfo", nrow(cves2cwes0))

  # One edge
  cves2cwes1 <- netsec.data$datasets$cves[c.cwes == 1, c("cve.id", "problem.type", "cvss2.score", "cvss3.score")]
  cves2cwes1$problem.type <- sapply(cves2cwes1$problem.type, function(x) jsonlite::fromJSON(x))
  names(cves2cwes1) <- c("src", "target", "risc2", "risc3")
  cves2cwes1$risc2[is.na(cves2cwes1$risc2)] <- 0
  cves2cwes1$risc3[is.na(cves2cwes1$risc3)] <- 0
  cves2cwes1 <- dplyr::mutate(cves2cwes1, weight = pmax(risc2, risc3))
  cves2cwes1$risc2 <- NULL
  cves2cwes1$risc3 <- NULL

  # Multiple edges
  cves2cwesN <- netsec.data$datasets$cves[c.cwes > 1, c("cve.id", "problem.type", "cvss2.score", "cvss3.score")]
  cves2cwesN$cvss2.score[is.na(cves2cwesN$cvss2.score)] <- 0
  cves2cwesN$cvss3.score[is.na(cves2cwesN$cvss3.score)] <- 0
  cves2cwesN <- dplyr::mutate(cves2cwesN, risk = pmax(cvss2.score, cvss3.score))
  cves2cwesN$cvss2.score <- NULL
  cves2cwesN$cvss3.score <- NULL
  cves2cwesN <- apply(cves2cwesN, 1,
                      function(x) {
                        pt <- jsonlite::fromJSON(x[["problem.type"]])
                        cve <- rep(x[["cve.id"]], length(pt))
                        data.frame(src = cve, target = pt, weight = as.numeric(x[["risk"]]),
                                   stringsAsFactors = F)
                      })
  cves2cwesN <- data.table::rbindlist(cves2cwesN)
  # Join edges
  cves2cwes <- dplyr::bind_rows(cves2cwes0, cves2cwes1, cves2cwesN)

  return(cves2cwes)
}

GetRelationCWE2CAPEC <- function() {
  netsec.data$datasets$cwes$Related_Attack_Patterns[is.na(netsec.data$datasets$cwes$Related_Attack_Patterns)] <- "{}"
  c.capec <- sapply(netsec.data$datasets$cwes$Related_Attack_Patterns, function(x) length(jsonlite::fromJSON(x)))
  # One edge
  cwes2capec1 <- netsec.data$datasets$cwes[c.capec == 1, c("Code_Standard", "Related_Attack_Patterns")]
  cwes2capec1$Related_Attack_Patterns <- as.character(sapply(cwes2capec1$Related_Attack_Patterns, function(x) jsonlite::fromJSON(x)))
  names(cwes2capec1) <- c("src", "target")

  # Multiple edges
  cwes2capecN <- netsec.data$datasets$cwes[c.capec > 1, c("Code_Standard", "Related_Attack_Patterns")]
  cwes2capecN <- apply(cwes2capecN, 1,
                       function(x) {
                         capec <- as.character(jsonlite::fromJSON(x[["Related_Attack_Patterns"]]))
                         cwe <- rep(x[["Code_Standard"]], length(capec))
                         data.frame(src = cwe, target = capec, stringsAsFactors = F)
                       })
  cwes2capecN <- data.table::rbindlist(cwes2capecN)
  # Join edges
  cwes2capec <- dplyr::bind_rows(cwes2capec1, cwes2capecN)
  cwes2capec$target <- as.character(sapply(cwes2capec$target, function(x) paste("CAPEC", x, sep = "-")))

  return(cwes2capec)
}

#' Given a net.security CWES data.frame it returns a data.frame prepared for
#' network representation of CWE relationships as edges.
#'
#' @param cwes data.frame, from net.security data sets
#' @param as_numbers if TRUE src and target are numbers, if FALSE as character starting with "CWE-"
#'
#' @return data.frame
GetCWEHierarcy <- function(as_numbers = T) {
  cwes <- GetDataFrame(ds = "cwes")
  cwes.weaknesses <- cwes[cwes$CWE_Type == "Weakness", ]
  cwes.categories <- cwes[cwes$CWE_Type == "Category", ]
  cwes.views <- cwes[cwes$CWE_Type == "View", ]

  # Experimental relationship weight
  relations <- data.frame(from = c("ChildOf", "ParentOf", "StartsWith", "CanFollow", "CanPrecede", "RequiredBy",
                                   "Requires", "CanAlsoBe", "PeerOf", "has_member", "member_of"),
                          to = c("ParentOf", "ChildOf", NA, "CanPrecede", "CanFollow", NA, NA,
                                 "CanAlsoBe", "PeerOf", "member_of", "has_member"),
                          weight = c(3, 3, 5, 4, 4, 7, 7, 5, 1, 5, 5),
                          stringsAsFactors = F)

  # Views hierarchy
  vh <- cwes.views[, c("ID", "Related_Weakness")]
  vh$Related_Weakness[is.na(vh$Related_Weakness)] <- "{}"
  vh <- apply(vh, 1,
              function(x) {
                y <- RJSONIO::fromJSON(x[2])
                if (length(y) > 0) {
                  y <- cbind(as.data.frame(t(as.matrix(as.data.frame(y))), stringsAsFactors = F),
                             data.frame(nature = row.names(as.matrix(y)), stringsAsFactors = F))
                  y$cwe_id <- as.character(y$cwe_id)
                  y$view_id <- as.character(y$view_id)
                  data.table::rbindlist(apply(y, 1,
                                              function(z){
                                                weight <- as.character(dplyr::select(dplyr::filter(relations, from == z[["nature"]]), weight))
                                                data.frame(src = c(x[1], z[["cwe_id"]]),
                                                           target = c(z[["cwe_id"]], x[1]),
                                                           nature = c(z[["nature"]], as.character(dplyr::select(dplyr::filter(relations, from == z[["nature"]]), to))),
                                                           weight = c(weight, weight),
                                                           stringsAsFactors = F)
                                              }
                  ))
                } else {
                  data.frame(src = x[1], target = NA,
                             nature = NA, weight = 0, stringsAsFactors = F)
                }
              }
  )
  vh <- unique(data.table::rbindlist(vh))
  vh <- vh[complete.cases(vh),]
  vh$type <- rep("view", nrow(vh))

  # Categories hierarchy
  ch <- cwes.categories[, c("ID", "Related_Weakness")]
  ch$Related_Weakness[is.na(ch$Related_Weakness)] <- "{}"
  ch <- apply(ch, 1,
              function(x) {
                y <- RJSONIO::fromJSON(x[2])
                if (length(y) > 0) {
                  y <- cbind(as.data.frame(t(as.matrix(as.data.frame(y))), stringsAsFactors = F),
                             data.frame(nature = row.names(as.matrix(y)), stringsAsFactors = F))
                  y$cwe_id <- as.character(y$cwe_id)
                  y$view_id <- as.character(y$view_id)
                  data.table::rbindlist(apply(y, 1,
                                              function(z){
                                                weight <- as.character(dplyr::select(dplyr::filter(relations, from == z[["nature"]]), weight))
                                                data.frame(src = c(x[1], z[["cwe_id"]]),
                                                           target = c(z[["cwe_id"]], x[1]),
                                                           nature = c(z[["nature"]], as.character(dplyr::select(dplyr::filter(relations, from == z[["nature"]]), to))),
                                                           weight = c(weight, weight),
                                                           stringsAsFactors = F)
                                              }
                  ))
                } else {
                  data.frame(src = x[1], target = NA,
                             nature = NA, weight = 0, stringsAsFactors = F)
                }
              }
  )
  ch <- unique(data.table::rbindlist(ch))
  ch <- ch[complete.cases(ch),]
  ch$type <- rep("category", nrow(ch))

  # Weakness hierarchy
  wh <- cwes.weaknesses[, c("ID", "Related_Weakness")]
  wh$Related_Weakness[is.na(wh$Related_Weakness)] <- "{}"
  wh <- apply(wh, 1,
              function(x) {
                y <- RJSONIO::fromJSON(x[2])
                data.table::rbindlist(lapply(y,
                                             function(z) {
                                               weight <- as.character(dplyr::select(dplyr::filter(relations, from == z[["nature"]]), weight))
                                               data.frame(src = c(x[1], z[["cwe_id"]]),
                                                          target = c(z[["cwe_id"]], x[1]),
                                                          nature = c(z[["nature"]], as.character(dplyr::select(dplyr::filter(relations, from == z[["nature"]]), to))),
                                                          weight = c(weight, weight),
                                                          stringsAsFactors = F)
                                             }
                ))

              }
  )
  wh <- unique(data.table::rbindlist(wh))
  wh <- wh[complete.cases(wh),]
  wh$type <- rep("weakness", nrow(wh))

  cwes2cwes <- dplyr::bind_rows(vh, ch, wh)
  cwes2cwes <- dplyr::arrange(cwes2cwes, src)
  if (as_numbers) {
    cwes2cwes$src <- as.numeric(cwes2cwes$src)
    cwes2cwes$target <- as.numeric(cwes2cwes$target)
  } else {
    cwes2cwes$src <- as.character(sapply(cwes2cwes$src, function(x) paste("CWE", x, sep = "-")))
    cwes2cwes$target <- as.character(sapply(cwes2cwes$target, function(x) paste("CWE", x, sep = "-")))
  }
  cwes2cwes$nature <- as.factor(cwes2cwes$nature)
  attributes(cwes2cwes)[[".internal.selfref"]] <- NULL

  return(cwes2cwes)
}

#' References
#' https://christophergandrud.github.io/networkD3/
#' http://kateto.net/networks-r-igraph
#'
