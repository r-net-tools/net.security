# References: https://www.mitre.org/publications/technical-papers/mitre-attack-design-and-philosophy

GetATTCKData <- function(savepath = tempdir(), verbose = T) {
  if (verbose) print("Downloading raw data from MITRE...")
  attck.files <- DownloadATTCKData(savepath, verbose)
  if (verbose) print("Processing ATT&CK raw data...")
  attck <- ParseATTCKData(attck.files, verbose)
  if (verbose) print(paste("ATT&CK data frame building process finished."))
  return(attck)
}

DownloadATTCKData <- function(savepath, verbose) {
  # Download ATT&CK matrix

  # Download Tactics raw data

  # Download Techniques raw data

  # Download Groups raw data

  # Download Software raw data

}

ParseATTCKData <- function(attck.files, verbose) {
  matrix <- ParseMatrix()
  tactics <- ParseTactics()
  techniques <- ParseTechniques()
  groups <- ParseGroups()
  software <- ParseSoftware()

  attck <- list(matrix, tactics, techniques, groups, software)
  return(attck)
}

ParseMatrix <- function() {
  m.pre.url <- "https://attack.mitre.org/pre-attack/index.php/Main_Page"
  m.ent.all <- "https://attack.mitre.org/wiki/Main_Page"
  m.ent.win <- "https://attack.mitre.org/wiki/Windows_Technique_Matrix"
  m.ent.mac <- "https://attack.mitre.org/wiki/Mac_Technique_Matrix"
  m.ent.lnx <- "https://attack.mitre.org/wiki/Linux_Technique_Matrix"
  m.mobile  <- "https://attack.mitre.org/mobile/index.php/Main_Page"

  matrix <- list(m.pre.url, m.ent.all, m.ent.win, m.ent.mac, m.ent.lnx, m.mobile)

  return(matrix)
}

ParseTactics <- function() {
  tactics.url <- "https://attack.mitre.org/wiki/All_Techniques"
  tactics.url <- "https://attack.mitre.org/wiki/Category:Technique"

  tactics <- data.frame()

  return(tactics)
}

ParseTechniques <- function() {
  techniques.url <- "https://attack.mitre.org/wiki/All_Techniques"

  techniques <- data.frame()

  return(techniques)
}

ParseGroups <- function() {
  groups.url <- "https://attack.mitre.org/wiki/Groups"

  groups <- data.frame()

  return(groups)

}

ParseSoftware <- function() {
  software.url <- "https://attack.mitre.org/wiki/Software"

  software <- data.frame()

  return(software)
}
