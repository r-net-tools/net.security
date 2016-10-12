#!/usr/bin/env Rscript
# Load required packages
list.of.packages <- c("net.security", "plumber")
new.packages <- list.of.packages[!(list.of.packages %in% installed.packages()[,"Package"])]
if(length(new.packages)) install.packages(new.packages)
library("net.security")
library("plumber")

# Define path
api.functions <- paste("R", "ddsecuriy.R", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
# Define api server
api.server <- plumber::plumb(api.functions)
# Run API server
api.server$run(port = 8000)
