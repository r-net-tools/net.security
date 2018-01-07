SoftwareCheck <- function(){
  return("")
}

GetWindowsSoftware <- function(){
  # Windows with powershell
  # Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize > .\ps.softwarelist.csv
  # Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize > .\ps.softwarelist2.csv
  # Get-WmiObject Win32_Product | Sort-Object Name | Format-Table Name, Version, Vendor -AutoSize > .\ps.softwarelist3.csv
}
