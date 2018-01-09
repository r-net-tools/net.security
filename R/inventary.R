SoftwareCheck <- function(){
  return("")
}

GetWindowsSoftware <- function(savepath = tempdir()){
  if (.Platform$OS.type == "windows") {
    # Windows with powershell
    system("powershell.exe \"Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-List\"", intern = T)
    system("powershell.exe \"Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-List\"", intern = T)
    system("powershell.exe \"Get-WmiObject Win32_Product | Sort-Object Name | Format-List Name, Version, Vendor\"", intern = T)
  }


}
