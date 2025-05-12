# Analyse-Log
Powershell wrapper for wevtutil for small-scale log search and aggregation

This can be used to leverage wectutil.exe either locally or remotely within an AD domain. It queries logs and can aggregate them, summarise or provide in a raw powershell custom object for further manipulation. Wevtutil.exe is preferred over Get-WineEvent given how slow the latter is. 
