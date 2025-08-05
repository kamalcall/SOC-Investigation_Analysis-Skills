
<#
.SYNOPSIS
    Collecte des informations système de base.
.DESCRIPTION
    Ce script collecte des informations essentielles sur le système, y compris le nom de l'ordinateur,
    le système d'exploitation, l'architecture, le temps de démarrage et les adresses IP.
.OUTPUTS
    PSCustomObject. Un objet contenant les informations système.
.NOTES
    Nécessite des privilèges d'administrateur pour certaines informations.
#>
function Get-SystemInfo {
    [CmdletBinding()]
    Param()

    $OSInfo = Get-ComputerInfo -Property OsName, OsVersion, OsBuildNumber, OsArchitecture
    $ComputerName = $env:COMPUTERNAME
    $BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $IPAddresses = @((Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress) -join ", ")

    $SystemInfo = [PSCustomObject]@{ 
        ComputerName = $ComputerName
        OSName = $OSInfo.OsName
        OSVersion = $OSInfo.OsVersion
        OSBuild = $OSInfo.OsBuildNumber
        OSArchitecture = $OSInfo.OsArchitecture
        BootTime = $BootTime
        IPAddresses = $IPAddresses
    }

    Write-Output $SystemInfo
}

# Exécution du script si appelé directement
if ($PSScriptRoot) {
    Get-SystemInfo
}


