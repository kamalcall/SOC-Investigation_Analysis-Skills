<#
.SYNOPSIS
    Analyse les connexions réseau actives et identifie les connexions suspectes.
.DESCRIPTION
    Ce script collecte des informations sur les connexions réseau actives, les interfaces réseau,
    et identifie les connexions potentiellement malveillantes.
.PARAMETER OutputPath
    Chemin de sortie pour le fichier JSON (optionnel).
.OUTPUTS
    PSCustomObject[]. Un tableau d'objets contenant les informations des connexions réseau.
.NOTES
    Nécessite des privilèges d'administrateur pour certaines informations.
#>
[CmdletBinding()]
Param(
    [string]$OutputPath = "network_analysis.json"
)

function Resolve-IPAddress {
    param([string]$IPAddress)
    
    try {
        $hostname = [System.Net.Dns]::GetHostEntry($IPAddress).HostName
        return $hostname
    }
    catch {
        return "N/A"
    }
}

function Test-SuspiciousConnection {
    param(
        [string]$RemoteAddress,
        [string]$RemoteHostname,
        [string]$ProcessName
    )
    
    $suspiciousIPs = @("192.168.1.100", "10.0.0.50")  # Exemples d'IPs suspectes
    $suspiciousDomains = @("malware.com", "badsite.net", "evil.org")  # Exemples de domaines suspects
    $suspiciousProcesses = @("cmd", "powershell", "wscript", "cscript")
    
    $reasons = @()
    
    if ($RemoteAddress -in $suspiciousIPs) {
        $reasons += "IP suspecte"
    }
    
    if ($RemoteHostname -ne "N/A") {
        foreach ($domain in $suspiciousDomains) {
            if ($RemoteHostname -like "*$domain*") {
                $reasons += "Domaine suspect"
                break
            }
        }
    }
    
    if ($ProcessName -in $suspiciousProcesses) {
        $reasons += "Processus suspect"
    }
    
    # Connexions vers des ports inhabituels
    if ($RemoteAddress -and $RemoteAddress -match ":(\d+)$") {
        $port = [int]$matches[1]
        if ($port -in @(4444, 5555, 6666, 7777, 8888, 9999)) {
            $reasons += "Port suspect"
        }
    }
    
    return $reasons
}

function Get-NetworkAnalysis {
    [CmdletBinding()]
    Param()

    Write-Host "=== Analyse des Connexions Réseau ===" -ForegroundColor Green
    
    # Collecte des interfaces réseau
    Write-Host "`n=== Interfaces Réseau ===" -ForegroundColor Yellow
    $networkInterfaces = @()
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | ForEach-Object {
        $interface = [PSCustomObject]@{
            InterfaceAlias = $_.InterfaceAlias
            IPAddress = $_.IPAddress
            PrefixLength = $_.PrefixLength
            AddressState = $_.AddressState
        }
        $networkInterfaces += $interface
        Write-Host "Interface: $($_.InterfaceAlias), IP: $($_.IPAddress)/$($_.PrefixLength)" -ForegroundColor Cyan
    }
    
    # Collecte des connexions actives
    Write-Host "`n=== Connexions Actives ===" -ForegroundColor Yellow
    $connections = @()
    $suspiciousConnections = @()
    
    Get-NetTCPConnection | ForEach-Object {
        try {
            $conn = $_
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            
            $localAddress = "$($conn.LocalAddress):$($conn.LocalPort)"
            $remoteAddress = if ($conn.RemoteAddress -ne "0.0.0.0") { "$($conn.RemoteAddress):$($conn.RemotePort)" } else { "N/A" }
            
            # Résolution DNS pour les adresses distantes
            $remoteHostname = "N/A"
            if ($conn.RemoteAddress -ne "0.0.0.0" -and $conn.RemoteAddress -ne "::") {
                $remoteHostname = Resolve-IPAddress -IPAddress $conn.RemoteAddress
            }
            
            $connectionInfo = [PSCustomObject]@{
                LocalAddress = $localAddress
                RemoteAddress = $remoteAddress
                State = $conn.State
                PID = $conn.OwningProcess
                ProcessName = if ($process) { $process.ProcessName } else { "N/A" }
                ProcessPath = if ($process) { $process.Path } else { "N/A" }
                RemoteHostname = $remoteHostname
                CreationTime = $conn.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            $connections += $connectionInfo
            
            # Vérification des connexions suspectes
            $suspiciousReasons = Test-SuspiciousConnection -RemoteAddress $remoteAddress -RemoteHostname $remoteHostname -ProcessName $connectionInfo.ProcessName
            
            if ($suspiciousReasons.Count -gt 0) {
                $connectionInfo | Add-Member -MemberType NoteProperty -Name "SuspiciousReasons" -Value ($suspiciousReasons -join ", ")
                $suspiciousConnections += $connectionInfo
            }
            
            Write-Host "Local: $localAddress -> Remote: $remoteAddress" -ForegroundColor White
            Write-Host "État: $($conn.State), Processus: $($connectionInfo.ProcessName) (PID: $($conn.OwningProcess))" -ForegroundColor Gray
            if ($remoteHostname -ne "N/A") {
                Write-Host "Hostname: $remoteHostname" -ForegroundColor Gray
            }
            Write-Host ("-" * 60)
        }
        catch {
            Write-Warning "Erreur lors de l'analyse de la connexion: $($_.Exception.Message)"
        }
    }
    
    # Connexions UDP
    Write-Host "`n=== Connexions UDP ===" -ForegroundColor Yellow
    Get-NetUDPEndpoint | ForEach-Object {
        try {
            $udp = $_
            $process = Get-Process -Id $udp.OwningProcess -ErrorAction SilentlyContinue
            
            $connectionInfo = [PSCustomObject]@{
                LocalAddress = "$($udp.LocalAddress):$($udp.LocalPort)"
                RemoteAddress = "N/A"
                State = "UDP"
                PID = $udp.OwningProcess
                ProcessName = if ($process) { $process.ProcessName } else { "N/A" }
                ProcessPath = if ($process) { $process.Path } else { "N/A" }
                RemoteHostname = "N/A"
                CreationTime = $udp.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            $connections += $connectionInfo
            
            Write-Host "UDP Local: $($connectionInfo.LocalAddress), Processus: $($connectionInfo.ProcessName)" -ForegroundColor White
        }
        catch {
            Write-Warning "Erreur lors de l'analyse de la connexion UDP: $($_.Exception.Message)"
        }
    }
    
    # Affichage des connexions suspectes
    if ($suspiciousConnections.Count -gt 0) {
        Write-Host "`n=== Connexions Suspectes Détectées ($($suspiciousConnections.Count)) ===" -ForegroundColor Red
        $suspiciousConnections | ForEach-Object {
            Write-Host "ALERTE: $($_.LocalAddress) -> $($_.RemoteAddress)" -ForegroundColor Red
            Write-Host "Processus: $($_.ProcessName) (PID: $($_.PID))" -ForegroundColor Yellow
            Write-Host "Raisons: $($_.SuspiciousReasons)" -ForegroundColor Yellow
            Write-Host ("-" * 60)
        }
    }
    
    # Statistiques réseau
    Write-Host "`n=== Statistiques Réseau ===" -ForegroundColor Yellow
    $netStats = Get-NetAdapterStatistics | Measure-Object -Property BytesReceived, BytesSent -Sum
    Write-Host "Total octets reçus: $($netStats[0].Sum.ToString("N0"))" -ForegroundColor Cyan
    Write-Host "Total octets envoyés: $($netStats[1].Sum.ToString("N0"))" -ForegroundColor Cyan
    
    # Sauvegarde des résultats
    $analysisData = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        NetworkInterfaces = $networkInterfaces
        TotalConnections = $connections.Count
        SuspiciousConnections = $suspiciousConnections.Count
        Connections = $connections
        SuspiciousConnectionsList = $suspiciousConnections
        NetworkStatistics = @{
            BytesReceived = $netStats[0].Sum
            BytesSent = $netStats[1].Sum
        }
    }
    
    $analysisData | ConvertTo-Json -Depth 3 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`nAnalyse sauvegardée dans $OutputPath" -ForegroundColor Green
    
    return $connections
}

# Exécution du script si appelé directement
if ($PSScriptRoot) {
    Get-NetworkAnalysis
}


