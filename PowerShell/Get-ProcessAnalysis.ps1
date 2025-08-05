<#
.SYNOPSIS
    Analyse les processus en cours d'exécution et identifie les processus suspects.
.DESCRIPTION
    Ce script collecte des informations détaillées sur tous les processus en cours d'exécution,
    calcule les hachages des fichiers exécutables et identifie les processus potentiellement suspects.
.PARAMETER OutputPath
    Chemin de sortie pour le fichier JSON (optionnel).
.OUTPUTS
    PSCustomObject[]. Un tableau d'objets contenant les informations des processus.
.NOTES
    Nécessite des privilèges d'administrateur pour accéder à certains processus.
#>
[CmdletBinding()]
Param(
    [string]$OutputPath = "process_analysis.json"
)

function Get-FileHash256 {
    param([string]$FilePath)
    
    try {
        if (Test-Path $FilePath) {
            $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
            return $hash.Hash
        }
    }
    catch {
        return "N/A"
    }
    return "N/A"
}

function Get-ProcessAnalysis {
    [CmdletBinding()]
    Param()

    Write-Host "=== Analyse des Processus ===" -ForegroundColor Green
    
    $processes = @()
    $suspiciousProcesses = @()
    
    # Collecte des informations sur tous les processus
    Get-Process | ForEach-Object {
        try {
            $proc = $_
            $processInfo = [PSCustomObject]@{
                PID = $proc.Id
                PPID = if ($proc.Parent) { $proc.Parent.Id } else { "N/A" }
                Name = $proc.ProcessName
                Path = if ($proc.Path) { $proc.Path } else { "N/A" }
                CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                StartTime = if ($proc.StartTime) { $proc.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                WorkingSet = [math]::Round($proc.WorkingSet / 1MB, 2)
                CPUTime = $proc.TotalProcessorTime.TotalSeconds
                FileHash = Get-FileHash256 -FilePath $proc.Path
                Company = if ($proc.Company) { $proc.Company } else { "N/A" }
                Description = if ($proc.Description) { $proc.Description } else { "N/A" }
            }
            
            $processes += $processInfo
            
            # Détection de processus suspects
            $isSuspicious = $false
            $suspiciousReasons = @()
            
            # Critères de suspicion
            if ($proc.ProcessName -match "^(cmd|powershell|wscript|cscript|mshta)$") {
                $isSuspicious = $true
                $suspiciousReasons += "Processus d'interpréteur"
            }
            
            if ($proc.Path -and $proc.Path -match "(temp|tmp|downloads|appdata)") {
                $isSuspicious = $true
                $suspiciousReasons += "Emplacement suspect"
            }
            
            if ($processInfo.CommandLine -and $processInfo.CommandLine -match "(download|invoke|base64|encoded|bypass)") {
                $isSuspicious = $true
                $suspiciousReasons += "Ligne de commande suspecte"
            }
            
            if ($proc.Company -eq $null -or $proc.Company -eq "") {
                $isSuspicious = $true
                $suspiciousReasons += "Pas d'informations sur l'éditeur"
            }
            
            if ($isSuspicious) {
                $processInfo | Add-Member -MemberType NoteProperty -Name "SuspiciousReasons" -Value ($suspiciousReasons -join ", ")
                $suspiciousProcesses += $processInfo
            }
        }
        catch {
            Write-Warning "Erreur lors de l'analyse du processus $($proc.ProcessName): $($_.Exception.Message)"
        }
    }
    
    # Affichage des résultats
    Write-Host "`nNombre total de processus: $($processes.Count)" -ForegroundColor Yellow
    
    if ($suspiciousProcesses.Count -gt 0) {
        Write-Host "`n=== Processus Suspects Détectés ($($suspiciousProcesses.Count)) ===" -ForegroundColor Red
        $suspiciousProcesses | ForEach-Object {
            Write-Host "PID: $($_.PID), Nom: $($_.Name), Chemin: $($_.Path)" -ForegroundColor Red
            Write-Host "Raisons: $($_.SuspiciousReasons)" -ForegroundColor Yellow
            Write-Host "Hash: $($_.FileHash)" -ForegroundColor Cyan
            Write-Host ("-" * 80)
        }
    }
    
    # Sauvegarde en JSON
    $analysisData = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        TotalProcesses = $processes.Count
        SuspiciousProcesses = $suspiciousProcesses.Count
        Processes = $processes
        SuspiciousProcessesList = $suspiciousProcesses
    }
    
    $analysisData | ConvertTo-Json -Depth 3 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`nAnalyse sauvegardée dans $OutputPath" -ForegroundColor Green
    
    return $processes
}

# Exécution du script si appelé directement
if ($PSScriptRoot) {
    Get-ProcessAnalysis
}

