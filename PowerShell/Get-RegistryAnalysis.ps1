<#
.SYNOPSIS
    Analyse les clés de registre critiques pour détecter les modifications suspectes.
.DESCRIPTION
    Ce script examine les clés de registre importantes pour la sécurité, notamment les clés de démarrage,
    les services, et autres emplacements couramment utilisés par les malwares.
.PARAMETER OutputPath
    Chemin de sortie pour le fichier JSON (optionnel).
.OUTPUTS
    PSCustomObject[]. Un tableau d'objets contenant les informations du registre.
.NOTES
    Nécessite des privilèges d'administrateur pour accéder à certaines clés de registre.
    Fonctionne uniquement sur Windows.
#>
[CmdletBinding()]
Param(
    [string]$OutputPath = "registry_analysis.json"
)

function Get-RegistryValues {
    param(
        [string]$RegistryPath,
        [string]$Description
    )
    
    $values = @()
    
    try {
        if (Test-Path $RegistryPath) {
            $key = Get-Item -Path $RegistryPath -ErrorAction SilentlyContinue
            if ($key) {
                foreach ($valueName in $key.GetValueNames()) {
                    try {
                        $value = $key.GetValue($valueName)
                        $valueInfo = [PSCustomObject]@{
                            RegistryPath = $RegistryPath
                            Description = $Description
                            ValueName = $valueName
                            ValueData = $value
                            ValueType = $key.GetValueKind($valueName)
                            LastWriteTime = $key.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        $values += $valueInfo
                    }
                    catch {
                        Write-Warning "Erreur lors de la lecture de la valeur $valueName dans $RegistryPath"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erreur lors de l'accès à $RegistryPath : $($_.Exception.Message)"
    }
    
    return $values
}

function Test-SuspiciousRegistryEntry {
    param(
        [PSCustomObject]$RegistryEntry
    )
    
    $suspiciousKeywords = @("temp", "tmp", "download", "appdata", "powershell", "cmd", "wscript", "cscript", "base64", "encoded")
    $suspiciousExtensions = @(".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr")
    
    $reasons = @()
    
    # Vérifier les mots-clés suspects dans les données de valeur
    if ($RegistryEntry.ValueData) {
        $valueDataLower = $RegistryEntry.ValueData.ToString().ToLower()
        
        foreach ($keyword in $suspiciousKeywords) {
            if ($valueDataLower -like "*$keyword*") {
                $reasons += "Mot-clé suspect: $keyword"
            }
        }
        
        foreach ($extension in $suspiciousExtensions) {
            if ($valueDataLower -like "*$extension*") {
                $reasons += "Extension suspecte: $extension"
            }
        }
        
        # Vérifier les chemins suspects
        if ($valueDataLower -match "(\\temp\\|\\tmp\\|\\downloads\\|\\appdata\\)") {
            $reasons += "Chemin suspect"
        }
        
        # Vérifier les URLs suspectes
        if ($valueDataLower -match "http[s]?://") {
            $reasons += "URL détectée"
        }
    }
    
    return $reasons
}

function Get-RegistryAnalysis {
    [CmdletBinding()]
    Param()

    Write-Host "=== Analyse du Registre Windows ===" -ForegroundColor Green
    
    if ($PSVersionTable.Platform -eq "Unix") {
        Write-Error "Ce script fonctionne uniquement sur Windows."
        return
    }
    
    $allRegistryEntries = @()
    $suspiciousEntries = @()
    
    # Définition des clés de registre critiques à analyser
    $criticalKeys = @(
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Description = "Programmes de démarrage automatique (Machine)"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Description = "Programmes de démarrage unique (Machine)"
        },
        @{
            Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Description = "Programmes de démarrage automatique (Utilisateur)"
        },
        @{
            Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Description = "Programmes de démarrage unique (Utilisateur)"
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services"
            Description = "Services système"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            Description = "Configuration de connexion Windows"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
            Description = "Objets d'aide du navigateur (BHO)"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
            Description = "Extensions shell approuvées"
        },
        @{
            Path = "HKLM:\SOFTWARE\Classes\exefile\shell\open\command"
            Description = "Association de fichiers .exe"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            Description = "Options d'exécution des fichiers image"
        }
    )
    
    # Analyse de chaque clé critique
    foreach ($keyInfo in $criticalKeys) {
        Write-Host "`nAnalyse de: $($keyInfo.Description)" -ForegroundColor Yellow
        Write-Host "Chemin: $($keyInfo.Path)" -ForegroundColor Gray
        
        $registryValues = Get-RegistryValues -RegistryPath $keyInfo.Path -Description $keyInfo.Description
        $allRegistryEntries += $registryValues
        
        Write-Host "Trouvé: $($registryValues.Count) entrées" -ForegroundColor Cyan
        
        # Vérifier les entrées suspectes
        foreach ($entry in $registryValues) {
            $suspiciousReasons = Test-SuspiciousRegistryEntry -RegistryEntry $entry
            
            if ($suspiciousReasons.Count -gt 0) {
                $entry | Add-Member -MemberType NoteProperty -Name "SuspiciousReasons" -Value ($suspiciousReasons -join ", ")
                $suspiciousEntries += $entry
            }
        }
    }
    
    # Analyse spéciale des services
    Write-Host "`n=== Analyse Détaillée des Services ===" -ForegroundColor Yellow
    $services = @()
    try {
        Get-Service | ForEach-Object {
            $service = $_
            $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
            
            if (Test-Path $servicePath) {
                try {
                    $serviceKey = Get-ItemProperty -Path $servicePath -ErrorAction SilentlyContinue
                    if ($serviceKey) {
                        $serviceInfo = [PSCustomObject]@{
                            ServiceName = $service.Name
                            DisplayName = $service.DisplayName
                            Status = $service.Status
                            StartType = $service.StartType
                            ImagePath = $serviceKey.ImagePath
                            Description = $serviceKey.Description
                            ObjectName = $serviceKey.ObjectName
                        }
                        $services += $serviceInfo
                        
                        # Vérifier les services suspects
                        if ($serviceKey.ImagePath) {
                            $imagePathLower = $serviceKey.ImagePath.ToLower()
                            if ($imagePathLower -match "(temp|tmp|downloads|appdata)" -or 
                                $imagePathLower -match "\.(bat|cmd|ps1|vbs|js)") {
                                $serviceInfo | Add-Member -MemberType NoteProperty -Name "Suspicious" -Value $true
                                $serviceInfo | Add-Member -MemberType NoteProperty -Name "SuspiciousReason" -Value "Chemin d'image suspect"
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Erreur lors de l'analyse du service $($service.Name)"
                }
            }
        }
    }
    catch {
        Write-Warning "Erreur lors de l'énumération des services: $($_.Exception.Message)"
    }
    
    # Affichage des résultats
    Write-Host "`n=== Résumé de l'Analyse ===" -ForegroundColor Green
    Write-Host "Total des entrées de registre analysées: $($allRegistryEntries.Count)" -ForegroundColor Yellow
    Write-Host "Entrées suspectes détectées: $($suspiciousEntries.Count)" -ForegroundColor Yellow
    Write-Host "Services analysés: $($services.Count)" -ForegroundColor Yellow
    
    if ($suspiciousEntries.Count -gt 0) {
        Write-Host "`n=== Entrées de Registre Suspectes ===" -ForegroundColor Red
        $suspiciousEntries | ForEach-Object {
            Write-Host "ALERTE: $($_.RegistryPath)" -ForegroundColor Red
            Write-Host "Valeur: $($_.ValueName) = $($_.ValueData)" -ForegroundColor Yellow
            Write-Host "Raisons: $($_.SuspiciousReasons)" -ForegroundColor Yellow
            Write-Host "Dernière modification: $($_.LastWriteTime)" -ForegroundColor Gray
            Write-Host ("-" * 80)
        }
    }
    
    # Services suspects
    $suspiciousServices = $services | Where-Object { $_.Suspicious -eq $true }
    if ($suspiciousServices.Count -gt 0) {
        Write-Host "`n=== Services Suspects ===" -ForegroundColor Red
        $suspiciousServices | ForEach-Object {
            Write-Host "Service: $($_.ServiceName) ($($_.DisplayName))" -ForegroundColor Red
            Write-Host "Chemin: $($_.ImagePath)" -ForegroundColor Yellow
            Write-Host "Raison: $($_.SuspiciousReason)" -ForegroundColor Yellow
            Write-Host ("-" * 60)
        }
    }
    
    # Sauvegarde des résultats
    $analysisData = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        TotalRegistryEntries = $allRegistryEntries.Count
        SuspiciousRegistryEntries = $suspiciousEntries.Count
        TotalServices = $services.Count
        SuspiciousServices = $suspiciousServices.Count
        RegistryEntries = $allRegistryEntries
        SuspiciousRegistryEntriesList = $suspiciousEntries
        Services = $services
        SuspiciousServicesList = $suspiciousServices
    }
    
    $analysisData | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`nAnalyse sauvegardée dans $OutputPath" -ForegroundColor Green
    
    return $allRegistryEntries
}

# Exécution du script si appelé directement
if ($PSScriptRoot) {
    Get-RegistryAnalysis
}

