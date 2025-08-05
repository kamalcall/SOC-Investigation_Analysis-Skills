<#
.SYNOPSIS
    Détecte les mécanismes de persistance couramment utilisés par les malwares.
.DESCRIPTION
    Ce script analyse les différents mécanismes de persistance sur un système Windows,
    incluant les tâches planifiées, les services, les clés de registre, et les WMI event consumers.
.PARAMETER OutputPath
    Chemin de sortie pour le fichier JSON (optionnel).
.OUTPUTS
    PSCustomObject. Un objet contenant tous les mécanismes de persistance détectés.
.NOTES
    Nécessite des privilèges d'administrateur pour une analyse complète.
    Fonctionne uniquement sur Windows.
#>
[CmdletBinding()]
Param(
    [string]$OutputPath = "persistence_analysis.json"
)

function Get-StartupPrograms {
    Write-Host "Analyse des programmes de démarrage..." -ForegroundColor Yellow
    
    $startupPrograms = @()
    
    # Clés de registre de démarrage
    $registryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($key in $registryKeys) {
        if (Test-Path $key) {
            try {
                $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($items) {
                    $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                        $startupPrograms += [PSCustomObject]@{
                            Location = $key
                            Name = $_.Name
                            Command = $_.Value
                            Type = "Registry"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Erreur lors de l'accès à $key"
            }
        }
    }
    
    # Dossiers de démarrage
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Get-ChildItem -Path $folder | ForEach-Object {
                $startupPrograms += [PSCustomObject]@{
                    Location = $folder
                    Name = $_.Name
                    Command = $_.FullName
                    Type = "StartupFolder"
                }
            }
        }
    }
    
    return $startupPrograms
}

function Get-ScheduledTasksAnalysis {
    Write-Host "Analyse des tâches planifiées..." -ForegroundColor Yellow
    
    $scheduledTasks = @()
    
    try {
        Get-ScheduledTask | ForEach-Object {
            $task = $_
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            
            if ($task.Actions) {
                foreach ($action in $task.Actions) {
                    $scheduledTasks += [PSCustomObject]@{
                        TaskName = $task.TaskName
                        TaskPath = $task.TaskPath
                        State = $task.State
                        Author = $task.Author
                        Description = $task.Description
                        Execute = $action.Execute
                        Arguments = $action.Arguments
                        WorkingDirectory = $action.WorkingDirectory
                        LastRunTime = if ($taskInfo) { $taskInfo.LastRunTime } else { "N/A" }
                        NextRunTime = if ($taskInfo) { $taskInfo.NextRunTime } else { "N/A" }
                        Type = "ScheduledTask"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erreur lors de l'analyse des tâches planifiées: $($_.Exception.Message)"
    }
    
    return $scheduledTasks
}

function Get-ServicesAnalysis {
    Write-Host "Analyse des services..." -ForegroundColor Yellow
    
    $services = @()
    
    Get-Service | ForEach-Object {
        $service = $_
        $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        
        if (Test-Path $servicePath) {
            try {
                $serviceKey = Get-ItemProperty -Path $servicePath -ErrorAction SilentlyContinue
                $services += [PSCustomObject]@{
                    ServiceName = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status
                    StartType = $service.StartType
                    ImagePath = $serviceKey.ImagePath
                    Description = $serviceKey.Description
                    ObjectName = $serviceKey.ObjectName
                    Type = "Service"
                }
            }
            catch {
                Write-Warning "Erreur lors de l'analyse du service $($service.Name)"
            }
        }
    }
    
    return $services
}

function Get-WMIEventConsumers {
    Write-Host "Analyse des WMI Event Consumers..." -ForegroundColor Yellow
    
    $wmiConsumers = @()
    
    try {
        # Event Consumers
        Get-WmiObject -Namespace "root\subscription" -Class "__EventConsumer" -ErrorAction SilentlyContinue | ForEach-Object {
            $wmiConsumers += [PSCustomObject]@{
                Name = $_.Name
                Class = $_.Class
                ConsumerType = $_.PSObject.TypeNames[0]
                Type = "WMIEventConsumer"
            }
        }
        
        # Event Filters
        Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" -ErrorAction SilentlyContinue | ForEach-Object {
            $wmiConsumers += [PSCustomObject]@{
                Name = $_.Name
                Query = $_.Query
                QueryLanguage = $_.QueryLanguage
                Type = "WMIEventFilter"
            }
        }
        
        # Filter to Consumer Bindings
        Get-WmiObject -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -ErrorAction SilentlyContinue | ForEach-Object {
            $wmiConsumers += [PSCustomObject]@{
                Filter = $_.Filter
                Consumer = $_.Consumer
                Type = "WMIFilterToConsumerBinding"
            }
        }
    }
    catch {
        Write-Warning "Erreur lors de l'analyse des WMI Event Consumers: $($_.Exception.Message)"
    }
    
    return $wmiConsumers
}

function Get-BrowserExtensions {
    Write-Host "Analyse des extensions de navigateur..." -ForegroundColor Yellow
    
    $extensions = @()
    
    # Chrome Extensions
    $chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    if (Test-Path $chromeExtPath) {
        Get-ChildItem -Path $chromeExtPath -Directory | ForEach-Object {
            $extensions += [PSCustomObject]@{
                Browser = "Chrome"
                ExtensionID = $_.Name
                Path = $_.FullName
                Type = "BrowserExtension"
            }
        }
    }
    
    # Firefox Extensions
    $firefoxProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfiles) {
        Get-ChildItem -Path $firefoxProfiles -Directory | ForEach-Object {
            $extPath = Join-Path $_.FullName "extensions"
            if (Test-Path $extPath) {
                Get-ChildItem -Path $extPath | ForEach-Object {
                    $extensions += [PSCustomObject]@{
                        Browser = "Firefox"
                        ExtensionID = $_.Name
                        Path = $_.FullName
                        Type = "BrowserExtension"
                    }
                }
            }
        }
    }
    
    return $extensions
}

function Test-SuspiciousPersistence {
    param([PSCustomObject]$Item)
    
    $suspiciousKeywords = @("temp", "tmp", "download", "appdata", "powershell", "cmd", "wscript", "cscript", "base64", "encoded", "bypass")
    $suspiciousExtensions = @(".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr")
    
    $reasons = @()
    
    # Vérifier la commande/chemin
    $commandToCheck = ""
    if ($Item.Command) { $commandToCheck = $Item.Command }
    elseif ($Item.Execute) { $commandToCheck = $Item.Execute }
    elseif ($Item.ImagePath) { $commandToCheck = $Item.ImagePath }
    
    if ($commandToCheck) {
        $commandLower = $commandToCheck.ToLower()
        
        foreach ($keyword in $suspiciousKeywords) {
            if ($commandLower -like "*$keyword*") {
                $reasons += "Mot-clé suspect: $keyword"
            }
        }
        
        foreach ($extension in $suspiciousExtensions) {
            if ($commandLower -like "*$extension*") {
                $reasons += "Extension suspecte: $extension"
            }
        }
        
        if ($commandLower -match "(\\temp\\|\\tmp\\|\\downloads\\|\\appdata\\)") {
            $reasons += "Chemin suspect"
        }
    }
    
    # Vérifier les noms suspects
    if ($Item.Name -and $Item.Name -match "(update|security|system|microsoft|windows)" -and $Item.Type -ne "Service") {
        $reasons += "Nom potentiellement trompeur"
    }
    
    return $reasons
}

function Get-PersistenceAnalysis {
    [CmdletBinding()]
    Param()

    Write-Host "=== Détection des Mécanismes de Persistance ===" -ForegroundColor Green
    
    if ($PSVersionTable.Platform -eq "Unix") {
        Write-Error "Ce script fonctionne uniquement sur Windows."
        return
    }
    
    # Collecte de tous les mécanismes de persistance
    $startupPrograms = Get-StartupPrograms
    $scheduledTasks = Get-ScheduledTasksAnalysis
    $services = Get-ServicesAnalysis
    $wmiConsumers = Get-WMIEventConsumers
    $browserExtensions = Get-BrowserExtensions
    
    # Analyse des éléments suspects
    $allItems = @()
    $allItems += $startupPrograms
    $allItems += $scheduledTasks
    $allItems += $services
    $allItems += $wmiConsumers
    $allItems += $browserExtensions
    
    $suspiciousItems = @()
    
    foreach ($item in $allItems) {
        $suspiciousReasons = Test-SuspiciousPersistence -Item $item
        
        if ($suspiciousReasons.Count -gt 0) {
            $item | Add-Member -MemberType NoteProperty -Name "SuspiciousReasons" -Value ($suspiciousReasons -join ", ")
            $suspiciousItems += $item
        }
    }
    
    # Affichage des résultats
    Write-Host "`n=== Résumé de l'Analyse ===" -ForegroundColor Green
    Write-Host "Programmes de démarrage: $($startupPrograms.Count)" -ForegroundColor Yellow
    Write-Host "Tâches planifiées: $($scheduledTasks.Count)" -ForegroundColor Yellow
    Write-Host "Services: $($services.Count)" -ForegroundColor Yellow
    Write-Host "WMI Event Consumers: $($wmiConsumers.Count)" -ForegroundColor Yellow
    Write-Host "Extensions de navigateur: $($browserExtensions.Count)" -ForegroundColor Yellow
    Write-Host "Éléments suspects: $($suspiciousItems.Count)" -ForegroundColor Red
    
    if ($suspiciousItems.Count -gt 0) {
        Write-Host "`n=== Mécanismes de Persistance Suspects ===" -ForegroundColor Red
        $suspiciousItems | ForEach-Object {
            Write-Host "ALERTE: $($_.Type) - $($_.Name)" -ForegroundColor Red
            if ($_.Command) { Write-Host "Commande: $($_.Command)" -ForegroundColor Yellow }
            if ($_.Execute) { Write-Host "Exécute: $($_.Execute)" -ForegroundColor Yellow }
            if ($_.ImagePath) { Write-Host "Chemin: $($_.ImagePath)" -ForegroundColor Yellow }
            Write-Host "Raisons: $($_.SuspiciousReasons)" -ForegroundColor Yellow
            Write-Host ("-" * 80)
        }
    }
    
    # Sauvegarde des résultats
    $analysisData = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Summary = @{
            StartupPrograms = $startupPrograms.Count
            ScheduledTasks = $scheduledTasks.Count
            Services = $services.Count
            WMIEventConsumers = $wmiConsumers.Count
            BrowserExtensions = $browserExtensions.Count
            SuspiciousItems = $suspiciousItems.Count
        }
        StartupPrograms = $startupPrograms
        ScheduledTasks = $scheduledTasks
        Services = $services
        WMIEventConsumers = $wmiConsumers
        BrowserExtensions = $browserExtensions
        SuspiciousItems = $suspiciousItems
    }
    
    $analysisData | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`nAnalyse sauvegardée dans $OutputPath" -ForegroundColor Green
    
    return $analysisData
}

# Exécution du script si appelé directement
if ($PSScriptRoot) {
    Get-PersistenceAnalysis
}

