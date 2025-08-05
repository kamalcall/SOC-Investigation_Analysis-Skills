<#
.SYNOPSIS
    Liste les applications configurées pour un lancement automatique au démarrage du système d'exploitation.
.DESCRIPTION
    Ce script examine les clés de registre Run et RunOnce pour HKEY_LOCAL_MACHINE et HKEY_CURRENT_USER
    afin d'identifier les programmes qui se lancent automatiquement au démarrage de Windows.
.OUTPUTS
    PSCustomObject[]. Un tableau d'objets contenant les informations sur les programmes de démarrage automatique.
.NOTES
    Nécessite des privilèges d'administrateur pour accéder à toutes les clés de registre HKLM.
    Fonctionne uniquement sur Windows.
#>
[CmdletBinding()]
Param()

function Get-AutoRunPrograms {
    Write-Host "=== Analyse des Programmes de Démarrage Automatique ===" -ForegroundColor Green
    
    if ($PSVersionTable.Platform -eq "Unix") {
        Write-Error "Ce script fonctionne uniquement sur Windows."
        return
    }
    
    $autoRunEntries = @()
    
    # Définition des clés de registre Run et RunOnce à analyser
    $registryKeys = @(
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Description = "Programmes de démarrage (Machine)"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Description = "Programmes de démarrage unique (Machine)"
        },
        @{
            Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Description = "Programmes de démarrage (Utilisateur)"
        },
        @{
            Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Description = "Programmes de démarrage unique (Utilisateur)"
        },
        @{
            Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
            Description = "Programmes de démarrage (Machine, 32-bit)"
        },
        @{
            Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
            Description = "Programmes de démarrage unique (Machine, 32-bit)"
        }
    )
    
    foreach ($keyInfo in $registryKeys) {
        Write-Host "`nAnalyse de: $($keyInfo.Description)" -ForegroundColor Yellow
        Write-Host "Chemin: $($keyInfo.Path)" -ForegroundColor Gray
        
        try {
            if (Test-Path $keyInfo.Path) {
                $items = Get-ItemProperty -Path $keyInfo.Path -ErrorAction SilentlyContinue
                if ($items) {
                    $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                        $autoRunEntries += [PSCustomObject]@{
                            Location = $keyInfo.Path
                            Name = $_.Name
                            Command = $_.Value
                            Type = "Registry"
                        }
                    }
                }
                Write-Host "Trouvé: $($items.PSObject.Properties.Count - 2) entrées" -ForegroundColor Cyan # -2 pour exclure PSPath et PSParentPath
            }
            else {
                Write-Host "Chemin de registre non trouvé: $($keyInfo.Path)" -ForegroundColor DarkGray
            }
        }
        catch {
            Write-Warning "Erreur lors de l'accès à $($keyInfo.Path) : $($_.Exception.Message)"
        }
    }
    
    Write-Host "`n=== Résumé de l'Analyse ===" -ForegroundColor Green
    Write-Host "Total des programmes de démarrage automatique trouvés: $($autoRunEntries.Count)" -ForegroundColor Yellow
    
    if ($autoRunEntries.Count -gt 0) {
        Write-Host "`n=== Détails des Programmes de Démarrage Automatique ===" -ForegroundColor Cyan
        $autoRunEntries | Format-Table -AutoSize
    }
    
    # Vous pouvez également sauvegarder les résultats dans un fichier JSON si vous le souhaitez
    # $autoRunEntries | ConvertTo-Json -Depth 3 | Out-File -FilePath "auto_run_programs.json" -Encoding UTF8
    # Write-Host "`nAnalyse sauvegardée dans auto_run_programs.json" -ForegroundColor Green
    
    return $autoRunEntries
}

# Exécution du script si appelé directement
if ($PSScriptRoot) {
    Get-AutoRunPrograms
}


