<#
.SYNOPSIS
    Menu principal pour exécuter les scripts d'analyse SOC.
.DESCRIPTION
    Ce script définit temporairement la politique d'exécution à 'Bypass' pour la session en cours,
    affiche un menu des scripts PowerShell disponibles dans le même répertoire, et exécute le script choisi par l'utilisateur.
.NOTES
    Doit être exécuté avec des privilèges d'administrateur pour que 'Set-ExecutionPolicy' fonctionne correctement.
#>

function Show-MainMenu {
    Write-Host "" # Ligne vide pour l'espacement
    Write-Host "=== Menu d'Exécution des Scripts SOC ===" -ForegroundColor Green
    Write-Host "--------------------------------------" -ForegroundColor Green
    
    # Obtenir la liste des scripts .ps1 dans le répertoire actuel
    $scripts = Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" | Where-Object { $_.Name -ne "Run-MAIN_MENU.ps1" } | Select-Object -ExpandProperty Name
    
    if ($scripts.Count -eq 0) {
        Write-Warning "Aucun script PowerShell (.ps1) trouvé dans le répertoire actuel (à l'exception de ce script)."
        Write-Host "Assurez-vous que les scripts sont dans le même dossier que Run-MAIN_MENU.ps1."
        return
    }
    
    Write-Host "Scripts disponibles :" -ForegroundColor Yellow
    for ($i = 0; $i -lt $scripts.Count; $i++) {
        Write-Host "$($i + 1). $($scripts[$i])"
    }
    Write-Host "0. Quitter"
    Write-Host "--------------------------------------" -ForegroundColor Green
    
    $choice = Read-Host "Entrez le numéro du script à exécuter (0 pour quitter)"
    
    if ($choice -eq "0") {
        Write-Host "Exécution annulée. Au revoir !" -ForegroundColor Cyan
        return
    }
    
    if ($choice -match "^\d+$" -and $choice -ge 1 -and $choice -le $scripts.Count) {
        $selectedScript = $scripts[$choice - 1]
        Write-Host "" # Ligne vide pour l'espacement
        Write-Host "Lancement de '$selectedScript' ..." -ForegroundColor Cyan
        Write-Host "" # Ligne vide pour l'espacement
        
        # Exécuter le script sélectionné
        # Utilisation de '&' (opérateur d'appel) pour exécuter le script par son chemin complet
        & "$PSScriptRoot\$selectedScript"
        
        Write-Host "" # Ligne vide pour l'espacement
        Write-Host "'$selectedScript' a terminé son exécution." -ForegroundColor Green
        Write-Host "Appuyez sur une touche pour continuer..." -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-MainMenu # Revenir au menu après l'exécution
    } else {
        Write-Warning "Choix invalide. Veuillez entrer un numéro valide."
        Show-MainMenu # Revenir au menu en cas de choix invalide
    }
}

# --- Début de l'exécution du script principal ---

# 1. Définir la politique d'exécution pour la session actuelle
Write-Host "Définition de la politique d'exécution à 'Bypass' pour cette session..." -ForegroundColor Yellow
try {
    Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
    Write-Host "Politique d'exécution définie avec succès." -ForegroundColor Green
} catch {
    Write-Error "Impossible de définir la politique d'exécution. Assurez-vous d'exécuter ce script en tant qu'administrateur."
    Write-Error "Erreur: $($_.Exception.Message)"
    Write-Host "Appuyez sur une touche pour quitter..." -ForegroundColor Red
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# 2. Afficher le menu principal
Show-MainMenu

# --- Fin de l'exécution du script principal ---
