Tâches automatisables de 'SOC Investigation & Analysis Skills':

**Niveau Basique:**

* **Triage/Évaluation Initial du Système:**

  * Collecte d'informations système de base (version de l'OS, nom d'hôte, services en cours d'exécution).
  * Vérification des journaux système pour des entrées suspectes.

* **Analyse des Processus en Cours:**

  * Liste des processus en cours d'exécution et leurs détails (PID, PID parent, utilisateur, chemin, ligne de commande).
  * Vérification de la réputation des processus par rapport aux sources de renseignement sur les menaces.
  * Identification des relations parent-enfant inhabituelles entre les processus.

* **Évaluation des Connexions Réseau:**

  * Liste des connexions réseau actives.
  * Résolution des adresses IP en noms d'hôte.
  * Vérification des connexions par rapport aux adresses IP/domaines malveillants connus.
  * Identification des connexions sortantes inhabituelles.

**Niveau Intermédiaire:**

* **Analyse Approfondie du Système:**

  * Collecte d'informations système plus détaillées.

* **Analyse du Registre:**

  * Exportation de ruches ou de clés de registre spécifiques.
  * Recherche d'entrées de registre suspectes (par exemple, clés Run, BHOs, services).

* **Investigation du Système de Fichiers:**

  * Liste des fichiers dans les répertoires critiques (par exemple, Program Files, Windows, Temp).
  * Calcul des hachages de fichiers (MD5, SHA256) pour la vérification de la réputation.
  * Identification des fichiers récemment modifiés ou créés.
  * Recherche de types de fichiers spécifiques (par exemple, exécutables, scripts).

* **Analyse de l'Activité Utilisateur:**

  * Collecte des événements de connexion/déconnexion des utilisateurs.
  * Analyse des fichiers ou programmes récemment accédés.

**Niveau Avancé:**

* **Analyse Légale Avancée:**

  * L'analyse des dumps mémoire est plus complexe et implique des outils spécialisés plutôt que de simples scripts, mais la collecte de dumps mémoire peut être scriptée.

* **Analyse Légale PowerShell:**

  * Utilisation de PowerShell pour des tâches d'investigation avancées (sera abordé dans la section PowerShell).

* **Détection des Mécanismes de Persistance:**

  * Identification des points de persistance courants (par exemple, tâches planifiées, services, WMI, clés de registre).

* **Détection Avancée des Menaces:**

  * Intégration avec des API de renseignement sur les menaces pour la corrélation des données.

* **Analyse Approfondie de la Mémoire et des Processus:**

  * Collecte d'informations détaillées sur la mémoire des processus (peut être partiellement scriptée).

* **Vérification de l'Intégrité du Système:**

Vérification de l'intégrité des fichiers système critiques.




les scripts Python et PowerShell que j'ai développés en me basant sur le document que vous avez fourni. Chaque script est conçu pour automatiser des tâches spécifiques d'investigation et d'analyse SOC.


Scripts Python :

system\_info.py: Collecte les informations système de base (OS, hostname, adresses IP, temps de démarrage).

process\_analysis.py: Analyse les processus en cours d'exécution, y compris le calcul des hachages de fichiers et l'identification des processus suspects.

network\_analysis.py: Examine les connexions réseau actives, les interfaces et détecte les connexions potentiellement malveillantes.

file\_system\_analysis.py: Analyse les répertoires critiques, identifie les fichiers récemment modifiés et les fichiers suspects.

persistence\_detection.py: Détecte les mécanismes de persistance courants (programmes de démarrage, tâches planifiées, services, extensions de navigateur).



Scripts PowerShell :

Get-SystemInfo.ps1: Collecte les informations système de base (similaire au script Python).

Get-ProcessAnalysis.ps1: Analyse les processus en cours d'exécution et identifie les processus suspects (similaire au script Python).

Get-NetworkAnalysis.ps1: Examine les connexions réseau actives et identifie les connexions suspectes (similaire au script Python).

Get-RegistryAnalysis.ps1: Analyse les clés de registre critiques pour détecter les modifications suspectes (spécifique à Windows).

Get-PersistenceAnalysis.ps1: Détecte les mécanismes de persistance (tâches planifiées, services, WMI, extensions de navigateur) (spécifique à Windows).

