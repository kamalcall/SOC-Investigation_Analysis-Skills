import os
import json
import subprocess
import platform
from datetime import datetime

def check_startup_programs():
    """Vérifie les programmes de démarrage"""
    startup_programs = []
    
    if platform.system() == "Windows":
        # Registre Windows - clés de démarrage
        registry_keys = [
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        ]
        
        for key in registry_keys:
            try:
                result = subprocess.run(['reg', 'query', key], 
                                      capture_output=True, text=True, shell=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'REG_SZ' in line or 'REG_EXPAND_SZ' in line:
                            parts = line.strip().split()
                            if len(parts) >= 3:
                                startup_programs.append({
                                    'location': key,
                                    'name': parts[0],
                                    'command': ' '.join(parts[2:]),
                                    'type': 'registry'
                                })
            except Exception as e:
                print(f"Erreur lors de la vérification de {key}: {e}")
        
        # Dossier de démarrage
        startup_folders = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup")
        ]
        
        for folder in startup_folders:
            if os.path.exists(folder):
                for item in os.listdir(folder):
                    item_path = os.path.join(folder, item)
                    startup_programs.append({
                        'location': folder,
                        'name': item,
                        'command': item_path,
                        'type': 'startup_folder'
                    })
    
    else:  # Linux/Unix
        # Fichiers de démarrage automatique
        autostart_dirs = [
            os.path.expanduser("~/.config/autostart"),
            "/etc/xdg/autostart"
        ]
        
        for directory in autostart_dirs:
            if os.path.exists(directory):
                for item in os.listdir(directory):
                    if item.endswith('.desktop'):
                        item_path = os.path.join(directory, item)
                        startup_programs.append({
                            'location': directory,
                            'name': item,
                            'command': item_path,
                            'type': 'autostart'
                        })
    
    return startup_programs

def check_scheduled_tasks():
    """Vérifie les tâches planifiées"""
    scheduled_tasks = []
    
    if platform.system() == "Windows":
        try:
            result = subprocess.run(['schtasks', '/query', '/fo', 'csv', '/v'], 
                                  capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) > 1:
                            scheduled_tasks.append({
                                'name': parts[0].strip('"'),
                                'status': parts[3].strip('"') if len(parts) > 3 else 'Unknown',
                                'command': parts[8].strip('"') if len(parts) > 8 else 'Unknown',
                                'type': 'scheduled_task'
                            })
        except Exception as e:
            print(f"Erreur lors de la vérification des tâches planifiées: {e}")
    
    else:  # Linux/Unix
        # Crontab utilisateur
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        scheduled_tasks.append({
                            'name': 'User Crontab',
                            'command': line.strip(),
                            'type': 'crontab'
                        })
        except Exception:
            pass
        
        # Crontab système
        system_cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', 
                           '/etc/cron.monthly', '/etc/cron.weekly']
        
        for cron_dir in system_cron_dirs:
            if os.path.exists(cron_dir):
                for item in os.listdir(cron_dir):
                    item_path = os.path.join(cron_dir, item)
                    if os.path.isfile(item_path):
                        scheduled_tasks.append({
                            'name': item,
                            'location': cron_dir,
                            'command': item_path,
                            'type': 'system_cron'
                        })
    
    return scheduled_tasks

def check_services():
    """Vérifie les services système"""
    services = []
    
    if platform.system() == "Windows":
        try:
            result = subprocess.run(['sc', 'query'], capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_service = {}
                for line in lines:
                    line = line.strip()
                    if line.startswith('SERVICE_NAME:'):
                        if current_service:
                            services.append(current_service)
                        current_service = {'name': line.split(':', 1)[1].strip(), 'type': 'windows_service'}
                    elif line.startswith('STATE:'):
                        current_service['status'] = line.split(':', 1)[1].strip()
                if current_service:
                    services.append(current_service)
        except Exception as e:
            print(f"Erreur lors de la vérification des services: {e}")
    
    else:  # Linux/Unix
        try:
            # Systemd services
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--no-pager'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip() and not line.startswith('●'):
                        parts = line.split()
                        if len(parts) >= 4:
                            services.append({
                                'name': parts[0],
                                'status': parts[2],
                                'description': ' '.join(parts[4:]),
                                'type': 'systemd_service'
                            })
        except Exception:
            pass
    
    return services

def check_browser_extensions():
    """Vérifie les extensions de navigateur (basique)"""
    extensions = []
    
    if platform.system() == "Windows":
        # Chrome extensions
        chrome_ext_path = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions")
        if os.path.exists(chrome_ext_path):
            for ext_id in os.listdir(chrome_ext_path):
                ext_path = os.path.join(chrome_ext_path, ext_id)
                if os.path.isdir(ext_path):
                    extensions.append({
                        'browser': 'Chrome',
                        'id': ext_id,
                        'path': ext_path,
                        'type': 'browser_extension'
                    })
        
        # Firefox extensions
        firefox_profiles = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
        if os.path.exists(firefox_profiles):
            for profile in os.listdir(firefox_profiles):
                ext_path = os.path.join(firefox_profiles, profile, "extensions")
                if os.path.exists(ext_path):
                    for ext in os.listdir(ext_path):
                        extensions.append({
                            'browser': 'Firefox',
                            'id': ext,
                            'path': os.path.join(ext_path, ext),
                            'type': 'browser_extension'
                        })
    
    return extensions

def analyze_persistence_mechanisms():
    """Analyse complète des mécanismes de persistance"""
    print("=== Détection des Mécanismes de Persistance ===")
    
    analysis_results = {
        'timestamp': datetime.now().isoformat(),
        'startup_programs': [],
        'scheduled_tasks': [],
        'services': [],
        'browser_extensions': []
    }
    
    # Programmes de démarrage
    print("\n1. Vérification des programmes de démarrage...")
    startup_programs = check_startup_programs()
    analysis_results['startup_programs'] = startup_programs
    print(f"   Trouvé: {len(startup_programs)} programmes de démarrage")
    
    # Tâches planifiées
    print("\n2. Vérification des tâches planifiées...")
    scheduled_tasks = check_scheduled_tasks()
    analysis_results['scheduled_tasks'] = scheduled_tasks
    print(f"   Trouvé: {len(scheduled_tasks)} tâches planifiées")
    
    # Services
    print("\n3. Vérification des services...")
    services = check_services()
    analysis_results['services'] = services
    print(f"   Trouvé: {len(services)} services")
    
    # Extensions de navigateur
    print("\n4. Vérification des extensions de navigateur...")
    browser_extensions = check_browser_extensions()
    analysis_results['browser_extensions'] = browser_extensions
    print(f"   Trouvé: {len(browser_extensions)} extensions")
    
    return analysis_results

def identify_suspicious_persistence(analysis_results):
    """Identifie les mécanismes de persistance suspects"""
    suspicious_items = []
    
    # Mots-clés suspects
    suspicious_keywords = ['temp', 'tmp', 'download', 'appdata', 'roaming', 'powershell', 'cmd', 'wscript', 'cscript']
    
    # Vérifier les programmes de démarrage
    for program in analysis_results['startup_programs']:
        command = program.get('command', '').lower()
        if any(keyword in command for keyword in suspicious_keywords):
            program['suspicious'] = True
            program['reason'] = 'Commande suspecte'
            suspicious_items.append(program)
    
    # Vérifier les tâches planifiées
    for task in analysis_results['scheduled_tasks']:
        command = task.get('command', '').lower()
        if any(keyword in command for keyword in suspicious_keywords):
            task['suspicious'] = True
            task['reason'] = 'Commande suspecte'
            suspicious_items.append(task)
    
    return suspicious_items

if __name__ == "__main__":
    # Analyse complète
    results = analyze_persistence_mechanisms()
    
    # Identification des éléments suspects
    suspicious = identify_suspicious_persistence(results)
    
    # Affichage des résultats
    print(f"\n=== Résumé de l'Analyse ===")
    print(f"Programmes de démarrage: {len(results['startup_programs'])}")
    print(f"Tâches planifiées: {len(results['scheduled_tasks'])}")
    print(f"Services: {len(results['services'])}")
    print(f"Extensions de navigateur: {len(results['browser_extensions'])}")
    print(f"Éléments suspects: {len(suspicious)}")
    
    if suspicious:
        print(f"\n=== Éléments Suspects Détectés ===")
        for item in suspicious:
            print(f"Type: {item['type']}")
            print(f"Nom: {item['name']}")
            print(f"Commande: {item.get('command', 'N/A')}")
            print(f"Raison: {item['reason']}")
            print("-" * 60)
    
    # Sauvegarde
    with open('persistence_analysis.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nAnalyse sauvegardée dans persistence_analysis.json")

