import psutil
import os
import hashlib
import json
from datetime import datetime

def get_process_info():
    processes = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'exe', 'cmdline', 'create_time', 'memory_info', 'cpu_percent']):
        try:
            proc_info = proc.info
            proc_info['create_time'] = datetime.fromtimestamp(proc_info['create_time']).strftime("%Y-%m-%d %H:%M:%S")
            
            # Calcul du hash du fichier exécutable si possible
            if proc_info['exe']:
                try:
                    with open(proc_info['exe'], 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    proc_info['file_hash'] = file_hash
                except (PermissionError, FileNotFoundError):
                    proc_info['file_hash'] = "N/A"
            else:
                proc_info['file_hash'] = "N/A"
            
            processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return processes

def find_suspicious_processes(processes):
    suspicious = []
    for proc in processes:
        # Critères de suspicion
        if proc['name'] and (
            proc['name'].lower() in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'] or
            proc['exe'] and 'temp' in proc['exe'].lower() or
            proc['cmdline'] and any(keyword in ' '.join(proc['cmdline']).lower() for keyword in ['download', 'invoke', 'base64', 'encoded'])
        ):
            suspicious.append(proc)
    return suspicious

if __name__ == "__main__":
    print("=== Analyse des Processus ===")
    processes = get_process_info()
    
    print(f"\nNombre total de processus: {len(processes)}")
    
    # Affichage des processus
    for proc in processes:
        print(f"\nPID: {proc['pid']}, PPID: {proc['ppid']}, Nom: {proc['name']}")
        print(f"Utilisateur: {proc['username']}, Exécutable: {proc['exe']}")
        print(f"Ligne de commande: {' '.join(proc['cmdline']) if proc['cmdline'] else 'N/A'}")
        print(f"Hash: {proc['file_hash']}")
        print("-" * 80)
    
    # Processus suspects
    suspicious = find_suspicious_processes(processes)
    if suspicious:
        print(f"\n=== Processus Suspects Détectés ({len(suspicious)}) ===")
        for proc in suspicious:
            print(f"PID: {proc['pid']}, Nom: {proc['name']}, Exécutable: {proc['exe']}")
    
    # Sauvegarde en JSON
    with open('process_analysis.json', 'w') as f:
        json.dump(processes, f, indent=2)
    print(f"\nAnalyse sauvegardée dans process_analysis.json")

