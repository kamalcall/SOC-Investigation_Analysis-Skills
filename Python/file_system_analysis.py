import os
import hashlib
import time
import json
from datetime import datetime, timedelta
from pathlib import Path

def calculate_file_hash(filepath, algorithm='sha256'):
    """Calcule le hash d'un fichier"""
    hash_func = hashlib.new(algorithm)
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return "N/A"

def scan_directory(directory, extensions=None, max_depth=3, current_depth=0):
    """Scanne un répertoire et retourne les informations des fichiers"""
    files_info = []
    
    if current_depth > max_depth:
        return files_info
    
    try:
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            
            if os.path.isfile(item_path):
                # Filtrer par extensions si spécifié
                if extensions and not any(item_path.lower().endswith(ext) for ext in extensions):
                    continue
                
                try:
                    stat_info = os.stat(item_path)
                    file_info = {
                        'path': item_path,
                        'name': item,
                        'size': stat_info.st_size,
                        'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                        'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                        'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                        'hash_sha256': calculate_file_hash(item_path),
                        'extension': os.path.splitext(item)[1].lower()
                    }
                    files_info.append(file_info)
                except (PermissionError, OSError):
                    pass
            
            elif os.path.isdir(item_path) and current_depth < max_depth:
                # Récursion dans les sous-répertoires
                files_info.extend(scan_directory(item_path, extensions, max_depth, current_depth + 1))
    
    except (PermissionError, OSError):
        pass
    
    return files_info

def find_recently_modified_files(files_info, hours=24):
    """Trouve les fichiers modifiés récemment"""
    cutoff_time = datetime.now() - timedelta(hours=hours)
    recent_files = []
    
    for file_info in files_info:
        try:
            modified_time = datetime.fromisoformat(file_info['modified'])
            if modified_time > cutoff_time:
                recent_files.append(file_info)
        except ValueError:
            pass
    
    return recent_files

def find_suspicious_files(files_info):
    """Identifie les fichiers potentiellement suspects"""
    suspicious_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr']
    suspicious_locations = ['temp', 'tmp', 'downloads', 'appdata']
    
    suspicious_files = []
    
    for file_info in files_info:
        is_suspicious = False
        reasons = []
        
        # Extension suspecte
        if file_info['extension'] in suspicious_extensions:
            is_suspicious = True
            reasons.append(f"Extension suspecte: {file_info['extension']}")
        
        # Emplacement suspect
        path_lower = file_info['path'].lower()
        for location in suspicious_locations:
            if location in path_lower:
                is_suspicious = True
                reasons.append(f"Emplacement suspect: {location}")
                break
        
        # Fichier très récent (moins d'1 heure)
        try:
            created_time = datetime.fromisoformat(file_info['created'])
            if datetime.now() - created_time < timedelta(hours=1):
                is_suspicious = True
                reasons.append("Fichier très récent")
        except ValueError:
            pass
        
        # Taille inhabituelle (très petit ou très gros)
        if file_info['size'] < 1024 or file_info['size'] > 100 * 1024 * 1024:  # < 1KB ou > 100MB
            is_suspicious = True
            reasons.append(f"Taille inhabituelle: {file_info['size']} bytes")
        
        if is_suspicious:
            file_info['suspicious_reasons'] = reasons
            suspicious_files.append(file_info)
    
    return suspicious_files

def analyze_critical_directories():
    """Analyse les répertoires critiques du système"""
    if os.name == 'nt':  # Windows
        critical_dirs = [
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Program Files',
            'C:\\Program Files (x86)',
            'C:\\Users\\Public',
            'C:\\Temp',
            'C:\\Windows\\Temp'
        ]
    else:  # Unix/Linux
        critical_dirs = [
            '/bin',
            '/sbin',
            '/usr/bin',
            '/usr/sbin',
            '/tmp',
            '/var/tmp',
            '/home',
            '/etc'
        ]
    
    all_files = []
    for directory in critical_dirs:
        if os.path.exists(directory):
            print(f"Analyse du répertoire: {directory}")
            files = scan_directory(directory, max_depth=2)
            all_files.extend(files)
    
    return all_files

if __name__ == "__main__":
    print("=== Analyse du Système de Fichiers ===")
    
    # Analyse des répertoires critiques
    print("\nAnalyse des répertoires critiques...")
    all_files = analyze_critical_directories()
    
    print(f"\nNombre total de fichiers analysés: {len(all_files)}")
    
    # Fichiers récemment modifiés
    recent_files = find_recently_modified_files(all_files, hours=24)
    print(f"\nFichiers modifiés dans les dernières 24h: {len(recent_files)}")
    
    if recent_files:
        print("\n=== Fichiers Récemment Modifiés ===")
        for file_info in recent_files[:10]:  # Afficher les 10 premiers
            print(f"Fichier: {file_info['path']}")
            print(f"Modifié: {file_info['modified']}")
            print(f"Taille: {file_info['size']} bytes")
            print("-" * 60)
    
    # Fichiers suspects
    suspicious_files = find_suspicious_files(all_files)
    print(f"\nFichiers suspects détectés: {len(suspicious_files)}")
    
    if suspicious_files:
        print("\n=== Fichiers Suspects ===")
        for file_info in suspicious_files:
            print(f"ALERTE: {file_info['path']}")
            print(f"Raisons: {', '.join(file_info['suspicious_reasons'])}")
            print(f"Hash: {file_info['hash_sha256']}")
            print("-" * 60)
    
    # Statistiques par extension
    extensions_count = {}
    for file_info in all_files:
        ext = file_info['extension'] or 'sans_extension'
        extensions_count[ext] = extensions_count.get(ext, 0) + 1
    
    print("\n=== Statistiques par Extension ===")
    for ext, count in sorted(extensions_count.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{ext}: {count} fichiers")
    
    # Sauvegarde des résultats
    analysis_data = {
        'timestamp': datetime.now().isoformat(),
        'total_files': len(all_files),
        'recent_files': recent_files,
        'suspicious_files': suspicious_files,
        'extensions_stats': extensions_count,
        'all_files': all_files[:1000]  # Limiter pour éviter des fichiers trop volumineux
    }
    
    with open('filesystem_analysis.json', 'w') as f:
        json.dump(analysis_data, f, indent=2)
    print(f"\nAnalyse sauvegardée dans filesystem_analysis.json")

