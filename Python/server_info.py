#!/usr/bin/env python3

import subprocess
import json
import platform
import os
from datetime import datetime

def run_cmd(cmd):
    """Exécute une commande shell et retourne la sortie."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout.strip() if result.returncode == 0 else ""
    except:
        return ""

def get_system_info():
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "distro": run_cmd("lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME=' | cut -d'=' -f2 || echo 'Inconnue'"),
        "kernel": run_cmd("uname -r"),
        "uptime": run_cmd("uptime -p"),
        "current_user": run_cmd("whoami"),
    }

def service_status(service):
    active = run_cmd(f"systemctl is-active {service}")
    enabled = run_cmd(f"systemctl is-enabled {service}")
    return {
        "installed": "oui" if active or enabled else "non",
        "active": active if active in ['active', 'inactive', 'failed'] else "non",
        "enabled": enabled if enabled in ['enabled', 'disabled'] else "non"
    }

def check_binary_and_service(name, service_hint=None):
    """Vérifie si un logiciel est installé (via binaire) et son statut service."""
    service = service_hint or name
    binary_path = run_cmd(f"which {name}")
    installed = bool(binary_path)
    status = service_status(service) if installed else {"installed": "non", "active": "non", "enabled": "non"}
    return {
        "installed": "oui" if installed else "non",
        "binary_path": binary_path if installed else "N/A",
        "version": run_cmd(f"{name} --version | head -n1") if installed else "N/A",
        "service": status
    }

def get_web_servers():
    return {
        "apache": check_binary_and_service("apache2", "apache2"),
        "nginx": check_binary_and_service("nginx", "nginx"),
        "lighttpd": check_binary_and_service("lighttpd", "lighttpd")
    }

def get_databases():
    return {
        "mysql": check_binary_and_service("mysql", "mysql"),
        "mariadb": check_binary_and_service("mariadb", "mariadb"),
        "postgresql": check_binary_and_service("psql", "postgresql"),
        "mongodb": check_binary_and_service("mongod", "mongod"),
        "redis": check_binary_and_service("redis-server", "redis-server"),
        "sqlite3": {
            "installed": "oui" if run_cmd("which sqlite3") else "non",
            "version": run_cmd("sqlite3 --version") or "N/A"
        }
    }

def get_open_ports():
    # Détecte les ports web et DB courants
    common_ports = "22,80,443,3306,5432,27017,6379"
    cmd = f"ss -tulnp | grep -E ':{common_ports.split(',')[0]}'"
    for port in common_ports.split(",")[1:]:
        cmd += f" || ss -tulnp | grep ':{port}'"
    
    raw = run_cmd(cmd)
    lines = [line.strip() for line in raw.split('\n') if line.strip()]
    
    services = []
    for line in lines:
        parts = line.split()
        proto = parts[0]
        local = parts[4]
        pid_name = parts[-1] if '/' in parts[-1] else "inconnu"
        services.append(f"{proto} {local} → {pid_name}")
    
    return {
        "detected_ports": common_ports,
        "open_services": services if services else ["Aucun service détecté sur les ports clés"]
    }

def get_website_info():
    # Vérifie si un serveur web écoute sur 80/443
    listening = run_cmd("ss -tuln | grep -E ':80 |:443 '")
    apache_sites = run_cmd("ls /etc/apache2/sites-enabled/ 2>/dev/null | grep .conf") if os.path.exists("/etc/apache2/sites-enabled/") else "N/A"
    nginx_sites = run_cmd("ls /etc/nginx/sites-enabled/ 2>/dev/null | grep -v default") if os.path.exists("/etc/nginx/sites-enabled/") else "N/A"

    return {
        "http_https_listening": bool(listening),
        "listening_details": listening if listening else "Aucun",
        "apache_vhosts": apache_sites.split() if apache_sites != "N/A" and "No such file" not in apache_sites else [],
        "nginx_vhosts": nginx_sites.split() if nginx_sites != "N/A" and "No such file" not in nginx_sites else []
    }

def get_disk_memory():
    return {
        "disk_root": run_cmd("df -h / | tail -n1"),
        "memory": run_cmd("free -h | grep Mem")
    }

def main():
    report = {
        "audit_generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "server_summary": get_system_info(),
        "web_servers": get_web_servers(),
        "databases": get_databases(),
        "network": {
            "open_ports_and_services": get_open_ports(),
            "web_server_status": get_website_info()
        },
        "system_resources": get_disk_memory()
    }

    # Affichage JSON
    print(json.dumps(report, indent=2, ensure_ascii=False))

    # Sauvegarde
    filename = "server_audit_report.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n✅ Rapport complet sauvegardé dans '{filename}'")

if __name__ == "__main__":
    main()
