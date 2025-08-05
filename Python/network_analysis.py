import psutil
import socket
import requests
import json
from datetime import datetime

def get_network_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            proc = psutil.Process(conn.pid) if conn.pid else None
            conn_info = {
                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                'status': conn.status,
                'pid': conn.pid,
                'process_name': proc.name() if proc else "N/A",
                'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            }
            
            # Résolution DNS inverse pour les adresses distantes
            if conn.raddr:
                try:
                    hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
                    conn_info['remote_hostname'] = hostname
                except (socket.herror, socket.gaierror):
                    conn_info['remote_hostname'] = "N/A"
            else:
                conn_info['remote_hostname'] = "N/A"
            
            connections.append(conn_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    return connections

def check_malicious_ips(connections):
    """
    Vérifie les IPs contre une liste de domaines/IPs malveillants connus
    Note: Dans un environnement réel, vous utiliseriez des API de threat intelligence
    """
    suspicious_domains = ['malware.com', 'badsite.net', 'evil.org']
    suspicious_ips = ['192.168.1.100', '10.0.0.50']  # Exemples
    
    flagged = []
    for conn in connections:
        if conn['remote_address'] != "N/A":
            remote_ip = conn['remote_address'].split(':')[0]
            if (remote_ip in suspicious_ips or 
                conn['remote_hostname'] != "N/A" and 
                any(domain in conn['remote_hostname'] for domain in suspicious_domains)):
                flagged.append(conn)
    
    return flagged

def get_network_interfaces():
    interfaces = {}
    for interface, addrs in psutil.net_if_addrs().items():
        interfaces[interface] = []
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interfaces[interface].append({
                    'ip': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                })
    return interfaces

if __name__ == "__main__":
    print("=== Analyse des Connexions Réseau ===")
    
    # Interfaces réseau
    print("\n=== Interfaces Réseau ===")
    interfaces = get_network_interfaces()
    for interface, addrs in interfaces.items():
        print(f"Interface: {interface}")
        for addr in addrs:
            print(f"  IP: {addr['ip']}, Masque: {addr['netmask']}")
    
    # Connexions actives
    print("\n=== Connexions Actives ===")
    connections = get_network_connections()
    
    for conn in connections:
        print(f"Local: {conn['local_address']} -> Remote: {conn['remote_address']}")
        print(f"Status: {conn['status']}, Type: {conn['type']}, PID: {conn['pid']}")
        print(f"Processus: {conn['process_name']}, Hostname: {conn['remote_hostname']}")
        print("-" * 60)
    
    # Connexions suspectes
    suspicious = check_malicious_ips(connections)
    if suspicious:
        print(f"\n=== Connexions Suspectes Détectées ({len(suspicious)}) ===")
        for conn in suspicious:
            print(f"ALERTE: {conn['local_address']} -> {conn['remote_address']}")
            print(f"Processus: {conn['process_name']} (PID: {conn['pid']})")
    
    # Statistiques réseau
    net_io = psutil.net_io_counters()
    print(f"\n=== Statistiques Réseau ===")
    print(f"Octets envoyés: {net_io.bytes_sent:,}")
    print(f"Octets reçus: {net_io.bytes_recv:,}")
    print(f"Paquets envoyés: {net_io.packets_sent:,}")
    print(f"Paquets reçus: {net_io.packets_recv:,}")
    
    # Sauvegarde
    analysis_data = {
        'timestamp': datetime.now().isoformat(),
        'interfaces': interfaces,
        'connections': connections,
        'suspicious_connections': suspicious,
        'network_stats': {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
    }
    
    with open('network_analysis.json', 'w') as f:
        json.dump(analysis_data, f, indent=2)
    print(f"\nAnalyse sauvegardée dans network_analysis.json")

