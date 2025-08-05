
import platform
import socket
import psutil
import datetime

def get_system_info():
    system_info = {
        "OS": platform.system(),
        "OS_Release": platform.release(),
        "OS_Version": platform.version(),
        "Architecture": platform.machine(),
        "Hostname": socket.gethostname(),
        "IP_Addresses": [addr.address for addr in psutil.net_if_addrs().get('Ethernet', []) if addr.family == socket.AF_INET],
        "Boot_Time": datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    }
    return system_info

if __name__ == "__main__":
    info = get_system_info()
    for key, value in info.items():
        print(f"{key}: {value}")


