import socket
import validators
from datetime import datetime
from pathlib import Path
import subprocess
from IPy import IP


host_output_dir = Path(Path(__file__).resolve().parent.parent, 'temp_outputs')
host_output_path = str(host_output_dir)

host_output_dir.mkdir(parents=True, exist_ok=True)

def IPValidation(target):
    try:
        IP(target)
        return True
    except Exception as e:
        return False

def scanner(target, output_dir = datetime.today().strftime('%Y_%m_%d_%H_%M_%S')):
    new_folder = Path(host_output_path, output_dir)
    new_folder.mkdir(parents=True, exist_ok=True)
    
    ip_addr = None
    if validators.url(target):
        ip_addr = ip_lookup(target)
        if ip_addr is not None:
            with open( host_output_dir / new_folder / 'ip_scan.txt', 'a') as f:
                f.write(f'{target} ip address is: {ip_addr}')
    elif IPValidation(target):
        ip_addr = target
    else:
        print(f'target given is not valid: {target}')
        return

    nmap_A_output_file = 'nmap_A_scan_output.xml'
    print(['nmap', '-A', '-oX', f'{host_output_dir / new_folder / nmap_A_output_file}', ip_addr])
    nmamp_A = subprocess.run(['nmap', '-A', '-oX', f'{host_output_dir / new_folder / nmap_A_output_file}', ip_addr], capture_output=True, check=True, text=True)
        


def ip_lookup(addr):

    ip_list = []
    ais = socket.getaddrinfo(addr, 0,0,0,0)
    for result in ais:
        ip_list.append(result[-1][0])
        ip_list = list(set(ip_list))

    return ip_list[0]

scanner('http://scanme.nmap.org')