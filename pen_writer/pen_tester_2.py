import socket
import validators
from datetime import datetime
from pathlib import Path


host_output_dir = Path(Path(__file__).resolve().parent.parent, 'temp_outputs')
host_output_path = str(host_output_dir)

host_output_dir.mkdir(parents=True, exist_ok=True)

def scanner(target, output_dir = datetime.today().strftime('%Y_%m_%d_%H_%M_%S')):
    new_folder = Path(host_output_path, output_dir)
    new_folder.mkdir(parents=True, exist_ok=True)
    
    ip_addr = None
    if validators.url(target):
        ip_addr = ip_lookup(target)
        if ip_addr is not None:
            with open( host_output_dir / new_folder / 'ip_scan.txt', 'a') as f:
                f.write(f'{target} ip address is: {ip_addr[0]}')
    else:
        ip_addr = target
        


def ip_lookup(addr):

    ip_list = []
    ais = socket.getaddrinfo(addr, 0,0,0,0)
    for result in ais:
        ip_list.append(result[-1][0])
        ip_list = list(set(ip_list))

    return ip_list

scanner('http://scanme.nmap.org')