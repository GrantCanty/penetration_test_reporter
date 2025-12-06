import socket
import validators
from datetime import datetime
from pathlib import Path
import subprocess
from IPy import IP
import xml.etree.ElementTree as ET


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

    #nmap_A_file_name = 'nmap_A_scan_output.xml'
    #nmap_A_file_path = f'{host_output_dir / new_folder / nmap_A_file_name}'
    nmap_A_file_path = '/Users/cheoso/ai_projects/tw3_internship/temp_outputs/2025_12_06_17_41_09/nmap_A_scan_output.xml'
    #print(['nmap', '-A', '-oX', f'{host_output_dir / new_folder / nmap_A_output_file}', ip_addr])
    #nmamp_A = subprocess.run(['nmap', '-A', '-oX', nmap_A_file_path, ip_addr], capture_output=True, check=True, text=True)
    open_ports = xml_scan(nmap_A_file_path)
    #print(open_ports)
    for port in open_ports:
        print(port, open_ports[port])
        


def ip_lookup(addr):

    ip_list = []
    ais = socket.getaddrinfo(addr, 0,0,0,0)
    for result in ais:
        ip_list.append(result[-1][0])
        ip_list = list(set(ip_list))

    return ip_list[0]


def xml_scan(xml_file_path):
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    host_elm = root.find('host')

    ports = {}

    if host_elm is not None:
        address = host_elm.find('address').get('addr')
        print(address)
        ports_element = host_elm.find('ports')
        if ports_element is not None:
            
            for port_elm in ports_element.findall('port'):
                state = port_elm.find('state').get('state')

                if state == 'open':
                    port_id = port_elm.get('portid')
                    protocol = port_elm.get('protocol')

                    serivce_elm = port_elm.find('service')
                    service_name = serivce_elm.get('name')
                    product = serivce_elm.get('product', 'N/A')
                    version = serivce_elm.get('version', 'N/A')

                    ports[port_id] = {'protocol': protocol, 'service': service_name, 'product': product, 'version': version}
            
    return ports

scanner('http://scanme.nmap.org')