import socket
import validators
from datetime import datetime
from pathlib import Path
import subprocess
from IPy import IP
import xml.etree.ElementTree as ET

from pen_writer import (
    TARGET_ERROR, RESPONSE_ERROR, SUCCESS, __app_name__
)

# create temp_outputs folder path for logging results
host_output_dir = Path(Path(__file__).resolve().parent.parent, 'temp_outputs')
host_output_path = str(host_output_dir)

# create temp_outputs folder if it does not exist
host_output_dir.mkdir(parents=True, exist_ok=True)

# checks to see if target arg is an IP address
# returns True if yes and False if no
def IPValidation(target):
    try:
        IP(target)
        return True
    except Exception:
        return False

# scans target and port if given. logs results to temp_outputs in a unique directory
def scanner(target, port = None, output_dir = datetime.today().strftime('%Y_%m_%d_%H_%M_%S')):
    # create unique directory to save logs to
    new_folder = Path(host_output_path, output_dir)
    new_folder.mkdir(parents=True, exist_ok=True)
    
    # check if target is a valid url or IP address
    #ip_addr = None
    if validators.url(target):
        # if valid url, return the ip address
        ip_addr = ip_lookup(target)
        if ip_addr is not None:
            # log the original url and its ip address
            with open( host_output_dir / new_folder / 'ip_scan.txt', 'a') as f:
                f.write(f'{target} ip address is: {ip_addr}')
    elif IPValidation(target):
        ip_addr = target
    else:
        print(f'target given is not valid: {target}')
        return None, TARGET_ERROR

    # 1st scan: nmap -A -oX directory ip_addr (optional: -p port )
    # create file name and file path
    nmap_A_file_name = 'nmap_A_scan_output.xml'
    nmap_A_file_path = f'{host_output_dir / new_folder / nmap_A_file_name}'

    # try scan with or without port, depending if it was given
    try:
        if port == None:
            subprocess.run(['nmap', '-A', '-oX', nmap_A_file_path, ip_addr], capture_output=True, check=True, text=True)
        else:
            subprocess.run(['nmap', '-A', '-p', port, '-oX', nmap_A_file_path, ip_addr], capture_output=True, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f'Error when nmap request. Response Code: {e.returncode}')
        return None, RESPONSE_ERROR
    except Exception as e:
        print(f'Error when nmap request: {e}')
        return None, RESPONSE_ERROR
    
    # common services and commands to try on these services
    NSE_SCRIPT_MAPPING = {
        'http': ['http-methods', 'http-enum', 'http-csrf'],
        'ssl/http': ['ssl-enum-ciphers', 'http-methods', 'http-enum'],
        'ssh': ['ssh-auth-methods', 'ssh-hostkey', 'ssh-enum-users'],
        'smtp': ['smtp-commands', 'smtp-enum-users', 'smtp-vuln-cve2010-4344'],
        'ftp': ['ftp-anon', 'ftp-brute'],
        'mysql': ['mysql-info', 'mysql-brute'],
        'microsoft-ds': ['smb-enum-shares', 'smb-vuln-ms17-010'],
    }

    # read open ports from nmap -A command
    #nmap_A_file_path = '/Users/cheoso/ai_projects/tw3_internship/temp_outputs/2025_12_06_17_41_09/nmap_A_scan_output.xml' # only used for testing
    open_ports = xml_scan(nmap_A_file_path)
    for port in open_ports:
        #print(port, open_ports[port])
        if open_ports[port]['service'] in NSE_SCRIPT_MAPPING:
            for command in NSE_SCRIPT_MAPPING[(open_ports[port]['service'])]:
                print(port, open_ports[port]['service'], command)
        
    return SUCCESS, None

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

#scanner('http://scanme.nmap.org')