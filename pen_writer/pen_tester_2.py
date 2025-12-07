import socket
import validators
from datetime import datetime
from pathlib import Path
import subprocess
from IPy import IP
import xml.etree.ElementTree as ET
import asyncio
from functools import partial
from concurrent.futures import ThreadPoolExecutor

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
        'ssh': ['ssh-auth-methods', 'ssh-hostkey', 'ssh-enum-users', 'ssh-brute'],
        'smtp': ['smtp-commands', 'smtp-enum-users', 'smtp-vuln-cve2010-4344'],
        'ftp': ['ftp-anon', 'ftp-brute'],
        'mysql': ['mysql-info', 'mysql-brute'],
        'microsoft-ds': ['smb-enum-shares', 'smb-vuln-ms17-010'],
    }

    # read open ports from nmap -A command
    # nmap_A_file_path = '/Users/cheoso/ai_projects/tw3_internship/temp_outputs/2025_12_06_17_41_09/nmap_A_scan_output.xml' # only used for testing
    open_ports = xml_scan(nmap_A_file_path)
    
    # commands to perform for each port using its service
    commands = [
        item for port in open_ports
        for item in get_port_and_command(port, open_ports, NSE_SCRIPT_MAPPING)
    ]

    save_dir = host_output_dir / new_folder
    res = asyncio.run(run_nmap_async(ip_addr, commands, save_dir))
    print(res)





        
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

def get_port_and_command(port, open_ports, script_map):
    service = open_ports[port]['service']
    if service in script_map:
        yield from ((port, command) for command in script_map[service])

def run_nmap_sync(ip_addr, port, command, output_dir):
    file_name = f'{port}_{command}.xml'
    file_path = f'{output_dir / file_name}'
    parent_dir = Path(__file__).resolve().parent.parent
    try:
        if command != 'ssh-brute':
            subprocess.run(['nmap', '--script', command, '-p', port, '-oX', file_path, ip_addr], capture_output=True, check=True, text=True)
        else:
            subprocess.run(['nmap', '-p', port, '-oX', file_path, '--script', command, '--script-args', f'userdb={parent_dir /"credentials/cirt-default-usernames.txt"},passdb={parent_dir /"credentials/Pwdb_top-1000.txt"}', ip_addr], capture_output=True, check=True, text=True)
    except Exception:
        return {'file_path': file_path, 'port': port, 'command': command, 'error': RESPONSE_ERROR}

    return {'file_path': file_path, 'port': port, 'command': command, 'error': None}

async def async_scan_worker(executor, ip_addr, port, command, output_dir):
    # run_in_executor offloads the synchronous subprocess call to a separate thread
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        executor,
        partial(run_nmap_sync, ip_addr, port, command, output_dir)
    )

async def run_nmap_async(ip_addr, commands, output_dir):
    results = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        tasks = [
            async_scan_worker(executor, ip_addr, port, command, output_dir)
            for port, command in commands
        ]
        
        # gather results as they complete
        completed_results = await asyncio.gather(*tasks)
        results.extend(completed_results)
        
    return results

#scanner('http://scanme.nmap.org')