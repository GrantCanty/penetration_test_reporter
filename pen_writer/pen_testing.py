import docker
from pathlib import Path
from datetime import datetime
import json


client = docker.from_env()

# get the parent path of the file. will be used to mount in docker
host_output_dir = Path(Path(__file__).resolve().parent.parent, 'temp_outputs')
host_output_path = str(host_output_dir)

host_output_dir.mkdir(parents=True, exist_ok=True)



def run_scanner(target, output_dir = datetime.today().strftime('%Y_%m_%d_%H_%M_%S')):
    new_folder = Path(host_output_path, output_dir)
    new_folder.mkdir(parents=True, exist_ok=True)

    new_folder_path = str(new_folder)

    #port_scan(target, new_folder_path)
    #subdomain_scan(target, new_folder_path)
    try:
        open_ports_path = open('../temp_outputs/2025_12_04_15_51_33/port_scan.json')
        open_ports_file = json.load(open_ports_path)

    except Exception as e:
        print(f'error with file: {e}')
    
    for open_port in open_ports_file:
        directory_scan(open_port, new_folder_path)
        #print(open_port)


# scans for open ports. returns results as json
def port_scan(target, output_dir):
    try:
        client.containers.run(
            image='nettacker',
            command=f"-i {target} -m port_scan -o /temp_outputs/port_scan.json",
            remove=True,
            network_mode='host',
            privileged=True,
            volumes={
                output_dir: {'bind': '/temp_outputs', 'mode': 'rw'}
                }
        )

        #return True
    except docker.errors.ContainerError as e:
        # non-zero exit statuses
        print(f'Scan failed with exit code: {e.exit_status}')
        raise(f"Container logs (STDOUT/STDERR):\n{e.stderr.decode('utf-8')}")
        #return False
    except docker.errors.ImageNotFound:
        raise(f"'nettacker' image not found")
        #return False
    except Exception as e:
        raise(f'error occurred when running: {e}')
        #return False
  
def subdomain_scan(target, output_dir):
    try:
        client.containers.run(
            image='nettacker',
            #command=f"-i {target} -m http_status_scan -o /temp_outputs/subdomain_scan.json",
            command=f"-i {target} -d -s -m http_status_scan -o /temp_outputs/subdomain_scan.json",
            remove=True,
            network_mode='host',
            privileged=True,
            volumes={
                output_dir: {'bind': '/temp_outputs', 'mode': 'rw'}
                }
        )

        #return True
    except docker.errors.ContainerError as e:
        # non-zero exit statuses
        print(f'Scan failed with exit code: {e.exit_status}')
        raise(f"Container logs (STDOUT/STDERR):\n{e.stderr.decode('utf-8')}")
        #return False
    except docker.errors.ImageNotFound:
        raise(f"'nettacker' image not found")
        #return False
    except Exception as e:
        raise(f'error occurred when running: {e}')
        #return False       

def directory_scan(ports_response, output_dir):
    link = f'http://{ports_response["target"]}:{ports_response["port"]}'
    save_file = f'directory_scan_{ports_response["port"]}'
    print(f'scanning {link}')
    try:
        client.containers.run(
            image='nettacker',
            #command=f"-i {target} -m http_status_scan -o /temp_outputs/subdomain_scan.json",
            command=f"-i {link} -m dir_scan -o /temp_outputs/{save_file}.json",
            remove=True,
            network_mode='host',
            privileged=True,
            volumes={
                output_dir: {'bind': '/temp_outputs', 'mode': 'rw'}
                }
        )

        #return True
    except docker.errors.ContainerError as e:
        # non-zero exit statuses
        print(f'Scan failed with exit code: {e.exit_status}')
        raise(f"Container logs (STDOUT/STDERR):\n{e.stderr.decode('utf-8')}")
        #return False
    except docker.errors.ImageNotFound:
        raise(f"'nettacker' image not found")
        #return False
    except Exception as e:
        raise(f'error occurred when running: {e}')
        #return False

run_scanner('http://ctf02.root-me.org/index.php')
#run_scanner('http://10.82.143.10')
#run_scanner('http://host.docker.internal:4280')