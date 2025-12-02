import docker
from pathlib import Path


client = docker.from_env()

# get the parent path of the file. will be used to mount in docker
host_output_dir = Path(Path(__file__).resolve().parent.parent, 'temp_outputs')
host_output_path = str(host_output_dir)

host_output_dir.mkdir(parents=True, exist_ok=True)

def run_scanner(target, output_dir = 'temp'):
    new_folder = Path(host_output_path, output_dir)
    print(f'folder path: {new_folder}')
    new_folder.mkdir(parents=True, exist_ok=True)

    port_scan(target, str(new_folder))
    subdomain_scan(target, str(new_folder))

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

        return True
    except docker.errors.ContainerError as e:
        # non-zero exit statuses
        print(f'Scan failed with exit code: {e.exit_status}')
        print(f"Container logs (STDOUT/STDERR):\n{e.stderr.decode('utf-8')}")
        return False
    except docker.errors.ImageNotFound:
        print(f"'nettacker' image not found")
        return False
    except Exception as e:
        print(f'error occurred when running: {e}')
        return False
  
def subdomain_scan(target, output_dir):
    try:
        client.containers.run(
            image='nettacker',
            command=f"-i {target} -d -s -m http_status_scan -o /temp_outputs/subdomain_scan.json",
            remove=True,
            network_mode='host',
            privileged=True,
            volumes={
                output_dir: {'bind': '/temp_outputs', 'mode': 'rw'}
                }
        )

        return True
    except docker.errors.ContainerError as e:
        # non-zero exit statuses
        print(f'Scan failed with exit code: {e.exit_status}')
        print(f"Container logs (STDOUT/STDERR):\n{e.stderr.decode('utf-8')}")
        return False
    except docker.errors.ImageNotFound:
        print(f"'nettacker' image not found")
        return False
    except Exception as e:
        print(f'error occurred when running: {e}')
        return False       

run_scanner('http://ctf10.root-me.org/',)