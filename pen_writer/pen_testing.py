import docker
from pathlib import Path


client = docker.from_env()

# get the parent path of the file. will be used to mount in docker
host_output_dir = Path(Path(__file__).resolve().parent.parent, 'temp_outputs')
host_output_path = str(host_output_dir)

host_output_dir.mkdir(parents=True, exist_ok=True)

def basic_port_scan(target):
    report_file_name = f'{target}_port_scan.json'
    try:
        client.containers.run(
            image='nettacker',
            #entrypoint='nettacker.py',
            #command=['-i' ,target, '-m', 'port_scan', '-o', '/' + str(Path('temp_outputs', report_file_name))],
            command=f"-i {target} -m port_scan -o /temp_outputs/{report_file_name}",
            #command=['-i' , target, '-m', 'port_scan', '-o', f'/temp_outputs/{report_file_name}'],
            remove=True,
            network_mode='host',
            privileged=True,
            volumes={
                host_output_path: {'bind': '/temp_outputs', 'mode': 'rw'}
                }
        )

        #output = output_b.decode('utf-8')
        #return output
    except docker.errors.ContainerError as e:
        # This catches non-zero exit statuses
        print(f'Scan failed with exit code: {e.exit_status}')
        print(f"Container logs (STDOUT/STDERR):\n{e.stderr.decode('utf-8')}")
    except docker.errors.ImageNotFound:
        print(f"'nettacker' image not found")
        #return None
    except Exception as e:
        print(f'error occurred when running: {e}')
        #return None


basic_port_scan('ctf10.root-me.org')