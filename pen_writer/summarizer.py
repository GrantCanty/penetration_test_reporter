from pathlib import Path
from datetime import datetime
import os


#parent_path = Path(Path(__file__).resolve().parent.parent, 'temp_outputs')
#output_dir = datetime.today().strftime('%Y_%m_%d_%H_%M_%S')

def get_files(parent_path, output_dir):
    files = os.listdir(f'{parent_path / output_dir}')
    
    file_dict = {}
    for file in files:
        print(file)
        file_content = open( f'{parent_path / output_dir / file}' )
        file_dict[file] = file_content.read()
        file_content.close()

    print(files)