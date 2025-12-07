from pathlib import Path
from datetime import datetime
import os

from openai import OpenAI


#parent_path = Path(Path(__file__).resolve().parent.parent, 'temp_outputs')
#output_dir = datetime.today().strftime('%Y_%m_%d_%H_%M_%S')

client = OpenAI(base_url="http://localhost:11434/v1", api_key="EMPTY")

def chat_wrapper(messages, **kwargs):
    response = client.chat.completions.create(
        model='qwen3:4B-instruct',
        messages=messages,
        **kwargs
    )

    return response.choices[0].message.content

def summarize(parent_path, output_dir):
    files, err = get_files(parent_path, output_dir)
    if err:
        return None, err
    
    messages = [{'role': 'system', 'content': 'You are a cybersecurity expert tasked in writing 1 page pdf reports that highlight security vulnerabilities from various penetration testing scans. Your job is to give clear output about the main risks of a site from multiple completed scans. List found vulnerabilities from most to least sever. Your reports must be formatted like an official report. No questions should be asked and no emojis should be used. Only stick to facts. Your reports will be used in the industry by other professionals. You will receive a dictionary with the file name, usually referring to the port number and scan that was completed as well as the contents of that scan in xml format.'},
                {'role': 'user', 'content': str(files)}]
    print(messages)
    
    response = chat_wrapper(messages)

    print(response)
    

    return

def get_files(parent_path, output_dir):
    files = os.listdir(f'{parent_path / output_dir}')
    
    file_dict = {}
    for file in files:
        print(file)
        file_content = open( f'{parent_path / output_dir / file}' )
        file_dict[file] = file_content.read()
        file_content.close()

    return file_dict, None

#parent_path = Path(Path(__file__).resolve().parent.parent, 'temp_outputs')

parent_path = Path('/Users', 'cheoso', 'Documents', 'rsa')
#print(parent_path)
summarize(parent_path, '2025_12_07_17_33_03')