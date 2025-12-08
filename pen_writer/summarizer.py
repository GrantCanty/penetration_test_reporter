import os
from openai import OpenAI
from markdown_pdf import MarkdownPdf, Section

from pen_writer import (
    DIRECTORY_ERROR, LLM_ERROR, SUCCESS, __app_name__
)


client = OpenAI(base_url="http://localhost:11434/v1", api_key="EMPTY")

def chat_wrapper(messages, **kwargs):
    response = client.chat.completions.create(
        #model='qwen3:4B-instruct',
        model='qwen3:4B-instruct',
        messages=messages,
        **kwargs
    )

    return response.choices[0].message.content

def summarize(parent_path, output_dir):
    files, err = get_files(parent_path, output_dir)
    if err:
        return None, err
    
    system_prompt = '''Your name is pen writer and you are a cybersecurity expert. Your role is to write concise 1 page 
    reports highlighting security vulnerabilities from various penetration testing scans. These reports are given to 
    outside regulatory agencies who have no decision making power over the target. Because of this, do not give 
    reccomendations about what to fix. Only talk about the issues on the site and the effect of the vulnerabilities. 
    If a scan does not return a vulnerability, there is no need to mention it. Your reports needs to be concise for 
    maximum impact. 
    
    You will receive a dictionary with the file name, usually referring to the port number and scan that was completed 
    as well as the contents of that scan in xml format. Your final output must be complete  and final. The ENTIRE output 
    must only be the report. NEVER include any conversational language, questions, follow-up prompts, or suggestions for 
    the next steps. Only output the markdown report content. Stop output immediately after the report content ends.'''
    user_prompt = f'User query: Give a 1 page report in markdown covering the main security issues found from the documents provided. Never use emojis or ask for any questions\nUser Content: {str(files)}'
    
    messages = [{'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt}]
    
    try:
        print('Analyzing results from scans')
        response = chat_wrapper(messages)
    except Exception as e:
        print(f'Error from LLM: {e}')
        return None, LLM_ERROR
    print('Finished analyzing results from scans')

    pdf = MarkdownPdf()
    pdf.meta["title"] = 'Title'
    pdf.add_section(Section(response, toc=False))
    
    print(f'Writing report')
    report_path = f'{parent_path / output_dir / "report.pdf"}'
    print(report_path)
    pdf.save(report_path)
    print(f'Finished writing report')
    

    return SUCCESS, None

def get_files(parent_path, output_dir):
    files = os.listdir(f'{parent_path / output_dir}')
    if len(files) == 0:
        return None, DIRECTORY_ERROR
    
    file_dict = {}
    for file in files:
        #print(file)
        file_content = open( f'{parent_path / output_dir / file}' )
        file_dict[file] = file_content.read()
        file_content.close()

    return file_dict, None

#parent_path = Path(Path(__file__).resolve().parent.parent, 'temp_outputs')

#parent_path = Path('/Users', 'cheoso', 'Documents', 'rsa')
#print(parent_path)
#summarize(parent_path, '2025_12_07_17_33_03')

#res, err = get_files(Path('/Users', 'cheoso', 'ai_projects', 'tw3_internship', 'temp_outputs'), '2025_12_08_14_53_24')
#print(res, err)