# Pen Writer  
Pen Writer is a CLI tool that performs automated penetration testing and creates a pdf report based on the scans using an LLM.  
Pentests were conducted on a local VM running bWAPP.  
NEVER run this project on a server that you are not allowed to do pentesting on.  

## Important Information:  
* This project requires that you run ollama locally using qwen3:4b-instruct.  
* You normally need to wait between 5-10 minutes for a report.  

## How to Use
How to run the project:
* Clone the github repo  using `git clone git@github.com:GrantCanty/penetration_test_reporter.git`
* Create a python virtual environment using `python3 -m venv venv`  
* Open python virtual environment  
* Install required packages with `pip install -r requirements.txt`
* Start ollama in your terminal using `ollama run qwen3:4b`  
* Scan and generate a report using `python3 -m pen_writer scan <ip or url>` (optional tags: `-b`: base path. ex: `bWAPP` and `-p`: port. ex: `4040`)  
  * a base path should never start with a `/`  

## Architecture:  
The program has the following architecture:  
* `/pen_writer`  
  * This directory contains code for the CLI, the scanner, and the report generator.  
* `/credentials`  
  * This directory contains a password and username file that could be used for various brute force attacks.  
* `/outputs`  
  * This directory contains/will contain the output of a scan in a unique folder. The folder contains the scans and a   `report.pdf` file. 

When you run the `python3 -m pen_writer ...` scanner, it runs scans, saves them to the `/outputs` directory, then the llm takes the scans in as context to generate a report.

## Scans  
The program always performs scans in a hierarchical way:
1. The program will always start with 2 scans to get open ports and an overview of the server:  
  * nmap -A  
  * nmap -sV -sC. 
2. Based on results the program enumerates over findings to perform secondary scans which are typically scripts based on the open port type. Example:  
  * If there is an open `ssh` port, perform `ssh-auth-methods`, `ssh-hostkey`, `ssh-brute` scans
  * If there is an open `http` port, perform `http-methods`, `http-enum`, `http-csrf` scans
3. Lastly, we index the server to get any explore any remaining pages. If there is a page containing `login`, `signup`, or `admin`, we run a `http-form-brute` attack to try to login

## Limitations
It's hard to find super reliable penetration testing sites that let you run commands on from your own terminal. Because of this, the project may be somewhat limited to running on the bWAPP site that I mainly used for testing. I tried to be wary of this, but it is not easy to predict the limitations at times.  

## Main Challenges  
* LLM Output:
  * LLM always asks a question at the end of its report. 
  * LLM generates more than 1 page of content. 
* Scans:
  * Dynamic scans based off of xml output is tedious.  
  * Creating a dict with a list possible scans and If/else statements for the scans is not always reliable. Might not have added a scan or may have missed not defined a service. 
* Reliable sites for pentesting:  
  * Most pentesting sites only let you do using a terminal on their own site. Hard to find a reliable way to do the testing from your own computer.  
* VM Setup:  
  * Setting up a VM is not always straightforward.  