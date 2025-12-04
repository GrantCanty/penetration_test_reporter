# Pen Writer  
Pen Writer is a CLI meant to automate penetration testing and create a 1 page report using an LLM.  

## Requirements:  
* Clone the following Github repositories:
  * https://github.com/OWASP/Nettacker.git: Nettacker package for automated tests  
  * https://github.com/digininja/DVWA.git: DVWA for pentesting sandbox  
* Build the required Docker image for the cloned Nettacker repository with: docker build -t nettacker .  
* Enter the DVWA directory and run `docker compose up -d` to run the image. This is accessible at `http://localhost:4280`

## Testing:  
Testing was done on the following links:  
* ctf01.root-me.org
