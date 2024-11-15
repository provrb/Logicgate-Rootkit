# Logicgate
_This project has a write-up with it. View it [here](https://provrb.github.io/Logicgate-Rootkit/)_

A user-mode RAT rootkit that elevates to Trusted Installer privileges by using DLL hijacking
and a System32 mock directory. Requests over sockets to and from remote hosts are encrypted using RSA
to obfuscate reverse engineering and anti-viruses monitoring network traffic. Commands can be sent from
the command-and-control server to remote hosts, these commands will be performed on the clients machine.
- Includes ransomware functionality. Encrypt files using uniquely generated 2048 RSA bit keys
for each client, and save them in a JSON file with the client machine GUID as the key index.

## Installing
Instructions for installing the source code...
## Building
Instructions for building the client DLL and server executable.
## Runnning
Instructions for running the client DLL and the server executable
## Configuration
Instructions on configuring the server, and commands such as TCP port, TCP ddns to use, etc..
## Commands
DEscriptions on commands you can perform on remote hosts.
