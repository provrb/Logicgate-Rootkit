
### This article is still a WIP.

# My Experience Writing This Program

Disclaimer: This project was made for educational and ethical purposes. This article was written
to inform computer users, Software Engineers, Cybersecurity Analysts, and others about how someone can exploit 
multiple vulnerabilities to create a sophisticated piece of malware, and my explanation on how to prevent these vulnerabilities.

During this project, I finally decided to document my experience. This includes the triumphs, roadblocks, ideas I thought of, and more that happened during the creation of this project.

## Backstory
Before I started this project, [I had previously made a chat room entirely implemented in C for Linux for my Computer Engineering Technology class final](https://github.com/provrb/AMS), 
a basic reverse shell written in C++ for Windows, I also have been programming in C and C++ while also using the Windows API for over 2 years.

As you can infer, I went into this project with a good understanding of POSIX threads and sockets and the WinSock API.
However, the basic reverse shell I wrote in a month wouldn't even pass an anti-virus heuristic analysis. After researching
the behaviour of anti-viruses, I understood how viruses could evade anti-virus software. One of these was the use of function
pointers, and this is why they will be prevalent throughout the code instead of making direct WinSock API calls. Furthermore,
undocumented Windows API functions that invoke syscalls are also used to further evade detection.

With all this information, I wanted to construct a sophisticated piece of malware for educational purposes and, of course, for fun.
I thought simple ransomware would be pretty boring and easy to crack. I did like the idea of ransomware
but I also liked the idea of a RAT. So I compromised by creating a RAT which could also invoke a Ransomware attack, among other
functions. 

### My first roadblock
Still thinking about this idea of sophisticated ransomware, I realized I hadn't worked with much cryptography, [apart from 'web hacker',
another project on my GitHub where I decrypted Chrome and Firefox cookies](https://github.com/provrb/web-hacker), passwords, history, etc, using AES, Base64, and managing SQL
Databases. The idea of encrypting files with a key that couldn't be reverse-engineered stumped me until I researched further into cryptography about RSA encryption.

You see, AES encryption is a symmetrical-based encryption method, meaning the key that encrypts their files
could also decrypt those files. This didn't seem like much of a problem until I remembered this key that can encrypt AND decrypt their files would
have to be on their computer at some point. This makes this 'sophisticated' ransomware not so sophisticated, as it would be easily susceptible
to reverse engineering for the key to decrypt all the files. 

The solution? An ASYMMETRICAL encryption method. In particular, RSA encryption. Rather than having one key that
can decrypt and encrypt, you have a public key that can only encrypt and a private key used to decrypt. Using this method, along with the RAT
idea, I realized I thought of an idea. In this RAT-Ransomware breed, the public and private RSA keys would be generated uniquely for each client
connection to the C2 server, the public key would then be sent to the client and the ransomware would use that RSA key to encrypt all the files
on the client. 

So basically, I thought of a way to encrypt the victims' files in a reverse engineer-proof way because the key to decrypt
the files would never actually be on the victims' computers until the ransom was paid. Anything involving keys would be done on the C2 server
to keep information confidential.

Here's a bit better description:
-> Client connects to C2 server
-> C2 server generates public and private RSA key pairs and sends the public key to the client
-> Client receives the public key and encrypts all the files
[ Because you can't decrypt with the public key, it doesn't matter if the public key is ever on the victims' machine ]
-> Client pays the ransom, C2 server verifies it has been paid
-> C2 server sends the client the private key to decrypt all their files

This idea allowed me to overcome my first obstacle of securely encrypting and decrypting files without worrying about being reverse-engineered.

## File format
After brainstorming and thinking about all these methods, I proposed myself with the question; Which file format would I want to approach this project with?
A regular old EXE? An ISO file? Maybe even a .SYS file. As the days went on with this idea in my head, I started digging deeper into how DLLs work,
how to write one in C++, and how can they be used for malicious intent. That is when I discovered a vulnerability that involved DLLs and System32.
Both are fascinating subjects, which ultimately influenced my decision to include the payload in a DLL. 

## DLL Hijacking
DLL hijacking is a vulnerability where an application loads a malicious DLL rather than the intended DLL and thus 
can execute malicious code in the background while everything appears normal to the user. 

Now why does this work is the question. 

When an application loads a DLL, Windows searches four different regions in this order to find a DLL matching the requested name:
1. The directory the application is in
2. System32
3. The current working directory
4. System paths set in the environment variables panel

This function is built into the Windows OS as a standard to search for requested DLLs.

The first DLL that is found will be loaded. If a process that has Administrator permission loads a DLL, that DLL will have Administrator permission.
Similarly, if a process has SYSTEM privileges and loads a DLL, that DLL will have SYSTEM privileges, and so on. A DLL can elevate permissions without
asking the user and can bypass UAC, but we'll cover that next.

One real-world example of where DLL hijacking was prevalent was the popular 'Stuxnet' worm discovered in 2010. This worm
exploited a total of FOUR zero-day exploits and leveraged DLL hijacking as a targeted attack toward Iranian nuclear facilities.

## Mock Directories
How does System32 correlate with DLL hijacking? In Windows, it is possible to make something called a "mock directory", where an empty character is present after a folder name.
For example, the System32 folder path is "C:\Windows\System32". We can mock the System32 directory by adding a space after "Windows". 
Using this method, this is what the mock Windows directory would be like "C:\Windows \System32". 
However, by using File Explorer, trying to create a folder with a space at the end will just remove the space. Instead
of using File Explorer, we can programmatically create this mock directory by using PowerShell or C++. Try it yourself! Simply input this command into a new
PowerShell process:

New-Item "\\?\C:\Windows \System32" -ItemType Directory

Interestingly, Windows treats this fake System32 directory just like the real Windows folder!
Once you make that mock directory, look in your new Windows folder, it will also contain every single folder and file that's in the real Windows folder.

You can't even make a text document in that folder or delete it from File Explorer, you must use PowerShell again. To
get a better understanding, I recommend that you try it for yourself, it will help when trying to 
wrap your head around this information.

## Using Mock Directories with DLL Hijacking to Bypass UAC
Using the information we learned about mock directories and DLL hijacking we can put these methods together to bypass
Windows User Account Controller. First of all, we need to search for System32 executables that auto-elevate to Administrator privileges,
we can use a repository posted on GitHub that describes all authentic System32 executables that will auto-elevate the respective DLLs.

https://github.com/wietze/windows-dll-hijacking/blob/master/dll_hijacking_candidates.csv

*In my case, I chose to exploit ComputerDefaults.exe and mlang.dll.*

I started with a blank DLL template that would run when a process attached to it, and I inserted ComputerDefaults.exe into my System32 mock directory. 
When I ran the EXE, I received a message showing that my version of MLANG.dll was loaded.

Doing all of this though would break the actual executable because the whole reason the DLL is getting loaded is because the executable
needs code from our DLL. To fix this, I told the linker to link all the functions as exports ComputerDefaults requested from us.
After, I loaded up PE-Bear to find what exports the authentic mlang.dll provided and copied all function names to my linker commands, though
I redirected the export to the path of the real mlang.dll so ComputerDefaults was able to use the real functions but also simultaneously run my DLL.

By making our DLL's export table identical to the authentic MLANG.dll, the executable requiring the DLL wouldn't break.
When the real ComputerDefaults.exe is executed, it would auto-elevate my DLL to Administrator privileges, bypassing the Windows UAC,
and allowing me to run malicious code in the context of an Administrator.

## Procutils.h
One of the first things I started to work on after dllmain.cpp was finished, was the procutils library. Here I created an interface for
loading different functions by getting the current processes PEB address and iterating over each LIST_ENTRY of the module
list until I found the library I was looking for. This would allow me to dynamically load libraries but, I would still need
to get the function address to actually import functions from the library. I started to research this area and found
that it was relatively easy to get the exports of a library by finding the export directory from the headers, all that was
left was to compare function names to the export I wanted. By iterating over the NumberOfNames field in the export directory
I can check the array of all the export names to my desired function, once I found the function I wanted, I would just
return the absolute address of the function. 

After a couple of these functions, it would be a breeze to load functions I need without polluting or even adding them
to my imports table, which is one way to attempt to evade AVs. Afterwards, I got started on trying to elevate my permissions even more.

## SYSTEM Permissions
In Windows, there is a built-in account known as SYSTEM or LocalSystem. This account is used by the operating system and
services which require higher privileges to manage important resources and processes. Luckily for threat-actors
but unlucky for users, these privileges aren't too difficult to obtain and can allow a program to execute malicious instructions
with these obtained privileges. By using my amazing and totally convenient procutils library, I was able to obtain a "token" to 
acquire these SYSTEM privileges. With this token, I can open and perform commands in the LocalSystem context. To obtain this token
we first got to take advantage of a process running with SYSTEM permissions. A known process in this category is winlogon.exe. 
This application is responsible for handling the login or logoff of a user, and securely authenticating said users. Winlogon.exe is
also used for handling the secure attention sequence, (pressing CTRL + ALT + DEL). One reason why this process is also to exploit
is because it runs at startup, runs all the time, and runs before the user logs in. Meaning this process will always be running!

To take advantage of winlogon.exe, we need to find the process ID of it. By taking a snapshot of all currently running processes
and iterating through them while comparing the name to the process we want, we can easily retrieve the process idea of Winlogon.
The next process is extremely tedious and involves getting a process's security token. A security token is pretty much a piece
of information identifying which permissions a process has.

To start, we need to open a handle to the Winlogon process using the PID acquired before. In this procedure, I took advantage of undocumented
syscalls for the Windows operating system. Which you'll see.

Firstly, We can use the NtOpenProcess undocumented syscall to retrieve a handle. 
Using this newly acquired process handle, we need to get the security token of that process. I used NtOpenProcessToken,
another undocumented syscall, along with the TOKEN_DUPLICATE permission, saying that we want permission to duplicate this security token. This
is allowed because we're running in the administrator context. With the security token for winlogon.exe, we can safely duplicate it by using NtDuplicateToken
and return a HANDLE to a SYSTEM token! With this token, we can execute commands with SYSTEM permissions.

But even though SYSTEM is almost equivalent to kernel-level control, is there any way to get a higher privilege context?

## Trusted Installer Permissions
You've probably seen something related to Trusted Installer on your computer before. Perhaps you tried deleting a system
file and were greeted with a message like "You require permission from Trusted Installer". Trusted Installer is a user account
like you, but it has the highest permissions available in user mode, higher than the previous group, SYSTEM. Windows has this group built-in to prevent damaging important
system files. My hypothesis: Is it possible to elevate to Trusted Installer privileges, considering how easy it was to obtain Administrator and SYSTEM privileges?

During this procedure, I used two main functions from the procutils header file. In particular, StartWindowsService and CreateProcessAccessToken use the same
function to obtain a SYSTEM token. You may see where this is going.

Rather than being an actual running process like winlogon.exe, TrustedInstaller is embedded into Windows as a service and thus has to be started.
To start any Windows process, we first need to obtain a handle for the Windows service control manager, a special process responsible for starting and stopping.
Windows processes, so we can start and stop Windows processes! After, we need to obtain another handle for the service by opening it with the SC manager.
Though, we do not know if this service is running, or pending start or a stop, so we must query the status of the service. Once the service is running, we can take the
process ID of that service, and run it through CreateProcessAccessToken to return a security token in the context of the provided process, in this case, the Trusted
Installer service.

In conclusion, we got the PID of the Trusted Installer service, started it using the Windows SCM, and duplicated the security token for that process as we did
with winlogon.exe. Using the handle of the security token, I can run and manipulate processes in the TrustedInstaller context. The highest possible User-Mode privileges
implemented in the Windows operating system. Meaning this has the potential to become a User-Mode root kit as we have persistence, privilege, and stealth.

## How could this malware be avoided; as you-the user?

## Conclusion, what I learned


