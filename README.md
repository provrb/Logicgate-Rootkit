
### This article is still to be finished.

# My Experience Writing This Program

Disclaimer: This project was made for educational and ethical purposes. This article was written
to inform computer users, Software Engineers, Cybersecurity Analysts, and more, of how someone can
exploit multiple vulnerabilities to create a sophisticated piece of malware, and my explanation
on preventing these vulnerabilities.

During this project, I finally decided to document my experience. This includes the triumphs, roadblocks, ideas I thought of, and more that happened during the creation of this project.

## Backstory
Before I started this project, I had previously made a chat room entirely implemented in C for Linux, 
a basic reverse shell written in C++ for Windows and have been writing C and C++ code and using the Windows API for over 2 years.

As you can infer, I went into this project with a good understanding of POSIX threads and sockets and the WinSock API.
However, the basic reverse shell I wrote in a month wouldn't even pass an anti-virus heuristic analysis. After researching
the behaviour of anti-viruses, I understood how viruses could evade anti-virus software. One of these was the use of function
pointers, and this is why they will be prevalent throughout the code instead of making direct WinSock32 API calls. Furthermore,
undocumented Windows API functions that invoke syscalls are also used to further evade detection.

With all of this information, I wanted to construct a sophisticated piece of malware for educational purposes, and of course,
to have fun since. I thought a simple ransomware would be pretty boring and easy to crack. I did like the idea of ransomware
but, I also liked the idea of a RAT. So I compromised by creating a RAT which could also invoke a Ransomware attack, among other
functions. 

### My first roadblock
Still thinking about this idea of sophisticated ransomware, I realized I hadn't worked with much cryptography, apart from 'web hacker',
the project found on my Github where I decrypted Chrome and Firefox cookies, passwords, history, etc, using AES, Base64, and managing SQL
Databases. The idea of encrypting files with a key that couldn't be reverse-engineered stumped me until I researched further into cryptography about RSA encryption.

You see, AES encryption ( Advanced Encryption Standard ) is a symmetrical-based encryption method, meaning the key that encrypts their files
could also decrypt their files. This didn't seem like much of a problem until I remembered this key that can encrypt AND decrypt their files would
have to be on their computer at some point. This makes this "sophisticated" ransomware, not so sophisticated as it would be easily susceptible
to reverse engineering for the key to decrypt all the files. 

The solution? An ASYMMETRICAL encryption method. In particular, RSA encryption ( Rivest–Shamir–Adleman ). Rather than having one key that
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

This idea allowed me to overcome my first obstacle on how to securely encrypt and decrypt files without worrying about being reverse-engineered.

## File format
After brainstorming and thinking about all these methods, I proposed myself with the question; Which file format would I want to approach this project with?
A regular old EXE? An ISO file? Maybe even a .SYS file. As the days went on with this idea in my head, I started digging deeper into how DLLs work,
how to write one in C++, and how can they be used for malicious intent. That is when I discovered a vulnerability that involved DLLs and System32.
Both are fascinating subjects, which ultimately influenced my decision to include the payload in a DLL. 

## DLL Hijacking
DLL hijacking is a vulnerability where an application loads a malicious DLL rather than the intended DLL and thus 
can execute malicious code in the background while everything appears normal to the user. 

Now why does this work is the question. 

When an application loads a DLL, Windows will search four different regions for any DLL that meets the name of the DLL requested in the application in this order.
1. The directory the application is in
2. System32
3. The current working directory
4. System paths set in the environment variables panel

This function is built into the Windows OS as a standard to search for requested DLLs.

The first DLL that is found will be loaded. If a process that has administrator permission loads a DLL, that DLL will have administrator permission.
Likewise, if a process has SYSTEM privileges and loads a DLL, that DLL will have SYSTEM privileges, and so on. A DLL can elevate permissions without
asking the user and can bypass UAC, but we'll cover that next.

One real-world example of where DLL hijacking was prevalent was the popular 'Stuxnet' worm discovered in 2010. This worm
exploited a total of FOUR zero-day exploits and leveraged DLL hijacking as a targeted attack toward Iranian nuclear facilities.

## Mock Directories
Now how does System32 correlate with DLL hijacking? In Windows, it is possible to make something called a "mock directory", where an empty character is present after a folder name.
For example, the System32 folder path is "C:\Windows\System32". We can mock the System32 directory by adding a space after "Windows". 
Using this method, this is what the mock Windows directory would be like "C:\Windows \System32". 
However, by using File Explorer, trying to create a folder with a space at the end will just remove the space. Instead
of using File Explorer, we can programmatically create this mock directory by using Powershell or C++. Try it yourself! Simply input this command into a new
Powershell process:

New-Item "\\?\C:\Windows \System32" -ItemType Directory

Now something funny about this fake System32 directory is that Windows treats it exactly like the real Windows folder!
Once you make that mock directory, look in your new Windows folder, it will also contain every single folder and file that's in the real Windows folder.

You can't even make a text document in that folder or delete it from File Explorer, you must use Powershell again. To
get a better understanding, I recommend that you to try it for yourself, it will help when trying to 
wrap your head around this information.

## Using Mock Directories with DLL Hijacking to Bypass UAC
Using the information we learned about mock directories and DLL hijacking we can put these methods together to bypass
Windows User Account Controller. First of all, we need to search for System32 exe's that auto elevate to administrator,
we can use a repo posted on Github that describes all authentic System32 executables that will auto-elevate the respectively loaded DLL.

https://github.com/wietze/windows-dll-hijacking/blob/master/dll_hijacking_candidates.csv

In my case, I chose to exploit ComputerDefaults.exe and mlang.dll.
I started out with a blank DLL template that would run when a process requested to attach and inserted ComputerDefaults.exe 
into my System32 mock directory so once I ran the EXE, I would get a message that showed my version of MLANG.dll was loaded.

Doing all of this though would break the actual executable because the whole reason the DLL is getting loaded is because the executable
needs code from our DLL. To fix this, I told the linker to link all the functions as exports ComputerDefaults requested from us.
After, I loaded up PE-Bear to find what exports the authentic mlang.dll provided and copied all function names to my linker commands, though
I redirected the export to the path of the real mlang.dll so ComputerDefaults was able to use the real functions but also simultaneously run my DLL.

Now nothing would break, and I at this point Windows UAC was by using these methods allowing me to run a dll unsuspected of the user with
malicious code AND with Adminastrator permission.

## Procutils.h
One of the first things I started to work on after dllmain was finished, was procutils. Here I created an interface for
loading different functions by getting the current processes PEB address and iterating over each LIST_ENTRY of the module
list until I found the library I was looking for. This would allow me to dynamically load librarys but, I would still need
to get the function address to actually import functions from the library. I started to research about this area and found
that it was relatively easy to get the exports of a library by finding the exporrt directory from the headers, all that was
left was to compare function names to the export I wanted. By iterating over the NumberOfNames field in the export directory
I can check the array of all the exports names to my desired function, once I found the function I wanted, I would just
return the absolute address of the function. 

After a couple of these functions, it would be a breeze to load functions I need without polluting or even adding them
to my imports table, which is one way to attempt to evade AVs. Afterwards, I got started on trying to elevate my permissions even more.

## Trusted Installer Permissions
You've probably seen something related to Trusted Installer on your computer before. Perhaps you tried deleting a system
file and were greeted with a message along the lines of "You require permission from Trusted Installer". Trusted Installer is a user account
just like you, but it has the highest permissions available in user-mode. Windows has this group built-in to prevent damaging important
system files. My hypothesis; is it possible to elevate to Trusted Installer privileges considering how easy it was to get Administrator privileges?

## How could this malware be avoided; as you-the user?

## Conclusion, what I learned


