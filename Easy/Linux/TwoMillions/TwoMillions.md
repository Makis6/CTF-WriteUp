
![[twomillion logo.png]]


nmap scan

![Pasted image 20251021201805](Images/Pasted%20image%2020251021201805.png)

Ok, so 2 ports are open, let's enumerate the webserver.
We see in the url that we can't resolve the name of the website (2million.htb), so we first add it to our /etc/hosts file

```
echo '10.129.35.108 2million.htb' >> /etc/hosts
```
And after refreshing the page, we get on a website that looks like an old hackthebox.

We found a panel where we can register an account but first we need an invite code.

![Pasted image 20251021203205](Images/Pasted%20image%2020251021203205.png)

After looking at the source code, we found a js script containing some info about how to get an invite code

![Pasted image 20251021203350](Images/Pasted%20image%2020251021203350.png)

![Pasted image 20251021203410](Images/Pasted%20image%2020251021203410.png)
We use the site https://lelinhtinh.github.io/de4js/ to deobfuscate the js and decode it and we see the function **makeInviteCode** that says we have to make a POST request to the endpoint `/api/v1/invite/how/to/generate`

![Pasted image 20251021203452](Images/Pasted%20image%2020251021203452.png)

So we make our curl request 

```
curl -X POST http://2million.htb/api/v1/invite/how/to/generate
```
And it returns a text that seems encoded. After going to CyberChef and trying the ROT13 encoding we found the message as seen below.

![Pasted image 20251021203505](Images/Pasted%20image%2020251021203505.png)

![Pasted image 20251021203528](Images/Pasted%20image%2020251021203528.png)

So we do our second curl request to generate our invite code and we get a code that is encoded too, and that looks like base64. Same process we go to CyberChef to decode it and we get our Invite Code.

![Pasted image 20251021203553](Images/Pasted%20image%2020251021203553.png)

![Pasted image 20251021203616](Images/Pasted%20image%2020251021203616.png)

We paste it in the planned area and we can register.
![Pasted image 20251021203656](Images/Pasted%20image%2020251021203656.png)
After creating an account and logging in, we see that we can download a VPN pack.

![Pasted image 20251021205702](Images/Pasted%20image%2020251021205702.png)

Let's use our Developper Tools to see what it's pointing.

![Pasted image 20251021205753](Images/Pasted%20image%2020251021205753.png)

It's pointing on `/api/v1/user/vpn/generate`, let's see what we can find on the api by first going to `/api/v1` and see our results.

![Pasted image 20251021205815](Images/Pasted%20image%2020251021205815.png)
We see that we can update the settings of the admin. Maybe we can try to grant us admin rights ? Let's do a PUT request with curl to see what we can do (Don't forget to add your cookie in the request so the web server knows we are authenticate).

![Pasted image 20251021205624](Images/Pasted%20image%2020251021205624.png)
The parameters **email** is missing, let's modify our request and add our mail address.

![Pasted image 20251021205925](Pasted%20image%2020251021205925.png)
The parameter **is_admin** is missing too, we recraft our request and setting the **is_admin** to **1**

![Pasted image 20251021205940](Pasted%20image%2020251021205940.png)
Looks like we are admin now, let's verify by going to `/api/v1/admin/auth`
![Pasted image 20251021210007](Pasted%20image%2020251021210007.png)

It returns **true** so that means we are admin now !

Ok let's see what we can do on the second interesting admin endpoint `/api/v1/admin/vpn/generate`

![Pasted image 20251021210609](Pasted%20image%2020251021210609.png)
We now add the parameter **username** since it's missing, and we put our own.

![Pasted image 20251021210631](Pasted%20image%2020251021210631.png)
We can see it generates us a vpn file. Maybe we can twist the request so it takes others command ? We add `;id;"` after our username so it execute the command after it looks for the vpn file.

![Pasted image 20251021210651](Pasted%20image%2020251021210651.png)
We can see that it returns us the result of the id command. After doing the `ls -la` command we see there is a `.env` file that might contains informations.
![Pasted image 20251021211203](Pasted%20image%2020251021211203.png)
And we got the username and password combo `admin:SuperPass123`

Let's trying those with ssh.

![Pasted image 20251021211511](Pasted%20image%2020251021211511.png)
It worked ! We grab the user flag and look for privesc.


Nothing interesting with linpeas but we found a mail in `/var/mail/admin` containing a piece of great information for us.

It says that there is an exploit with **OverlayFS / FUSE**. So we google it to find something like a CVE or even better an exploit.

We found an exploit on github that might works for us https://github.com/xkaneiki/CVE-2023-0386. First lets grab it on our attacking machine

```
git clone https://github.com/xkaneiki/CVE-2023-0386
```
We zip it to it's easier to transfer it to the target.

```
zip -r cve.zip CVE-2023-0386
```

And we use scp to tranfer it

```
scp cve.zip admin@2million.htb:/tmp
```

And we follow the exploit to get root.

We get the root flag and that end the box !









