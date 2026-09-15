

![[BoardLight Logo.png]]




![Pasted image 20251019183142](Pasted%20image%2020251019183142.png)



![Pasted image 20251019184103](Pasted%20image%2020251019184103.png)

```
echo '10.129.83.246 board.htb' >> /etc/hosts
```

![Pasted image 20251019184026](Pasted%20image%2020251019184026.png)

```
echo '10.129.83.246 crm.board.htb' >> /etc/hosts
```

![Pasted image 20251019184237](Pasted%20image%2020251019184237.png)

admin:admin >ok

![Pasted image 20251019185923](Pasted%20image%2020251019185923.png)
Click on website

![Pasted image 20251019190033](Pasted%20image%2020251019190033.png)


Let's create one, we can see that we can write php code by changing php to pHp when we click on edit html code

![Pasted image 20251019190158](Pasted%20image%2020251019190158.png)
![Pasted image 20251019190239](Pasted%20image%2020251019190239.png)
![Pasted image 20251019190255](Pasted%20image%2020251019190255.png)
So we put a reverse shell on it, we start our listener, and we refresh the page

![Pasted image 20251019190355](Pasted%20image%2020251019190355.png)

After stabilising our shell, we enumerate the folder and find the file conf.php under /var/www/html/crm.board.htb/htdocs/conf 

which reveal a password

![Pasted image 20251019191414](Pasted%20image%2020251019191414.png)

We try the password for user "larissa" that we found under the home directory and it worked

So we login under larissa via ssh and grab the user.txt

![Pasted image 20251019191516](Pasted%20image%2020251019191516.png)

We look for SUID binary and we found enlightnment that look interesting

We check it's version and after some research we found that it's vulnerable

After doing the exploit we found here, we got root