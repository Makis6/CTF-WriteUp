
![[steamcloud logo.png]]


Nmap scan

```
nmap -sVC -p- 10.129.79.50 -oN scan.txt
```

![Pasted image 20251023210257](Image/Pasted%20image%2020251023210257.png)

Looks like we have to pwn a kubernetes cluster machine.
When going on the port 8443 it says that the access is forbidden to anonymous user.

After a lot of research on HackTricks to see how to pentest kubernetes (cause i didn't know how to do it). 
I found the tool **kubeletctl** to enumerate the port 10250 which is the service that **run in every node of the cluster**. It's the service that will **control** the pods inside the **node**. It talks with the **kube-apiserver**.

First, let's enumerate the pods 

```
kubeletctl --server 10.129.96.167 pods
```

![Pasted image 20251023210810](Image/Pasted%20image%2020251023210810.png)

There is a default container that might be interesting, let's see on which container we can have an rce

![Pasted image 20251023210924](Image/Pasted%20image%2020251023210924.png)

We indeed have an rce on the nginx conteiner, let's get a shell into it

![Pasted image 20251023211029](Image/Pasted%20image%2020251023211029.png)

Ok we got root access in the container. We grab the user flag in the root directory and let's see what we can find. According to HackTricks, we might find a token in one of these place 
- `/run/secrets/kubernetes.io/serviceaccount`
- `/var/run/secrets/kubernetes.io/serviceaccount`
- `/secrets/kubernetes.io/serviceaccount`

![Pasted image 20251023211246](Image/Pasted%20image%2020251023211246.png)

Ok we got a token and a cert. Let's save them to enumerate the 8443 port since we can now authentify with these 2.

First we add the token to the variable token

![Pasted image 20251023211425](Image/Pasted%20image%2020251023211425.png)
and create a file ca.crt containing the certificate previously gained.

Let's now use the tool **`kubectl`** now which focus on the port 8443.

Again we will enumerate the pods to see if have access to the kube-apiserver

![Pasted image 20251023211810](Image/Pasted%20image%2020251023211810.png)

Ok so it's indeed working.
Let's see our rights to see what we can do

![Pasted image 20251023211937](Image/Pasted%20image%2020251023211937.png)

We have the privilege to create pods. 

So it means that we can create a privileged pods that could get access to the files that the node has. To do so, we look at the docs of Kubernetes that indicate how to do so. 
https://kubernetes.io/fr/docs/concepts/storage/volumes/#hostpath

We first need to create a yml file to create our pod, it has information such has it's name, the image of the container (if we go on http://10.129.96.167:10250 we can see that the image for nginx is **1.14.2**), the path on the host that we want to copy, etc...

Here is our file 

```
apiVersion: v1
kind: Pod
metadata:
  name: a
spec:
  containers:
  - image: nginx:1.14.2
    name: a
    volumeMounts:
    - mountPath: /root
      name: test-volume
  volumes:
  - name: test-volume
    hostPath:
      # chemin du dossier sur l'hôte
      path: /
```

Let's create the pod now

```
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.167:8443 apply -f a.yml
```
![Pasted image 20251023213021](Image/Pasted%20image%2020251023213021.png)

We get back to the tool **kubeletctl** to get a shell in the conteiner and get the root flag

![Pasted image 20251023213135](Image/Pasted%20image%2020251023213135.png)




