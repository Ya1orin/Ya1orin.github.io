---
title: "THM Boiler CTF"
description: "TryHackMe篇之Boiler CTF"

date: 2024-10-07T15:17:47+08:00
lastmod: 2025-11-11T10:58:45+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.20.169

# 信息收集

## nmap扫描

`nmap --min-rate 10000 -p- -sV -sC 10.10.20.169 -oN reports/namp`

![image-20241007155136615](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007155138247-2005312162.png)

发现开放21，80，10000，55007端口，55007端口运行着ssh服务

## 21端口

根据nmap的结果发现ftp可以匿名登录

`ftp anonymous@10.10.20.169`

![image-20241007153622117](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007153623844-1063595684.png)

发现隐藏文件`.info.txt`，`get`下来查看

![image-20241007153721753](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007153723166-2130415327.png)

内容像是被`rot13`加密过的，尝试解密

![image-20241007154328354](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007154329949-234648714.png)

解密后发现是一个提示性的文字，告诉我们需要枚举

## 80端口

![image-20241007155407443](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007155409570-1133252866.png)

默认页面是一个`apache`的初始页面

先扫描一下目录

`gobuster dir -u http://10.10.20.169/ -w /usr/share/wordlists/dirb/common.txt`

![image-20241007160928359](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007160930195-2042932885.png)

发现很多有意思的目录，查看一下

### robots.txt

![image-20241007161041169](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007161042789-96937162.png)

给的目录并没有内容返回都是404，重点看下面的一串数据

![image-20241007162015403](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007162017100-1297401618.png)

解密后得到另一串数据`99b0660cd95adea327c54182baa51584`

看起来像md5数据，使用`hashcat`解密

`hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt`

![image-20241007162347491](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007162349391-1423906262.png)

解出来的数据是`kidding`，现在看来没什么用

### manual

![image-20241007162653988](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007162655725-2004416225.png)

是一个`apache`的文档，可以知道的是版本号是2.4

### joomla

![image-20241007162746149](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007162747852-2035223215.png)

这是一个cms

# 获取初始shell

刚才知道了是`joomla`系统，继续深入扫描一下目录

`gobuster dir -u http://10.10.20.169/joomla -w /usr/share/wordlists/dirb/common.txt`

![image-20241007163606266](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007163608399-43319589.png)

这次目录有点多

测试后发现只有几个有内容

![image-20241007164554560](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007164556241-928049236.png)

最重要的是这个，在`/joomla/_test`目录下发现有[sar2html](https://www.onworks.net/zh-CN/software/app-sar2html)

使用`searchsploit`搜索一下相关漏洞

![image-20241007165327179](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007165329033-1102727197.png)

用的是第一个，复制到当前目录

![image-20241007165422004](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007165423725-2036887988.png)

查看内容后发现是在url处控制`plot`参数，通过值拼接实现RCE，利用一下

![image-20241007170009665](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007170011069-1384604430.png)

命令执行成功

查看一下`log.txt`

![image-20241007170050140](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007170051671-1800575054.png)

发现`basterd`用户使用密码 `superduperp@$$`通过ssh连接机器，我们之前扫描结果中ssh端口发现是55007

我们使用这个凭据尝试连接

`ssh basterd@10.10.20.169 -p 55007`

![image-20241007170418958](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007170420582-601376213.png)

连接成功，拿到`basterd`用户的shell

# 横向移动

![image-20241007170545779](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007170547184-1714231114.png)

在`/home/basterd`目录发现`backup.sh`文件

![image-20241007170639847](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007170641598-69828711.png)

查看后发现另一个用户`stoner`，以及密码`superduperp@$$no1knows`，直接登录`stoner`用户

![image-20241007171142250](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007171143692-1069757611.png)

登陆成功

![image-20241007171245935](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007171247398-1778280610.png)

在`/home/stoner`目录下找到隐藏文件`.secret`，其内容就是`user.txt`

# 权限提升

![image-20241007171442288](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007171443860-578181515.png)

并没有什么可以利用的

使用`find`看看能否有提权的机会

`find / -perm -u=s -type f 2> /dev/null`

![image-20241007171621747](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007171623374-472604132.png)

发现有find，利用find命令提权

![image-20241007171907091](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007171908473-623085440.png)

提权成功

![image-20241007171949819](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007171951300-1248330287.png)

同样在`/root`目录下获取到`root.txt`

![image-20241007172143822](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007172145341-43973699.png)