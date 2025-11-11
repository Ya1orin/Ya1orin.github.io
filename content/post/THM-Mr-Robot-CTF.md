---
title: "THM Mr Robot CTF"
description: "TryHackMe篇之Mr Robot CTF"

date: 2024-10-09T20:04:27+08:00
lastmod: 2025-11-11T12:00:47+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.202.26

# 信息收集

## nmap扫描

`nmap --min-rate 10000 -sS -sV -sC 10.10.202.26`

![image-20241009200954547](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009200958952-1307236102.png)

发现22，80等端口，但是ssh服务关闭了

## 80端口

![image-20241009201522229](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009201526558-368574539.png)

默认页面是一个类似于linux终端的界面，正常的命令执行不了，只能执行页面提供的命令

每个命令都测试了一下，并没有什么她特别重要的信息，先扫描一下目录

`gobuster dir -u http://10.10.202.26/ -w /usr/share/wordlists/dirb/common.txt`

![image-20241009203013287](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009203017797-1719379315.png)

结果很多，但是可以看出来这是一个`wordpress`的站

# 后台getshell

先查看一下哎`robots.txt`

![image-20241009203645784](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009203649868-7394202.png)

![image-20241009203724196](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009203728050-509535539.png)

找到第一个`key`

另一个文件`fsocity.dic`访问后自动下载了

![image-20241009204036224](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009204040584-1051975220.png)

打开后是个字典

接着访问扫描出来的结果时，发现在`/license`文件下有信息

![image-20241009204822920](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009204827064-1879933782.png)

很像`base64`编码，解码试试

![image-20241009204958248](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009205002306-1782867748.png)

得到一个用户名密码：`elliot:ER28-0652`

尝试登陆`wordpress`

![image-20241009205215191](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009205219208-88514281.png)

没想到这是个admn用户，赚翻啦

直接kali监听一手

![image-20241009210505770](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009210509904-1918358012.png)

将准备好的[php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)写在`404.php`上

![image-20241009212106883](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009212111435-983517017.png)

设置好ip和port后保存

浏览器访问`http://10.10.202.26/theme/twentyfifteen/404.php`

![image-20241009212844443](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009212848299-908977679.png)

拿到初始权限

# 提升至user权限

切换交互式shell

`python -c 'import pty;pty.spawn("/bin/bash")'`

![image-20241009213059186](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009213103248-2017368856.png)

`/home`下有`robot`用户，进入之后发现第二个`key`，但是我们查看不了，我们能查看另一个文件，根据其内容可以判断出这是`robot`的用户名和密码

将密码保存到文件`hash`中，用`hashcat`离线破解试试

`hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt`

![image-20241009213504820](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009213509026-1986403223.png)

破解成功，拿到`robot`用户的明文密码`abcdefghijklmnopqrstuvwxyz`

![image-20241009213612441](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009213616619-415158260.png)

![image-20241009213647123](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009213650967-1591154118.png)

拿到第二个`key`

# 提升至root权限

先尝试`sudo -l`

![image-20241009214043116](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009214047420-696985946.png)

ok，不让用

用`find`查一下特权命令

`find / -perm -u=s -type f 2> /dev/null`

![image-20241009214110829](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009214115004-1182315555.png)

发现有`nmap`，可以利用`nmap`提权

![image-20241009214558352](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009214602683-1592532035.png)

提权成功

![image-20241009214640433](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241009214644568-905281974.png)

在`/root`目录下找到最后一个`key`

