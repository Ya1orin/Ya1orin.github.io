---
title: "THM Bolt"
description: "TryHackMe篇之Bolt"

date:  2024-10-01T10:07:48+08:00
lastmod: 2025-11-11T10:32:24+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

>  靶机ip：10.10.48.19

# 信息收集

## nmap扫描

`nmap -sS -sV -sC 10.10.48.19`

```text
# Nmap 7.94SVN scan initiated Tue Oct  1 10:13:36 2024 as: nmap -sS -sV -sC -o out.txt 10.10.48.19
Nmap scan report for 10.10.48.19
Host is up (0.37s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 f3:85:ec:54:f2:01:b1:94:40:de:42:e8:21:97:20:80 (RSA)
|   256 77:c7:c1:ae:31:41:21:e4:93:0e:9a:dd:0b:29:e1:ff (ECDSA)
|_  256 07:05:43:46:9d:b2:3e:f0:4d:69:67:e4:91:d3:d3:7f (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
8000/tcp open  http    (PHP 7.2.32-1)
|_http-title: Bolt | A hero is unleashed
|_http-generator: Bolt
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 Not Found
|     Date: Tue, 01 Oct 2024 02:14:09 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.32-1+ubuntu18.04.1+deb.sury.org+1
|     Cache-Control: private, must-revalidate
|     Date: Tue, 01 Oct 2024 02:14:09 GMT
|     Content-Type: text/html; charset=UTF-8
|     pragma: no-cache
|     expires: -1
|     X-Debug-Token: 5d427e
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Bolt | A hero is unleashed</title>
|     <link href="https://fonts.googleapis.com/css?family=Bitter|Roboto:400,400i,700" rel="stylesheet">
|     <link rel="stylesheet" href="/theme/base-2018/css/bulma.css?8ca0842ebb">
|     <link rel="stylesheet" href="/theme/base-2018/css/theme.css?6cb66bfe9f">
|     <meta name="generator" content="Bolt">
|     </head>
|     <body>
|     href="#main-content" class="vis
|   GetRequest:
|     HTTP/1.0 200 OK
|     Date: Tue, 01 Oct 2024 02:14:09 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.32-1+ubuntu18.04.1+deb.sury.org+1
|     Cache-Control: public, s-maxage=600
|     Date: Tue, 01 Oct 2024 02:14:09 GMT
|     Content-Type: text/html; charset=UTF-8
|     X-Debug-Token: cc4424
|     <!doctype html>
|     <html lang="en-GB">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Bolt | A hero is unleashed</title>
|     <link href="https://fonts.googleapis.com/css?family=Bitter|Roboto:400,400i,700" rel="stylesheet">
|     <link rel="stylesheet" href="/theme/base-2018/css/bulma.css?8ca0842ebb">
|     <link rel="stylesheet" href="/theme/base-2018/css/theme.css?6cb66bfe9f">
|     <meta name="generator" content="Bolt">
|     <link rel="canonical" href="http://0.0.0.0:8000/">
|     </head>
|_    <body class="front">
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=10/1%Time=66FB5AEF%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,29E1,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Tue,\x2001\x20Oct\
SF:x202024\x2002:14:09\x20GMT\r\nConnection:\x20close\r\nX-Powered-By:\x20
SF:PHP/7\.2\.32-1\+ubuntu18\.04\.1\+deb\.sury\.org\+1\r\nCache-Control:\x2
SF:0public,\x20s-maxage=600\r\nDate:\x20Tue,\x2001\x20Oct\x202024\x2002:14
SF::09\x20GMT\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\nX-Debug-T
SF:oken:\x20cc4424\r\n\r\n<!doctype\x20html>\n<html\x20lang=\"en-GB\">\n\x
SF:20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20charset=
SF:\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20name=\"viewport\"\
SF:x20content=\"width=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<title>Bolt\x20\|\x
SF:20A\x20hero\x20is\x20unleashed</title>\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<link\x20href=\"https://fonts\.googleapis\.com/css\?family=Bitter\|Rob
SF:oto:400,400i,700\"\x20rel=\"stylesheet\">\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20<link\x20rel=\"stylesheet\"\x20href=\"/theme/base-2018/css/bulma\.c
SF:ss\?8ca0842ebb\">\n\x20\x20\x20\x20\x20\x20\x20\x20<link\x20rel=\"style
SF:sheet\"\x20href=\"/theme/base-2018/css/theme\.css\?6cb66bfe9f\">\n\x20\
SF:x20\x20\x20\t<meta\x20name=\"generator\"\x20content=\"Bolt\">\n\x20\x20
SF:\x20\x20\t<link\x20rel=\"canonical\"\x20href=\"http://0\.0\.0\.0:8000/\
SF:">\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body\x20class=\"front\">\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20<a\x20")%r(FourOhFourRequest,1527,"HTT
SF:P/1\.0\x20404\x20Not\x20Found\r\nDate:\x20Tue,\x2001\x20Oct\x202024\x20
SF:02:14:09\x20GMT\r\nConnection:\x20close\r\nX-Powered-By:\x20PHP/7\.2\.3
SF:2-1\+ubuntu18\.04\.1\+deb\.sury\.org\+1\r\nCache-Control:\x20private,\x
SF:20must-revalidate\r\nDate:\x20Tue,\x2001\x20Oct\x202024\x2002:14:09\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\npragma:\x20no-ca
SF:che\r\nexpires:\x20-1\r\nX-Debug-Token:\x205d427e\r\n\r\n<!doctype\x20h
SF:tml>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20init
SF:ial-scale=1\.0\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20<title>Bolt\x20\|\x20A\x20hero\x20is\x20unleashed</title>\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20<link\x20href=\"https://fonts\.googleap
SF:is\.com/css\?family=Bitter\|Roboto:400,400i,700\"\x20rel=\"stylesheet\"
SF:>\n\x20\x20\x20\x20\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=
SF:\"/theme/base-2018/css/bulma\.css\?8ca0842ebb\">\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/theme/base-2018/css/t
SF:heme\.css\?6cb66bfe9f\">\n\x20\x20\x20\x20\t<meta\x20name=\"generator\"
SF:\x20content=\"Bolt\">\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"#main-content\"\x20class=
SF:\"vis");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Oct  1 10:14:51 2024 -- 1 IP address (1 host up) scanned in 75.38 seconds
```

访问后发现，在80端口存在`apache`默认页面，在8000端口运行着`Bolt CMS`

## Bolt CMS

![image-20241001102140990](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001102149429-713047204.png)

在页面找到用户名和密码`bolt : boltadmin123`

网上搜索发现该CMS默认登录路由是`/bolt`，利用刚才获得的用户名密码登录

![image-20241001103512011](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001103519405-1390007359.png)

登录成功后发现该版本为`3.7.1`

# 漏洞利用

通过`searchsploit`查找后发现早期的RCE漏洞

![image-20241001103932318](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001103939174-1828313295.png)

为了方便后续操作，这里使用msf进行攻击

通过`msfconsole`启动msf后，使用search命令进行查询

![image-20241001104030417](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001104037415-657957668.png)

使用`use 0`命令使用

![image-20241001104155662](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001104202808-726963840.png)

输入`show options`查看必要参数

![image-20241001104300043](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001104306826-932568411.png)

将必要参数设置好

![image-20241001104529924](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001104536892-1525270064.png)

`run`启动

![image-20241001104654139](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001104701130-877158465.png)

发现直接就是`root`权限

![image-20241001105107234](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241001105113891-316756031.png)

最终在`/home`目录下找到flag