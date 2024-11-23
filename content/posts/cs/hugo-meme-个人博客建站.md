+++
title = 'hugo meme 个人博客建站'
date = 2024-09-17T01:52:54+08:00
draft = false
categories = ['CS']
+++


## 配置

配置文件：config.xoml

---
## 命令

### 新建文章

```bash
hugo new minimal_categories/xxx.md
```
- 为了找到对应的原型模板，以最底层的分类为创建目录


### Makefile
```makefile
run:
	# 复制图片
	cp -r /Users/jz/Library/Mobile\ Documents/iCloud~md~obsidian/Documents/ZJ\'s\ vault/img/Users/jz/blog_hugo/static/
	cp -r /Users/jz/Library/Mobile\Documents/iCloud~md~obsidian/Documents/ZJ\'s\ vault/img /Users/jz/blog_hugo/
	hugo
	hugo server

git:
	hugo; cd public; git add .; git commit -m 'update'; git push origin master;

```

- 注意：hugo server -D 是指包含草稿（draft）的本地预览

---
## 文章分类 categories

- 由于 font matter 繁琐但是重要，所以每篇文章都应该自动化写好 font matter
- font matter 中对应的 categories 反应了文章分类

可以利用 archetypes 原型模板来实现这一点：
![](../../img/Pasted%20image%2020240917013840.png)

当新建文件时，Hugo 会自动判断文章的原型模板，没找到对应的会使用 default。
```bash
hugo new sec/xxx.md
```

但是，Hugo 不能识别多层目录：
```bash
hugo new posts/sec/xxx.md
# 找不到对应原型，会使用 default
```

所以，content 中的文章内容是以最底层的分类为一个文件夹：
![](../../img/Pasted%20image%2020240917014514.png)

但是，font matter中可以设置多个 categories，实现类似树状的分类（多层分类），虽然本地 content文件夹中内容的呈现较乱一些，没有多层，但是网页文章真正分类的逻辑上还是可以呈现树状，记得每次 hugo new 创建新文章使用原型模板时，要以最底层的分类为创建目录即可。
![](../../img/Pasted%20image%2020240917014725.png)
- 另外，当创建 `cs/xxx.md` 时，我设定的原型中的 categories 是 `categories = ['CS', 'others']` ，感觉这样的逻辑是很好的，保证不会有零散的文章直接出现在一级分类之下。所有属于一级分类且没有进一步对应二级分类的文章应该全部归档到相应一级分类的 others 这个类别之下。


### 参考

- [Archetypes | Hugo](https://gohugo.io/content-management/archetypes/)

---
## 添加图片

### 配置

```bash
# 保存本地图片的真实目录
static/img

# 自动生成的网页的图片目录
public/img

# 仅是为了便于在obsidian编辑文章时能够查看图片额外设置的目录
img
```


### 原理

Hugo 在执行 `hugo` 命令时，将根目录下的 static 文件夹中的内容直接复制到 public 文件夹。对于网页来说 public 就是根目录，所以我们在 static 中 创建一个 img 放图片，对应网页应该访问：
```
![](/img/local.png)
```

在此基础上，由于 obsidian 在使用绝对路径时，生成的地址如下：
```
![](img/local.png)
```
- 因为开头缺少一个 `/` ，Hugo无法找到图片

所以决定改成相对路径，这样在原来 obsidian 的仓库中写的文章可以直接迁移到新的用于发博客的仓库，不用修改图片地址。

但是，由于本地图片实际位置是在 `static/img`，所以为了能在发博客的（obsidian）仓库中也能正常预览图片，我们在博客仓库根目录也复制一个 img 文件夹，至此问题解决。
- 原仓库的附件也同一放在根目录的 img 文件夹，这样地址是天然正确的

从已经写好的仓库中迁移文章到博客仓库的工作流就是：
- `bugo new posts/xxx.md`
- 复制原仓库 img文件夹 到 博客仓库的 static/img 和 img 文件夹
- 直接复制文章
- git 推上去


### 参考

- 基本原理：[Hugo如何在markdown里引用本地图片 - Jincheng9's blog](https://jincheng9.github.io/post/hugo-add-img/)
- 相对路径可行：[Hugo 博客插入图片的方法 | Cassius's Blog](https://www.yuweihung.com/posts/2021/hugo-blog-picture/)

---
## 修改网站图标

选一个图片，通过 [Favicon Generator for perfect icons on all browsers](https://realfavicongenerator.net/) 生成图标相关文件。

保留以下文件：
![](../../img/Pasted%20image%2020240916224159.png)

将这些文件移动到 ~/blog/static/icons/目录下，再将 favicon.ico、site.webmanifest
移动到 ~/blog/static/ 目录下。
![](../../img/Pasted%20image%2020240916224456.png)


最后将 site.webmanifest 重命名为 manifest.json，并修改：
```json
{
  "name": "Jolly",
  "short_name": "Jolly",
  "icons": [
    {
      "src": "./icons/android-chrome-512x512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ],
  "theme_color": "#ffffff",
  "background_color": "#ffffff",
  "display": "standalone"
}

```

- 要等一会才会生效


### 参考

- [MemE美化1 | 悠闲の小屋](https://keepjolly.com/posts/create/meme-custom-1/)


---
## gitalk 评论

直接在配置文件修改：
```
    ## Gitalk
    enableGitalk = true
    gitalkClientID = "Ov23liPEu4AuKJ8pJngH"
    gitalkClientSecret = "7d4d1885f291fa044647ca789920beb4fdae7fc4"
    gitalkRepo = "cynicalight.github.io"
    gitalkOwner = "cynicalight"
    gitalkAdmin = ["cynicalight"]

    # 1. default (`location.href`)
    # 2. pathname (`location.pathname`)
    # 3. hash (hash_filepath)
    # 4. custom:your_gitalk_id ("your_gitalk_id")
    gitalkID = "hash"

    gitalkNumber = -1
    gitalkLables = ["Gitalk"]

    # 1. default (`document.title`)
    # 2. custom:your_gitalk_title ("your_gitalk_title")
    gitalkTitle = "default"

    # 1. default (`location.href` + header.meta[description])
    # 2. href (`location.href`)
    # 3. custom:your_gitalk_body ("your_gitalk_body")
    gitalkBody = "default"

    # 1. default (`navigator.language || navigator.userLanguage`)
    # 2. Support [en, zh-CN, zh-TW, es-ES, fr, ru, de, pl, ko, fa, ja]
    gitalkLanguage = "zh-CN"

    gitalkDistractionFreeMode = false
    gitalkPerPage = 10
    gitalkPagerDirection = "last"
    gitalkCreateIssueManually = false
    gitalkProxy = "https://cors-anywhere.azm.workers.dev/https://github.com/login/oauth/access_token"
    gitalkStaggerDelayBy = 150
    gitalkAppearAnimation = "accordionVertical"
    gitalkEnterAnimation = "accordionVertical"
    gitalkLeaveAnimation = "accordionVertical"
    gitalkEnableHotKey = true
    # 说明：https://github.com/gitalk/gitalk

```

- 本地预览没效果，推到git上在线访问有效果





