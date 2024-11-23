+++
title = 'hugo图片插入 结合obsidian的工作流'
date = 2024-09-16T18:03:22+08:00
draft = false
categories = ['CS']
+++

## hugo 添加图片

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