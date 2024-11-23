+++
title = '在 macOS m1 上使用 哋它亢 安装 WinXP 解决 哋它亢 传输问题'
date = 2024-10-14T22:25:31+08:00
draft = false
categories = ['CS']
slug = 'dj32292'
+++

## 安装系统

UTM 安装，选择模拟或者从 UTM 库中下载，xp 的 iso 要自己另外下载：
![](../../img/Pasted%20image%2020241014221729.png)

---
## 文件传输

用 spice tools / 网上邻居 / qq邮箱 都无效，最终被这个 meta 老哥启发了：
- [milen.me — Exploring Windows XP on macOS ARM64](https://milen.me/writings/exploring-windows-xp-on-macos-arm64/)
![](../../img/Pasted%20image%2020241014222157.png)

直接把软件打包成一个 iso，插入虚拟机当作磁盘就完事了。
![](../../img/Pasted%20image%2020241014222252.png)

- win.iso 是我打包的一些软件，打包操作在 macOS 上很方便，磁盘工具打包成 cdr 文件，再 `hdiutil makehybrid -iso -joliet -o win.iso win.cdr` 转成 iso 文件
