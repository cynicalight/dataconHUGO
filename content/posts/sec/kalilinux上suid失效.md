+++
title = 'kali linux上suid失效'
date = 2024-11-11T11:50:27+08:00
draft = false
categories = ['CS', 'sec']
+++


经过 gpt 的指点，发现问题在于文件系统挂载设置了 nosuid：
![](../../img/Pasted%20image%2020241110234106.png)

查看目标文件的文件系统挂载设置的命令：
```bash
mount | grep `df --output=target targetfile | tail -1`
```
- df 查找目标文件所在的文件系统

换个目录就行了，一般 `~` 是不会设置  nosuid 的，可以正常使用 suid。
