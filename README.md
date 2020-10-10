## 简介

> Various encryption algorithms such as: **Base64, AES, DES, RSA, MD5, SHA1, SHA256...**

- 支持`.Net Framework`、`.Net Core`
- 支持常见的对称加密(AES\DES\\...)、非对称加密(RSA)、哈希算法（MD5\SHA1\\...）
- RSA：支持使用OpenSSL生成的密匙（`RSACryptoByOpenSslProvider`）加密\解密\签名\验签

```
特殊说明：
1. RSACryptoProvider：基于RSACryptoServiceProvider这个类，因为这个类并不支持跨平台，在windows上运行没有问题，但是只要你一放到Linux下运行就会异常。
2. RSACryptoByOpenSslProvider：支持跨平台（Windows\Linux\Mac\...），同时兼容RSACryptoProvider。
3. 如果仅在windows平台下使用，使用RSACryptoProvider或RSACryptoByOpenSslProvider都可以，建议使用后者（兼容前者）。
4. 如果在非windows平台下使用，请使用RSACryptoByOpenSslProvider，不要使用RSACryptoProvider（编译虽然没问题，但运行会报错）。

注：如果 .NETFramework < 4.6 的话，是无法使用RSACryptoByOpenSslProvider的。
```
- RSA算法优化：分段加密

```
已经通过分段加密的方式解决了当加密数据内容过长时会出现的报错：

使用非对称密钥加密数据时，一次加密的数据长度是：密钥长度/8-11，超过这个大小会报错：The message exceeds the maximum allowable length for the chosen options (117).
如果key的长度为1024位，1024/8 - 11 = 117，一次加密内容不能超过117bytes。
如果key的长度为2048位，2048/8 - 11 = 245，一次加密内容不能超过245bytes。
```

## Nuget包引用

> **Id：Sean.Core.Encryption**

- Package Manager

```
PM> Install-Package Sean.Core.Encryption
```

## 使用示例

> 项目：test\Demo.NetCore