# 通过官方demo剖析spring security原理

> 请注意，本次简析尽可能的照顾了初学者，也会循序渐进的解释很多spring相关机制，
但是仍然希望读者能对spring有一定的了解，个人水平有限，很难面面俱到。

>再注意，作者心态是在个人做记录前提下所写，会优先照顾个人感官。
>但还是建议想看spring源码但不知道如何下手并且在这个spring boot大时代下更是一脸蒙的小朋友坚持看一下


阅读本文可能对你有以下帮助：

* 完全不知道怎么查看spring/spring boot源码的小盆宇知道怎么去从哪里开始捋spring相关代码
* 了解spring security整体配置工作流程（这里不得不吐槽一下为什么网上博文大多都是如何运行，却不说spring security写得最绕的配置流程如何实现的）
* 了解到spring security强大的设计哲学，并惊叹一声：牛逼！

阅读本文你可能需要：

* 一丢丢spring boot使用经验
* 你不能太了解spring boot
* 你不能太了解spring security
* 你可以了解spring

# 项目构建

戳>>>>>>>[官方文档](https://spring.io/guides/gs/securing-web/)

戳>>>>>>>[我的示例](https://github.com/zidoshare/spring-boot-security-demo)

# 系列文章

* [从spring boot的逻辑里看spring security如何生效](./pre.md)