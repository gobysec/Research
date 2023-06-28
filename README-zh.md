[English](https://github.com/gobysec/Research/blob/main/README.md)｜ [中文](https://github.com/gobysec/Research/blob/main/README-zh.md)

# 安全技术研究 - Goby

## [《漏洞分析｜死磕Jenkins漏洞回显与利用效果》](https://github.com/gobysec/Research/blob/main/Exploring_Jenkins_Vulnerability_for_Echoing_and_Exploitation_Effects_zh_CN.md)

摘要：本文以Jenkins反序列化漏洞作为优化案例，分享我们的解决漏洞问题的方式。首先，用户反馈了Jenkins 漏洞无法利用的问题。在漏洞分析过程中，发现之前的EXP利用中依赖了一个jar包，由于Goby没有外挂该jar包导致漏洞的无法利用。如果我们重新加入这个jar包的话，会使Goby程序变得臃肿，且这种利用方式没有回显效果，这并不符合Goby简洁高效、多版本兼容性、具有直接的回显效果的漏洞标准。因此，我们通过分析CVE-2017-1000353的相关材料，研究Jenkins的回显功能，最终在Goby上完成了高版本兼容、一键命令执行、反弹shell的效果，让漏洞利用变得更加简洁、直观、高效。

## [《Headshot ⼀击即中，对指定URL进行漏洞批量扫描》](https://github.com/gobysec/Research/blob/main/Headshot_One_Strike_Vulnerability_Scanning_for_Designated_URLs_in_Batches_zh_CN.md)

摘要：插件 Headshot，其功能是给用户提供自定义选择POC以及输入URL地址的渠道，让用户在真实的攻防场景中，能够较快的对指定URL地址完成POC检测和利用，这使得我们在面对类似Struts2这样的攻防场景的时候，可以更为灵活的使用Goby来解决问题。

## [《死磕RDP协议，从截图和爆破说起》](https://github.com/gobysec/Research/blob/main/RDP_protocol_research_%20we_have_implemented_RDP_screenshot_and_brute-force_functionalities_on_Goby_zh_CN.md)

摘要：大家聊到 RDP 除了协议信息提取之外，更多的是从两个方面来进行研究：密码爆破和截图。在 RDP 爆破领域用得比较多的是 ncrack/hydra/medusa 等，截图工具讨论比较多的是 RDPy 和 Scryin 等，但经过我们的实际测试，发现存在很多不足的地方。其结果甚至可以用惨不忍睹来形容。我们决定用纯 Golang 的形式实现更快、更轻松地暴力破解和更全面的屏幕截图，最终，我们在 Goby 中完成了所有工作。

<br/>

<br/>

**[Goby 官网: https://gobysec.net/](https://gobysec.net/)** 

如果您有任何反馈建议，您可通过提交 issue 或是以下方式联系我们：

1. GitHub issue: [https://github.com/gobysec/Goby/issues](https://github.com/gobysec/Goby/issues)
2. 微信群：关注公众号“GobySec“，回复暗号”加群“ （社群优势：可第一时间了解Goby功能发布、活动等咨询）
3. Telegram Group: [http://t.me/gobies](http://t.me/gobies) 
4. 推特：[https://twitter.com/GobySec](https://twitter.com/GobySec)
