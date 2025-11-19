[English](https://github.com/gobysec/Research/blob/main/README.md)｜ [中文](https://github.com/gobysec/Research/blob/main/README-zh.md)

# AI技术研究 - Goby

## [《什么？这条Poc/EXP的作者竟是？ 》 ](https://github.com/gobysec/Research/blob/main/%E4%BB%80%E4%B9%88%EF%BC%81%E8%BF%99%E6%9D%A1PoCEXP%E7%9A%84%E4%BD%9C%E8%80%85%E7%AB%9F%E6%98%AF%EF%BC%9F.md)

摘要：文为展示Goby AI 2.0的对EXP智能生成的技术攻略，及GobyAI 2.0 对《Supabase 后端服务平台 SQL注入漏洞》的实战检测成果演示。最终，AI Bot智能输出的Poc/EXP完美符合Goby漏洞收录标准。

# 安全技术研究 - Goby

## [《技术分享 | EXP能力升级（第一期）：从CVE-2025-61882看Goby如何破解路径固定难题 》 ]([https://github.com/gobysec/Research/blob/main/A_shortcut_to_vulnerability_debugging%3A_streamlining_code_to_speed_up_analysis_and_exploitation_zh_CN.md](https://github.com/gobysec/Research/blob/main/%E6%8A%80%E6%9C%AF%E5%88%86%E4%BA%AB%20%7C%20EXP%E8%83%BD%E5%8A%9B%E5%8D%87%E7%BA%A7%EF%BC%88%E7%AC%AC%E4%B8%80%E6%9C%9F%EF%BC%89%EF%BC%9A%E4%BB%8ECVE-2025-61882%E7%9C%8BGoby%E5%A6%82%E4%BD%95%E7%A0%B4%E8%A7%A3%E8%B7%AF%E5%BE%84%E5%9B%BA%E5%AE%9A%E9%9A%BE%E9%A2%98.md
))


摘要：本文为了便于调试能够快速复现该漏洞（CVE-2023-47246），尝试通过只使用部分的单元代码来模拟漏洞的主要逻辑流程进行动态调试分析。最终，成功利用 Goby 工具完美地实现了该漏洞的利用。
## [《漏洞分析 | 漏洞调试的捷径：精简代码加速分析与利用 》 ](https://github.com/gobysec/Research/blob/main/A_shortcut_to_vulnerability_debugging%3A_streamlining_code_to_speed_up_analysis_and_exploitation_zh_CN.md)

摘要：本文为了便于调试能够快速复现该漏洞（CVE-2023-47246），尝试通过只使用部分的单元代码来模拟漏洞的主要逻辑流程进行动态调试分析。最终，成功利用 Goby 工具完美地实现了该漏洞的利用。

## [《技术分享 | 针对蜜罐反制Goby背后的故事 》 ](https://github.com/gobysec/Research/blob/main/The_story_behind_countering_Goby_against_honeypots_zh_CN.md)

摘要：本文分享了Goby在实战过程中所遇到的蜜罐，并进一步进行了深入分析。

## [《技术分享 | 跨越语言的艺术：Flask Session 伪造 》 ](https://github.com/gobysec/Research/blob/main/The_Art_of_Crossing_Languages:_Flask_Session_Forgery_zh_CN.md)

摘要：本文以 Apache Superset 权限绕过漏洞（CVE-2023-27524） 为例讲述我们是如何在 Go 中实现 Flask 框架的 Session 验证、生成功能的。


## [《漏洞分析｜Adobe ColdFusion WDDX 序列化漏洞利用 》 ](https://github.com/gobysec/Research/blob/main/Adobe_ColdFusion_WDDX_Serialization_Vulnerability_Exploitation_zh_CN.md)

摘要：本文将分享继 CVE-2023-29300 之后的不出网利用方式，提出 C3P0 和 JGroups 两条基于服务错误部署的新利用链。

现 Goby 中实现了 C3P0 和 JGroups 利用链的完整利用，完全支持命令执行以及结果回显功能。


## [《漏洞分析｜Adobe ColdFusion 序列化漏洞（CVE-2023-29300）》](https://github.com/gobysec/Research/blob/main/Adobe_Coldfusion_remote_code_execution_vulnerability_Analysis_(CVE-2023-38204)_zh_CN.md)

摘要：本文将从 ColdFusion 2023 发布版的 Update 1 安全更新内容入手，详细分析 CVE-2023-29300 的漏洞成因，并提出一些后续的研究方向。

我们在 Goby 中已经集成了 CVE-2023-29300 漏洞的 JNDI 利用链（CVE-2023-38204），实现了命令执行回显和自定义 ldap 服务器地址的功能。

## [《漏洞分析｜Metabase 远程代码执行(CVE-2023-38646): H2 JDBC 深入利用》](https://github.com/gobysec/Research/blob/main/Metabase_Code_Execution_Vulnerability_(CVE-2023-38646)_Exploing_H2_JDBC_in_Depthzh_CN.md)

摘要：最近 Metabase 出了一个远程代码执行漏洞（CVE-2023-38646），我们通过研究分析发现该漏洞是通过 JDBC 来利用的。在 Metabase 中兼容了多种数据库，本次漏洞中主要通过 H2 JDBC 连接信息触发漏洞。目前公开针对 H2 数据库深入利用的技术仅能做到简单命令执行，无法满足实际攻防场景。

之前 pyn3rd 发布的 《Make JDBC Attacks Brilliant Again I 》 对 H2 数据库的利用中可以通过 RUNSCRIPT、TRIGGER 来执行代码，通过本次漏洞利用 TRIGGER + DefineClass 完整的实现了 JAVA 代码执行和漏洞回显，且在公开仅支持 Jetty10 版本的情况下兼容到了 Jetty11，以下是我们在 Goby 中成果。


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
