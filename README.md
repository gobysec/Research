[English](https://github.com/gobysec/Research/blob/main/README.md)｜ [中文](https://github.com/gobysec/Research/blob/main/README-zh.md)

# Research—By Goby

## [*Metabase Code Execution Vulnerability (CVE-2023-38646): Exploiting H2 JDBC in Depth* ](https://github.com/gobysec/Research/blob/main/Metabase_Code_Execution_Vulnerability_(CVE-2023-38646)_Exploiting_H2_JDBC_in_Depth_en_US.md)

Abstract：Recently, Metabase has encountered a remote code execution vulnerability (CVE-2023-38646). Our research and analysis have revealed that this vulnerability is exploited through JDBC. Metabase supports multiple databases, and in this particular vulnerability, it is primarily triggered through H2 JDBC connection information. Currently, the publicly available techniques for in-depth exploitation of the H2 database only allow for simple command execution, which does not meet the requirements of real-world attack and defense scenarios.

Previously, pyn3rd published "Make JDBC Attacks Brilliant Again I," which demonstrated the exploitation of the H2 database. By using RUNSCRIPT and TRIGGER, they were able to execute code. Through the exploitation of this vulnerability using TRIGGER + DefineClass, complete Java code execution and vulnerability echo were achieved. Additionally, this technique is compatible with Jetty11, even though only Jetty10 is officially supported. The following is the achievement we made in Goby.

## [*Vulnerability Analysis | Exploring Jenkins Vulnerability for Echoing and Exploitation Effects* ](https://github.com/gobysec/Research/blob/main/Exploring_Jenkins_Vulnerability_for_Echoing_and_Exploitation_Effects_en_US.md)

Abstract：In this article, we take the Jenkins deserialization vulnerability as an optimization case study to share our approach in addressing vulnerability issues. First, users reported an issue with the inability to exploit the Jenkins vulnerability. During the vulnerability analysis process, we found that the previous exploit relied on a specific JAR file, which Goby did not have integrated, resulting in the inability to exploit the vulnerability. Reintroducing this JAR file into Goby would make the program bloated, and this exploitation method lacks the desired echo effect, which is not in line with Goby's standards of simplicity, efficiency, high compatibility with multiple versions, and direct echo effect for vulnerabilities. Therefore, by analyzing the relevant materials of CVE-2017-1000353 and studying Jenkins' echo functionality, we ultimately achieved high version compatibility, one-click command execution, and reverse shell effect on Goby. This made the vulnerability exploitation process more concise, intuitive, and efficient.

## [*Headshot: One Strike, Vulnerability Scanning for Designated URLs in Batches* ](https://github.com/gobysec/Research/blob/main/Headshot_One_Strike_Vulnerability_Scanning_for_Designated_URLs_in_Batches_en_US.md)

Abstract：Headshot，it allows users to input URLs and select custom PoCs, making it easier to conduct real-world penetration testing and exploitation. With this plugin, we can now use Goby more flexibly to deal with scenarios like Struts2 vulnerabilities.

## [*RDP protocol research, we have implemented RDP screenshot and brute-force functionalities on Goby* ](https://github.com/gobysec/Research/blob/main/RDP_protocol_research_%20we_have_implemented_RDP_screenshot_and_brute-force_functionalities_on_Goby_en_US.md)

Abstract：When people talk about RDP, in addition to protocol information extraction, they mostly focus on two aspects of research: password cracking and screenshots. Ncrack/hydra/medusa are commonly used in the field of RDP cracking, while RDPy and Scryin are popular screenshot tools. However, through our actual testing, we found that there were many shortcomings, and the results were even described as terrible. We decided to implement faster, easier brute-force cracking and more comprehensive screenshot functionalities purely in Golang. In the end, we accomplished all the work in Goby.

<br/>

<br/>

[Goby Official URL](https://gobies.org/)

If you have a functional type of issue, you can raise an issue on GitHub or in the discussion group below:

1. GitHub issue: https://github.com/gobysec/Goby/issues
2. Telegram Group: http://t.me/gobies (Community advantage: Stay updated with the latest information about Goby features, events, and other announcements in real-time.) 
3. Telegram Channel: https://t.me/joinchat/ENkApMqOonRhZjFl 
4. Twitter：[https://twitter.com/GobySec](https://twitter.com/GobySec)
