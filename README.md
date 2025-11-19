[English](https://github.com/gobysec/Research/blob/main/README.md)｜ [中文](https://github.com/gobysec/Research/blob/main/README-zh.md)

# AI Technology Research - Goby
## [*What! The author of this PoCEXP is actually...?* ](https://github.com/gobysec/Research/blob/main/What!%20The%20author%20of%20this%20PoCEXP%20is%20actually...%3F.md)
Abstract:This article aims to showcase the technical approach of Goby AI 2.0 in intelligently generating EXP (exploit codes) and demonstrate the practical detection results of GobyAI 2.0 on the "SQL Injection Vulnerability in Supabase Backend Service Platform". Ultimately, the Poc/EXP intelligently output by the AI Bot perfectly meets the inclusion criteria for Goby vulnerabilities.

# Research—By Goby
## [*Technical Sharing | EXP Capability Upgrade (Part 1): Solving the Fixed-Path Challenge in Goby – Insights from CVE-2025-61882* ](https://github.com/gobysec/Research/blob/44fc6dc51027ab732b92122e24c0958916474f7c/Technical%20Sharing%20%7C%20EXP%20Capability%20Upgrade%20(Part%201)%3A%20Solving%20the%20Fixed-Path%20Challenge%20in%20Goby%20%E2%80%93%20Insights%20from%20CVE-2025-61882.md)
Abstract：When the target only parses the Payload for fixed paths (e.g., CVE-2025-61882), the Goby EXP module cannot adapt. This article mainly introduces how the Goby EXP module upgrades its capabilities to address and break through this issue.

## [*A_shortcut_to_vulnerability_debugging:_streamlining_code_to_speed_up_analysis_and_exploitation* ](https://github.com/gobysec/Research/blob/main/A_shortcut_to_vulnerability_debugging%3A_streamlining_code_to_speed_up_analysis_and_exploitation_en_US.md)
Abstract：In order to facilitate debugging and quickly reproduce the vulnerability, this article attempts to simulate the main logic flow of the vulnerability by using only part of the unit code for dynamic debugging analysis.

## [*The_story_behind_countering_Goby_against_honeypots* ](https://github.com/gobysec/Research/blob/main/The_story_behind_countering_Goby_against_honeypots_en_US.md#the-story-behind-countering-goby-against-honeypots)
Abstract：This article shares the honeypots that Goby encountered in actual combat and further conducted in-depth analysis.

## [*The Art of Crossing Languages: Flask Session Forgery* ](https://github.com/gobysec/Research/blob/main/The_Art_of_Crossing_Languages%3A_Flask_Session_Forgery_en_US.md)
Abstract：This article takes the Apache Superset permission bypass vulnerability (CVE-2023-27524) as an example to describe how we implement the Session verification and generation functions of the Flask framework in Go.

## [*Adobe ColdFusion WDDX Serialization Vulnerability Exploitation* ](https://github.com/gobysec/Research/blob/main/Adobe_ColdFusion_WDDX_Serialization_Vulnerability_Exploitation_en_US.md)

Abstract：This article will share the non-network exploitation method following CVE-2023-29300, and propose two new exploitation chains based on service error deployment, C3P0 and JGroups. 

## [*Adobe Coldfusion remote code execution vulnerability Analysis (CVE-2023-38204)* ](https://github.com/gobysec/Research/blob/main/Adobe_Coldfusion_remote_code_execution_vulnerability_Analysis_(CVE-2023-38204)_en_US.md)

Abstract：This article will start by examining the content of the security update in ColdFusion 2023 Release Update 1, analyze the cause of CVE-2023-29300, and propose some follow-up research directions.

In Goby, we have integrated the JNDI exploitation chain (CVE-2023-38204) for CVE-2023-29300, enabling command execution and custom LDAP server address functionality. 

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
