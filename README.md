# Digging into the RDP protocol, starting from screenshots and brute force.

## 0x01 Overview

RDP (Remote Desktop Protocol) can be said to be the most widely used protocol under Windows. Just like SSH to Linux, RDP cannot be avoided in protocol analysis and network security research. We have previously written related articles on this, which are also reflected in the FOFA platform and Goby product. In fact, when people talk about RDP, in addition to protocol information extraction, they mostly focus on two aspects of research: password cracking and screenshots. Ncrack/hydra/medusa are commonly used in the field of RDP cracking, while RDPy and Scryin are popular screenshot tools. However, through our actual testing, we found that there were many shortcomings, and the results were even described as terrible.

Previously, in the Goby product, in order to achieve higher protocol compatibility (and for laziness), we completed the encapsulation of cracking and screenshot functions through the CGO compilation method using the embedded freerdp library. However, the user feedback was not good: low compatibility, low efficiency, easy to report errors, and a large program package size. Therefore, we decided to implement it in pure Golang form. Finally, we completed all the work in Goby.

## 0x02 Let's take a look

### 2.1 Our Goals

- Strong cross-platform compatibility

By using Golang and not using CGO, the compatibility of the tool is excellent, and there is no need to endure the terrible compilation and porting experience of C language.

- Faster login detection speed

The judgment logic of login detection is completely different in different RDP protocol versions, but one thing is the same: to be as fast as possible while ensuring accuracy.

- More protocol version compatibility

We have made every effort to be compatible with as many versions of RDP protocol and operating system versions as possible.

- More comprehensive RDP screenshots

We have gone through the entire process from establishing a connection to image processing for various versions of RDP protocols. Therefore, we cannot just focus on RDP brute force cracking alone.

### 2.2 Brute force cracking capability comparison

Since we have developed a tool for this purpose, we compared it with some of the best RDP brute force cracking tools currently available in the industry. We let the data speak for itself. In terms of brute force cracking capability, we selected a total of 7 widely used RDP brute force cracking tools for horizontal comparison. For more detailed test results, please refer to section 3.3 of this article.

[![p9lEYy8.png](https://s1.ax1x.com/2023/04/28/p9lEYy8.png)](https://imgse.com/i/p9lEYy8)



### 2.3 RDP screenshot capability comparison

#### 2.3.1 Don't you need to enter the password to see the screen first?

Microsoft officially introduced new security protocol versions, PROTOCL_HYBRID and PROTOCOL_HYBRID_EX, to address certain security issues and prevent users from entering the remote login interface without logging in. However, by default, to achieve higher compatibility, the server-side supports multiple security protocols simultaneously. Therefore, we just need to make some minor adjustments in ClientConnectionRequest to bypass NLA authentication and enter the remote login interface directly (of course, you are still not logged in).

Usually, we would use a lower version of mstsc.exe client to do this, but it doesn't work well on newer Windows operating systems (Windows 10):

[![p9lEGSP.png](https://s1.ax1x.com/2023/04/28/p9lEGSP.png)](https://imgse.com/i/p9lEGSP)

#### 2.3.2 Let the data speak for itself

Of course, we eventually solved this problem. But before that, let's take a look at the data. For RDP screenshot capability, we selected well-known RDP connection clients and RDP screenshot tools for horizontal comparison:

[![p9lEJQf.png](https://s1.ax1x.com/2023/04/28/p9lEJQf.png)](https://imgse.com/i/p9lEJQf)

- Scryin, as a tool focusing on screenshot implementation, performed very poorly in this test. I almost didn't get a complete picture using it.
- RDPy has not been maintained for a long time, but its popularity is exceptionally high, and it comes with a screenshot feature. However, we found that its support for lower versions of Windows is not good. (PS: I must complain that the environment configuration for RDPy is too difficult!)
- JumpDesktop, as a paid RDP connection client on the Mac platform, is very qualified. It will prioritize higher security protocols in newer operating systems and will not enter the interface directly.
- Although rdesktop has not been maintained for a long time, its compatibility is excellent!
- xfreerdp can be said to be the most well-known RDP library in the industry, but when we actually tested it, it crashed directly in the XRDP and Windows 2000 scenarios. This may be related to the version, but we did not do more testing.
- mstsc, as the official RDP connection tool provided by Windows, has excellent compatibility. The client of Windows 2003 version only has compatibility issues with Windows 10, and the client of Windows 7 version almost has no compatibility defects.
- Shodan is a network space mapping platform that should not be on this comparison list, but it has done quite a lot of RDP screenshot practice. We selected some assets of XRDP, Windows 2000, and Windows XP and did not find any successful screenshot cases.

In addition to achieving compatibility with all versions of Windows, Goby also supports some special versions, such as XRDP.

[![](https://res.cloudinary.com/marcomontalbano/image/upload/v1682651770/video_to_markdown/images/youtube--yAmDE3kx7ss-c05b58ac6eb4c4700831b2b3070cd403.jpg)](https://youtu.be/yAmDE3kx7ss "")

### 2.4 More detailed test results

All brute force cracking capability comparison tests were conducted in an intranet environment using a single username, single thread, and 100 dictionaries (the correct password is at the end). If the tool can correctly detect the password, it is judged as a success.

#### 2.4.1 Windows XP and Windows 2003

Since Windows XP and Windows 2003 both use the PROTOCOL_RDP protocol, the entire RDP protocol negotiation process needs to be completed before the user's login status can be determined. Therefore, successful tool detection times are longer. Ncrack's performance was very poor. Although it could correctly recognize the username and password directly, it was stuck in the brute force cracking scenario.

As you can see, Goby's performance is excellent. Both types of operating systems do not support NLA for verification, so we had to implement the entire process from establishing a connection to image processing. By using the auto-login feature, we can successfully log in to the system. However, we did a lot of experimental work on "how to determine if we have successfully logged in to the system". Finally, we decided to use the SAVE_SESSION_INFO event as the basis for judging whether the login was successful, which gave us a considerable advantage in verification speed (PS: about 40% faster).

[![p9lE1JI.png](https://s1.ax1x.com/2023/04/28/p9lE1JI.png)](https://imgse.com/i/p9lE1JI)

#### 2.4.2 Windows 7 and Windows 2008

In theory, Windows 7 and Windows 2008 can both support NLA, but some tools took more than 10 seconds for single detection because the tool prioritizes PROTOCOL_RDP, which requires the complete protocol negotiation process and causes efficiency issues. Surprisingly, Hydra and Medusa were unable to detect the correct password. After trying the first login, Medusa directly ends without performing subsequent brute force cracking, and Hydra reports an error: all children were disabled due to too many connection errors. Fscan's performance was astonishing. It only took 2 seconds to run through 100 dictionaries in the Windows 2008 scenario and finally successfully detected the correct password.

Goby's performance is still in the top tier. To avoid the server-side selecting inefficient PROTOCOL_RDP protocol, we made some slight adjustments in the ClientConnectionRequest stage, which made the detection speed qualitatively leap forward. In good network conditions, single detection only takes about 0.02 seconds.

[![p9lE3Wt.png](https://s1.ax1x.com/2023/04/28/p9lE3Wt.png)](https://imgse.com/i/p9lE3Wt)

#### 2.4.3 Windows 10

The test results on Windows 10 were surprising. More than half of the tools were unable to detect the correct password, which may be related to Windows 10's priority selection of the security protocol version: PROTOCOL_HYBRID_EX. Surprisingly, medusa, which had poor results in the previous test, performed very well. In the Windows 10 scenario, although Goby's performance was not the best, its detection speed was acceptable, with a single detection time of about 1 second.

[![p9lEtOS.png](https://s1.ax1x.com/2023/04/28/p9lEtOS.png)](https://imgse.com/i/p9lEtOS)

#### 2.4.4 XRDP and Windows2000

Based on the test results mentioned earlier, currently there is no tool that can perform brute-force attacks perfectly on XRDP and Windows2000 scenarios. Although Medusa claims to have Windows2000 brute-force cracking capabilities, we found a specialized optimization plan for brute-force cracking on Windows2000 using Medusa in a document. The principle is to utilize the excellent protocol compatibility of rdesktop and identify successful login by recognizing the feedback effect of input and output. However, our tests show that Medusa did not achieve the expected results.

We also tried many methods to achieve brute-force cracking ability for the XRDP and Windows2000 scenarios, but unfortunately, we ultimately failed.

We implemented the entire process from establishing a connection to image processing in the XRDP scenario, and XRDP supports automatic login function. We were able to smoothly enter the login interface, but after entering the desktop, we lacked a clear identifier to determine the login status. Because the applicable range of XRDP is very wide, the interface after successful login is diverse and difficult to identify, which would inevitably lead to some false positives. We cannot accept this, so we gave up.

As for Windows2000, the first obstacle we encountered was that it did not have an automatic login function. We had to simulate keyboard input to attempt login. Fortunately, we succeeded in this regard. However, we still could not accurately determine the login status because it may be due to the early version, Windows2000 does not send the SAVE_SESSION_INFO event after successful login, which caused us to encounter the same problem as XRDP.



## 0x03 Why do other tools perform so poorly in this scenario?

To find the reason, we need to start with the historical background of the RDP protocol. To date, the RDP protocol has developed six versions of its security protocols: PROTOCOL_RDP, PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_RDSTLS, PROTOCOL_HYBRID_EX, and PROTOCOL_RDSAAD.

[![p9lEawQ.png](https://s1.ax1x.com/2023/04/28/p9lEawQ.png)](https://imgse.com/i/p9lEawQ)

- In simple terms, these six protocols determine the way in which authentication and data protection are carried out during the RDP connection establishment process.

  ### 3.1 PROTOCL_RDP, PROTOCL_SSL

  PROTOCL_RDP is the original RDP connection interaction protocol, which implements data security in the RDP protocol itself. Its communication data is encrypted using RC4, with a specific key length ranging from 40 bits to 128 bits. PROTOCOL_SSL, on the other hand, is a layer of TLS on top of PROTOCOL_RDP. It was created because PROTOCOL_RDP had the risk of man-in-the-middle attacks. The relationship between the two can be compared to HTTP and HTTPS. In terms of brute-force attacks, we need to note the following:

  - PROTOCOL_RDP itself does not have Windows operating system authentication function at the protocol level. The protocol is only responsible for data transmission. This is why in earlier versions of Windows, users had to enter the graphical interface before entering the password.

  - In order to achieve single sign-on (SSO) (allowing users to enter the desktop without entering a username and password in the remote desktop interface), automatic login (AUTOLOGIN) was introduced in Windows2000 and later versions. Its effect is equivalent to the client helping the user complete the process of entering the password.

[![p9lEUeg.png](https://s1.ax1x.com/2023/04/28/p9lEUeg.png)](https://imgse.com/i/p9lEUeg)

### 3.2 PROTOCL_HYBRID, PROTOCOL_HYBRID_EX

As mentioned earlier, both PROTOCOL_RDP and PROTOCOL_SSL only carry out data transmission at the protocol level and do not carry out operating system authentication. This means that anyone can access the operating system login interface without identity authentication, which poses significant security risks. Older readers may remember some unique backdoor techniques from that era, such as input method backdoors and shift backdoors, which took advantage of this characteristic of the RDP protocol. From a usage perspective, the lack of identity authentication at the protocol level also means that single sign-on cannot be implemented, which is problematic.

PROTOCL_HYBRID and PROTOCOL_HYBRID_EX were designed to solve this problem. Starting with PROTOCOL_HYBRID, operating system authentication is provided by the Credential Security Support Provider (CredSSP) protocol during the TLS negotiation phase. In simple terms, the correct username and password must be entered before entering the remote desktop interface, which is commonly known as Network Level Authentication (NLA). This change has improved the security of the RDP protocol in most cases, but it has also introduced some new security risks, which will be discussed in detail later in this article.

[![p9lEdoj.png](https://s1.ax1x.com/2023/04/28/p9lEdoj.png)](https://imgse.com/i/p9lEdoj)

### 3.3 PROTOCOL_RDSTLS, PROTOCOL_RDSAAD

PROTOCOL_RDSTLS is an enhanced version of PROTOCOL_RDP that is usually applied in server redirection scenarios (RDP protocol load balancing, bastion hosts, etc.). Its data protection, encryption and decryption, and integrity verification are all completed by TLS. User authentication is accomplished by exchanging RDSTLS PUD during the PDU negotiation phase. PROTOCOL_RDSAAD is a variant of PROTOCOL_RDSTLS, and its authentication function is implemented by Azure AD-joined devices.

This protocol is generally not used for regular servers or personal office terminals, and after testing, almost all RDP objects that are compatible with PROTOCOL_RDSTLS and PROTOCOL_RDSAAD are also compatible with at least one of PROTOCOL_HYBRID and PROTOCOL_HYBRID_EX. Therefore, from the perspective of brute-force attacks, we can ignore these two protocols.

[![p9lE0Fs.png](https://s1.ax1x.com/2023/04/28/p9lE0Fs.png)](https://imgse.com/i/p9lE0Fs)

### 3.4 The Key Point

Please note that a server does not necessarily only support one security protocol. A server can support multiple security protocols. So how is the security protocol to be used determined in an independent RDP connection?

In all RDP protocol connections, the first packet sent by the client, called the ClientConnectionRequest, has a parameter called RequestedProtocol, which represents the protocols that the client tells the server it **can** use for the RDP connection (we can assume it is PROTOCOL_SSL and PROTOCOL_HYBRID). The server will **choose** one of them (such as PROTOCOL_HYBRID), and then return it to the client for **confirmation**. This **determines** the security protocol used in this RDP connection: PROTOCOL_HYBRID.

With the above prerequisites in mind, we can now attempt to answer why the test results of these tools are so terrible

#### 3.4.1、XRDP和Windows2000

- Almost all tools are unable to perform brute-force attacks on XRDP and Windows 2000 for the following reasons:
  1. Both Windows 2000 and XRDP do not support NLA, which means that all RDP connections will enter the remote desktop interface. Some tools use entering the remote desktop interface as the criterion for successful login, so they may mistakenly judge incorrect passwords as successful login attempts.
  2. The security protocol version used by Windows 2000 is PROTOCOL_RDP, which is also version-specific. The version used by Windows 2000 is RDP_VERSION_4, which is incompatible with most tools.
  3. Windows 2000 does not support the AUTOLOGIN function.
  4. There are certain differences between the RDP protocol used by XRDP and Windows, which most tools are unable to be compatible with.

#### 3.4.2 Windows XP and Windows 2003

Similar to Windows 2000 and XRDP, Windows XP and Windows 2003 also do not support NLA. However, weak password detection tools and 7kbscan-RDP-Sniper can still successfully perform brute-force attacks. This is because Windows 2003 and later versions support the AUTOLOGIN feature, which allows tools to determine whether a login attempt was successful in various ways after logging in.

#### 3.4.3 Windows 7 and Windows 2008

Almost all brute-force tools can support these two operating systems because they use the default security protocol PROTOCL_HYBRID, which allows easy use of NLA for login attempts without dealing with subsequent complex and strict RDP protocol negotiations and image processing. This is also the reason why the introduction of NLA has improved business scenarios and solved some security issues but also brought new security problems.

#### 3.4.4 Windows 10

Windows 10 uses the security protocol PROTOCL_HYBRID_EX by default, and some brute-force tools may not support this protocol.

## 0x04 Conclusion

With this, we are nearing the end of this article. Whether it is the development of tools or the testing of various tools with RDP screenshots or brute-force attacks, it has taken a lot of time and effort. The purpose of this article is not to belittle other tools, as they are all pioneers and pave the way for later advancements. Rather, it is to encourage us to speak up and criticize the imperfections of the tools during the usage process, and even try to make improvements. By using falsehood to attain the truth, we can make tools better. What is false and what is true? In Buddhism, the body is false, while the path to enlightenment is true. Tools are false, and technology is true. This applies not only to tools, but also to the industry and to ourselves. Ultimately, the goal is to improve ourselves through learning from our experiences.

Goby now possesses all the capabilities mentioned in this article. We welcome our readers to try it out by clicking on this link: https://gobysec.net/#dl

## 0x05 References

If there are any errors or omissions in the technical details mentioned in this article, please feel free to point them out and provide additional information.

- [MS-RDPBCGR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)
- [MS-RDPELE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/)
- [Extracting Operating System Information and Login Screenshots from RDP like Fofa](https://blog.csdn.net/u014736206/article/details/104154168)
- [Protocol Identification (RDP)](https://zhuanlan.zhihu.com/p/336936793)
- [tomatome/grdp](https://github.com/tomatome/grdp)
- [citronneur/rdpy](https://github.com/citronneur/rdpy)
- [rdesktop/rdesktop](https://github.com/rdesktop/rdesktop)

<br/>

<br/>
[Goby Official URL](https://gobies.org/)

If you have a functional type of issue, you can raise an issue on GitHub or in the discussion group below:

1. GitHub issue: https://github.com/gobysec/Goby/issues
2. Telegram Group: http://t.me/gobies (Community advantage: Stay updated with the latest information about Goby features, events, and other announcements in real-time.) 
3. Telegram Channel: https://t.me/joinchat/ENkApMqOonRhZjFl 
4. Twitter：[https://twitter.com/GobySec](https://twitter.com/GobySec)
