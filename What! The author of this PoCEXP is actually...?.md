I'm not sure if any meticulous experts have noticed that a mysterious label has been attached to a vulnerability in today's routine update of our vulnerability list.

**![](https://s3.bmp.ovh/imgs/2024/11/22/da58c99c47a976a3.webp)**

As you may have guessed, this is the first PoC/EXP created and written by AI Bot, a new member of the Goby Security Community.

Those who have submitted vulnerabilities to Goby know that every Goby vulnerability that goes online undergoes multiple layers of review. Not only is there a strict requirement for the detection logic of the PoC, but also for the verification effectiveness of the EXP related to the vulnerability. However, beyond our expectations, the PoC/EXP written by AI Bot fully meets the Goby vulnerability inclusion criteria.

Let's first take a look at the smooth operation process of AI Bot's intelligent conversion through a video:
**![](https://s3.bmp.ovh/imgs/2024/11/22/e20edd0c3d6f2c30.gif)**


# AI's Initial Attempt

One day, an anonymous expert from the Goby vulnerability team came up with a bold idea: "Since AI can already help us achieve semi-automatic PoC writing, then can we further train it to reach the level of fully automatic writing? Even better, if it can directly generate a PoC by just providing a document link with reference information, wouldn't that be amazing!"

Imagine how this can significantly lower the barrier to PoC writing, allowing even inexperienced "novices" to easily use Goby to write effective PoCs. This will undoubtedly bring significant efficiency improvements to our security research and vulnerability reproduction efforts.

Facing such challenges and opportunities, the Goby team took the first step without hesitation.

Soon, the first beta version of GobyAI was launched. Based on the feedback from the first batch of beta testers, although GobyAI performed well in the basic writing of PoCs, there is still room for improvement in conversion success rates. More importantly, in practical application scenarios, everyone is more concerned about the intelligent output of EXPs. Therefore, we have identified the key research and development direction of intelligent EXP output to fully demonstrate the value of GobyAI in practical applications.

# Teaching AI to Write EXPs is Not an Easy Task
In our previous practice of AI-generated PoC/EXPs, we found that it is almost impossible to write an EXP through pure JSON based on Goby's existing JSON framework, because different vulnerability types have completely different vulnerability validation parameters and may also have complex internal relationships.

Therefore, when manually entering vulnerabilities, EXPs are usually written in Go code, but this approach is difficult to implement on AI, and the quality of EXPs written directly by AI-generated Go code is very low due to significant differences in validation methods among different vulnerability types. So we must implement a vulnerability entry framework that achieves complex EXP validation effects through pure JSON.

In the latest Goby version, we have upgraded the JSON writing framework by introducing richer syntax and keywords to support diverse vulnerability validation methods. While providing a simpler way to write EXPs, it also opens up new possibilities for teaching AI to write EXPs.

Through the previous video, we can see that AI can fully implement various EXP validation effects of SQL injection vulnerabilities by generating JSON code. Before introducing the specific EXP code, it is necessary to first understand the operation logic of our ExpParams parameters, which determines what kind of Payload we will send for EXP validation.
EXPParams:

**![](https://s3.bmp.ovh/imgs/2024/11/22/645918494da79f84.webp)**
In Goby's vulnerability framework, we use a parameter array to pass specific vulnerability validation effects, first specifying all available validation methods through attackType, and then switching to the corresponding validation method using attackType=xxx. In each validation method, users can further define specific validation effects to meet the needs of different scenarios. Due to the excessive flexibility of EXPParams, it is not possible to process complex EXPParams in the original vulnerability framework, and the main difficulties are as follows:

How to send different Payloads based on the input EXPParams
How to echo different data based on different EXPParams
Therefore, in the new vulnerability framework, we have added various syntaxes to enhance the flexibility and execution ability of vulnerability validation:

switch :

To solve the first problem, we provide new function keywords to switch between different vulnerability validation methods. For example, in the case of SQL injection, three validation methods are usually supported: default, user input, and sqlpoint. The switch keyword can flexibly select the currently required validation method, thereby facilitating subsequent coding and related operations.

As shown in the figure below, different Payloads will be defined based on the value passed to attackType.
**![](https://s3.bmp.ovh/imgs/2024/11/22/168d44bf08be101c.webp)**

when:

Similarly, after solving the Payload problem, we need to solve the second problem. The when keyword is used to control the output content. In the EXP of SQL injection, when the attackType is sqlPoint, we need to print the sent request packet so that users can extract it for subsequent detection.
**![](https://s3.bmp.ovh/imgs/2024/11/22/b9e6f8fe0e91ab6c.webp)**

# Now It's AI's Turn

To address AI's support for different vulnerability types, we solve the EXP writing problem by constructing a collective agent model, with each vulnerability type handled by a dedicated agent. When the user inputs a vulnerability reproduction link or related article, the vulnerability information integration agent is responsible for mining the vulnerability information on the page, including parsing images and text content. Subsequently, the supervisory agent receives and further parses the vulnerability information, assigning tasks to the corresponding EXP agents based on the vulnerability type.

Taking the SQL injection agent as an example, when receiving vulnerability reference text, the agent first identifies the database type and generates corresponding SQL validation commands, while locating the position of the SQL command and replacing it with corresponding variables. The agent flexibly selects the switch and when keywords based on vulnerability characteristics and determines whether encoding is required. After writing, the agent feeds back the generated EXP file to the supervisory agent for review and confirmation, and outputs the final EXP file after approval.

As of now, the team continues to train and optimize GobyAI agents, enhancing the accuracy of EXP intelligent writing for complex vulnerability types (such as SQL injection, file upload, etc.). Compared to the 1.0 beta results, the intelligent conversion success rate of PoCs has been significantly improved. More importantly, the GobyAI 2.0 version can efficiently and accurately complete the intelligent writing of EXPs for some complex vulnerability types, achieving full-process intelligent practical application capabilities for PoC/EXP.

# AI Bot's Practical Test: SQL Injection Vulnerability in Supabase Backend Service Platform
By examining the publicly available reference information, we can understand the cause of the vulnerability: The Supabase backend service platform's /api/pg:meta/defaultquery does not validate and filter user-input data, allowing attackers to directly inject SQL statements into the database, resulting in SQL injection. This can lead to the acquisition of sensitive database information, and further exploitation may grant server permissions.

Here is the practical testing process of AI Bot:

1.Collect the reference link for vulnerability details: https://blog.csdn.net/qq_41904294/article/details/135443624

2.Automatically collect and complete information: The AI engine quickly parses the link content and extracts image content, distributing the parsed content to different subtasks for rapid parsing; √

3.Extract the vulnerability type as [SQL Injection] and analyze the payload; √

4.Assign the SQL Injection vulnerability type agent and parse the database type; √

5.Automatically generate PoC/EXP code that complies with Goexp standards, including Payload request parameters, database SQL execution statements for validation, execution methods, etc.; √
**![](https://s3.bmp.ovh/imgs/2024/11/22/3dc44275c8549c71.webp)**

6.One-click detection: Input the target of the test environment to accurately detect whether the target has the vulnerability; √
**![](https://s3.bmp.ovh/imgs/2024/11/22/7e1e51bdd3c32b33.webp)**

7.One-click verification: Click to verify, and accurately output the output information through the automatically generated SQL execution statement. √
**![](https://s3.bmp.ovh/imgs/2024/11/22/0d3d2c10c40ac2db.webp)**

An AI bot has fully automatically and intelligently written a PoC/EXP within 5 minutes, and the output has perfectly met the inclusion criteria for Goexp SQL injection vulnerabilities upon verification!

After completing the submission and review process, Goby officially announces the launch of its first PoC independently created by an AI bot!

Now, here's the highlight!

How can you experience this amazing GobyAI?

# Goby AI Seed Experience Officer Program 2.0 Launched!
Upgrade to the latest version 2.9.10 (download the latest version package from the official website or update your old client), and you will see the entry for GobyAI.
**![](https://s3.bmp.ovh/imgs/2024/11/22/745c9c7f98940cc0.webp)**

Scan the QR code to add GobyBot on WeChat and apply for the experience.

Note: All version users can apply for a free trial during this test period, with no thresholds!

Goby invites everyone to grow together with GobyAI!

At the same time, Goby welcomes all masters to join our community family, where you can chat, share interesting life stories, gossip, and make countless friends.

**![](https://s3.bmp.ovh/imgs/2024/11/22/1ccf55e76bb5402a.webp)**
